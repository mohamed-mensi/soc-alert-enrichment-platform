"""
live_watch.py
=============
One-process LIVE watcher for case management platform. Polls on an interval and routes every new
alert to exactly one enrichment pipeline, based on its tags:

    tag 'dlp-alert'        ->  DLPRunner          (outbound DLP investigation)
    tag 'phishing-report'  ->  PhishingEnrichment (inbound phishing triage)
    anything else          ->  EnrichmentEngine   (generic observable enrichment)

Why this file exists
--------------------
The generic pipeline already has a continuous loop (main.py + scheduler.py), but
the phishing and DLP runners poll once and exit. This watcher gives all three a
single live loop so alerts can be injected during a demo and enriched in real
time, in whatever order they arrive.

Design rules
------------
* ONE CasePlatformClient, so there is ONE poll cursor. Each alert is claimed by exactly
  one pipeline and processed exactly once (exclusive routing). Running the three
  standalone runners side by side would give each its own cursor, and every
  email alert would be enriched twice with conflicting write-backs.
* Listening starts from "now" by default, so a demo does not replay the whole
  alert history. Use --backfill to process alerts already in case management platform.
* This file adds NO enrichment logic. It calls the same code paths the
  standalone runners call, so behaviour is identical to running them by hand.
  Nothing in the platform imports this file, so it cannot regress production.
* Threat-feed collection is deliberately excluded (that is main.py's job) so a
  slow feed or network hiccup cannot stall the watcher.
* Every alert is processed inside its own try/except: one failing alert logs and
  the loop keeps listening.

Usage:
    cd soc_enrichment
    python live_watch.py                  # listen for NEW alerts, 10s poll
    python live_watch.py --interval 5     # faster poll
    python live_watch.py --backfill       # also process pre-existing alerts
    python live_watch.py --once           # single pass, then exit
    python live_watch.py --log-level WARNING   # quiet the component chatter

Stop with Ctrl+C. A per-route summary is printed on exit.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Repo root on sys.path before any project import, so the watcher can be started
# from any working directory. Relative paths (reports/, templates/) still resolve
# against the current directory, so run it from the repo root.
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("live_watch")

DLP_TAG         = "dlp-alert"
PHISHING_TAG    = "phishing-report"
REPORT_BASE_URL = os.getenv("REPORT_BASE_URL", "http://localhost:5000")
DEFAULT_INTERVAL = 10

ROUTE_LABELS = {"dlp": "DLP  ", "phishing": "PHISH", "generic": "GEN  "}


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(level: str):
    """Configure the root logger BEFORE project modules are imported.

    Several project modules call logging.basicConfig() at import time; whichever
    runs first wins, so this has to happen before build_pipelines() imports them.
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(levelname)-8s %(name)s - %(message)s",
    )
    for noisy in ("urllib3", "requests", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ── Wiring ────────────────────────────────────────────────────────────────────

class Pipelines:
    """Everything the watcher needs, built once at startup."""

    def __init__(self, case_platform_client, engine, dlp_runner, phishing, notes):
        self.case_platform_client = case_platform_client
        self.engine      = engine
        self.dlp_runner  = dlp_runner
        self.phishing    = phishing
        self.notes       = notes          # startup facts for the banner


def build_pipelines() -> Pipelines:
    """Instantiate every component once and share them across all routes."""
    from database.db_manager import DBManager
    from enrichment.identity_lookup import IdentityLookup
    from enrichment.company_enrichment import CompanyEnrichment, COMPANIES_API_KEY
    from enrichment.enrichment_engine import EnrichmentEngine
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.llm_analyzer import LLMAnalyzer
    from case_platform.case_platform_client import CasePlatformClient
    from case_platform.case_platform_updater import CasePlatformUpdater
    from phishing.dlp_enrichment import DLPEnrichment
    from phishing.dlp_runner import DLPRunner, ORG_DOMAIN

    notes = {}

    db  = DBManager()
    llm = LLMAnalyzer()
    notes["llm"] = (
        f"available (model {llm.model})" if llm.is_available()
        else "not available - deterministic narrative only"
    )

    # Same mock/real switch main.py uses, so the watcher behaves like the service.
    mock_ad = os.getenv("MOCK_AD", "true").lower() != "false"
    ad_lookup  = IdentityLookup(mock_mode=mock_ad)
    ioc_lookup = IOCLookup(db)
    notes["directory"] = "mock" if mock_ad else "real (Graph API)"

    case_platform_client  = CasePlatformClient()
    case_platform_updater = CasePlatformUpdater()

    # Generic pipeline
    engine = EnrichmentEngine(
        case_platform_client  = case_platform_client,
        case_platform_updater = case_platform_updater,
        ioc_lookup   = ioc_lookup,
        ad_lookup    = ad_lookup,
        llm_analyzer = llm,
    )

    # DLP pipeline - recipient business context follows the same COMPANIES_REAL
    # gate as the standalone runner, and stays descriptive/non-scoring.
    company_real = os.getenv("COMPANIES_REAL", "").lower() in ("1", "true", "yes")
    company_enrichment = CompanyEnrichment(
        mock_mode=not (company_real and bool(COMPANIES_API_KEY)),
    )
    notes["business_context"] = (
        "REAL (The Companies API)" if company_real and COMPANIES_API_KEY
        else "mock (set COMPANIES_REAL=1 with a key in .env for live lookups)"
    )

    dlp_runner = DLPRunner(
        enrichment = DLPEnrichment(
            ad_lookup  = ad_lookup,
            ioc_lookup = ioc_lookup,
            llm        = None,          # the runner drives the LLM, not the enricher
            org_domain = ORG_DOMAIN,
        ),
        case_platform_updater       = case_platform_updater,   # write-back; polling is done here
        llm                = llm,
        company_enrichment = company_enrichment,
    )
    notes["org_domain"] = ORG_DOMAIN

    # Phishing pipeline - imported last and defensively: it pulls in dns.resolver,
    # dkim and whois at module import. If any of those is missing, the watcher
    # still runs the generic and DLP routes instead of refusing to start.
    phishing = None
    try:
        from phishing.phishing_enrichment import PhishingEnrichment
        phishing = PhishingEnrichment(engine, llm=llm)
        notes["phishing"] = "ready"
    except Exception as exc:
        notes["phishing"] = f"UNAVAILABLE - {exc}"
        logger.warning(f"Phishing pipeline unavailable: {exc}")

    return Pipelines(case_platform_client, engine, dlp_runner, phishing, notes)


# ── Routing ───────────────────────────────────────────────────────────────────

def route_for(alert: dict) -> str:
    """Pick the single pipeline that owns this alert, by tag."""
    tags = {str(t).lower() for t in (alert.get("tags") or [])}
    if DLP_TAG in tags:
        return "dlp"
    if PHISHING_TAG in tags:
        return "phishing"
    return "generic"


# ── Per-route handlers ────────────────────────────────────────────────────────

def handle_dlp(p: Pipelines, alert: dict) -> str:
    """Outbound DLP investigation. Saves a report and writes back to case management platform."""
    report = p.dlp_runner.process_alert(alert)
    risk = report.get("risk_assessment") or {}
    return (
        f"verdict {report.get('verdict_level')} | "
        f"risk {risk.get('score')}/100 ({str(risk.get('band')).upper()}) | "
        f"report {REPORT_BASE_URL}/report/{alert['_id']}"
    )


def handle_phishing(p: Pipelines, alert: dict) -> str:
    """Inbound phishing triage. Saves a report and writes back to case management platform."""
    if not p.phishing:
        return "SKIPPED - phishing pipeline unavailable (see startup banner)"
    record = p.phishing._process_phishing_alert(alert)
    verdict = (record or {}).get("verdict_level", "unknown")
    signals = len((record or {}).get("risk_signals") or [])
    return (
        f"verdict {verdict} | {signals} signal(s) | "
        f"report {REPORT_BASE_URL}/report/{alert['_id']}"
    )


def handle_generic(p: Pipelines, alert: dict) -> str:
    """Generic observable enrichment (identity + IOC reputation) and write-back.

    Mirrors EnrichmentEngine.run_once() for a single, already-fetched alert:
    run_once() would poll case management platform again with its own cursor, which is exactly the
    double-processing this watcher exists to avoid. There is no JSON report for
    this route - the enrichment is written into the case management platform alert itself.
    """
    observables = p.case_platform_client.get_alert_observables(alert["_id"])
    record = p.engine._enrich_target("alert", alert, observables)
    if p.engine.case_platform_updater:
        p.engine._write_back(record)

    signals = record.get("risk_signals") or []
    summary = record.get("summary") or {}
    top = signals[0]["message"] if signals else "no significant risk signals"
    return (
        f"verdict {p.engine._signals_to_level(signals)} | "
        f"{len(observables)} observable(s) | {len(signals)} signal(s) | "
        f"malicious={summary.get('any_malicious')} | {top}"
    )


HANDLERS = {"dlp": handle_dlp, "phishing": handle_phishing, "generic": handle_generic}


# ── Console output ────────────────────────────────────────────────────────────

def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def print_banner(p: Pipelines, args):
    n = p.notes
    print()
    print("=" * 78)
    print("  SOC ENRICHMENT PLATFORM - LIVE ALERT WATCHER")
    print("=" * 78)
    print(f"  case management platform          : {p.case_platform_client.url}")
    print(f"  Report viewer    : {REPORT_BASE_URL}/report/<alert_id>")
    print(f"  Poll interval    : {args.interval}s"
          f"{'  (single pass)' if args.once else ''}")
    print(f"  Starting from    : "
          f"{'ALL existing alerts (backfill)' if args.backfill else 'now - new alerts only'}")
    print(f"  Org domain       : {n.get('org_domain')}")
    print(f"  corporate directory         : {n.get('directory')}")
    print(f"  Business context : {n.get('business_context')}")
    print(f"  Local LLM        : {n.get('llm')}")
    print(f"  Phishing route   : {n.get('phishing')}")
    print("-" * 78)
    print("  Routing (exclusive - one pipeline per alert):")
    print(f"    tag '{DLP_TAG}'       -> DLP investigation")
    print(f"    tag '{PHISHING_TAG}' -> phishing triage")
    print("    otherwise            -> generic observable enrichment")
    print("-" * 78)
    print("  Listening. Inject alerts now. Ctrl+C to stop.")
    print("=" * 78)
    print()


def print_summary(counts: dict, errors: int, cycles: int):
    total = sum(counts.values())
    print()
    print("-" * 78)
    print(f"  Watcher stopped after {cycles} poll cycle(s) - {total} alert(s) enriched")
    print(f"    generic  : {counts['generic']}")
    print(f"    phishing : {counts['phishing']}")
    print(f"    dlp      : {counts['dlp']}")
    if errors:
        print(f"    errors   : {errors} (see the log lines above)")
    print("-" * 78)
    print()


# ── Main loop ─────────────────────────────────────────────────────────────────

def process_alert(p: Pipelines, alert: dict) -> str:
    """Route and process one alert. Returns the route that handled it."""
    route    = route_for(alert)
    alert_id = alert.get("_id", "unknown")
    title    = (alert.get("title") or "")[:52]

    print(f"[{stamp()}] {ROUTE_LABELS[route]} {alert_id}  {title}")
    started = time.monotonic()
    outcome = HANDLERS[route](p, alert)
    print(f"           -> {outcome}  ({time.monotonic() - started:.1f}s)")
    return route


def main():
    args = parse_args()
    setup_logging(args.log_level)

    try:
        p = build_pipelines()
    except Exception as exc:
        logger.critical(f"Failed to initialize pipelines: {exc}", exc_info=True)
        return 1

    if not p.case_platform_client.check_connection():
        logger.critical(
            "Cannot connect to case management platform - check CASE_PLATFORM_URL and CASE_PLATFORM_API_KEY in .env, "
            "and that case management platform is running (docker compose up -d)."
        )
        return 1

    # Cursor: 0 replays everything, now_ms() listens for new alerts only.
    start_ts = 0 if args.backfill else p.case_platform_client.now_ms()
    p.case_platform_client.reset_alert_timestamp(start_ts)

    print_banner(p, args)

    counts = {"generic": 0, "phishing": 0, "dlp": 0}
    errors = 0
    cycles = 0

    try:
        while True:
            cycles += 1
            try:
                alerts = p.case_platform_client.get_new_alerts()
            except Exception as exc:
                errors += 1
                logger.error(f"Poll failed: {exc}")
                alerts = []

            for alert in alerts:
                try:
                    counts[process_alert(p, alert)] += 1
                except Exception as exc:
                    errors += 1
                    logger.exception(
                        f"Enrichment failed for alert {alert.get('_id')}: {exc}"
                    )

            if args.once:
                break

            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    print_summary(counts, errors, cycles)
    return 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Live case management platform watcher - routes new alerts to the generic, "
                    "phishing, or DLP enrichment pipeline by tag."
    )
    parser.add_argument(
        "--interval", type=int, default=int(os.getenv("WATCH_INTERVAL_SECS", DEFAULT_INTERVAL)),
        metavar="SECONDS", help=f"Seconds between polls (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--backfill", action="store_true",
        help="Process alerts already in case management platform as well as new ones",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single poll cycle and exit",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
