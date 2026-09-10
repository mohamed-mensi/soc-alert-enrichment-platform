"""
main.py
========
Single entry point for the SOC Enrichment Platform.

Wires together all components and starts the scheduler:
  - DBManager                : SQLite database
  - IOCLookup                : reputation lookups against local IOC DB
  - IdentityLookup           : identity lookups (mock or real directory API)
  - CasePlatformClient       : polls the case management platform for new alerts/cases
  - CasePlatformUpdater      : writes enrichment back to the case platform
  - EnrichmentEngine         : orchestrates the enrichment pipeline
  - Scheduler                : runs feed collection (24h) + enrichment (30s) loops

Handles Ctrl+C / SIGTERM cleanly — both scheduler threads are stopped
and the process exits with code 0.

Configuration is read from environment variables (.env file).
Key settings:
    CASE_PLATFORM_URL        : case platform base URL (default: http://localhost:9000)
    CASE_PLATFORM_API_KEY    : case platform API key (required)
    ABUSECH_AUTH_KEY         : abuse.ch Auth-Key (required for feeds)
    OTX_API_KEY              : AlienVault OTX API key (required for feeds)
    DIRECTORY_TENANT_ID      : directory tenant (optional — mock mode if absent)
    DIRECTORY_CLIENT_ID      : directory app client ID (optional)
    DIRECTORY_CLIENT_SECRET  : directory app secret (optional)
    MOCK_DIRECTORY           : "true" to force mock mode regardless (default: true)
    ENRICH_INTERVAL_SECS     : enrichment poll interval in seconds (default: 30)
    FEED_INTERVAL_HOURS      : feed collection interval in hours (default: 24)
    RUN_FEED_ON_STARTUP      : "true" to run feeds immediately on start (default: true)

Usage:
    python main.py
    python main.py --no-feed-on-startup
    python main.py --enrich-interval 10   # faster polling for testing
"""

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from enrichment.llm_analyzer import LLMAnalyzer

# ── Project root on sys.path BEFORE all package imports ──────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
load_dotenv()

# ── Logging setup ─────────────────────────────────────────────────────────────
def _setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# ── Project imports ───────────────────────────────────────────────────────────
from database.db_manager import DBManager
from enrichment.ioc_lookup import IOCLookup
from enrichment.identity_lookup import IdentityLookup
from enrichment.enrichment_engine import EnrichmentEngine
from case_platform.case_platform_client import CasePlatformClient
from case_platform.case_platform_updater import CasePlatformUpdater
from scheduler import Scheduler


# ── Component factory ─────────────────────────────────────────────────────────

def build_components(args):
    """
    Initialize all components from environment variables and CLI args.
    Raises clearly if required config is missing rather than crashing later.
    """
    db = DBManager()

    # Directory — use mock mode unless real credentials are present
    mock_dir = os.getenv("MOCK_DIRECTORY", os.getenv("MOCK_AD", "true")).lower() != "false"
    if not mock_dir:
        required = ["DIRECTORY_TENANT_ID", "DIRECTORY_CLIENT_ID", "DIRECTORY_CLIENT_SECRET"]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            logger.warning(
                f"MOCK_DIRECTORY=false but missing: {missing} — falling back to mock mode"
            )
            mock_dir = True

    dir_lookup = IdentityLookup(mock_mode=mock_dir)
    ioc_lookup = IOCLookup(db)
    platform_client = CasePlatformClient()
    platform_updater = CasePlatformUpdater()
    llm = LLMAnalyzer()

    engine = EnrichmentEngine(
        case_platform_client=platform_client,
        case_platform_updater=platform_updater,
        ioc_lookup=ioc_lookup,
        ad_lookup=dir_lookup,
        llm_analyzer=llm,
    )

    enrich_interval = args.enrich_interval or int(
        os.getenv("ENRICH_INTERVAL_SECS", 30)
    )
    feed_interval = args.feed_interval or int(
        os.getenv("FEED_INTERVAL_HOURS", 24)
    )

    scheduler = Scheduler(
        engine=engine,
        db=db,
        feed_interval_hours=feed_interval,
        enrich_interval_secs=enrich_interval,
    )

    return db, scheduler


# ── Startup feed run ──────────────────────────────────────────────────────────

def run_feeds_now(db):
    """Run one feed collection cycle immediately on startup."""
    from feeds.feed_collector import run_all_feeds
    logger.info("Running initial feed collection...")
    try:
        summary = run_all_feeds(db)
        totals = summary.get("totals", {})
        logger.info(
            f"Initial feed collection complete — "
            f"{totals.get('new', 0)} new IOCs, "
            f"{totals.get('updated', 0)} updated"
        )
    except Exception as exc:
        logger.error(f"Initial feed collection failed: {exc}", exc_info=True)
        logger.warning("Continuing startup — enrichment will use existing IOC database")


# ── Graceful shutdown ─────────────────────────────────────────────────────────

def _install_signal_handlers(scheduler):
    """
    Handle Ctrl+C and SIGTERM by stopping the scheduler cleanly
    instead of letting Python raise KeyboardInterrupt mid-operation.
    """
    def _handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name} — shutting down...")
        scheduler.stop()

    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args():
    parser = argparse.ArgumentParser(
        description="SOC Enrichment Platform — main service entry point"
    )
    parser.add_argument(
        "--no-feed-on-startup",
        action="store_true",
        help="Skip the initial feed collection run on startup",
    )
    parser.add_argument(
        "--enrich-interval",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Override ENRICH_INTERVAL_SECS (useful for testing — e.g. 10)",
    )
    parser.add_argument(
        "--feed-interval",
        type=int,
        default=None,
        metavar="HOURS",
        help="Override FEED_INTERVAL_HOURS",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return parser.parse_args()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = _parse_args()
    _setup_logging(args.log_level)

    logger.info("=" * 60)
    logger.info("SOC Enrichment Platform — starting")
    logger.info("=" * 60)

    # Build all components
    try:
        db, scheduler = build_components(args)
    except Exception as exc:
        logger.critical(f"Failed to initialize components: {exc}", exc_info=True)
        sys.exit(1)

    # Verify case platform is reachable before starting loops
    from case_platform.case_platform_client import CasePlatformClient
    client = CasePlatformClient()
    if not client.check_connection():
        logger.critical(
            "Cannot connect to case management platform — check CASE_PLATFORM_URL and CASE_PLATFORM_API_KEY. "
            "Start the platform with: docker compose up -d"
        )
        sys.exit(1)

    # Optionally run feeds immediately so the IOC DB is fresh on first start
    run_on_startup = (
        not args.no_feed_on_startup
        and os.getenv("RUN_FEED_ON_STARTUP", "true").lower() != "false"
    )
    if run_on_startup:
        run_feeds_now(db)

    # Install signal handlers and start the scheduler
    _install_signal_handlers(scheduler)
    scheduler.start()

    logger.info("Platform running — press Ctrl+C to stop")

    # Keep main thread alive while scheduler threads run
    try:
        while not scheduler._stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — shutting down...")
        scheduler.stop()

    scheduler.join(timeout=15)
    logger.info("SOC Enrichment Platform stopped")
    sys.exit(0)


if __name__ == "__main__":
    main()
