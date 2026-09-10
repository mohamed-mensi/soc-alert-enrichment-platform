"""
phishing/dlp_runner.py
======================
Standalone runner for the DLP (Data Loss Prevention) email investigation
workflow. Mirrors phishing_enrichment.py but for the internal→external
direction ("is our data walking out the door?").

Pipeline (Parts 1, 5-8):
  1. Poll case management platform for new alerts tagged 'dlp-alert'
  2. Parse the raw .eml from the alert description (via DLPEnrichment,
     which reuses EmailParser)
  3. Enrich: sender identity, recipient analysis, WHOIS/domain intel,
     IOC checks, self-send, content/keyword scoring, file & document
     analysis, timing, prior-correspondence
  4. Derive organization context, recipient legitimacy and a contextual
     risk score with explicit risk + mitigating factors
     (enrichment/report_common.py)
  5. Build the AI narrative — deterministic 7-section narrative always;
     an additive local-LLM triage when Ollama is available
  6. Assemble the structured machine-readable JSON report
     (report_type 'dlp_email_investigation') and save it
  7. Update case management platform with the verdict and a link to the hosted report

Nothing here fabricates intelligence: organization/description come only
from verifiable enrichment, and every derived value degrades to a safe
default when a source is unavailable.

Usage:
    cd soc_enrichment
    python -m phishing.dlp_runner            # poll case management platform
    python -m phishing.dlp_runner <file.eml> # enrich a single .eml offline
"""

import logging
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from enrichment import report_common as rc
from enrichment.report_generator import save_report

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

DLP_TAG        = "dlp-alert"
REPORT_BASE_URL = os.getenv("REPORT_BASE_URL", "http://localhost:5000")
ORG_DOMAIN      = os.getenv("ORG_DOMAIN", "example-corp.com")


class DLPRunner:
    """
    Orchestrates the DLP investigation for case management platform alerts tagged 'dlp-alert'.

    Parameters
    ----------
    enrichment  : DLPEnrichment instance (does the per-email enrichment)
    case_platform_client : CasePlatformClient (optional — required only for polling mode)
    case_platform_updater: CasePlatformUpdater (optional — writes verdict + report link back)
    llm         : LLMAnalyzer (optional — additive AI triage)
    company_enrichment : CompanyEnrichment (optional — recipient business
                  context keyed by domain). Descriptive-only; its result is
                  surfaced in the report but never feeds the risk score or the
                  legitimacy verdict. When None, the report simply shows "not
                  retrieved" and nothing else changes.
    """

    def __init__(self, enrichment, case_platform_client=None, case_platform_updater=None, llm=None,
                 company_enrichment=None):
        self.enrichment  = enrichment
        self.case_platform_client = case_platform_client
        self.case_platform_updater = case_platform_updater
        self.llm         = llm
        self.company_enrichment = company_enrichment

    # ── Polling entry point ────────────────────────────────────────────────────

    def run(self):
        """Poll case management platform once and process every new 'dlp-alert'."""
        if not self.case_platform_client:
            raise RuntimeError("DLPRunner.run() requires a case_platform_client")

        alerts = self.case_platform_client.get_new_alerts()
        logger.info(f"Found {len(alerts)} new alert(s)")

        processed = 0
        for alert in alerts:
            tags = [t.lower() for t in (alert.get("tags") or [])]
            if DLP_TAG not in tags:
                continue
            try:
                self.process_alert(alert)
                processed += 1
            except Exception as exc:
                logger.exception(f"DLP enrichment failed for {alert.get('_id')}: {exc}")

        logger.info(f"DLP run complete — {processed} alert(s) processed")
        return processed

    # ── Single-alert processing ────────────────────────────────────────────────

    def process_alert(self, alert: dict) -> dict:
        """Enrich a single case management platform alert dict and build/save its report."""
        alert_id = alert.get("_id", "unknown")
        start = time.monotonic()

        enrichment = self.enrichment.enrich_alert(alert)
        report = self._build_report(alert_id, alert, enrichment)

        save_report(alert_id, report)
        logger.info(f"DLP report saved for {alert_id}")

        self._update_hive(alert_id, report)

        elapsed = time.monotonic() - start
        link = f"{REPORT_BASE_URL}/report/{alert_id}"
        logger.info(f"DLP enrichment complete for {alert_id} in {elapsed:.2f}s")
        print(f"✅ DLP alert {alert_id} enriched "
              f"({report['risk_assessment']['band'].upper()} / "
              f"{report['verdict_level']}) — link: {link}")
        return report

    def process_file(self, path: str) -> dict:
        """Enrich a single .eml file offline (no case management platform required)."""
        enrichment = self.enrichment.enrich_file(path)
        alert_id   = Path(path).stem
        alert_meta = {"title": f"DLP Email Investigation — {alert_id}"}
        report     = self._build_report(alert_id, alert_meta, enrichment)
        save_report(alert_id, report)
        print(f"✅ DLP file {path} enriched — report saved for {alert_id}")
        return report

    # ── Report assembly ────────────────────────────────────────────────────────

    def _build_report(self, alert_id: str, alert_meta: dict, enrichment: dict) -> dict:
        """
        Turn a raw enrichment record into the structured DLP report using the
        shared, deterministic building blocks.
        """
        to_domain    = enrichment.get("to_domain", "")
        recipient_type = enrichment.get("recipient_type", "unknown")
        domain_intel = enrichment.get("domain_intel") or {}
        prior_corr   = enrichment.get("prior_correspondence") or {"has_prior": False, "evidence": []}

        # Organization context (WHOIS-only; never fabricated)
        org_context = rc.derive_organization_context(
            to_domain=to_domain,
            recipient_type=recipient_type,
            domain_intel=domain_intel,
            org_domain=ORG_DOMAIN,
        )

        # Recipient BUSINESS context (descriptive-only; NON-SCORING).
        # Looked up only for external corporate/suspicious/unknown domains —
        # never internal or personal-webmail (that would describe the mail host,
        # not an employer). Kept entirely out of the scoring/legitimacy calls
        # below: it is passed only to build_dlp_report at the end.
        business_lookup = self._lookup_business_context(recipient_type, to_domain)
        business_context = rc.build_recipient_business_context(
            business_lookup=business_lookup,
            recipient_type=recipient_type,
            to_domain=to_domain,
            org_domain=ORG_DOMAIN,
            keyword_results=enrichment.get("keyword_results"),
        )

        # Recipient legitimacy (5-level, evidence-based)
        legitimacy = rc.assess_recipient_legitimacy(
            recipient_type=recipient_type,
            ioc_domain_hit=enrichment.get("ioc_domain_hit") or {},
            domain_intel=domain_intel,
            self_send_fuzzy=enrichment.get("self_send_fuzzy") or {},
            prior_correspondence=prior_corr,
            org_context=org_context,
            to_domain=to_domain,
            org_domain=ORG_DOMAIN,
        )

        # Contextual risk score (explicit risk + mitigating factors)
        risk = rc.score_dlp_risk(
            enrichment=enrichment,
            legitimacy=legitimacy,
            org_context=org_context,
            prior_correspondence=prior_corr,
        )

        # Evidence list (observed facts + source)
        evidence = rc.build_dlp_evidence(enrichment, prior_corr)

        # Narrative — deterministic 7-section is always present and grounded.
        narrative = rc.build_dlp_narrative(
            enrichment, org_context, legitimacy, risk, prior_corr
        )
        narrative_source = "deterministic"

        # Additive local-LLM triage layered on top of the grounded brief.
        if self.llm:
            llm_text = self._llm_triage(enrichment, org_context, legitimacy, risk,
                                        prior_corr, alert_id)
            if llm_text:
                narrative = (
                    f"{narrative}\n\n"
                    f"--- AI TRIAGE (local LLM, advisory) ---\n{llm_text}"
                )
                narrative_source = "deterministic+llm"

        raw_email = enrichment.get("raw_headers", "")
        if enrichment.get("body_text"):
            raw_email = f"{raw_email}\n\n{enrichment['body_text']}"

        return rc.build_dlp_report(
            alert_id=alert_id,
            alert_meta=alert_meta or {},
            enrichment=enrichment,
            org_context=org_context,
            legitimacy=legitimacy,
            risk=risk,
            prior_correspondence=prior_corr,
            evidence=evidence,
            narrative=narrative,
            narrative_source=narrative_source,
            raw_email=raw_email,
            business_context=business_context,
        )

    def _lookup_business_context(self, recipient_type: str, to_domain: str):
        """
        Resolve recipient business context via the optional CompanyEnrichment
        provider. Returns the raw lookup dict, or None when no provider is
        wired or the recipient isn't a domain worth looking up. Never raises —
        any provider error degrades to None (report shows "not retrieved").

        Gated deliberately: only external corporate/suspicious/unknown domains.
        Internal + personal-webmail/disposable are skipped (a lookup there
        describes the mail host, not the recipient's employer) and also avoids
        spending provider credits on non-company domains.
        """
        if not self.company_enrichment:
            return None
        if recipient_type not in ("corporate", "suspicious", "unknown"):
            return None
        if not to_domain or to_domain == ORG_DOMAIN.lower():
            return None
        try:
            return self.company_enrichment.lookup_domain(to_domain)
        except Exception as exc:
            logger.warning(f"Company business lookup failed for {to_domain}: {exc}")
            return None

    def _llm_triage(self, enrichment, org_context, legitimacy, risk,
                    prior_corr, alert_id):
        """Ask the local LLM for a triage, grounded strictly in our evidence."""
        try:
            if hasattr(self.llm, "is_available") and not self.llm.is_available():
                return None
            description = rc.build_dlp_llm_description(
                enrichment, org_context, legitimacy, risk, prior_corr
            )
            return self.llm.generate_narrative({
                "target_id":   alert_id,
                "title":       f"DLP Investigation — {enrichment.get('subject', '')}",
                "description": description,
                "risk_signals": enrichment.get("risk_signals", []),
                "summary": {
                    "any_malicious": risk["verdict_level"] == "ESCALATE",
                    "high_risk_identity": (enrichment.get("sender_identity") or {})
                        .get("criticality") in ("CRITICAL", "HIGH"),
                    "max_reputation_score": (enrichment.get("ioc_domain_hit") or {})
                        .get("reputation_score", 0),
                },
                "verdict_level": risk["verdict_level"],
            })
        except Exception as exc:
            logger.warning(f"LLM triage failed for {alert_id}: {exc}")
            return None

    # ── case management platform write-back ──────────────────────────────────────────────────────

    def _update_hive(self, alert_id: str, report: dict):
        """Write the verdict, reasons and a report link back to case management platform."""
        if not self.case_platform_updater:
            return
        link = f"{REPORT_BASE_URL}/report/{alert_id}"
        risk = report["risk_assessment"]
        reasons = [f["detail"] for f in risk.get("risk_factors", [])[:5]]
        if not reasons:
            reasons = ["No individual risk factors exceeded threshold."]
        try:
            self.case_platform_updater.update_alert(
                alert_id=alert_id,
                enrichments=[],
                verdict=report["verdict_level"],
                verdict_reasons=reasons,
                narrative=(
                    f"DLP risk {risk['score']}/100 ({risk['band'].upper()}). "
                    f"Recipient legitimacy: "
                    f"{report['recipient']['legitimacy']['level']}. "
                    f"Full report: {link}"
                ),
            )
            logger.info(f"Updated alert {alert_id} with DLP verdict + report link")
        except Exception as exc:
            logger.warning(f"Failed to update case management platform alert {alert_id}: {exc}")


# ── Standalone runner ───────────────────────────────────────────────────────────

def _build_default_runner():
    """Wire the runner with the real project components."""
    from enrichment.identity_lookup import IdentityLookup
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.llm_analyzer import LLMAnalyzer
    from enrichment.company_enrichment import CompanyEnrichment, COMPANIES_API_KEY
    from database.db_manager import DBManager
    from phishing.dlp_enrichment import DLPEnrichment

    db  = DBManager()
    llm = LLMAnalyzer()
    enrichment = DLPEnrichment(
        ad_lookup=IdentityLookup(mock_mode=True),
        ioc_lookup=IOCLookup(db),
        llm=None,              # LLM is invoked by the runner, not the enricher
        org_domain=ORG_DOMAIN,
    )

    # Recipient business context (descriptive-only). Offline/deterministic by
    # default; set COMPANIES_REAL=1 (with COMPANIES_API_KEY in .env) to call the
    # live provider. Never affects the risk score or the legitimacy verdict.
    company_real = os.getenv("COMPANIES_REAL", "").lower() in ("1", "true", "yes")
    company_enrichment = CompanyEnrichment(
        mock_mode=not (company_real and bool(COMPANIES_API_KEY)),
    )
    return enrichment, llm, company_enrichment


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    enrichment, llm, company_enrichment = _build_default_runner()

    # Offline single-file mode: python -m phishing.dlp_runner <file.eml>
    if len(sys.argv) > 1:
        runner = DLPRunner(enrichment=enrichment, llm=llm,
                           company_enrichment=company_enrichment)
        for eml in sys.argv[1:]:
            runner.process_file(eml)
        print("✅ DLP offline run complete — reports saved to reports/")
        sys.exit(0)

    # Polling mode against case management platform
    from case_platform.case_platform_client import CasePlatformClient
    from case_platform.case_platform_updater import CasePlatformUpdater

    runner = DLPRunner(
        enrichment=enrichment,
        case_platform_client=CasePlatformClient(),
        case_platform_updater=CasePlatformUpdater(),
        llm=llm,
        company_enrichment=company_enrichment,
    )
    runner.run()
    print("✅ DLP enrichment run complete — check case management platform alerts for report links")
