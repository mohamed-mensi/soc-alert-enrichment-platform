"""
tests/test_dlp_and_phishing.py
==============================
Offline, deterministic test harness for the DLP + phishing investigation
pipelines and their JSON/HTML reports.

Everything here runs WITHOUT network, Ollama, case management platform, a real WHOIS API or a
real IOC SQLite DB:
  - corporate directory          → IdentityLookup(mock_mode=True)   (already offline)
  - IOC reputation    → IOCLookup(FakeDB)               (in-memory)
  - WHOIS / domain age→ DLPEnrichment._whois_lookup override (per scenario)
  - Local LLM         → StubLLM                          (controllable)
  - External phishing → module-level functions monkeypatched
  - Report persistence→ monkeypatched / temp dirs

Run any of:
    cd soc_enrichment
    python -m unittest tests.test_dlp_and_phishing -v
    python tests/test_dlp_and_phishing.py
    pytest tests/test_dlp_and_phishing.py -v

Covers the Part 13 matrix:
  DLP      — internal / legit-external / unknown / suspicious / freemail /
             unverified-org / sensitive+legit / sensitive+suspicious /
             historical (prior correspondence) / newly-registered / malicious
  Phishing — different alerts produce different stats + narratives, evidence is
             alert-specific, no stale/cache leakage between alerts, verdict is
             not the old hardcoded ESCALATE, signals are not the old 2 statics
  Reports  — valid JSON, correct alert data, Flask renders both templates,
             missing enrichment / AI failure never break generation
"""

import json
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from enrichment import report_common as rc          # noqa: E402
from phishing.email_parser import EmailParser        # noqa: E402


# ── Email builder ─────────────────────────────────────────────────────────────

def make_eml(from_addr, to_addr, subject, body="Please review the attached.",
             date="Tue, 15 Jul 2026 02:30:00 +0000", auth=None,
             received=None, headers=None, attachments=None):
    """Build a real MIME .eml (bytes) so the shared EmailParser can parse it."""
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = date
    if auth:
        msg["Authentication-Results"] = auth
    for rcv in (received or []):
        msg["Received"] = rcv
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(body)
    for att in (attachments or []):
        data = att.get("data", b"x" * att.get("size", 16))
        msg.add_attachment(
            data,
            maintype=att.get("maintype", "application"),
            subtype=att.get("subtype", "octet-stream"),
            filename=att["filename"],
        )
    return msg.as_bytes()


# ── Offline doubles ───────────────────────────────────────────────────────────

class FakeDB:
    """Minimal DBManager stand-in for IOCLookup — no SQLite, fully offline."""

    def __init__(self, malicious=None):
        # malicious: {"domain": {"evil.com"}, "ip": {"1.2.3.4"}, ...}
        self.malicious = malicious or {}

    def lookup_ioc(self, ioc_type, value):
        if value in self.malicious.get(ioc_type, set()):
            return [{
                "source": "abusech_urlhaus", "malware_family": "TestBot",
                "threat_actor": None, "tags": ["c2"], "severity": "critical",
                "confidence": "high", "first_seen": "2026-01-01",
                "last_seen": "2026-06-01",
            }]
        return []


class StubLLM:
    """Deterministic stand-in for LLMAnalyzer."""

    def __init__(self, available=False, raises=False):
        self._available = available
        self._raises = raises

    def is_available(self):
        return self._available

    def generate_narrative(self, record):
        if self._raises:
            raise RuntimeError("simulated LLM failure")
        return "STUB-LLM-NARRATIVE"


class FakeUpdater:
    def __init__(self):
        self.calls = []

    def update_alert(self, **kwargs):
        self.calls.append(kwargs)


class FakeEngine:
    def __init__(self):
        self.case_platform_updater = FakeUpdater()
        self.case_platform_client = None


class StubCompanyEnrichment:
    """
    Deterministic stand-in for CompanyEnrichment (business context). Returns a
    canned normalized lookup dict keyed by domain, mirroring the real
    lookup_domain() schema. Records lookups so tests can assert gating (e.g.
    that internal/webmail domains are never looked up).
    """

    def __init__(self, by_domain=None, raises=False):
        self.by_domain = by_domain or {}
        self.raises = raises
        self.lookups = []

    def lookup_domain(self, domain):
        self.lookups.append(domain)
        if self.raises:
            raise RuntimeError("simulated company-provider failure")
        domain = (domain or "").lower()
        if domain in self.by_domain:
            return self.by_domain[domain]
        # Unknown domain → found=False, mirroring CompanyEnrichment._not_found.
        return {
            "found": False, "domain": domain, "name": None, "legal_name": None,
            "description": None, "industry": None, "industries": [],
            "business_type": None, "employee_range": None, "revenue": None,
            "country": None, "city": None, "website": None, "linkedin_url": None,
            "year_founded": None, "match_score": None, "source": "none",
            "confidence": "low", "mock": True, "reason": "not in stub",
        }


def found_company(name, industry, **extra):
    """Build a found=True normalized lookup dict for the stub."""
    base = {
        "found": True, "name": name, "legal_name": extra.get("legal_name"),
        "description": extra.get("description"), "industry": industry,
        "industries": extra.get("industries", []),
        "business_type": extra.get("business_type"),
        "employee_range": extra.get("employee_range"),
        "revenue": extra.get("revenue"), "country": extra.get("country"),
        "city": extra.get("city"), "website": extra.get("website"),
        "linkedin_url": extra.get("linkedin_url"),
        "year_founded": extra.get("year_founded"),
        "match_score": extra.get("match_score"),
        "source": "thecompaniesapi", "confidence": "medium", "mock": True,
    }
    return base


# ── DLP helpers ───────────────────────────────────────────────────────────────

DEFAULT_WHOIS = {
    "registrar": "unknown", "created": "unknown", "age_days": None,
    "age_label": "unknown", "country": "unknown", "organization": None,
}


def build_dlp_enricher(malicious=None, whois=None):
    from phishing.dlp_enrichment import DLPEnrichment
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.identity_lookup import IdentityLookup

    dlp = DLPEnrichment(
        ad_lookup=IdentityLookup(mock_mode=True),
        ioc_lookup=IOCLookup(FakeDB(malicious)),
        llm=None,
        org_domain="example-corp.com",
    )
    # Force WHOIS offline & deterministic — never touches the network in tests.
    resolved = dict(whois or DEFAULT_WHOIS)
    dlp._whois_lookup = lambda domain: dict(resolved)
    return dlp


def run_dlp(eml_bytes, alert_id="test", malicious=None, whois=None, llm=None,
            company=None):
    """Enrich an .eml and build the full DLP report — the real pipeline.

    `company` is an optional CompanyEnrichment-like double (business context).
    When None, the runner behaves exactly as before (no business lookup).
    """
    from phishing.dlp_runner import DLPRunner
    dlp = build_dlp_enricher(malicious=malicious, whois=whois)
    enrichment = dlp.enrich_bytes(eml_bytes, alert_id=alert_id)
    runner = DLPRunner(enrichment=dlp, llm=llm, company_enrichment=company)
    report = runner._build_report(alert_id, {"title": "DLP Test"}, enrichment)
    return enrichment, report


ESTABLISHED_WHOIS = {
    "registrar": "MarkMonitor Inc.", "created": "2005-03-01",
    "age_days": 7000, "age_label": "19 years", "country": "US",
    "organization": "Acme Industries Inc",
}

# Corporate domain, established, but WHOIS discloses no registrant org.
NO_ORG_ESTABLISHED_WHOIS = {
    "registrar": "GoDaddy.com, LLC", "created": "2018-01-01",
    "age_days": 2600, "age_label": "7 years", "country": "US",
    "organization": None,
}
# Corporate domain registered days ago.
NEW_WHOIS = {
    "registrar": "NameCheap, Inc.", "created": "2026-08-01",
    "age_days": 5, "age_label": "5 days ⚠️ very new", "country": "unknown",
    "organization": None,
}


# ── Phishing helper (deterministic, no mxtoolbox / whois / dkim / DB) ──────────

PASS_AUTH = "spf=pass dkim=pass dmarc=pass"
FAIL_AUTH = "spf=fail dkim=fail dmarc=fail"


def run_phishing(eml_bytes, ioc_hits=None, whois_info=None):
    """Drive the shared, pure phishing helpers over a parsed .eml."""
    parsed = EmailParser().parse_bytes(eml_bytes)
    ioc_hits = ioc_hits or []
    whois_info = whois_info or {}
    signals = rc.compute_phishing_signals(parsed, ioc_hits, whois_info)
    summary = rc.compute_phishing_summary(parsed, ioc_hits, signals)
    verdict = rc.phishing_verdict_from_summary(summary)
    narrative = rc.build_phishing_narrative(
        parsed, signals, ioc_hits, whois_info, summary
    )
    return parsed, signals, summary, verdict, narrative


# ══════════════════════════════════════════════════════════════════════════════
# DLP scenario matrix (Part 13)
# ══════════════════════════════════════════════════════════════════════════════

class TestDLPScenarios(unittest.TestCase):

    def _factors(self, report, key="risk_factors"):
        return {f["factor"] for f in report["risk_assessment"][key]}

    # 1 — internal → internal ---------------------------------------------------
    def test_internal_recipient_is_legitimate(self):
        eml = make_eml("adele.vance@example-corp.com", "alex.wilber@example-corp.com",
                       "Q3 numbers")
        _, report = run_dlp(eml, alert_id="dlp-internal")
        self.assertEqual(report["report_type"], "dlp_email_investigation")
        self.assertEqual(report["recipient"]["type"], "internal")
        self.assertEqual(report["recipient"]["legitimacy"]["level"], "LEGITIMATE")
        self.assertEqual(
            report["recipient"]["organization_context"]["confidence"], "high")
        self.assertEqual(report["risk_assessment"]["band"], "low")
        self.assertEqual(report["verdict_level"], "LIKELY_FP")

    # 2 — established external corporate w/ WHOIS org ---------------------------
    def test_legitimate_external_corporate(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        _, report = run_dlp(eml, alert_id="dlp-legit-ext", whois=ESTABLISHED_WHOIS)
        oc = report["recipient"]["organization_context"]
        self.assertEqual(report["recipient"]["type"], "corporate")
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "LIKELY_LEGITIMATE")
        self.assertEqual(oc["organization"], "Acme Industries Inc")
        self.assertEqual(oc["org_source"], "whois")
        self.assertEqual(oc["confidence"], "medium")

    # 3 — unknown external corporate (no WHOIS) --------------------------------
    def test_unknown_external_corporate(self):
        eml = make_eml("adele.vance@example-corp.com", "contact@some-partner.com",
                       "Documents")
        _, report = run_dlp(eml, alert_id="dlp-unknown")  # DEFAULT_WHOIS
        oc = report["recipient"]["organization_context"]
        self.assertEqual(report["recipient"]["type"], "corporate")
        self.assertEqual(report["recipient"]["legitimacy"]["level"], "UNKNOWN")
        self.assertIsNone(oc["organization"])            # never fabricated
        self.assertEqual(oc["org_source"], "none")
        self.assertEqual(oc["confidence"], "low")

    # 4 — structurally suspicious recipient domain -----------------------------
    def test_suspicious_recipient_domain(self):
        eml = make_eml("adele.vance@example-corp.com", "data@mail12345.io", "x")
        _, report = run_dlp(eml, alert_id="dlp-suspicious")
        self.assertEqual(report["recipient"]["type"], "suspicious")
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "SUSPICIOUS")
        self.assertIn("suspicious_recipient", self._factors(report))

    # 5 — personal webmail (freemail) ------------------------------------------
    def test_personal_webmail_recipient(self):
        eml = make_eml("adele.vance@example-corp.com", "partner.contact@gmail.com",
                       "Notes")
        _, report = run_dlp(eml, alert_id="dlp-webmail")
        oc = report["recipient"]["organization_context"]
        self.assertEqual(report["recipient"]["type"], "webmail")
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "LIKELY_LEGITIMATE")
        self.assertEqual(oc["organization"], "Google (Gmail)")
        self.assertIn("personal_webmail", self._factors(report))

    # 6 — disposable / throwaway recipient -------------------------------------
    def test_disposable_recipient(self):
        eml = make_eml("adele.vance@example-corp.com", "drop@mailinator.com", "x")
        _, report = run_dlp(eml, alert_id="dlp-disposable")
        self.assertEqual(report["recipient"]["type"], "disposable")
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "SUSPICIOUS")
        self.assertIn("disposable_recipient", self._factors(report))

    # 7 — fuzzy self-send to a personal address --------------------------------
    def test_fuzzy_self_send_to_freemail(self):
        eml = make_eml("adele.vance@example-corp.com", "adelevance92@gmail.com",
                       "backup")
        enrichment, report = run_dlp(eml, alert_id="dlp-selfsend")
        self.assertTrue(
            enrichment["self_send_fuzzy"]["is_fuzzy_match"])
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "SUSPICIOUS")
        self.assertIn("self_send_fuzzy", self._factors(report))

    # 8 — sensitive data to a legitimate external recipient --------------------
    def test_sensitive_data_to_legit_recipient(self):
        eml = make_eml("adele.vance@example-corp.com", "ap@acme-industries.com",
                       "Confidential — invoice reconciliation",
                       headers={"In-Reply-To": "<prev-thread@acme-industries.com>"})
        _, report = run_dlp(eml, alert_id="dlp-sens-legit", whois=ESTABLISHED_WHOIS)
        self.assertIn("critical_keywords", self._factors(report))
        # A legitimate, established, in-thread recipient must generate mitigants.
        self.assertTrue(report["risk_assessment"]["mitigating_factors"])
        self.assertIn(
            report["recipient"]["legitimacy"]["level"],
            ("LIKELY_LEGITIMATE", "LEGITIMATE"))

    # 9 — sensitive data to a suspicious recipient -----------------------------
    def test_sensitive_data_to_suspicious_recipient(self):
        eml = make_eml(
            "adele.vance@example-corp.com", "x@mailinator.com",
            "Confidential Restricted client portfolio export",
            attachments=[{"filename": "confidential_clients.zip",
                          "maintype": "application", "subtype": "zip",
                          "size": 2048}])
        _, report = run_dlp(eml, alert_id="dlp-sens-susp")
        factors = self._factors(report)
        self.assertIn("critical_keywords", factors)
        self.assertIn("disposable_recipient", factors)
        self.assertIn(report["risk_assessment"]["band"], ("high", "critical"))
        self.assertIn(report["verdict_level"], ("NEEDS_REVIEW", "ESCALATE"))

    # 10 — prior correspondence lowers the score -------------------------------
    def test_prior_correspondence_mitigates(self):
        eml = make_eml("adele.vance@example-corp.com", "ap@acme-industries.com",
                       "Re: ongoing project",
                       headers={"References": "<a@acme-industries.com>",
                                "X-Prior-Correspondence": "thread-4821"})
        _, report = run_dlp(eml, alert_id="dlp-prior", whois=ESTABLISHED_WHOIS)
        self.assertTrue(
            report["behavioral_analysis"]["prior_correspondence"]["has_prior"])
        self.assertIn(
            "prior_correspondence", self._factors(report, "mitigating_factors"))

    # 11 — newly-registered recipient domain -----------------------------------
    def test_newly_registered_recipient_domain(self):
        eml = make_eml("adele.vance@example-corp.com", "invoice@fresh-supplier.com",
                       "Payment update")
        _, report = run_dlp(eml, alert_id="dlp-new", whois=NEW_WHOIS)
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "SUSPICIOUS")
        self.assertIn("newly_registered_domain", self._factors(report))

    # 12 — recipient domain on a threat feed -----------------------------------
    def test_malicious_recipient_domain(self):
        eml = make_eml("adele.vance@example-corp.com", "drop@evil-exfil.com", "x")
        _, report = run_dlp(eml, alert_id="dlp-malicious",
                            malicious={"domain": {"evil-exfil.com"}})
        self.assertTrue(
            report["threat_intelligence"]["recipient_domain_ioc"]["is_malicious"])
        self.assertEqual(
            report["recipient"]["legitimacy"]["level"], "MALICIOUS")
        self.assertEqual(report["verdict_level"], "ESCALATE")
        self.assertTrue(report["summary"]["any_malicious"])
        self.assertIn("recipient_ioc", self._factors(report))

    # AI layering — success appends, failure degrades gracefully --------------
    def test_ai_narrative_appended_when_llm_available(self):
        eml = make_eml("adele.vance@example-corp.com", "x@acme-industries.com", "Z")
        _, report = run_dlp(eml, alert_id="dlp-ai",
                            whois=ESTABLISHED_WHOIS, llm=StubLLM(available=True))
        self.assertEqual(
            report["ai_analysis"]["narrative_source"], "deterministic+llm")
        self.assertIn("STUB-LLM-NARRATIVE", report["ai_analysis"]["narrative"])

    def test_ai_failure_falls_back_to_deterministic(self):
        eml = make_eml("adele.vance@example-corp.com", "x@acme-industries.com", "Z")
        _, report = run_dlp(eml, alert_id="dlp-ai-fail", whois=ESTABLISHED_WHOIS,
                            llm=StubLLM(available=True, raises=True))
        self.assertEqual(
            report["ai_analysis"]["narrative_source"], "deterministic")
        self.assertTrue(report["ai_analysis"]["narrative"])


# ══════════════════════════════════════════════════════════════════════════════
# DLP report integrity  (Part 13 → Reports)
# ══════════════════════════════════════════════════════════════════════════════

class TestDLPReports(unittest.TestCase):

    def test_report_is_valid_json_and_carries_alert_data(self):
        eml = make_eml("adele.vance@example-corp.com", "x@acme-industries.com",
                       "Subject Z")
        _, report = run_dlp(eml, alert_id="dlp-json", whois=ESTABLISHED_WHOIS)
        blob = json.dumps(report, ensure_ascii=False)      # must not raise
        parsed = json.loads(blob)
        self.assertEqual(parsed["report_type"], "dlp_email_investigation")
        self.assertEqual(parsed["schema_version"], "1.0")
        self.assertEqual(parsed["alert_id"], "dlp-json")
        self.assertEqual(parsed["alert"]["title"], "DLP Test")
        self.assertEqual(parsed["sender"]["address"], "adele.vance@example-corp.com")
        self.assertEqual(parsed["recipient"]["address"], "x@acme-industries.com")

    def test_missing_enrichment_does_not_break_report(self):
        from phishing.dlp_runner import DLPRunner
        runner = DLPRunner(enrichment=None, llm=None)
        report = runner._build_report("empty", {}, {})     # empty enrichment
        json.dumps(report)                                  # still serializable
        self.assertEqual(report["report_type"], "dlp_email_investigation")
        self.assertEqual(report["risk_assessment"]["band"], "low")
        self.assertEqual(report["recipient"]["legitimacy"]["level"], "UNKNOWN")


# ══════════════════════════════════════════════════════════════════════════════
# Recipient BUSINESS context (Part C) — descriptive-only, MUST NOT score
# ══════════════════════════════════════════════════════════════════════════════

class TestBusinessContext(unittest.TestCase):
    """
    The business-context layer must (a) surface for external corporate domains,
    (b) flag found=False for unknown/suspicious ones, (c) be skipped for
    internal/webmail, and — the load-bearing guarantee — (d) NEVER change the
    risk score, band or verdict versus the identical run without it.
    """

    ACME_BC = {
        "acme-industries.com": found_company(
            "Acme Industries", "Manufacturing",
            legal_name="Acme Industries Inc", description="Industrial widgets",
            industries=["Manufacturing", "Industrial"], business_type="Public Company",
            employee_range="12,000", revenue="Over 1b", country="United States",
            city="Chicago", website="https://acme-industries.com",
            linkedin_url="https://www.linkedin.com/company/123",
            year_founded=1971, match_score=88,
        )
    }

    def _company(self, raises=False):
        return StubCompanyEnrichment(by_domain=dict(self.ACME_BC), raises=raises)

    # (a) found → full descriptive block, marked non-scoring ---------------------
    def test_found_business_context_surfaces(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        company = self._company()
        _, report = run_dlp(eml, alert_id="bc-found", whois=ESTABLISHED_WHOIS,
                            company=company)
        bc = report["recipient"]["business_context"]
        self.assertTrue(bc["applicable"])
        self.assertTrue(bc["looked_up"])
        self.assertTrue(bc["found"])
        self.assertEqual(bc["name"], "Acme Industries")
        self.assertEqual(bc["industry"], "Manufacturing")
        self.assertEqual(bc["confidence"], "medium")      # never "high"
        self.assertEqual(bc["scoring_impact"], "none")
        self.assertEqual(company.lookups, ["acme-industries.com"])

    # (b) unknown external domain → found=False flagged, still non-scoring -------
    def test_unknown_domain_flags_not_found(self):
        eml = make_eml("adele.vance@example-corp.com", "contact@some-partner.com",
                       "Documents")
        company = self._company()
        _, report = run_dlp(eml, alert_id="bc-unknown", company=company)
        bc = report["recipient"]["business_context"]
        self.assertTrue(bc["applicable"])
        self.assertTrue(bc["looked_up"])
        self.assertFalse(bc["found"])
        self.assertTrue(any("No business record" in n for n in bc["notes"]))

    # (b2) suspicious domain → found=False phrased as corroborating -------------
    def test_suspicious_domain_notes_corroborate(self):
        eml = make_eml("adele.vance@example-corp.com", "data@mail12345.io", "x")
        _, report = run_dlp(eml, alert_id="bc-susp", company=self._company())
        bc = report["recipient"]["business_context"]
        self.assertTrue(bc["applicable"])
        self.assertFalse(bc["found"])
        self.assertTrue(any("suspicious" in n.lower() for n in bc["notes"]))

    # (c) internal + webmail → lookup skipped entirely --------------------------
    def test_internal_and_webmail_are_not_looked_up(self):
        internal = make_eml("adele.vance@example-corp.com", "alex.wilber@example-corp.com", "x")
        webmail  = make_eml("adele.vance@example-corp.com", "someone@gmail.com", "x")
        for eml, aid in ((internal, "bc-int"), (webmail, "bc-web")):
            company = self._company()
            _, report = run_dlp(eml, alert_id=aid, company=company)
            bc = report["recipient"]["business_context"]
            self.assertFalse(bc["applicable"])
            self.assertFalse(bc["looked_up"])
            self.assertEqual(company.lookups, [])         # gated: no credit spend

    # (d) THE GUARANTEE — business context never moves the score/verdict --------
    def test_business_context_does_not_affect_scoring(self):
        cases = [
            # (eml, whois, malicious) — spanning legit, sensitive+suspicious, IOC
            (make_eml("adele.vance@example-corp.com", "ap@acme-industries.com",
                      "Confidential — invoice reconciliation",
                      headers={"In-Reply-To": "<t@acme-industries.com>"}),
             ESTABLISHED_WHOIS, None),
            (make_eml("adele.vance@example-corp.com", "x@mailinator.com",
                      "Confidential Restricted client portfolio export",
                      attachments=[{"filename": "confidential_clients.zip",
                                    "maintype": "application", "subtype": "zip",
                                    "size": 2048}]),
             None, None),
            (make_eml("adele.vance@example-corp.com", "contact@some-partner.com",
                      "Documents"), None, None),
            (make_eml("adele.vance@example-corp.com", "drop@evil-exfil.com", "x"),
             None, {"domain": {"evil-exfil.com"}}),
        ]
        for i, (eml, whois, mal) in enumerate(cases):
            _, without = run_dlp(eml, alert_id=f"bc-noscore-a{i}",
                                 whois=whois, malicious=mal)
            _, with_bc = run_dlp(eml, alert_id=f"bc-noscore-b{i}",
                                 whois=whois, malicious=mal, company=self._company())
            ra_wo = without["risk_assessment"]
            ra_bc = with_bc["risk_assessment"]
            self.assertEqual(ra_wo["score"], ra_bc["score"], f"score moved (case {i})")
            self.assertEqual(ra_wo["band"], ra_bc["band"], f"band moved (case {i})")
            self.assertEqual(without["verdict_level"], with_bc["verdict_level"],
                             f"verdict moved (case {i})")
            self.assertEqual(ra_wo["risk_factors"], ra_bc["risk_factors"],
                             f"risk factors changed (case {i})")
            self.assertEqual(ra_wo["mitigating_factors"], ra_bc["mitigating_factors"],
                             f"mitigating factors changed (case {i})")
            # Legitimacy verdict must also be untouched.
            self.assertEqual(without["recipient"]["legitimacy"]["level"],
                             with_bc["recipient"]["legitimacy"]["level"],
                             f"legitimacy moved (case {i})")

    # (e) provider failure degrades gracefully, still non-scoring ---------------
    def test_provider_failure_degrades_gracefully(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        _, report = run_dlp(eml, alert_id="bc-fail", whois=ESTABLISHED_WHOIS,
                            company=self._company(raises=True))
        bc = report["recipient"]["business_context"]
        self.assertTrue(bc["applicable"])
        self.assertFalse(bc["looked_up"])                 # lookup returned None
        self.assertTrue(any("not retrieved" in n for n in bc["notes"]))

    # (f) no provider wired → block present, marked not-looked-up ---------------
    def test_no_provider_still_produces_block(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        _, report = run_dlp(eml, alert_id="bc-none", whois=ESTABLISHED_WHOIS)
        bc = report["recipient"]["business_context"]
        self.assertTrue(bc["applicable"])
        self.assertFalse(bc["looked_up"])
        self.assertEqual(bc["scoring_impact"], "none")

# ══════════════════════════════════════════════════════════════════════════════
# Phishing signals / narrative  (Part 13 → Phishing, Parts 10 & 11 fixes)
# ══════════════════════════════════════════════════════════════════════════════

class TestPhishingSignals(unittest.TestCase):
    """Different alerts must yield different, alert-specific stats + narrative,
    with no stale/cache leakage and no static values."""

    MAL_URL = "http://example-corp.com.verify-account.net/login"

    def _benign(self):
        eml = make_eml("newsletter@trusted-partner.com",
                       "adele.vance@example-corp.com",
                       "Weekly partner newsletter",
                       body="Hello team, here is our regular weekly update.",
                       auth=PASS_AUTH)
        return run_phishing(eml)

    def _malicious(self):
        eml = make_eml("security@example-corp.com.verify-account.net",
                       "adele.vance@example-corp.com",
                       "[URGENT] Unusual activity - verify immediately",
                       body=("We detected unusual activity. Verify now: "
                             + self.MAL_URL + " This is your final notice."),
                       auth=FAIL_AUTH)
        ioc = [{"value": self.MAL_URL, "source": "abusech_urlhaus",
                "malware_family": "CredHarvest"}]
        return run_phishing(eml, ioc_hits=ioc)

    def test_benign_and_malicious_alerts_differ(self):
        _, _, bsum, bverd, bnar = self._benign()
        _, _, msum, mverd, mnar = self._malicious()
        # Summaries differ on every meaningful, per-alert axis (no static stats).
        self.assertNotEqual(bsum, msum)
        self.assertEqual(bsum["risk_level"], "low")
        self.assertEqual(msum["risk_level"], "critical")
        self.assertTrue(bsum["auth_pass"])
        self.assertFalse(msum["auth_pass"])
        self.assertFalse(bsum["any_malicious"])
        self.assertTrue(msum["any_malicious"])
        self.assertEqual(bsum["ioc_hit_count"], 0)
        self.assertEqual(msum["ioc_hit_count"], 1)
        self.assertEqual(bsum["url_count"], 0)
        self.assertEqual(msum["url_count"], 1)
        # Signal counts are computed, not the old two hardcoded signals.
        self.assertEqual(bsum["signal_count"], 0)
        self.assertGreater(msum["signal_count"], 2)
        # Verdict is derived — benign is NOT the old hardcoded ESCALATE.
        self.assertEqual(bverd, "LIKELY_FP")
        self.assertEqual(mverd, "ESCALATE")
        # Narratives are distinct and grounded in each alert's own evidence.
        self.assertNotEqual(bnar, mnar)
        self.assertIn("trusted-partner.com", bnar)
        self.assertIn("verify-account.net", mnar)
        self.assertIn("CredHarvest", mnar)

    def test_no_stale_data_leaks_between_alerts(self):
        # Enrich the malicious alert first, then the benign one immediately after.
        self._malicious()
        _, _, bsum, bverd, bnar = self._benign()
        self.assertEqual(bsum["ioc_hit_count"], 0)
        self.assertFalse(bsum["any_malicious"])
        self.assertNotIn("CredHarvest", bnar)          # no leaked malware family
        self.assertNotIn("verify-account.net", bnar)   # no leaked IOC/domain
        # Pure + stateless: re-running benign is byte-identical.
        _, _, bsum2, bverd2, bnar2 = self._benign()
        self.assertEqual(bsum, bsum2)
        self.assertEqual(bnar, bnar2)
        self.assertEqual(bverd, bverd2)

    def test_auth_pass_reflects_actual_headers(self):
        p = run_phishing(make_eml("a@partner.com", "adele.vance@example-corp.com",
                                  "hi", auth=PASS_AUTH))
        f = run_phishing(make_eml("a@partner.com", "adele.vance@example-corp.com",
                                  "hi", auth=FAIL_AUTH))
        self.assertTrue(p[2]["auth_pass"])
        self.assertFalse(f[2]["auth_pass"])

    def test_recent_sender_domain_raises_signal(self):
        eml = make_eml("noreply@brand-new-domain.com",
                       "adele.vance@example-corp.com", "hello", auth=PASS_AUTH)
        _, signals, summary, _, _ = run_phishing(
            eml, whois_info={"age_days": 10, "Registrar": "NameCheap",
                             "Age": "10 days"})
        self.assertIn("registered recently",
                      " ".join(s["message"] for s in signals))
        self.assertGreaterEqual(summary["signal_count"], 1)

    def test_ioc_hit_escalates_even_when_auth_passes(self):
        url = "http://malware-drop.example/x"
        eml = make_eml("x@somewhere.com", "adele.vance@example-corp.com",
                       "see this", body="link " + url, auth=PASS_AUTH)
        _, signals, summary, verdict, _ = run_phishing(
            eml, ioc_hits=[{"value": url, "source": "otx"}])
        self.assertTrue(summary["any_malicious"])
        self.assertEqual(summary["risk_level"], "critical")
        self.assertEqual(verdict, "ESCALATE")
        self.assertIn("threat feed",
                      " ".join(s["message"] for s in signals))

# ══════════════════════════════════════════════════════════════════════════════
# Template rendering  (Part 13 → Reports: Flask templates render both types)
# ══════════════════════════════════════════════════════════════════════════════

class TestTemplateRendering(unittest.TestCase):
    """Render both Jinja templates the Flask report server dispatches, using the
    real report dicts — no Flask/network required, just the Jinja engine."""

    @classmethod
    def setUpClass(cls):
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except Exception as exc:                        # pragma: no cover
            raise unittest.SkipTest(f"jinja2 unavailable: {exc}")
        cls.env = Environment(
            loader=FileSystemLoader(str(ROOT / "templates")),
            autoescape=select_autoescape(["html"]),
        )

    def test_dlp_template_renders_real_report(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        _, report = run_dlp(eml, alert_id="dlp-render", whois=ESTABLISHED_WHOIS)
        html = self.env.get_template("dlp_report.html").render(**report)
        self.assertIn("DLP Email Investigation", html)
        self.assertIn("dlp-render", html)
        self.assertIn("Acme Industries Inc", html)      # enrichment surfaced

    def test_dlp_template_renders_business_context(self):
        eml = make_eml("adele.vance@example-corp.com", "finance@acme-industries.com",
                       "Partnership follow-up")
        company = StubCompanyEnrichment(by_domain={
            "acme-industries.com": found_company(
                "Acme Industries", "Manufacturing",
                description="Industrial widgets", country="United States",
                city="Chicago", website="https://acme-industries.com"),
        })
        _, report = run_dlp(eml, alert_id="dlp-bc-render",
                            whois=ESTABLISHED_WHOIS, company=company)
        html = self.env.get_template("dlp_report.html").render(**report)
        self.assertIn("Recipient Business Context", html)
        self.assertIn("Industrial widgets", html)        # description surfaced
        self.assertIn("non-scoring", html)               # disclaimer present

    def test_dlp_template_flags_no_business_record(self):
        eml = make_eml("adele.vance@example-corp.com", "contact@some-partner.com", "x")
        company = StubCompanyEnrichment()                 # every domain → not found
        _, report = run_dlp(eml, alert_id="dlp-bc-none", company=company)
        html = self.env.get_template("dlp_report.html").render(**report)
        self.assertIn("no business record found", html)

    def test_phishing_template_renders_real_record(self):
        url = "http://example-corp.com.evil.net/x"
        eml = make_eml("security@example-corp.com.evil.net",
                       "adele.vance@example-corp.com", "[URGENT] verify now",
                       body="verify now " + url, auth=FAIL_AUTH)
        ioc = [{"value": url, "type": "url", "source": "abusech",
                "malware_family": "CredHarvest", "threat_actor": None,
                "severity": "critical"}]
        parsed, signals, summary, verdict, narrative = run_phishing(
            eml, ioc_hits=ioc)
        record = {
            "alert_id": "phish-render", "summary": summary,
            "risk_signals": signals, "urls": parsed["urls"], "ioc_hits": ioc,
            "sender": parsed["from_address"], "subject": parsed["subject"],
            "reply_to": parsed.get("reply_to"),
            "reply_to_mismatch": parsed.get("reply_to_mismatch"),
            "spoofs_domain": parsed.get("spoofs_domain"),
            "urgency_words": parsed.get("urgency_words"),
            "received_ips": parsed.get("received_ips"),
            "spf_result": parsed.get("spf"), "dkim_result": parsed.get("dkim"),
            "dmarc_result": parsed.get("dmarc"),
            "whois_info": {"Registrar": "NameCheap",
                           "CreationDate": "2026-01-01", "Age": "unknown"},
            "homoglyph_flag": "clean", "narrative": narrative,
            "narrative_source": "deterministic",
            "raw_email": eml.decode("utf-8", "replace"),
        }
        html = self.env.get_template("report.html").render(**record)
        self.assertIn("Phishing Enrichment Report", html)
        self.assertIn("phish-render", html)
        self.assertIn("IOC HIT", html)                  # URL matched a feed
        self.assertIn("CredHarvest", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
