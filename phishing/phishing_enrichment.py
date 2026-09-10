"""
phishing_enrichment.py
======================

Standalone runner for phishing enrichment:
  - Poll case management platform for new alerts tagged 'phishing-report'
  - Parse raw .eml content from description
  - Extract observables (sender, subject, URLs)
  - Check SPF/DKIM/DMARC, WHOIS, homoglyphs, IOC hits
  - Save JSON report for external server
  - Update case management platform alert with link to hosted report
"""

import logging
import os
import re
import sqlite3
import time
import ipaddress
import unicodedata
import socket
from datetime import datetime
from email import policy
from email.parser import BytesParser

from dotenv import load_dotenv
import requests


import dns.resolver
import dkim
import whois

from enrichment.report_generator import save_report
from enrichment.enrichment_engine import EnrichmentEngine
from case_platform.case_platform_client import CasePlatformClient
from case_platform.case_platform_updater import CasePlatformUpdater
from enrichment.ioc_lookup import IOCLookup
from enrichment.identity_lookup import IdentityLookup
from database.db_manager import DBManager
from enrichment.llm_analyzer import LLMAnalyzer
from enrichment import report_common as rc
from phishing.email_parser import EmailParser


load_dotenv()
MXTOOLBOX_API_KEY = os.getenv("MXTOOLBOX_API_KEY")
BASE_URL = "https://api.mxtoolbox.com/api/v1/lookup"

WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")
WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

analyzer = LLMAnalyzer()

# Global socket timeout for WHOIS
socket.setdefaulttimeout(3)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

# ── Helper functions ────────────────────────────────────────────────

def whois_lookup(domain):
    params = {
        "apiKey": WHOISXML_API_KEY,
        "domainName": domain,
        "outputFormat": "JSON"
    }
    try:
        r = requests.get(WHOIS_URL, params=params, timeout=20)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": r.status_code, "message": r.text}
    except Exception as e:
        return {"error": "exception", "message": str(e)}

def parse_whois(whois_json):
    if not whois_json or "error" in whois_json:
        return {"Registrar": "WHOIS lookup failed", "CreationDate": "N/A", "Age": "N/A"}
    
    record = whois_json.get("WhoisRecord", {})
    registrar = record.get("registrarName", "Unknown")
    creation = record.get("createdDateNormalized", "Unknown")
    age_days = record.get("estimatedDomainAge", None)
    age = f"{age_days//365} years" if age_days else "Unknown"
    
    return {
        "Registrar": registrar,
        "CreationDate": creation,
        "Age": age,
        # Expose the numeric age so downstream signal logic
        # (compute_phishing_signals) can flag recently-registered
        # sender domains; without this the "registered recently"
        # signal could never fire in production.
        "age_days": age_days,
    }


def mxtoolbox_lookup(command, argument):
    headers = {"Authorization": MXTOOLBOX_API_KEY}
    url = f"{BASE_URL}/{command}/{argument}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": r.status_code, "message": r.text}
    except Exception as e:
        return {"error": "exception", "message": str(e)}

def extract_ips(raw_email: str):
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw_email)


def check_spf(domain, ip=""):
    start = time.time()
    try:
        txt_records = dns.resolver.resolve(domain, "TXT", lifetime=2)
        for r in txt_records:
            if "v=spf1" in r.to_text():
                result = "pass" if ip and ip in r.to_text() else "policy found"
                break
        else:
            result = "none"
    except Exception as e:
        logger.warning(f"SPF check failed for {domain}: {e}")
        result = "unknown"
    finally:
        logger.info(f"SPF check for {domain} took {time.time()-start:.2f}s")
    return result

def check_dkim(raw_email):
    start = time.time()
    try:
        result = "pass" if dkim.verify(raw_email.encode()) else "fail"
    except Exception as e:
        logger.warning(f"DKIM check failed: {e}")
        result = "unknown"
    finally:
        logger.info(f"DKIM check took {time.time()-start:.2f}s")
    return result

def check_dmarc(domain):
    start = time.time()
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=2)
        result = next((r.to_text() for r in txt_records if "v=DMARC1" in r.to_text()), "none")
    except Exception as e:
        logger.warning(f"DMARC check failed for {domain}: {e}")
        result = "unknown"
    finally:
        logger.info(f"DMARC check for {domain} took {time.time()-start:.2f}s")
    return result
def parse_spf(spf_list):
    if isinstance(spf_list, list):
        record = next((r for r in spf_list if r.get("Type") == "record"), None)
        if record:
            desc = record.get("Description", "")
            if "-all" in desc:
                return f"{desc} (strict -all)"
            elif "~all" in desc:
                return f"{desc} (softfail ~all)"
            elif "+all" in desc:
                return f"{desc} (permissive +all — red flag)"
            return desc
        return "No SPF record found"
    return "SPF lookup failed"


def parse_dmarc(dmarc_list):
    if isinstance(dmarc_list, list):
        record = next((r for r in dmarc_list if r.get("Name") == "record"), None)
        if record:
            desc = record.get("Description", "")
            policy = next((r for r in dmarc_list if r.get("Name") == "Policy"), None)
            if policy:
                return f"{desc} (policy={policy.get('TagValue')})"
            return desc
        return "No DMARC record found"
    return "DMARC lookup failed"


def domain_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        registrar = w.registrar
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.now() - creation).days if creation else None
        return {
            "registrar": registrar or "none",
            "creation_date": str(creation) if creation else "not registered",
            "age_days": age_days or "N/A"
        }
    except Exception as e:
        return {"registrar": "unknown", "creation_date": "unknown", "age_days": "unknown"}

def detect_homoglyph(domain: str):
    try:
        suspicious_chars = []
        for ch in domain:
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name or "GREEK" in name:
                suspicious_chars.append(f"{ch} ({name})")
        if suspicious_chars:
            return f"⚠️ homoglyph detected — suspicious chars: {', '.join(suspicious_chars)}"
        else:
            return "clean"
    except Exception as e:
        logger.warning(f"Homoglyph check failed for {domain}: {e}")
        return "unknown"

def check_ioc(observables):
    start = time.time()
    conn = sqlite3.connect("data/ioc_database.db")
    cur = conn.cursor()
    hits = []
    for o in observables:
        try:
            cur.execute("SELECT type, source, malware_family, threat_actor, confidence, severity FROM iocs WHERE value=?", (o,))
            rows = cur.fetchall()
            for row in rows:
                hits.append({
                    "value": o,
                    "type": row[0],
                    "source": row[1],
                    "malware_family": row[2] or "N/A",
                    "threat_actor": row[3] or "N/A",
                    "confidence": row[4] or "N/A",
                    "severity": row[5] or "N/A"
                })
        except Exception as e:
            logger.warning(f"IOC check failed for {o}: {e}")
    conn.close()
    logger.info(f"IOC check for {len(observables)} observables took {time.time()-start:.2f}s")
    return hits if hits else []


# ── Main class ──────────────────────────────────────────────────────
class PhishingEnrichment:
    def __init__(self, engine, parser=None, llm=None):
        self.engine = engine
        # Reuse the shared EmailParser so the phishing flow extracts the same
        # rich, structured signals (auth results, URLs, spoofing, reply-to
        # mismatch, urgency, attachments) the DLP flow relies on — instead of a
        # bare BytesParser that only pulled From/Subject.
        self.parser = parser or EmailParser()
        self.llm = llm or analyzer

    def run(self):
        alerts = self.engine.case_platform_client.get_new_alerts()
        logger.info(f"Found {len(alerts)} new alert(s)")
        for alert in alerts:
            tags = alert.get("tags") or []
            if "phishing-report" in [t.lower() for t in tags]:
                start_alert = time.time()
                record = self._process_phishing_alert(alert)
                elapsed = time.time() - start_alert
                logger.info(f"Phishing enrichment complete for {alert['_id']} in {elapsed:.2f}s")
                print(f"✅ Alert {alert['_id']} enriched — link: http://localhost:5000/report/{alert['_id']}")

    def _process_phishing_alert(self, alert: dict):
        alert_id = alert["_id"]
        raw_content = alert.get("description", "")

        logger.info(f"Processing alert {alert_id}")

        # ── Parse raw .eml via the shared EmailParser ──────────────────────────
        start_parse = time.time()
        parsed = self.parser.parse_bytes(raw_content.encode(errors="ignore"))
        logger.info(f"Email parsing took {time.time()-start_parse:.2f}s")

        sender        = parsed.get("from_address") or "unknown"
        subject       = parsed.get("subject") or "(no subject)"
        sender_domain = parsed.get("from_domain") or "unknown"
        urls          = parsed.get("urls") or []

        # ── External checks (unchanged) ────────────────────────────────────────
        spf_raw     = mxtoolbox_lookup("spf", sender_domain)
        dkim_result = check_dkim(raw_content)
        dmarc_raw   = mxtoolbox_lookup("dmarc", sender_domain)
        whois_raw   = whois_lookup(sender_domain)
        whois_info  = parse_whois(whois_raw)
        homoglyph_flag = detect_homoglyph(sender_domain)

        observables = urls + [sender_domain] + (parsed.get("received_ips") or [])
        ioc_hits    = check_ioc(observables)

        spf_result   = parse_spf(spf_raw.get("Information") if isinstance(spf_raw, dict) else spf_raw)
        dmarc_result = parse_dmarc(dmarc_raw.get("Information") if isinstance(dmarc_raw, dict) else dmarc_raw)

        # Fold the header-derived authentication verdicts back into the parsed
        # record so signal computation sees a coherent SPF/DKIM/DMARC view.
        # DKIM comes from cryptographic verification (check_dkim); SPF/DMARC come
        # from the email's own Authentication-Results header (parsed).
        parsed["dkim"] = dkim_result
        parsed["auth_summary"] = (
            f"SPF:{parsed.get('spf')} DKIM:{parsed.get('dkim')} "
            f"DMARC:{parsed.get('dmarc')}"
        )

        # ── Real, per-alert signals / summary / verdict ────────────────────────
        risk_signals = rc.compute_phishing_signals(parsed, ioc_hits, whois_info)
        summary      = rc.compute_phishing_summary(parsed, ioc_hits, risk_signals)
        verdict_level = rc.phishing_verdict_from_summary(summary)

        # Deterministic, evidence-grounded narrative is always available.
        narrative = rc.build_phishing_narrative(
            parsed, risk_signals, ioc_hits, whois_info, summary
        )
        narrative_source = "deterministic"

        record = {
            "report_type": "phishing",
            "target_type": "alert",
            "target_id": alert_id,
            "alert_id": alert_id,
            "title": alert.get("title", "Phishing Alert"),
            "description": (
                f"Phishing email detected\n"
                f"Subject: {subject}\n"
                f"Sender: {sender}\n"
                f"URLs: {', '.join(urls) if urls else 'none'}\n"
                f"SPF: {spf_result}, DKIM: {dkim_result}, DMARC: {dmarc_result}"
            ),
            "summary": summary,
            "risk_signals": risk_signals,
            "verdict_level": verdict_level,
            "raw_email": raw_content or "no raw content",
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": subject,
            "reply_to": parsed.get("reply_to"),
            "reply_to_mismatch": parsed.get("reply_to_mismatch"),
            "spoofs_domain": parsed.get("spoofs_domain"),
            "auth_summary": parsed.get("auth_summary"),
            "received_ips": parsed.get("received_ips") or [],
            "attachments": parsed.get("attachments") or [],
            "urgency_words": parsed.get("urgency_words") or [],
            "urls": urls if urls else ["none"],
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "spf": parsed.get("spf"),
            "dkim": parsed.get("dkim"),
            "dmarc": parsed.get("dmarc"),
            "whois_info": whois_info,
            "homoglyph_flag": homoglyph_flag,
            "ioc_hits": ioc_hits,
        }

        # ── Additive local-LLM narrative, grounded on this alert's evidence ────
        llm_text = self._llm_narrative(parsed, risk_signals, summary, verdict_level,
                                       whois_info, alert_id)
        if llm_text:
            narrative = (
                f"{narrative}\n\n"
                f"--- AI TRIAGE (local LLM, advisory) ---\n{llm_text}"
            )
            narrative_source = "deterministic+llm"

        record["narrative"] = narrative
        record["narrative_source"] = narrative_source

        # Save JSON report
        save_report(alert_id, record)
        logger.info(f"Report saved for {alert_id}")

        # Update case management platform with link
        link = f"http://localhost:5000/report/{alert_id}"
        if self.engine.case_platform_updater:
            reasons = [s["message"] for s in risk_signals[:5]] or \
                ["Phishing enrichment available"]
            self.engine.case_platform_updater.update_alert(
                alert_id=alert_id,
                enrichments=[],
                verdict=verdict_level,
                verdict_reasons=reasons,
                narrative=f"Full enrichment report: {link}"
            )
            logger.info(f"Updated alert {alert_id} with external report link")

        return record

    def _llm_narrative(self, parsed, risk_signals, summary, verdict_level,
                       whois_info, alert_id):
        """
        Ask the local LLM for a narrative grounded strictly in this alert's
        parsed evidence. Degrades to None (deterministic narrative stands) when
        the LLM is unavailable or errors — it never blocks report generation.
        """
        try:
            if hasattr(self.llm, "is_available") and not self.llm.is_available():
                return None
            description = rc.build_phishing_llm_description(parsed, whois_info)
            return self.llm.generate_narrative({
                "target_id":    alert_id,
                "title":        f"Phishing Investigation — {parsed.get('subject')}",
                "description":  description,
                "risk_signals": risk_signals,
                "summary": {
                    "any_malicious":       summary.get("any_malicious"),
                    "high_risk_identity":  False,
                    "max_reputation_score": 0,
                },
                "verdict_level": verdict_level,
            })
        except Exception as exc:
            logger.warning(f"LLM narrative failed for {alert_id}: {exc}")
            return None

# ── Standalone runner ────────────────────────────────────────────────
if __name__ == "__main__":
    db = DBManager()
    engine = EnrichmentEngine(
        case_platform_client=CasePlatformClient(),
        case_platform_updater=CasePlatformUpdater(),
        ioc_lookup=IOCLookup(db),
        ad_lookup=IdentityLookup(mock_mode=True),
    )

    pe = PhishingEnrichment(engine)
    pe.run()
    print("✅ Phishing enrichment run complete — check case management platform alert for link")
