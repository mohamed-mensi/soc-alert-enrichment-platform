"""
tests/mock_data/inject_dlp_alerts.py
=====================================
Injects mock DLP email alerts into case management platform for testing.

Reads .eml files from tests/sample_emails/ and creates
case management platform alerts tagged 'dlp-alert' so the DLP enrichment
pipeline picks them up.

Usage:
    cd soc_enrichment
    python tests/mock_data/inject_dlp_alerts.py
"""

import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

CASE_PLATFORM_URL     = os.getenv("CASE_PLATFORM_URL", "http://localhost:9000")
CASE_PLATFORM_API_KEY = os.getenv("CASE_PLATFORM_API_KEY")

# case management platform rejects a duplicate (type, source, sourceRef) triple with HTTP 400, so
# a fixed sourceRef makes this script single-use per environment. A per-run
# suffix keeps every injection valid without needing to delete old alerts first.
# No pipeline reads sourceRef - routing is by tag - so this is display-only.
RUN_ID = int(time.time())

if not CASE_PLATFORM_API_KEY:
    print("ERROR: CASE_PLATFORM_API_KEY not set in .env")
    sys.exit(1)

HEADERS = {
    "Authorization": f"Bearer {CASE_PLATFORM_API_KEY}",
    "Content-Type":  "application/json"
}

# ── DLP scenarios ─────────────────────────────────────────────────────────────

DLP_SCENARIOS = [
    {
        "title":    "DLP Alert — Confidential Financial Data Sent to Personal Email",
        "source":   "SIEM-DLP",
        "sourceRef": "dlp-001",
        "severity": 3,
        "tags":     ["dlp-alert", "self-send", "financial-data", "after-hours"],
        "eml_file": "tests/sample_emails/dlp_internal_to_gmail.eml",
        "observables": [
            {
                "dataType": "mail",
                "data":     "adele.vance@example-corp.com",
                "message":  "Sender — internal Finance user",
                "tags":     ["sender", "internal", "finance"]
            },
            {
                "dataType": "mail",
                "data":     "adelevance92@gmail.com",
                "message":  "Recipient — personal Gmail address",
                "tags":     ["recipient", "external", "webmail"]
            },
        ]
    },
    {
        "title":    "DLP Alert — Client Portfolio Data Sent to Unknown External Domain",
        "source":   "SIEM-DLP",
        "sourceRef": "dlp-002",
        "severity": 4,
        "tags":     ["dlp-alert", "client-data", "external-domain", "restricted"],
        "eml_file": "tests/sample_emails/dlp_confidential_external.eml",
        "observables": [
            {
                "dataType": "mail",
                "data":     "lee.grant@example-corp.com",
                "message":  "Sender — internal Marketing user",
                "tags":     ["sender", "internal", "marketing"]
            },
            {
                "dataType": "mail",
                "data":     "contact@databroker-services.net",
                "message":  "Recipient — unknown external domain",
                "tags":     ["recipient", "external", "unknown-domain"]
            },
            {
                "dataType": "domain",
                "data":     "databroker-services.net",
                "message":  "Recipient domain — unknown, check WHOIS",
                "tags":     ["recipient-domain", "external"]
            },
        ]
    },
    {
        "title":    "DLP Alert — Financial Statements Sent to Audit Firm (Possible FP)",
        "source":   "SIEM-DLP",
        "sourceRef": "dlp-003",
        "severity": 2,
        "tags":     ["dlp-alert", "audit", "vendor", "possible-fp"],
        "eml_file": "tests/sample_emails/dlp_legitimate_vendor.eml",
        "observables": [
            {
                "dataType": "mail",
                "data":     "alex.wilber@example-corp.com",
                "message":  "Sender — IT Manager",
                "tags":     ["sender", "internal", "it-admin"]
            },
            {
                "dataType": "mail",
                "data":     "audit.team@pwc.com",
                "message":  "Recipient — PwC audit team",
                "tags":     ["recipient", "external", "vendor"]
            },
            {
                "dataType": "domain",
                "data":     "pwc.com",
                "message":  "Recipient domain — established Big 4 audit firm",
                "tags":     ["recipient-domain", "known-vendor"]
            },
        ]
    },
]


# ── Injector ──────────────────────────────────────────────────────────────────

def read_eml(path: str) -> str:
    """Read .eml file content as string for case management platform description field."""
    eml_path = Path(path)
    if not eml_path.exists():
        raise FileNotFoundError(f"EML file not found: {path}")
    return eml_path.read_text(encoding="utf-8", errors="replace")


def create_alert(scenario: dict) -> dict:
    """Create a case management platform alert with the .eml content in the description."""
    eml_content  = read_eml(scenario["eml_file"])
    observables  = scenario.pop("observables", [])

    alert_payload = {
        "title":       scenario["title"],
        "type":        "dlp",
        "source":      scenario["source"],
        "sourceRef":   f"{scenario['sourceRef']}-{RUN_ID}",
        "severity":    scenario["severity"],
        "tags":        scenario["tags"],
        "description": eml_content,   # full .eml content in description
    }

    response = requests.post(
        f"{CASE_PLATFORM_URL}/api/v1/alert",
        headers=HEADERS,
        json=alert_payload,
        timeout=10
    )
    # Surface case management platform's own error message instead of a bare "400 Bad Request",
    # which says nothing about which field it rejected.
    if response.status_code >= 400:
        raise RuntimeError(
            f"HTTP {response.status_code} from case management platform: {response.text[:400]}"
        )
    created  = response.json()
    alert_id = created["_id"]

    # Add observables
    for obs in observables:
        obs_resp = requests.post(
            f"{CASE_PLATFORM_URL}/api/v1/alert/{alert_id}/observable",
            headers=HEADERS,
            json=obs,
            timeout=10
        )
        if obs_resp.status_code not in (200, 201):
            print(f"  ⚠ Observable failed: {obs['data']} — {obs_resp.text[:60]}")

    return created


def run():
    print(f"Injecting {len(DLP_SCENARIOS)} DLP alert(s) into case management platform")
    print(f"Target: {CASE_PLATFORM_URL}\n")

    success = 0
    failed  = 0

    for i, scenario in enumerate(DLP_SCENARIOS, 1):
        title = scenario.get("title", "")
        try:
            created  = create_alert(scenario)
            alert_id = created["_id"]
            print(f"  ✅ [{i}/{len(DLP_SCENARIOS)}] {title[:65]}")
            print(f"       ID: {alert_id} | Severity: {created.get('severityLabel')}")
            success += 1
        except Exception as exc:
            print(f"  ❌ [{i}/{len(DLP_SCENARIOS)}] {title[:65]}")
            print(f"       Error: {exc}")
            failed += 1

    print(f"\nDone — {success} created, {failed} failed")
    print(f"View at: {CASE_PLATFORM_URL}/alerts (login as analyst@example.local)")


if __name__ == "__main__":
    run()