"""
Standalone test for phishing_enrichment.py
"""

import logging
from pathlib import Path
from phishing.phishing_enrichment import PhishingEnrichment
from enrichment.enrichment_engine import EnrichmentEngine
from case_platform.case_platform_client import CasePlatformClient
from case_platform.case_platform_updater import CasePlatformUpdater
from enrichment.ioc_lookup import IOCLookup
from enrichment.identity_lookup import IdentityLookup
from database.db_manager import DBManager

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

def main():
    # Build dummy engine (no scheduler)
    db = DBManager()
    engine = EnrichmentEngine(
        case_platform_client=CasePlatformClient(),
        case_platform_updater=CasePlatformUpdater(),
        ioc_lookup=IOCLookup(db),
        ad_lookup=IdentityLookup(mock_mode=True),
    )

    # Load a sample phishing email from file
    eml_path = Path("tests/sample_emails/obvious_phishing.eml")
    raw_content = eml_path.read_text(errors="ignore")

    # Fake alert object with raw content in description
    fake_alert = {
        "_id": "test-alert-001",
        "title": "User-Reported Phishing",
        "description": raw_content,
        "tags": ["phishing"],
        "severityLabel": "Medium",
        "_createdAt": "2026-07-23T10:00:00Z"
    }

    # Run phishing enrichment directly
    pe = PhishingEnrichment(engine)
    record = pe._process_phishing_alert(fake_alert)

    print("\n=== Enrichment Output ===")
    print(f"Title: {record['title']}")
    print(f"Summary: {record['summary']}")
    print(f"Risk signals: {record['risk_signals']}")
    print(f"Narrative:\n{record['narrative']}")

if __name__ == "__main__":
    main()
