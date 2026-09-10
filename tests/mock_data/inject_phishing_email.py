"""
Injects a phishing .eml file into case management platform as an alert.
Renders raw email in Summary (description) and uploads the .eml
into the Attachments tab as a file observable.
"""

import sys
import logging
import time
import json
import requests
from pathlib import Path
from case_platform.case_platform_client import CasePlatformClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

def inject_phishing_email(eml_path: str, reporter_email: str):
    client = CasePlatformClient()

    file_path = Path(eml_path)
    if not file_path.exists():
        logging.error(f"File not found: {eml_path}")
        return

    eml_bytes = file_path.read_bytes()
    raw_content = eml_bytes.decode(errors="ignore")

    # Alert payload — description is what case management platform renders in Summary
    alert = {
        "title": "User-Reported Phishing",
        "type": "external",
        "source": "Outlook",
        "sourceRef": f"phish-{int(time.time())}",
        "description": raw_content[:5000],   # raw email goes here
        "severity": 2,
        "tlp": 2,
        "tags": ["phishing-report", "user-reported", "outlook"]
    }

    try:
        # Create alert
        created = client.create_alert(alert)
        alert_id = created["_id"]

        # Reporter email observable
        reporter_obs = {
            "dataType": "mail",
            "data": reporter_email,
            "message": "Reporter email address",
            "tags": ["reporter"]
        }
        client._post(f"/api/v1/alert/{alert_id}/observable", reporter_obs)

       
        logging.info(f"Injected phishing alert into case management platform: {alert_id}")

    except Exception as e:
        logging.error(f"Failed to inject alert: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python inject_phishing_email.py <eml_path> <reporter_email>")
        sys.exit(1)

    inject_phishing_email(sys.argv[1], sys.argv[2])
