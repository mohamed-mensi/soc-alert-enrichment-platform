"""
hive/case_platform_client.py
====================
Polls case management platform for new alerts and cases, reads their observables,
and passes them to the enrichment engine.

Responsibilities:
- Authenticate with case management platform via API key
- Poll for new alerts since last check (every 30s)
- Poll for new cases since last check (every 30s)
- Fetch observables for each alert/case
- Track last-seen timestamp to avoid re-processing

case management platform API v1 is used throughout.
All timestamps are in milliseconds (case management platform standard).

Usage:
    from case_platform.case_platform_client import CasePlatformClient

    client = CasePlatformClient()
    new_alerts = client.get_new_alerts()
    for alert in new_alerts:
        observables = client.get_alert_observables(alert["_id"])
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_CASE_PLATFORM_URL = "http://localhost:9000"
REQUEST_TIMEOUT  = 30
PAGE_SIZE        = 50   # max alerts/cases per poll


class CasePlatformClient:
    """
    case management platform API v1 client for the SOC Enrichment Platform.

    Polls for new alerts and cases, fetches their observables,
    and tracks the last-seen timestamp to avoid re-processing.

    Parameters
    ----------
    url     : case management platform base URL (defaults to CASE_PLATFORM_URL env var)
    api_key : API key (defaults to CASE_PLATFORM_API_KEY env var)
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.url     = (url or os.getenv("CASE_PLATFORM_URL", DEFAULT_CASE_PLATFORM_URL)).rstrip("/")
        self.api_key = api_key or os.getenv("CASE_PLATFORM_API_KEY")

        if not self.api_key:
            raise ValueError(
                "case management platform API key not set. "
                "Add CASE_PLATFORM_API_KEY to your .env file."
            )

        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }

        # Last-seen timestamps in milliseconds
        # Initialized to now so first poll only catches alerts created after startup
        # Set to 0 to backfill all existing alerts on first run
        self._last_alert_ts: int = 0
        self._last_case_ts:  int = 0

        logger.info(f"CasePlatformClient initialized — {self.url}")

    # ── Connection ────────────────────────────────────────────────────────────

    def check_connection(self) -> bool:
        """
        Verify case management platform is reachable and the API key is valid.
        Returns True if connected, False otherwise.
        """
        try:
            response = self._get("/api/v1/status")
            version  = response.get("version", "unknown")
            logger.info(f"Connected to case management platform {version}")
            return True
        except Exception as exc:
            logger.error(f"Cannot connect to case management platform: {exc}")
            return False

    # ── Alert polling ─────────────────────────────────────────────────────────

    def get_new_alerts(self) -> list[dict]:
        """
        Return all alerts created since the last poll.
        Updates the internal timestamp on each call.

        Returns
        -------
        list[dict] : alert objects, newest last (chronological order)
        """
        since = self._last_alert_ts
        alerts = self._query_alerts(since)

        if alerts:
            # Update timestamp to the most recent alert we saw
            latest = max(a.get("_createdAt", 0) for a in alerts)
            self._last_alert_ts = latest + 1  # +1 to exclude on next poll
            logger.info(f"Found {len(alerts)} new alert(s) since ts={since}")
        else:
            logger.debug("No new alerts since last poll")

        return alerts

    def get_alert(self, alert_id: str) -> dict:
        """Fetch a single alert by ID."""
        return self._get(f"/api/v1/alert/{alert_id}")

    def get_alert_observables(self, alert_id: str) -> list[dict]:
        """
        Fetch all observables attached to an alert.

        Returns
        -------
        list[dict] with keys: _id, dataType, data, tags, message, ioc
        """
        body = {
            "query": [
                {"_name": "getAlert", "idOrName": alert_id},
                {"_name": "observables"}
            ]
        }
        result = self._post("/api/v1/query?name=alert-observables", body)
        observables = result if isinstance(result, list) else []
        logger.debug(f"Alert {alert_id}: {len(observables)} observable(s)")
        return observables

    # ── Case polling ──────────────────────────────────────────────────────────

    def get_new_cases(self) -> list[dict]:
        """
        Return all cases created since the last poll.
        Updates the internal timestamp on each call.
        """
        since = self._last_case_ts
        cases = self._query_cases(since)

        if cases:
            latest = max(c.get("_createdAt", 0) for c in cases)
            self._last_case_ts = latest + 1
            logger.info(f"Found {len(cases)} new case(s) since ts={since}")
        else:
            logger.debug("No new cases since last poll")

        return cases

    def get_case(self, case_id: str) -> dict:
        """Fetch a single case by ID."""
        return self._get(f"/api/v1/case/{case_id}")

    def get_case_observables(self, case_id: str) -> list[dict]:
        """Fetch all observables attached to a case."""
        body = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"}
            ]
        }
        result = self._post("/api/v1/query?name=case-observables", body)
        observables = result if isinstance(result, list) else []
        logger.debug(f"Case {case_id}: {len(observables)} observable(s)")
        return observables

    # ── Alert promotion ───────────────────────────────────────────────────────

    def get_cases_for_alert(self, alert_id: str) -> list[dict]:
        """
        Return cases that were promoted from this alert.
        Used to check if an alert has already been escalated to a case.
        """
        body = {
            "query": [
                {"_name": "getAlert", "idOrName": alert_id},
                {"_name": "cases"}
            ]
        }
        result = self._post("/api/v1/query?name=alert-cases", body)
        return result if isinstance(result, list) else []

    # ── Search ────────────────────────────────────────────────────────────────

    def search_alerts_by_observable(self, value: str) -> list[dict]:
        """
        Find past alerts containing a specific observable value.
        Used by case_history.py for recurrence detection.
        """
        body = {
            "query": [
                {"_name": "listAlert"},
                {
                    "_name": "filter",
                    "_contains": {
                        "_field": "observables.data",
                        "_value": value
                    }
                },
                {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                {"_name": "page", "from": 0, "to": 20}
            ]
        }
        result = self._post("/api/v1/query?name=search-alerts-by-observable", body)
        return result if isinstance(result, list) else []

    def search_cases_by_observable(self, value: str) -> list[dict]:
        """
        Find past cases containing a specific observable value.
        Used by case_history.py for recurrence detection.
        """
        body = {
            "query": [
                {"_name": "listCase"},
                {
                    "_name": "filter",
                    "_contains": {
                        "_field": "observables.data",
                        "_value": value
                    }
                },
                {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                {"_name": "page", "from": 0, "to": 20}
            ]
        }
        result = self._post("/api/v1/query?name=search-cases-by-observable", body)
        return result if isinstance(result, list) else []

    # ── Timestamp helpers ─────────────────────────────────────────────────────

    def reset_alert_timestamp(self, ts_ms: int = 0):
        """
        Reset the alert polling timestamp.
        Set to 0 to reprocess all existing alerts.
        Set to a specific ms timestamp to start from that point.
        """
        self._last_alert_ts = ts_ms
        logger.info(f"Alert timestamp reset to {ts_ms}")

    def reset_case_timestamp(self, ts_ms: int = 0):
        """Reset the case polling timestamp."""
        self._last_case_ts = ts_ms
        logger.info(f"Case timestamp reset to {ts_ms}")

    @staticmethod
    def now_ms() -> int:
        """Current UTC time in milliseconds."""
        return int(datetime.now(timezone.utc).timestamp() * 1000)

    # ── Internal query builders ───────────────────────────────────────────────

    def _query_alerts(self, since_ms: int) -> list[dict]:
        """
        Query case management platform for alerts created after since_ms.
        Uses case management platform's query API for server-side filtering.
        """
        body = {
            "query": [
                {"_name": "listAlert"},
                {
                    "_name": "filter",
                    "_gt": {
                        "_field": "_createdAt",
                        "_value": since_ms
                    }
                },
                {
                    "_name": "sort",
                    "_fields": [{"_createdAt": "asc"}]
                },
                {
                    "_name": "page",
                    "from": 0,
                    "to": PAGE_SIZE,
                    "extraData": ["observableCount"]
                }
            ]
        }
        result = self._post("/api/v1/query?name=new-alerts", body)
        return result if isinstance(result, list) else []

    def _query_cases(self, since_ms: int) -> list[dict]:
        """Query case management platform for cases created after since_ms."""
        body = {
            "query": [
                {"_name": "listCase"},
                {
                    "_name": "filter",
                    "_gt": {
                        "_field": "_createdAt",
                        "_value": since_ms
                    }
                },
                {
                    "_name": "sort",
                    "_fields": [{"_createdAt": "asc"}]
                },
                {
                    "_name": "page",
                    "from": 0,
                    "to": PAGE_SIZE
                }
            ]
        }
        result = self._post("/api/v1/query?name=new-cases", body)
        return result if isinstance(result, list) else []

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        """HTTP GET to case management platform API."""
        url = f"{self.url}{path}"
        logger.debug(f"GET {url}")
        response = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict) -> list | dict:
        """HTTP POST to case management platform API."""
        url = f"{self.url}{path}"
        logger.debug(f"POST {url}")
        response = requests.post(
            url, headers=self.headers,
            json=body, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    # hive/case_platform_client.py (add inside CasePlatformClient class)

    def create_alert(self, alert: dict) -> dict:
        """
        Create a new alert in case management platform and attach observables if provided.
        """
        observables = alert.pop("observables", [])

        url = f"{self.url}/api/v1/alert"
        response = requests.post(url, headers=self.headers, json=alert, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        created = response.json()
        alert_id = created["_id"]

        # Attach observables separately
        for obs in observables:
            obs_url = f"{self.url}/api/v1/alert/{alert_id}/observable"
            obs_resp = requests.post(obs_url, headers=self.headers, json=obs, timeout=REQUEST_TIMEOUT)
            obs_resp.raise_for_status()

        return created   # <-- return full dict, not just alert_id



# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    client = CasePlatformClient()

    # Test connection
    if not client.check_connection():
        print("Cannot connect to case management platform — check CASE_PLATFORM_URL and CASE_PLATFORM_API_KEY in .env")
        sys.exit(1)

    # Fetch all alerts (reset timestamp to 0 to get everything)
    client.reset_alert_timestamp(0)
    alerts = client.get_new_alerts()
    print(f"\nFound {len(alerts)} alert(s):\n")

    for alert in alerts:
        print(f"  [{alert['_id']}] {alert['title']}")
        print(f"    Severity : {alert.get('severityLabel')}")
        print(f"    Status   : {alert.get('status')}")
        print(f"    Created  : {alert.get('_createdAt')}")

        # Fetch observables
        observables = client.get_alert_observables(alert["_id"])
        for obs in observables:
            print(f"    Observable: [{obs.get('dataType')}] {obs.get('data')} — tags: {obs.get('tags', [])}")
        print()