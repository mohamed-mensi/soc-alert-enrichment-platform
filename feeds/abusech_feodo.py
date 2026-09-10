"""
feeds/abusech_feodo.py
======================
Collects botnet C2 IP indicators from abuse.ch Feodo Tracker.

Feodo Tracker tracks C2 servers associated with banking trojans
and ransomware loaders: Emotet, TrickBot, QakBot, Dridex, BazarLoader.

Feed URL  : https://feodotracker.abuse.ch/downloads/ipblocklist.json
Auth      : None required — public feed
Updates   : Every 5 minutes on abuse.ch side
Schedule  : Called every 24h by feeds/feed_collector.py

NOTE: As of mid-2024, Feodo Tracker datasets may be sparse due to
law enforcement takedowns (Operation Endgame, Emotet takedown 2021).
The collector handles empty datasets gracefully.

Response format (JSON):
    {
        "query_status": "ok",
        "urls_count": 150,
        "data": [
            {
                "id": 1,
                "ioc": "185.220.101.45",
                "id_online": 1,
                "first_seen_utc": "2024-01-15 10:23:00",
                "last_online": "2024-06-01",
                "malware": "TrickBot",
                "confidence_level": 75,
                "anonymous": 0,
                "reporter": "abuse_ch",
                "ports": [443, 8080],
                "tags": ["TrickBot", "c2"]
            }
        ]
    }

Usage:
    from feeds.abusech_feodo import FeodoCollector
    from database.db_manager import DBManager

    db = DBManager()
    collector = FeodoCollector(db)
    result = collector.run()
    print(result)
    # {"status": "success", "fetched": 150, "new": 12, "updated": 138}
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

FEED_URL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SOURCE_NAME  = "abusech_feodo"
REQUEST_TIMEOUT_SECS = 30

# Map Feodo confidence levels (0-100) to our schema values
def _confidence(level: int) -> str:
    if level >= 75:
        return "high"
    if level >= 40:
        return "medium"
    return "low"

# All malware families Feodo tracks are high severity for a financial SOC
def _severity(malware: str) -> str:
    critical = {"trickbot", "emotet", "qakbot", "bazarloader", "dridex"}
    if malware.lower() in critical:
        return "critical"
    return "high"


# ── Collector ────────────────────────────────────────────────────────────────

class FeodoCollector:
    """
    Pulls the Feodo Tracker IP blocklist and stores results in the
    IOC database via DBManager.

    Parameters
    ----------
    db : DBManager
        Initialized database manager instance.
    feed_url : str, optional
        Override the default feed URL (useful for testing with a local fixture).
    """

    def __init__(self, db, feed_url: str = FEED_URL):
        self.db       = db
        self.feed_url = feed_url

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Fetch, parse, normalize, and store Feodo Tracker IOCs.

        Returns
        -------
        dict with keys:
            status       : "success" | "failed" | "partial"
            fetched      : total IOCs in the feed response
            new          : IOCs inserted for the first time
            updated      : existing IOCs refreshed
            empty        : True if feed returned 0 IOCs (e.g. post-takedown)
            error        : error message string (only on failure)
            duration_secs: float, how long the run took
        """
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        t0         = time.monotonic()

        logger.info(f"[{SOURCE_NAME}] Starting feed collection from {self.feed_url}")

        # ── Step 1: Fetch ──────────────────────────────────────────────────
        try:
            raw_data = self._fetch()
        except Exception as exc:
            duration = round(time.monotonic() - t0, 2)
            logger.error(f"[{SOURCE_NAME}] Fetch failed: {exc}")
            self.db.record_feed_run(
                source=SOURCE_NAME, status="failed",
                error_message=str(exc), duration_seconds=duration,
                started_at=started_at
            )
            return {"status": "failed", "error": str(exc), "duration_secs": duration}

        # ── Step 2: Validate ───────────────────────────────────────────────
        records = raw_data.get("data", [])
        total   = len(records)

        if total == 0:
            duration = round(time.monotonic() - t0, 2)
            logger.warning(
                f"[{SOURCE_NAME}] Feed returned 0 IOCs — "
                "may be empty due to law enforcement takedowns"
            )
            self.db.record_feed_run(
                source=SOURCE_NAME, status="success",
                iocs_fetched=0, iocs_new=0, iocs_updated=0,
                duration_seconds=duration, started_at=started_at
            )
            return {
                "status": "success", "fetched": 0,
                "new": 0, "updated": 0, "empty": True,
                "duration_secs": duration
            }

        logger.info(f"[{SOURCE_NAME}] Fetched {total} IOCs — normalizing...")

        # ── Step 3: Normalize and store ────────────────────────────────────
        new_count     = 0
        updated_count = 0
        error_count   = 0

        for record in records:
            try:
                ioc    = self._normalize(record)
                is_new = self.db.upsert_ioc(ioc)
                if is_new:
                    new_count += 1
                else:
                    updated_count += 1
            except Exception as exc:
                error_count += 1
                logger.warning(f"[{SOURCE_NAME}] Failed to store record {record}: {exc}")

        duration = round(time.monotonic() - t0, 2)
        status   = "success" if error_count == 0 else "partial"

        logger.info(
            f"[{SOURCE_NAME}] Done in {duration}s — "
            f"{new_count} new, {updated_count} updated, {error_count} errors"
        )

        self.db.record_feed_run(
            source=SOURCE_NAME, status=status,
            iocs_fetched=total,
            iocs_new=new_count,
            iocs_updated=updated_count,
            error_message=f"{error_count} parse errors" if error_count else None,
            duration_seconds=duration,
            started_at=started_at
        )

        return {
            "status":        status,
            "fetched":       total,
            "new":           new_count,
            "updated":       updated_count,
            "errors":        error_count,
            "empty":         False,
            "duration_secs": duration,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch(self) -> dict:
        """
        HTTP GET the Feodo Tracker JSON feed.

        Raises
        ------
        requests.HTTPError   if the server returns a non-2xx status
        requests.Timeout     if the request exceeds REQUEST_TIMEOUT_SECS
        requests.ConnectionError if the host is unreachable
        """
        logger.debug(f"[{SOURCE_NAME}] GET {self.feed_url}")
        response = requests.get(
            self.feed_url,
            timeout=REQUEST_TIMEOUT_SECS,
            headers={"User-Agent": "SOC-Enrichment-Platform/1.0 (internal)"}
        )
        response.raise_for_status()
        return response.json()

    def _normalize(self, record: dict) -> dict:
        """
        Convert a single Feodo Tracker record into the standard IOC schema
        used by DBManager.upsert_ioc().

        Feodo record keys used:
            id, ioc, malware, confidence_level, first_seen_utc,
            last_online, tags, ports, anonymous, reporter
        """
        malware    = (record.get("malware") or "unknown").strip()
        confidence = _confidence(record.get("confidence_level", 75))
        severity   = _severity(malware)

        # Build tags: malware family + c2 + port info
        tags = list({
            malware.lower(),
            "c2",
            "botnet",
            "banking-trojan",
        })
        for port in (record.get("ports") or []):
            tags.append(f"port:{port}")
        # Merge any tags already present in the record
        for t in (record.get("tags") or []):
            if t:
                tags.append(t.lower())
        tags = sorted(set(tags))  # deduplicate

        # Normalize first_seen — Feodo uses "YYYY-MM-DD HH:MM:SS"
        first_seen = self._parse_date(record.get("first_seen_utc"))
        last_seen  = self._parse_date(record.get("last_online"))

        return {
            "type":           "ip",
            "value":          (record.get("ioc") or "").strip(),
            "source":         SOURCE_NAME,
            "source_id":      str(record.get("id", "")),
            "malware_family": malware,
            "threat_actor":   None,   # Feodo doesn't attribute to specific actors
            "campaign":       None,
            "tags":           tags,
            "confidence":     confidence,
            "severity":       severity,
            "first_seen":     first_seen,
            "last_seen":      last_seen,
            "expires_at":     None,
            "raw":            record,
        }

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[str]:
        """
        Normalize various date string formats to ISO 8601.
        Returns None if the value is missing or unparseable.
        """
        if not value:
            return None

        formats = [
            "%Y-%m-%d %H:%M:%S",  # Feodo first_seen_utc
            "%Y-%m-%d",           # Feodo last_online
            "%Y-%m-%dT%H:%M:%SZ", # ISO 8601 with Z
            "%Y-%m-%dT%H:%M:%S",  # ISO 8601 without Z
        ]
        for fmt in formats:
            try:
                return datetime.strptime(value.strip(), fmt).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

        logger.debug(f"[{SOURCE_NAME}] Could not parse date: {value!r}")
        return None