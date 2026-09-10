"""
feeds/abusech_urlhaus.py
========================
Collects malicious URL indicators from abuse.ch URLhaus.

URLhaus tracks URLs actively used for malware distribution —
drive-by downloads, payload delivery, phishing infrastructure.
Particularly relevant for a financial SOC because many banking
trojans (Emotet, QakBot) use URLhaus-tracked URLs for initial
delivery.

Auth      : Required — free Auth-Key from https://auth.abuse.ch/
            Set ABUSECH_AUTH_KEY in your .env file
Feed URL  : https://urlhaus-api.abuse.ch/v1/urls/recent/
Updates   : Continuous — URLhaus ingests URLs in real time
Schedule  : Called every 24h by feeds/feed_collector.py

What we pull:
    Recent URLs (last 1000) with status "online" only —
    offline URLs are already dead and not worth storing.
    We also extract the HOST from each URL as a domain IOC
    so the enrichment engine can match on domain observables
    too, not just full URLs.

Response format:
    {
        "query_status": "ok",
        "urls": [
            {
                "id": "223622",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
                "url": "http://45.61.49.78/razor/r4z0r.mips",
                "url_status": "online",
                "host": "45.61.49.78",
                "date_added": "2024-08-10 09:02:05 UTC",
                "threat": "malware_download",
                "blacklists": {
                    "spamhaus_dbl": "not listed",
                    "surbl": "not listed"
                },
                "reporter": "zbetcheckin",
                "tags": ["elf", "mips"]
            }
        ]
    }

Usage:
    from feeds.abusech_urlhaus import URLhausCollector
    from database.db_manager import DBManager

    db = DBManager()
    collector = URLhausCollector(db, auth_key="YOUR_KEY")
    result = collector.run()
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from pathlib import Path


import requests

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

BASE_URL        = "https://urlhaus-api.abuse.ch/v1"
RECENT_ENDPOINT = f"{BASE_URL}/urls/recent/limit/1000/"
SOURCE_NAME     = "abusech_urlhaus"
REQUEST_TIMEOUT = 30

# Only store URLs that are currently active — offline ones are noise
ACTIVE_STATUSES = {"online"}

# Threat types URLhaus uses
THREAT_SEVERITY = {
    "malware_download": "high",
    "botnet_cc":        "critical",
    "phishing":         "high",
}


def _severity(threat: str) -> str:
    return THREAT_SEVERITY.get(threat, "medium")


def _confidence(record: dict) -> str:
    """
    Derive confidence from blacklist presence and reporter reputation.
    Listed on Spamhaus DBL or SURBL = high confidence.
    """
    blacklists = record.get("blacklists") or {}
    spamhaus   = blacklists.get("spamhaus_dbl", "not listed")
    surbl      = blacklists.get("surbl", "not listed")

    if spamhaus != "not listed" or surbl != "not listed":
        return "high"
    return "medium"


def _extract_host(url: str) -> Optional[str]:
    """Extract the hostname/IP from a URL string."""
    try:
        parsed = urlparse(url)
        host   = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None


# ── Collector ────────────────────────────────────────────────────────────────

class URLhausCollector:
    """
    Pulls recent malicious URLs from URLhaus and stores both the
    full URL and the extracted host as separate IOC entries.

    Parameters
    ----------
    db       : DBManager
    auth_key : str
        Your abuse.ch Auth-Key. Falls back to ABUSECH_AUTH_KEY env var.
    """

    def __init__(self, db, auth_key: Optional[str] = None):
        self.db       = db
        self.auth_key = auth_key or os.getenv("ABUSECH_AUTH_KEY")

        if not self.auth_key:
            raise ValueError(
                "URLhaus requires an Auth-Key. "
                "Set ABUSECH_AUTH_KEY in your .env or pass auth_key= directly. "
                "Get a free key at https://auth.abuse.ch/"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Fetch, filter, normalize and store URLhaus IOCs.

        Stores two IOC types per record where possible:
          - type=url  : the full malicious URL
          - type=ip or type=domain : the extracted host

        Returns
        -------
        dict: status, fetched, new, updated, errors, duration_secs
        """
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        t0         = time.monotonic()

        logger.info(f"[{SOURCE_NAME}] Starting feed collection")

        # ── Fetch ──────────────────────────────────────────────────────────
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

        # ── Filter — online URLs only ──────────────────────────────────────
        all_records = raw_data.get("urls", [])
        records     = [r for r in all_records if r.get("url_status") in ACTIVE_STATUSES]
        total       = len(all_records)
        active      = len(records)

        logger.info(
            f"[{SOURCE_NAME}] {total} total URLs — "
            f"{active} active (online) — {total - active} offline skipped"
        )

        if active == 0:
            duration = round(time.monotonic() - t0, 2)
            self.db.record_feed_run(
                source=SOURCE_NAME, status="success",
                iocs_fetched=0, duration_seconds=duration,
                started_at=started_at
            )
            return {
                "status": "success", "fetched": 0,
                "new": 0, "updated": 0, "empty": True,
                "duration_secs": duration
            }

        # ── Normalize and store ────────────────────────────────────────────
        new_count     = 0
        updated_count = 0
        error_count   = 0

        for record in records:
            try:
                # Store the full URL as a url-type IOC
                url_ioc = self._normalize_url(record)
                if url_ioc:
                    is_new = self.db.upsert_ioc(url_ioc)
                    if is_new:
                        new_count += 1
                    else:
                        updated_count += 1

                # Also store the host as an ip or domain IOC
                host_ioc = self._normalize_host(record)
                if host_ioc:
                    is_new = self.db.upsert_ioc(host_ioc)
                    if is_new:
                        new_count += 1
                    else:
                        updated_count += 1

            except Exception as exc:
                error_count += 1
                logger.warning(
                    f"[{SOURCE_NAME}] Failed to store record "
                    f"{record.get('id')}: {exc}"
                )

        duration = round(time.monotonic() - t0, 2)
        status   = "success" if error_count == 0 else "partial"

        logger.info(
            f"[{SOURCE_NAME}] Done in {duration}s — "
            f"{new_count} new, {updated_count} updated, {error_count} errors"
        )

        self.db.record_feed_run(
            source=SOURCE_NAME, status=status,
            iocs_fetched=active,
            iocs_new=new_count,
            iocs_updated=updated_count,
            error_message=f"{error_count} parse errors" if error_count else None,
            duration_seconds=duration,
            started_at=started_at
        )

        return {
            "status":        status,
            "fetched":       active,
            "new":           new_count,
            "updated":       updated_count,
            "errors":        error_count,
            "empty":         False,
            "duration_secs": duration,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch(self) -> dict:
        """GET the URLhaus recent URLs feed."""
        logger.debug(f"[{SOURCE_NAME}] GET {RECENT_ENDPOINT}")
        response = requests.get(
            RECENT_ENDPOINT,
            headers={
                "Auth-Key":   self.auth_key,
                "User-Agent": "SOC-Enrichment-Platform/1.0 (internal)"
            },
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def _normalize_url(self, record: dict) -> Optional[dict]:
        """
        Build a url-type IOC from a URLhaus record.
        Returns None if the URL value is missing.
        """
        url = (record.get("url") or "").strip()
        if not url:
            return None

        tags = self._build_tags(record)
        date = self._parse_date(record.get("date_added"))

        return {
            "type":           "url",
            "value":          url,
            "source":         SOURCE_NAME,
            "source_id":      str(record.get("id", "")),
            "malware_family": self._extract_malware(record),
            "threat_actor":   None,
            "campaign":       None,
            "tags":           tags,
            "confidence":     _confidence(record),
            "severity":       _severity(record.get("threat", "")),
            "first_seen":     date,
            "last_seen":      date,
            "expires_at":     None,
            "raw":            record,
        }

    def _normalize_host(self, record: dict) -> Optional[dict]:
        """
        Extract the host from the URL and store it as an ip or domain IOC.
        This allows the enrichment engine to match on host-level observables,
        not just exact full URLs.
        """
        url  = (record.get("url") or "").strip()
        host = record.get("host") or _extract_host(url)
        if not host:
            return None

        # Determine if host is an IP or a domain
        ioc_type = self._classify_host(host)
        tags     = self._build_tags(record) + [f"urlhaus-host"]
        date     = self._parse_date(record.get("date_added"))

        return {
            "type":           ioc_type,
            "value":          host.lower(),
            "source":         SOURCE_NAME,
            "source_id":      f"host_{record.get('id', '')}",
            "malware_family": self._extract_malware(record),
            "threat_actor":   None,
            "campaign":       None,
            "tags":           tags,
            "confidence":     _confidence(record),
            "severity":       _severity(record.get("threat", "")),
            "first_seen":     date,
            "last_seen":      date,
            "expires_at":     None,
            "raw":            {"host_extracted_from": record.get("id"), "host": host},
        }

    def _build_tags(self, record: dict) -> list:
        """Build normalized tag list from URLhaus record."""
        tags = set()

        # Threat type
        threat = record.get("threat", "")
        if threat:
            tags.add(threat.replace("_", "-"))

        # Tags from the record
        for t in (record.get("tags") or []):
            if t:
                tags.add(t.lower().strip())

        # Blacklist presence
        blacklists = record.get("blacklists") or {}
        if blacklists.get("spamhaus_dbl") not in (None, "not listed"):
            tags.add("spamhaus-dbl")
        if blacklists.get("surbl") not in (None, "not listed"):
            tags.add("surbl")

        tags.add("malware-distribution")
        return sorted(tags)

    def _extract_malware(self, record: dict) -> Optional[str]:
        """
        Try to identify a specific malware family from tags.
        URLhaus doesn't have a dedicated malware field — it's in the tags.
        """
        known_families = {
            "emotet", "trickbot", "qakbot", "dridex", "bazarloader",
            "ursnif", "formbook", "asyncrat", "remcos", "nanocore",
            "agentTesla", "lokibot", "raccoon", "redline"
        }
        for tag in (record.get("tags") or []):
            if tag and tag.lower() in known_families:
                return tag.capitalize()
        return None

    @staticmethod
    def _classify_host(host: str) -> str:
        """Return 'ip' if the host looks like an IP address, else 'domain'."""
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return "ip"
        return "domain"

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[str]:
        """Normalize URLhaus date strings to ISO 8601."""
        if not value:
            return None
        formats = [
            "%Y-%m-%d %H:%M:%S UTC",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(value.strip(), fmt).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        logger.debug(f"[{SOURCE_NAME}] Could not parse date: {value!r}")
        return None
    
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

if __name__ == "__main__":
    import sys
    import logging
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from database.db_manager import DBManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    auth_key = os.getenv("ABUSECH_AUTH_KEY")
    if not auth_key:
        print("ERROR: Set ABUSECH_AUTH_KEY in your .env file")
        print("Get a free key at https://auth.abuse.ch/")
        sys.exit(1)

    db = DBManager()
    collector = URLhausCollector(db, auth_key=auth_key)
    result = collector.run()
    print(result)