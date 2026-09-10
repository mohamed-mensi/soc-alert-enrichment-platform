"""
feeds/abusech_threatfox.py
===========================
Collects IOCs from abuse.ch ThreatFox — C2 infrastructure, malware
distribution indicators, tagged with malware family and a per-indicator
confidence score.

Auth      : Required — ThreatFox allows no anonymous requests at all
            (unlike URLhaus's recent feed). Free Auth-Key from
            https://auth.abuse.ch/ — set ABUSECH_AUTH_KEY in .env
Feed URL  : https://threatfox-api.abuse.ch/api/v1/  (query: get_iocs)
Updates   : Continuous
Schedule  : Called every 24h by feeds/feed_collector.py

What we pull:
    IOCs reported in the last `lookback_days` days. ThreatFox encodes
    ports inside "ip:port" values and uses per-hash-algorithm types
    (md5_hash, sha256_hash, ...) — both get normalized onto this
    project's taxonomy (ip, domain, url, hash, email) before storage,
    since db_manager's schema enforces that type set via CHECK
    constraint. IOCs older than 6 months are not returned by the API.

Usage:
    from feeds.abusech_threatfox import ThreatFoxCollector
    from database.db_manager import DBManager

    db = DBManager()
    collector = ThreatFoxCollector(db, auth_key="YOUR_KEY")
    result = collector.run()
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
SOURCE_NAME   = "threatfox"
REQUEST_TIMEOUT = 30

# ThreatFox ioc_type -> this project's normalized taxonomy.
# db schema only allows: ip, url, hash, domain, email
TYPE_MAP = {
    "ip:port": "ip",
    "ip":      "ip",
    "domain":  "domain",
    "url":     "url",
    "md5_hash":    "hash",
    "sha1_hash":   "hash",
    "sha256_hash": "hash",
}


def _confidence_bucket(confidence_level) -> str:
    """Map ThreatFox's 0-100 confidence_level to this project's categorical scale."""
    try:
        level = int(confidence_level)
    except (TypeError, ValueError):
        return "medium"
    if level >= 75:
        return "high"
    if level >= 40:
        return "medium"
    return "low"


def _split_type_and_value(raw_type: str, raw_value: str):
    """
    Normalize ThreatFox's ioc_type/ioc into (clean_type, clean_value, extra_tag).
    Handles "ip:port" specifically — the port is stripped from the value
    and kept as a tag instead of being lost, since the rest of the
    pipeline looks up plain IPs, not "ip:port" strings.
    """
    clean_type = TYPE_MAP.get(raw_type, raw_type)
    extra_tag = None

    if raw_type == "ip:port" and ":" in raw_value:
        ip_part, _, port_part = raw_value.rpartition(":")
        if ip_part:
            return clean_type, ip_part, f"port:{port_part}"

    return clean_type, raw_value, extra_tag


# ── Collector ────────────────────────────────────────────────────────────────

class ThreatFoxCollector:
    """
    Pulls recent IOCs from ThreatFox and stores them as normalized
    IOC entries.

    Parameters
    ----------
    db            : DBManager
    auth_key      : str
        Your abuse.ch Auth-Key. Falls back to ABUSECH_AUTH_KEY env var.
    lookback_days : int
        How many days back to query. Defaults to THREATFOX_DAYS env
        var or 7.
    """

    def __init__(self, db, auth_key: Optional[str] = None, lookback_days: Optional[int] = None):
        self.db = db
        self.auth_key = auth_key or os.getenv("ABUSECH_AUTH_KEY")
        self.lookback_days = lookback_days or int(os.getenv("THREATFOX_DAYS", 7))

        if not self.auth_key:
            raise ValueError(
                "ThreatFox requires an Auth-Key. "
                "Set ABUSECH_AUTH_KEY in your .env or pass auth_key= directly. "
                "Get a free key at https://auth.abuse.ch/"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Fetch, normalize, and store ThreatFox IOCs.

        Returns
        -------
        dict: status, fetched, new, updated, errors, duration_secs
        """
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        t0 = time.monotonic()

        logger.info(f"[{SOURCE_NAME}] Starting feed collection (last {self.lookback_days} day(s))")

        try:
            result = self._fetch()
        except Exception as exc:
            duration = round(time.monotonic() - t0, 2)
            logger.error(f"[{SOURCE_NAME}] Fetch failed: {exc}")
            self.db.record_feed_run(
                source=SOURCE_NAME, status="failed",
                error_message=str(exc), duration_seconds=duration,
                started_at=started_at
            )
            return {"status": "failed", "error": str(exc), "duration_secs": duration}

        if result.get("query_status") != "ok":
            duration = round(time.monotonic() - t0, 2)
            logger.warning(f"[{SOURCE_NAME}] Non-ok query_status: {result.get('query_status')}")
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

        iocs = result.get("data") or []
        fetched = len(iocs)

        if fetched == 0:
            duration = round(time.monotonic() - t0, 2)
            logger.info(f"[{SOURCE_NAME}] No IOCs returned for this window")
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

        new_count = updated_count = error_count = 0

        for raw in iocs:
            try:
                normalized = self._normalize_ioc(raw)
                if normalized is None:
                    error_count += 1
                    continue
                is_new = self.db.upsert_ioc(normalized)
                if is_new:
                    new_count += 1
                else:
                    updated_count += 1
            except Exception as exc:
                error_count += 1
                logger.warning(f"[{SOURCE_NAME}] Failed to store IOC {raw.get('ioc')}: {exc}")

        duration = round(time.monotonic() - t0, 2)
        status = "success" if error_count == 0 else "partial"

        logger.info(
            f"[{SOURCE_NAME}] Done in {duration}s — {fetched} fetched, "
            f"{new_count} new, {updated_count} updated, {error_count} errors"
        )

        self.db.record_feed_run(
            source=SOURCE_NAME, status=status,
            iocs_fetched=fetched, iocs_new=new_count, iocs_updated=updated_count,
            error_message=f"{error_count} store errors" if error_count else None,
            duration_seconds=duration, started_at=started_at
        )

        return {
            "status": status, "fetched": fetched,
            "new": new_count, "updated": updated_count,
            "errors": error_count, "empty": False,
            "duration_secs": duration,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch(self) -> dict:
        headers = {"Auth-Key": self.auth_key}
        payload = {"query": "get_iocs", "days": self.lookback_days}
        response = requests.post(THREATFOX_URL, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _normalize_ioc(self, raw: dict) -> Optional[dict]:
        raw_value = raw.get("ioc")
        raw_type = raw.get("ioc_type")
        if not raw_value or not raw_type:
            return None

        clean_type, clean_value, port_tag = _split_type_and_value(raw_type, raw_value)

        base_tags = raw.get("tags") or []
        threat_type = raw.get("threat_type")
        tags = list(filter(None, set(base_tags + [threat_type, port_tag])))

        last_seen = raw.get("last_seen") or raw.get("first_seen")
        expires_at = None
        if last_seen:
            try:
                last_seen_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S UTC")
                expires_at = (last_seen_dt + timedelta(days=180)).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

        return {
            "type": clean_type,
            "value": clean_value,
            "source": SOURCE_NAME,
            "source_id": raw.get("id"),
            "malware_family": raw.get("malware_printable") or raw.get("malware"),
            "threat_actor": None,
            "campaign": None,
            "tags": tags,
            "confidence": _confidence_bucket(raw.get("confidence_level")),
            "severity": "high",
            "first_seen": raw.get("first_seen"),
            "last_seen": last_seen,
            "expires_at": expires_at,
            "raw": raw,
        }


from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from database.db_manager import DBManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    auth_key = os.getenv("ABUSECH_AUTH_KEY")
    if not auth_key:
        print("ERROR: Set ABUSECH_AUTH_KEY in your .env file")
        print("Get a free key at https://auth.abuse.ch/")
        sys.exit(1)

    db = DBManager()
    collector = ThreatFoxCollector(db, auth_key=auth_key)
    result = collector.run()
    print(result)