"""
feeds/otx_collector.py
=======================
Collects indicators of compromise from AlienVault OTX (Open Threat
Exchange) pulses the configured account is subscribed to.

Unlike abuse.ch's feeds, OTX is subscription-based — this collector
only sees pulses your API key's account is subscribed to. By default
that's just AlienVault's own generic pulses. For relevant coverage,
log in at https://otx.alienvault.com and subscribe to pulses tagged
for banking trojans, financial-sector threat actors (FIN7, Carbanak),
and phishing infrastructure.

Auth      : Required — free API key from https://otx.alienvault.com/settings
            Set OTX_API_KEY in your .env file
Feed URL  : https://otx.alienvault.com/api/v1/pulses/subscribed
Updates   : Depends on pulse authors — no fixed cadence
Schedule  : Called every 24h by feeds/feed_collector.py

What we pull:
    Pulses modified since the last lookback window, and the
    indicators embedded in each pulse. Only indicator types that
    map onto this project's taxonomy (ip, domain, url, hash, email)
    are stored — types like CVE, YARA, Mutex are skipped, not errors.

Response format (pulses/subscribed):
    {
        "results": [
            {
                "id": "abc123",
                "name": "FIN7 banking campaign",
                "author_name": "some_researcher",
                "modified": "2026-06-20T10:00:00",
                "created": "2026-06-18T08:00:00",
                "tags": ["fin7", "banking", "c2"],
                "adversary": "FIN7",
                "indicators": [
                    {
                        "indicator": "185.220.101.45",
                        "type": "IPv4",
                        "is_active": 1,
                        "created": "2026-06-18T08:00:00"
                    }
                ]
            }
        ],
        "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?...&page=2"
    }

NOTE: field names above are based on current public OTX docs/SDK source.
Print one raw pulse on your first run and confirm field names — OTX's
schema has shifted over time (e.g. "adversary" is not present on every
pulse).

Usage:
    from feeds.otx_collector import OTXCollector
    from database.db_manager import DBManager

    db = DBManager()
    collector = OTXCollector(db, api_key="YOUR_KEY")
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

BASE_URL        = "https://otx.alienvault.com/api/v1"
SUBSCRIBED_URL  = f"{BASE_URL}/pulses/subscribed"
SOURCE_NAME     = "otx"
REQUEST_TIMEOUT = 30
PAGE_LIMIT      = 50
MAX_PAGES       = 50  # safety guard against runaway pagination
MAX_INDICATORS_PER_PULSE = 500

# OTX indicator "type" -> this project's normalized taxonomy.
# db schema only allows: ip, url, hash, domain, email
OTX_TYPE_MAP = {
    "IPv4":          "ip",
    "IPv6":          "ip",
    "CIDR":          "ip",
    "domain":        "domain",
    "hostname":      "domain",
    "URL":           "url",
    "URI":           "url",
    "FileHash-MD5":     "hash",
    "FileHash-SHA1":    "hash",
    "FileHash-SHA256":  "hash",
    "FileHash-PEHASH":  "hash",
    "FileHash-IMPHASH": "hash",
    "email":         "email",
}

# Tags/keywords on a pulse that bump severity above the default.
# OTX gives no built-in confidence/severity score (unlike ThreatFox's
# confidence_level) — this is a simple heuristic, worth revisiting once
# you see what real subscribed pulses look like.
HIGH_SEVERITY_KEYWORDS = {"apt", "ransomware", "c2", "botnet", "banking", "fin7", "carbanak"}


def _severity_from_tags(tags: list) -> str:
    lowered = {t.lower() for t in tags if t}
    if lowered & HIGH_SEVERITY_KEYWORDS:
        return "high"
    return "medium"


# ── Collector ────────────────────────────────────────────────────────────────

class OTXCollector:
    """
    Pulls indicators from subscribed OTX pulses and stores them as
    normalized IOC entries.

    Parameters
    ----------
    db      : DBManager
    api_key : str
        Your OTX API key. Falls back to OTX_API_KEY env var.
    lookback_days : int
        How far back to look via modified_since. Defaults to
        OTX_LOOKBACK_DAYS env var or 3 (a buffer beyond the 24h
        schedule, in case a run is missed).
    """

    def __init__(self, db, api_key: Optional[str] = None, lookback_days: Optional[int] = None):
        self.db      = db
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        self.lookback_days = lookback_days or int(os.getenv("OTX_LOOKBACK_DAYS", 3))

        if not self.api_key:
            raise ValueError(
                "OTX requires an API key. "
                "Set OTX_API_KEY in your .env or pass api_key= directly. "
                "Get a free key at https://otx.alienvault.com/settings"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Fetch subscribed pulses modified since the lookback window,
        normalize their indicators, and store them.

        Returns
        -------
        dict: status, fetched, new, updated, errors, duration_secs
        """
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        t0         = time.monotonic()

        logger.info(f"[{SOURCE_NAME}] Starting feed collection (last {self.lookback_days} day(s))")

        try:
            pulses = self._fetch_all_pulses()
        except Exception as exc:
            duration = round(time.monotonic() - t0, 2)
            logger.error(f"[{SOURCE_NAME}] Fetch failed: {exc}")
            self.db.record_feed_run(
                source=SOURCE_NAME, status="failed",
                error_message=str(exc), duration_seconds=duration,
                started_at=started_at
            )
            return {"status": "failed", "error": str(exc), "duration_secs": duration}

        logger.info(f"[{SOURCE_NAME}] {len(pulses)} pulses retrieved")

        # Flatten indicators across all pulses, carrying pulse-level context
        all_indicators = []
        for pulse in pulses:
            if self._is_low_quality_pulse(pulse):
                logger.info(f"[{SOURCE_NAME}] Skipping low-quality pulse: {pulse.get('name')}")
                continue
            
            indicators = pulse.get("indicators") or []

            if len(indicators) > MAX_INDICATORS_PER_PULSE:
                logger.warning(
                    f"[{SOURCE_NAME}] Skipping bulk pulse ({len(indicators)} indicators): "
                    f"{pulse.get('name')}"
                )
                continue


            for indicator in (pulse.get("indicators") or []):
                all_indicators.append((pulse, indicator))

        fetched = len(all_indicators)

        if fetched == 0:
            duration = round(time.monotonic() - t0, 2)
            logger.info(f"[{SOURCE_NAME}] No indicators in subscribed pulses for this window")
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

        new_count   = 0
        updated_count = 0
        error_count = 0
        skipped_count = 0  # unsupported indicator types — not an error

        for pulse, indicator in all_indicators:
            try:
                # Skip inactive indicators (OTX marks expired/retracted IOCs this way)
                if indicator.get("is_active") == 0:
                    skipped_count += 1
                    continue

                ioc = self._normalize_indicator(pulse, indicator)
                if ioc is None:
                    skipped_count += 1
                    continue

                is_new = self.db.upsert_ioc(ioc)
                if is_new:
                    new_count += 1
                else:
                    updated_count += 1

            except Exception as exc:
                error_count += 1
                logger.warning(
                    f"[{SOURCE_NAME}] Failed to store indicator "
                    f"{indicator.get('indicator')}: {exc}"
                )

        duration = round(time.monotonic() - t0, 2)
        status    = "success" if error_count == 0 else "partial"

        logger.info(
            f"[{SOURCE_NAME}] Done in {duration}s — {fetched} indicators seen, "
            f"{new_count} new, {updated_count} updated, "
            f"{skipped_count} skipped (unsupported type/inactive), {error_count} errors"
        )

        self.db.record_feed_run(
            source=SOURCE_NAME, status=status,
            iocs_fetched=fetched,
            iocs_new=new_count,
            iocs_updated=updated_count,
            error_message=f"{error_count} store errors" if error_count else None,
            duration_seconds=duration,
            started_at=started_at
        )

        return {
            "status":        status,
            "fetched":       fetched,
            "new":           new_count,
            "updated":       updated_count,
            "skipped":       skipped_count,
            "errors":        error_count,
            "empty":         False,
            "duration_secs": duration,
        }
    


    # ── Private helpers ───────────────────────────────────────────────────────
    def _is_low_quality_pulse(self, pulse: dict) -> bool:
        """
        Flag pulses that look like generic bulk lists rather than
        targeted threat intel: a large indicator count concentrated
        in a single type (e.g. 800 bare IPs, no domains/hashes/urls)
        is a stronger 'this is a dump' signal than keyword-matching
        free text, which tends to false-positive on well-written,
        narrow campaign writeups (see PROGRESS.md known issues).
        """
        indicators = pulse.get("indicators") or []
        if len(indicators) < 100:
            return False  # too small to be a meaningful bulk dump either way

        types_present = {i.get("type") for i in indicators if i.get("type")}
        return len(types_present) <= 1

    def _fetch_all_pulses(self) -> list:
        """
        Fetch all pages of subscribed pulses modified since the
        lookback window, following OTX's `next` pagination link.
        """
        since = (
            datetime.now(timezone.utc) - timedelta(days=self.lookback_days)
        ).strftime("%Y-%m-%dT%H:%M:%S")

        pulses = []
        url = f"{SUBSCRIBED_URL}?limit={PAGE_LIMIT}&modified_since={since}"
        pages = 0

        while url and pages < MAX_PAGES:
            logger.debug(f"[{SOURCE_NAME}] GET {url}")
            response = requests.get(
                url,
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "User-Agent":    "SOC-Enrichment-Platform/1.0 (internal)"
                },
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            pulses.extend(data.get("results", []))
            url = data.get("next")
            pages += 1

        if pages >= MAX_PAGES:
            logger.warning(f"[{SOURCE_NAME}] Hit MAX_PAGES guard ({MAX_PAGES}) — "
                            f"there may be more pulses not yet fetched")

        return pulses

    def _normalize_indicator(self, pulse: dict, indicator: dict) -> Optional[dict]:
        """
        Build an IOC dict from an OTX indicator + its parent pulse context.
        Returns None if the indicator type isn't in our taxonomy.
        """
        raw_type = indicator.get("type")
        value    = (indicator.get("indicator") or "").strip()

        clean_type = OTX_TYPE_MAP.get(raw_type)
        if not clean_type or not value:
            return None  # unsupported type (CVE, YARA, Mutex, etc.) — not an error

        tags = self._build_tags(pulse)
        date = self._parse_date(indicator.get("created") or pulse.get("created"))

        return {
            "type":           clean_type,
            "value":          value.lower() if clean_type != "url" else value,
            "source":         SOURCE_NAME,
            "source_id":      f"{pulse.get('id', '')}_{indicator.get('id', '')}",
            "malware_family": self._extract_malware_family(pulse),
            "threat_actor":   pulse.get("adversary") or None,
            "campaign":       pulse.get("name"),
            "tags":           tags,
            "confidence":     "medium",  # OTX gives no per-indicator confidence score
            "severity":       _severity_from_tags(pulse.get("tags") or []),
            "first_seen":     date,
            "last_seen":      date,
            "expires_at":     None,
            "raw":            {"pulse_id": pulse.get("id"), "indicator": indicator},
        }

    def _build_tags(self, pulse: dict) -> list:
        """Build normalized tag list from pulse metadata."""
        tags = set()
        for t in (pulse.get("tags") or []):
            if t:
                tags.add(t.lower().strip())
        tags.add("otx")
        return sorted(tags)

    def _extract_malware_family(self, pulse: dict) -> Optional[str]:
        """
        OTX doesn't always expose a dedicated malware_families field —
        fall back to checking pulse tags against common families.
        """
        malware_families = pulse.get("malware_families")
        if malware_families:
            return malware_families[0] if isinstance(malware_families, list) else malware_families

        known_families = {
            "emotet", "trickbot", "qakbot", "dridex", "bazarloader",
            "ursnif", "formbook", "asyncrat", "remcos", "nanocore",
            "agenttesla", "lokibot", "raccoon", "redline"
        }
        for tag in (pulse.get("tags") or []):
            if tag and tag.lower() in known_families:
                return tag.capitalize()
        return None

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[str]:
        """Normalize OTX date strings to this project's standard format."""
        if not value:
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        cleaned = value.strip().replace("Z", "")
        for fmt in formats:
            try:
                return datetime.strptime(cleaned, fmt).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        logger.debug(f"[{SOURCE_NAME}] Could not parse date: {value!r}")
        return None


from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

if __name__ == "__main__":
    import sys
    import logging
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from database.db_manager import DBManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        print("ERROR: Set OTX_API_KEY in your .env file")
        print("Get a free key at https://otx.alienvault.com/settings")
        sys.exit(1)

    db = DBManager()
    collector = OTXCollector(db, api_key=api_key)
    result = collector.run()
    print(result)