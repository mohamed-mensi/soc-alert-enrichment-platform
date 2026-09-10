"""
enrichment/ioc_lookup.py
=========================
Queries the local SQLite IOC database for a given observable value.

This is the reputation layer of the enrichment engine.
Called for every external IP, URL, hash, and domain observable.
NOT called for internal IPs or user emails (those go to corporate directory).

Returns a structured reputation result that the enrichment engine
combines with identity context and history to produce a verdict.

Usage:
    from enrichment.ioc_lookup import IOCLookup
    from database.db_manager import DBManager

    db     = DBManager()
    lookup = IOCLookup(db)

    result = lookup.check("ip", "1.94.187.246")
    # {
    #     "is_malicious": True,
    #     "reputation_score": 90,
    #     "matched_sources": ["abusech_feodo"],
    #     "malware_families": ["TrickBot"],
    #     "threat_actors": [],
    #     "tags": ["c2", "banking-trojan", "port:443"],
    #     "confidence": "high",
    #     "severity": "critical",
    #     "first_seen": "2024-01-15 10:23:00",
    #     "last_seen": "2026-06-25 00:00:00",
    # }

    result = lookup.check("ip", "8.8.8.8")
    # {"is_malicious": False, "reputation_score": 0, ...}
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Severity → numeric score mapping for reputation scoring
SEVERITY_SCORE = {
    "critical": 100,
    "high":      75,
    "medium":    50,
    "low":       25,
    "info":      10,
}

# Confidence → score multiplier
CONFIDENCE_MULTIPLIER = {
    "high":   1.0,
    "medium": 0.75,
    "low":    0.5,
}

# Observable type aliases — normalize case management platform types to our schema types
TYPE_MAP = {
    "ip":     "ip",
    "mail":   "email",
    "email":  "email",
    "hash":   "hash",
    "url":    "url",
    "domain": "domain",
    "fqdn":   "domain",
}


class IOCLookup:
    """
    Reputation lookup against the local IOC database.

    Parameters
    ----------
    db : DBManager
        Initialized database manager instance.
    """

    def __init__(self, db):
        self.db = db

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, observable_type: str, value: str) -> dict:
        """
        Check a single observable against the IOC database.

        Parameters
        ----------
        observable_type : str
            case management platform observable type: "ip", "mail", "hash", "url", "domain"
        value : str
            The observable value to look up

        Returns
        -------
        dict with keys:
            is_malicious     : bool
            reputation_score : int (0-100)
            matched_sources  : list[str]
            malware_families : list[str]
            threat_actors    : list[str]
            tags             : list[str]
            confidence       : str
            severity         : str
            first_seen       : str or None
            last_seen        : str or None
            match_count      : int (how many feed entries matched)
        """
        # Normalize type
        ioc_type = TYPE_MAP.get(observable_type, observable_type)
        value    = value.strip().lower()

        # Query database
        matches = self.db.lookup_ioc(ioc_type, value)

        if not matches:
            logger.debug(f"IOC lookup: {ioc_type}/{value} → CLEAN")
            return self._clean_result()

        # Aggregate across all matching feed entries
        result = self._aggregate(matches)
        logger.info(
            f"IOC lookup: {ioc_type}/{value} → MALICIOUS "
            f"(score={result['reputation_score']}, "
            f"sources={result['matched_sources']})"
        )
        return result

    def check_bulk(self, observables: list[dict]) -> dict[str, dict]:
        """
        Check multiple observables at once.
        Returns a dict keyed by observable value.

        Parameters
        ----------
        observables : list of dicts with keys: dataType, data

        Returns
        -------
        dict: { "1.94.187.246": {...result...}, "8.8.8.8": {...result...} }
        """
        results = {}
        for obs in observables:
            obs_type  = obs.get("dataType", "")
            obs_value = obs.get("data", "")
            if obs_type and obs_value:
                results[obs_value] = self.check(obs_type, obs_value)
        return results

    # ── Aggregation ───────────────────────────────────────────────────────────

    def _aggregate(self, matches: list[dict]) -> dict:
        """
        Aggregate multiple feed matches for the same observable
        into a single reputation result.

        Multiple source matches increase confidence:
          - 1 source  → score as-is
          - 2 sources → score × 1.1
          - 3+ sources → score × 1.2 (capped at 100)
        """
        sources   = []
        families  = []
        actors    = []
        all_tags  = []
        scores    = []
        severities = []
        confidences = []
        first_seen_dates = []
        last_seen_dates  = []

        for match in matches:
            source = match.get("source")
            if source and source not in sources:
                sources.append(source)

            family = match.get("malware_family")
            if family and family not in families:
                families.append(family)

            actor = match.get("threat_actor")
            if actor and actor not in actors:
                actors.append(actor)

            tags = match.get("tags") or []
            if isinstance(tags, str):
                import json
                try:
                    tags = json.loads(tags)
                except Exception:
                    tags = []
            for tag in tags:
                if tag and tag not in all_tags:
                    all_tags.append(tag)

            severity   = match.get("severity", "high")
            confidence = match.get("confidence", "medium")
            severities.append(severity)
            confidences.append(confidence)

            base_score  = SEVERITY_SCORE.get(severity, 75)
            multiplier  = CONFIDENCE_MULTIPLIER.get(confidence, 0.75)
            scores.append(int(base_score * multiplier))

            if match.get("first_seen"):
                first_seen_dates.append(match["first_seen"])
            if match.get("last_seen"):
                last_seen_dates.append(match["last_seen"])

        # Multi-source boost
        base_score = max(scores) if scores else 0
        if len(sources) >= 3:
            base_score = min(100, int(base_score * 1.2))
        elif len(sources) == 2:
            base_score = min(100, int(base_score * 1.1))

        # Pick highest severity and confidence
        severity_order   = ["critical", "high", "medium", "low", "info"]
        confidence_order = ["high", "medium", "low"]

        top_severity   = next((s for s in severity_order if s in severities), "high")
        top_confidence = next((c for c in confidence_order if c in confidences), "medium")

        return {
            "is_malicious":     True,
            "reputation_score": base_score,
            "matched_sources":  sources,
            "malware_families": families,
            "threat_actors":    actors,
            "tags":             sorted(set(all_tags)),
            "confidence":       top_confidence,
            "severity":         top_severity,
            "first_seen":       min(first_seen_dates) if first_seen_dates else None,
            "last_seen":        max(last_seen_dates)  if last_seen_dates  else None,
            "match_count":      len(matches),
        }

    @staticmethod
    def _clean_result() -> dict:
        """Return a clean (not malicious) result."""
        return {
            "is_malicious":     False,
            "reputation_score": 0,
            "matched_sources":  [],
            "malware_families": [],
            "threat_actors":    [],
            "tags":             [],
            "confidence":       "high",   # high confidence it's clean
            "severity":         "info",
            "first_seen":       None,
            "last_seen":        None,
            "match_count":      0,
        }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from database.db_manager import DBManager

    db     = DBManager()
    lookup = IOCLookup(db)

    # Test IPs — mix of known malicious (from our feeds) and clean
    test_cases = [
        ("ip",   "1.94.187.246"),   # likely in feeds — Tor/C2
        ("ip",   "91.92.128.33"),     # likely in feeds — C2
        ("ip",   "8.8.8.8"),          # Google DNS — clean
        ("ip",   "10.0.0.45"),        # internal — clean
        ("url",  "http://malicious-domain.ru/phish/login.php"),  # in URLhaus
        ("hash", "d41d8cd98f00b204e9800998ecf8427e"),            # MD5 of empty file
        ("ip",   "203.0.113.55"),     # test range — clean
    ]

    print("IOC Lookup Tests")
    print("=" * 60)

    for obs_type, value in test_cases:
        result = lookup.check(obs_type, value)
        status = "⚠️  MALICIOUS" if result["is_malicious"] else "✅ CLEAN"
        print(f"\n  [{obs_type}] {value}")
        print(f"  Status  : {status}")
        if result["is_malicious"]:
            print(f"  Score   : {result['reputation_score']}/100")
            print(f"  Sources : {result['matched_sources']}")
            print(f"  Malware : {result['malware_families']}")
            print(f"  Tags    : {result['tags'][:5]}")  # first 5 tags
        else:
            print(f"  Score   : {result['reputation_score']}/100")

    # Test bulk lookup
    print("\n\nBulk Lookup Test")
    print("=" * 60)
    observables = [
        {"dataType": "ip",   "data": "1.94.187.246"},
        {"dataType": "ip",   "data": "10.0.0.15"},
        {"dataType": "mail", "data": "adele.vance@example-corp.com"},
        {"dataType": "url",  "data": "http://malicious-domain.ru/phish/login.php"},
    ]
    bulk = lookup.check_bulk(observables)
    for value, result in bulk.items():
        status = "⚠️  MALICIOUS" if result["is_malicious"] else "✅ CLEAN"
        print(f"  {value:45} → {status}")