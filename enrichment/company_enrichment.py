"""
enrichment/company_enrichment.py
================================
Recipient BUSINESS context — "who is this external recipient and what do
they do?" — sourced from The Companies API (https://thecompaniesapi.com),
keyed by the recipient's email domain.

Design rules (same as report_common.py):
  - NEVER fabricate. Every field is either returned by the provider or left
    as None. A domain with no business record returns found=False — which is
    itself useful signal ("no company record anywhere" corroborates a
    suspicious destination), not something to paper over.
  - This is DESCRIPTIVE context for the analyst, NOT a trust/legitimacy
    signal. Company self-description can be gamed, so callers must treat the
    output as "confidence: medium" at best and MUST NOT feed it into the risk
    score or legitimacy verdict. Trust still comes from WHOIS age / registry /
    IOC reputation.
  - Gated + graceful: no API key, provider down, timeout, or not-found all
    degrade to a safe not-found result. Never raises to the caller.
  - Mirrors the IdentityLookup pattern: mock_mode for offline/deterministic
    tests; real mode when COMPANIES_API_KEY is set.

⚠️ The endpoint path, Bearer auth, and JSON field names for The Companies API
   were verified against the live /v2/companies/{domain} response (2026-08).
   Transport lives in `_request()` and mapping in `_parse_response()`; if the
   provider changes its schema, only those two methods need updating.

Usage:
    from enrichment.company_enrichment import CompanyEnrichment
    ce = CompanyEnrichment(mock_mode=True)      # or False with a key in .env
    info = ce.lookup_domain("veridian-audit.test")
"""

import logging
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

COMPANIES_API_KEY = os.getenv("COMPANIES_API_KEY")

# Base URL for a single company keyed by domain: GET {BASE}/companies/{domain}
# Verified against the live API (2026-08). Overridable via env for future
# version bumps without a code change.
COMPANIES_API_BASE = os.getenv(
    "COMPANIES_API_BASE", "https://api.thecompaniesapi.com/v2"
)
REQUEST_TIMEOUT = 8


# ── Deterministic mock data (offline tests / demo) ──────────────────────────────
# Keyed by domain. Shaped like a PARSED real response (post-_parse_response), so
# offline tests exercise the same normalized schema production returns. Values
# for known partners in the sample scenarios. Unknown domains → not-found.
_MOCK_BY_DOMAIN = {
    "veridian-audit.test": {
        "name":           "Veridian Audit",
        "legal_name":     "Veridian Audit International Reference Ltd",
        "description":    "Audit and assurance, consulting and tax services",
        "industry":       "Professional Services",
        "industries":     ["Auditing", "Tax Services", "Consulting",
                           "Financial Services", "Accounting"],
        "business_type":  "Public Company",
        "employee_range": "268,160",
        "revenue":        "Over 1b",
        "country":        "United Kingdom",
        "city":           "London",
        "website":        "https://veridian-audit.test",
        "linkedin_url":   "https://www.linkedin.com/company/2732",
        "year_founded":   1998,
        "match_score":    84,
    },
    "microsoft.com": {
        "name":           "Microsoft",
        "legal_name":     "Microsoft Corporation",
        "description":    "Software, cloud services and hardware",
        "industry":       "Software",
        "industries":     ["Software", "Cloud Computing", "Technology"],
        "business_type":  "Public Company",
        "employee_range": "100,000+",
        "revenue":        "Over 1b",
        "country":        "United States",
        "city":           "Redmond",
        "website":        "https://microsoft.com",
        "linkedin_url":   "https://www.linkedin.com/company/1035",
        "year_founded":   1975,
        "match_score":    90,
    },
    # NOTE: suspicious destinations from the sample set (e.g.
    # databroker-services.net, quickdump.io) are intentionally ABSENT so the
    # mock returns found=False — demonstrating that "no business record"
    # corroborates suspicion rather than inventing a profile.
}


class CompanyEnrichment:
    """
    Resolve an email/recipient domain to business context.

    Parameters
    ----------
    mock_mode : bool
        True  → return deterministic mock data (no network); use offline / in tests.
        False → call The Companies API (requires COMPANIES_API_KEY in .env).
    api_key : str, optional
        Overrides COMPANIES_API_KEY.
    """

    def __init__(self, mock_mode: bool = True, api_key: Optional[str] = None):
        self.mock_mode = mock_mode
        self.api_key = api_key or COMPANIES_API_KEY
        # Per-process cache so the same domain isn't looked up twice per run.
        self._cache: dict[str, dict] = {}

        if not mock_mode and not self.api_key:
            logger.warning(
                "CompanyEnrichment real mode requested but COMPANIES_API_KEY "
                "is not set — every lookup will degrade to not-found."
            )
        mode = "MOCK" if mock_mode else "REAL (The Companies API)"
        logger.info(f"CompanyEnrichment initialized — mode: {mode}")

    # ── Public API ──────────────────────────────────────────────────────────────

    def lookup_domain(self, domain: str) -> dict:
        """
        Return normalized business context for a domain. Never raises.

        Returns (normalized schema — every field verifiable or None):
            found          : bool
            domain         : str
            name           : str | None    (common/brand name)
            legal_name     : str | None
            description    : str | None    (concise tagline — "what they do")
            industry       : str | None    (primary, humanized)
            industries     : list[str]     (up to 5, humanized; [] if none)
            business_type  : str | None    (e.g. "Public Company")
            employee_range : str | None    (exact count if known, else range)
            revenue        : str | None
            country        : str | None    (HQ country name)
            city           : str | None    (HQ city name)
            website        : str | None
            linkedin_url   : str | None
            year_founded   : int | None
            match_score    : int | None    (provider's 0-100 match confidence)
            source         : "thecompaniesapi" | "none"
            confidence     : "medium" | "low"
            mock           : bool
        """
        domain = (domain or "").strip().lower()
        if not domain:
            return self._not_found("", "empty domain")
        if domain in self._cache:
            return self._cache[domain]

        result = (
            self._mock_lookup(domain) if self.mock_mode
            else self._real_lookup(domain)
        )
        self._cache[domain] = result
        return result

    # ── Mock mode ─────────────────────────────────────────────────────────────

    def _mock_lookup(self, domain: str) -> dict:
        data = _MOCK_BY_DOMAIN.get(domain)
        if not data:
            return self._not_found(domain, "not in mock data")
        return self._found(domain, data, mock=True)

    # ── Real mode ───────────────────────────────────────────────────────────────

    def _real_lookup(self, domain: str) -> dict:
        if not self.api_key:
            return self._not_found(domain, "no API key")
        raw = self._request(domain)
        if raw is None:
            return self._not_found(domain, "lookup failed / not found")
        return self._parse_response(domain, raw)

    def _request(self, domain: str) -> Optional[dict]:
        """
        HTTP call to The Companies API. Endpoint + Bearer auth verified against
        the live API (2026-08). Isolated so the transport can change without
        touching the parser. Returns parsed JSON dict, or None on any
        failure / non-200 / not-found.
        """
        import requests
        url = f"{COMPANIES_API_BASE}/companies/{domain}"
        try:
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                logger.info(f"[companies] no record for {domain}")
                return None
            if resp.status_code != 200:
                logger.warning(
                    f"[companies] {domain} → HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
                return None
            return resp.json()
        except Exception as exc:
            logger.warning(f"[companies] request failed for {domain}: {exc}")
            return None

    def _parse_response(self, domain: str, raw: dict) -> dict:
        """
        Map The Companies API JSON → our normalized schema.
        Verified against a real /v2/companies/{domain} payload (2026-08).
        Defensive .get chains throughout; anything missing stays None
        (never fabricated). Slugs are humanized (formatting only, no new facts).
        """
        about   = raw.get("about") or {}
        descs   = raw.get("descriptions") or {}
        loc     = ((raw.get("locations") or {}).get("headquarters")) or {}
        dom     = raw.get("domain") or {}
        fin     = raw.get("finances") or {}
        socials = raw.get("socials") or {}
        meta    = raw.get("meta") or {}

        # "What they do": prefer the concise tagline, then the website blurb,
        # then the humanized industry. The localized `primary` blob (often a
        # single regional office's multi-language text) is deliberately avoided.
        description = (
            _clean(descs.get("tagline"))
            or _clean(descs.get("website"))
            or _humanize(about.get("industry"))
        )

        # Employees: prefer the exact count, else the coarse range slug.
        exact = about.get("totalEmployeesExact")
        employee_range = (
            f"{exact:,}" if isinstance(exact, int) and exact > 0
            else _humanize(about.get("totalEmployees"))
        )

        industries = [
            _humanize(i) for i in (about.get("industries") or [])[:5] if i
        ]

        name = _clean(about.get("name")) or _clean(dom.get("domainName"))

        # Provider responded but with nothing usable → treat as not-found.
        if not any([name, description, about.get("industry")]):
            return self._not_found(domain, "response had no usable fields")

        website = f"https://{dom['domain']}" if dom.get("domain") else None
        founded = about.get("yearFounded")
        score   = meta.get("score")

        return self._found(domain, {
            "name":           name,
            "legal_name":     _clean(about.get("nameLegal")),
            "description":    description,
            "industry":       _humanize(about.get("industry")),
            "industries":     industries,
            "business_type":  _humanize(about.get("businessType")),
            "employee_range": employee_range,
            "revenue":        _humanize(fin.get("revenue")),
            "country":        _clean((loc.get("country") or {}).get("name")),
            "city":           _clean((loc.get("city") or {}).get("name")),
            "website":        website,
            "linkedin_url":   _clean((socials.get("linkedin") or {}).get("url")),
            "year_founded":   founded if isinstance(founded, int) else None,
            "match_score":    score if isinstance(score, int) else None,
        }, mock=False)

    # ── Result builders ───────────────────────────────────────────────────────

    @staticmethod
    def _found(domain: str, data: dict, mock: bool) -> dict:
        return {
            "found":          True,
            "domain":         domain,
            "name":           data.get("name"),
            "legal_name":     data.get("legal_name"),
            "description":    data.get("description"),
            "industry":       data.get("industry"),
            "industries":     data.get("industries") or [],
            "business_type":  data.get("business_type"),
            "employee_range": data.get("employee_range"),
            "revenue":        data.get("revenue"),
            "country":        data.get("country"),
            "city":           data.get("city"),
            "website":        data.get("website"),
            "linkedin_url":   data.get("linkedin_url"),
            "year_founded":   data.get("year_founded"),
            # Provider's own match confidence (0-100), when present.
            "match_score":    data.get("match_score"),
            # Descriptive, self/third-party-sourced → medium at best.
            "source":         "thecompaniesapi",
            "confidence":     "medium",
            "mock":           mock,
        }

    @staticmethod
    def _not_found(domain: str, reason: str = "") -> dict:
        return {
            "found":          False,
            "domain":         domain,
            "name":           None,
            "legal_name":     None,
            "description":    None,
            "industry":       None,
            "industries":     [],
            "business_type":  None,
            "employee_range": None,
            "revenue":        None,
            "country":        None,
            "city":           None,
            "website":        None,
            "linkedin_url":   None,
            "year_founded":   None,
            "match_score":    None,
            "source":         "none",
            "confidence":     "low",
            "mock":           None,
            "reason":         reason,
        }


def _clean(val) -> Optional[str]:
    """Coerce a scalar to a clean string, or None. Never fabricates."""
    if val in (None, "", [], {}):
        return None
    if isinstance(val, (list, tuple)):
        val = val[0] if val else None
    s = str(val).strip()
    return s or None


def _humanize(slug) -> Optional[str]:
    """
    Turn a provider slug into a readable label — FORMATTING ONLY, adds no
    facts. 'professional-services' → 'Professional Services';
    'over-10k' → 'Over 10k'. Returns None for empty input.
    """
    s = _clean(slug)
    if not s:
        return None
    return " ".join(w.capitalize() for w in s.replace("_", "-").split("-"))


# ── Standalone self-test ────────────────────────────────────────────────────────
# Prints the RAW provider JSON in real mode so the parser can be corrected.
#   python -m enrichment.company_enrichment veridian-audit.test
#   python -m enrichment.company_enrichment veridian-audit.test --real
if __name__ == "__main__":
    import sys, json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    real = "--real" in sys.argv
    domain = args[0] if args else "veridian-audit.test"

    ce = CompanyEnrichment(mock_mode=not real)

    if real:
        print(f"\n--- RAW response for {domain} (paste this back to correct the parser) ---")
        print(json.dumps(ce._request(domain), indent=2, default=str))
        print("--- end raw ---\n")

    print(f"Normalized lookup for {domain}:")
    print(json.dumps(ce.lookup_domain(domain), indent=2, default=str))
