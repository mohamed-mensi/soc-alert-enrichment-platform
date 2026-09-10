"""
enrichment/report_common.py
============================
Reusable, deterministic building blocks shared by the DLP and phishing
investigation workflows.

Why this module exists
----------------------
Both the DLP flow (phishing/dlp_enrichment.py + phishing/dlp_runner.py) and
the phishing flow (phishing/phishing_enrichment.py) need the same primitives:

  - contextual risk scoring that exposes *why* (risk factors) AND
    *why not* (mitigating factors), not a single opaque number
  - recipient / domain classification and organization context that is
    derived from verifiable data only and NEVER fabricated
  - an evidence-based, 5-level recipient legitimacy assessment
  - deterministic narrative builders that separate observed facts,
    enrichment results, inference and recommendation, and that work even
    when the local LLM is offline
  - a stable, machine-readable JSON report schema

Design rules (enforced here, not just documented):
  - No invented intelligence. Organization names come from WHOIS
    registrantOrganization or the internal directory only. If a value
    cannot be verified it is returned as None / "Unknown" with
    confidence "low" — never guessed.
  - No hardcoded per-company business descriptions. We classify the
    *category* of a domain (internal / personal-webmail / disposable /
    corporate) because that is a fact about the address, but we do not
    assert "what this company does".
  - "What this company does" business context, when available, comes from
    an external provider (see enrichment/company_enrichment.py) and is
    handled by build_recipient_business_context() below. It is DESCRIPTIVE
    ONLY: it is deliberately kept OUT of derive_organization_context /
    assess_recipient_legitimacy / score_dlp_risk (all of which consume
    org_context), so self-reported business data can never move the risk
    score or the legitimacy verdict. The formatter here is still pure —
    the network call happens in the runner and the result is passed in.
  - Everything is deterministic and pure-Python (stdlib only) so it can
    be unit-tested offline without case management platform, WHOIS or Ollama.

This module has NO side effects and imports nothing from the rest of the
project, so it is safe to import from anywhere.
"""

from __future__ import annotations

import re
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Reference data
#
# These are *category* labels for the mailbox provider behind a domain — a
# verifiable fact about the address itself, not an invented description of a
# recipient's employer. Used only to render a human-friendly provider name.
# ──────────────────────────────────────────────────────────────────────────────
WEBMAIL_PROVIDER_LABELS = {
    "gmail.com": "Google (Gmail)",
    "googlemail.com": "Google (Gmail)",
    "yahoo.com": "Yahoo Mail",
    "yahoo.fr": "Yahoo Mail",
    "yahoo.co.uk": "Yahoo Mail",
    "hotmail.com": "Microsoft (Outlook/Hotmail)",
    "hotmail.fr": "Microsoft (Outlook/Hotmail)",
    "hotmail.co.uk": "Microsoft (Outlook/Hotmail)",
    "outlook.com": "Microsoft (Outlook)",
    "live.com": "Microsoft (Live)",
    "live.fr": "Microsoft (Live)",
    "icloud.com": "Apple (iCloud)",
    "me.com": "Apple (iCloud)",
    "mac.com": "Apple (iCloud)",
    "protonmail.com": "Proton Mail",
    "proton.me": "Proton Mail",
    "yandex.com": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "mail.com": "mail.com",
    "aol.com": "AOL Mail",
    "gmx.com": "GMX Mail",
    "tutanota.com": "Tuta (Tutanota)",
    "tutanota.de": "Tuta (Tutanota)",
    "zoho.com": "Zoho Mail",
}

# Risk-scoring bands
RISK_BANDS = (
    (70, "critical"),
    (45, "high"),
    (25, "medium"),
    (0,  "low"),
)

# Legitimacy levels (ordered from most trusted to least)
LEGITIMACY_LEVELS = (
    "LEGITIMATE",
    "LIKELY_LEGITIMATE",
    "UNKNOWN",
    "SUSPICIOUS",
    "MALICIOUS",
)


# ──────────────────────────────────────────────────────────────────────────────
# Small header / domain helpers
# ──────────────────────────────────────────────────────────────────────────────

def extract_domain(address: str) -> str:
    """Return the lowercased domain from an email address (or '')."""
    if not address or "@" not in address:
        return (address or "").strip().lower()
    return address.split("@")[-1].strip().lower()


def header_value(raw_headers: str, header_name: str) -> Optional[str]:
    """Return the first value of a header from a raw header block, or None."""
    if not raw_headers:
        return None
    m = re.search(
        rf"^{re.escape(header_name)}:\s*(.+)$",
        raw_headers, re.IGNORECASE | re.MULTILINE,
    )
    return m.group(1).strip() if m else None


def detect_prior_correspondence(raw_headers: str) -> dict:
    """
    Detect evidence that this email is part of an existing thread /
    ongoing business relationship.

    Uses only verifiable headers:
      - In-Reply-To / References  → a reply to a previous message
      - X-Prior-Correspondence    → explicit prior-relationship marker
        (set by some DLP/Exchange gateways)

    Returns
    -------
    {"has_prior": bool, "evidence": list[str]}
    """
    evidence = []
    in_reply_to = header_value(raw_headers, "In-Reply-To")
    references = header_value(raw_headers, "References")
    prior = header_value(raw_headers, "X-Prior-Correspondence")

    if in_reply_to:
        evidence.append(f"In-Reply-To header present ({in_reply_to[:60]})")
    if references:
        evidence.append("References header present (part of an existing thread)")
    if prior:
        evidence.append(f"X-Prior-Correspondence marker: {prior}")

    return {"has_prior": bool(evidence), "evidence": evidence}


def is_newly_registered(domain_intel: dict, threshold_days: int = 30) -> Optional[bool]:
    """
    True/False if we know the domain age, None if unknown.
    """
    if not domain_intel:
        return None
    age = domain_intel.get("age_days")
    if age is None:
        return None
    return age < threshold_days


# ──────────────────────────────────────────────────────────────────────────────
# Organization context  (Part 3)
#
# "What does this company do?" — answered only from verifiable sources.
# We DO NOT invent business descriptions. When the recipient is an unknown
# external corporate domain and WHOIS gives us no registrant organization,
# we return Organization: Unknown / confidence: low.
# ──────────────────────────────────────────────────────────────────────────────

def derive_organization_context(
    to_domain: str,
    recipient_type: str,
    domain_intel: dict,
    org_domain: str,
) -> dict:
    """
    Build recipient organization context from verifiable data only.

    Returns
    -------
    dict:
        domain          : str
        organization    : str | None   (WHOIS registrantOrganization, or a
                                         provider/category label, or None)
        org_source      : "internal_directory" | "mailbox_provider" |
                          "whois" | "none"
        category        : human-readable category of the recipient endpoint
        country         : str | None   (WHOIS registrant country)
        registrar       : str | None
        age_label       : str | None
        description      : None         (intentionally never fabricated)
        confidence      : "high" | "medium" | "low"
        notes           : list[str]
    """
    to_domain = (to_domain or "").lower()
    domain_intel = domain_intel or {}
    notes: list[str] = []

    # Internal recipient — authoritative, from our own directory
    if recipient_type == "internal" or to_domain == (org_domain or "").lower():
        return {
            "domain": to_domain,
            "organization": _org_display_name(org_domain),
            "org_source": "internal_directory",
            "category": "Internal organization mailbox",
            "country": None,
            "registrar": None,
            "age_label": None,
            "description": None,
            "confidence": "high",
            "notes": ["Recipient is inside the organization's own mail domain."],
        }

    # Personal webmail / disposable — provider is a fact about the address
    if recipient_type in ("webmail", "disposable"):
        provider = WEBMAIL_PROVIDER_LABELS.get(to_domain)
        category = (
            "Personal webmail provider (not a corporate/business recipient)"
            if recipient_type == "webmail"
            else "Disposable / temporary mailbox provider"
        )
        notes.append(
            "This is the mailbox provider, not the recipient's employer — "
            "the identity of the individual behind a personal address is not "
            "verifiable from the email alone."
        )
        return {
            "domain": to_domain,
            "organization": provider,               # provider label, not employer
            "org_source": "mailbox_provider",
            "category": category,
            "country": None,
            "registrar": None,
            "age_label": None,
            "description": None,
            "confidence": "medium" if provider else "low",
            "notes": notes,
        }

    # External corporate / suspicious / unknown — use WHOIS if available
    whois_org = _clean_whois_org(domain_intel.get("organization"))
    country = _clean_whois_value(domain_intel.get("country"))
    registrar = _clean_whois_value(domain_intel.get("registrar"))
    age_label = domain_intel.get("age_label")

    if whois_org:
        confidence = "medium"          # WHOIS registrant orgs can be resellers/proxies
        org_source = "whois"
        notes.append("Organization name taken from public WHOIS registrant data.")
    else:
        confidence = "low"
        org_source = "none"
        notes.append(
            "No organization could be verified for this domain "
            "(WHOIS registrant organization is empty, redacted, or the "
            "lookup was unavailable). Reported as Unknown."
        )

    category = {
        "corporate": "External corporate/other domain",
        "suspicious": "External domain with suspicious characteristics",
        "unknown": "Unclassified external domain",
    }.get(recipient_type, "External domain")

    return {
        "domain": to_domain,
        "organization": whois_org,      # may be None → caller shows "Unknown"
        "org_source": org_source,
        "category": category,
        "country": country,
        "registrar": registrar,
        "age_label": age_label,
        "description": None,            # never fabricated
        "confidence": confidence,
        "notes": notes,
    }


def _org_display_name(org_domain: str) -> str:
    """Turn 'example-corp.com' into a readable org label without inventing data."""
    if not org_domain:
        return "Organization"
    base = org_domain.split(".")[0]
    return base.upper() if base.isalpha() and len(base) <= 8 else base


# ──────────────────────────────────────────────────────────────────────────────
# Recipient BUSINESS context  (Part C — descriptive only, NON-SCORING)
#
# "Who is this external recipient and what do they do?" — formatted from an
# external company-data provider (enrichment/company_enrichment.py), which the
# runner calls and passes in here as `business_lookup`.
#
# IMPORTANT — this is intentionally SEPARATE from derive_organization_context.
# org_context feeds score_dlp_risk() and assess_recipient_legitimacy(); business
# context does NOT and MUST NOT. A company's self-reported description can be
# gamed, so it can never move the risk score or the legitimacy verdict. It is
# analyst-facing colour only. Two things here ARE useful signal but are surfaced
# as notes, not score inputs:
#   - found=False for an external corporate/suspicious domain ("no business
#     record anywhere") corroborates suspicion;
#   - a mismatch between what the company does and the data leaving the org
#     (e.g. client portfolios → a data-broker) is worth an analyst's eye.
# This function is pure/deterministic (no network); the lookup happens upstream.
# ──────────────────────────────────────────────────────────────────────────────

# Recipient types for which a business lookup is meaningful. Internal mailboxes
# are authoritative from our own directory; webmail/disposable are personal
# mailbox providers, not employers — looking them up would be misleading.
_BUSINESS_CONTEXT_TYPES = ("corporate", "suspicious", "unknown")


def build_recipient_business_context(
    business_lookup: Optional[dict],
    recipient_type: str,
    to_domain: str,
    org_domain: str,
    keyword_results: Optional[dict] = None,
) -> dict:
    """
    Format a CompanyEnrichment.lookup_domain() result into a report-ready,
    analyst-facing business-context block. Pure and deterministic.

    Parameters
    ----------
    business_lookup : dict | None
        The raw dict from CompanyEnrichment.lookup_domain(), or None if the
        lookup was not performed (no provider configured, internal/webmail
        recipient, etc.). None → an "not applicable / not looked up" block.
    recipient_type : str
        internal / webmail / disposable / corporate / suspicious / unknown.
    to_domain, org_domain : str
    keyword_results : dict | None
        The enrichment keyword_results, used only to phrase a soft "relevance"
        note comparing the recipient's business to the data types in the email.
        Never used to compute a score.

    Returns
    -------
    dict:
        applicable   : bool          (was a lookup meaningful for this type?)
        looked_up    : bool          (did we actually receive a lookup dict?)
        found        : bool
        name         : str | None
        legal_name   : str | None
        description  : str | None
        industry     : str | None
        industries   : list[str]
        business_type: str | None
        employee_range: str | None
        revenue      : str | None
        country      : str | None
        city         : str | None
        website      : str | None
        linkedin_url : str | None
        year_founded : int | None
        match_score  : int | None
        source       : str
        confidence   : str
        scoring_impact: "none"        (constant — documents the guarantee)
        relevance_note: str | None
        notes        : list[str]
    """
    to_domain = (to_domain or "").lower()
    notes: list[str] = []

    applicable = recipient_type in _BUSINESS_CONTEXT_TYPES and to_domain != (
        (org_domain or "").lower()
    )

    base = {
        "applicable":     applicable,
        "looked_up":      False,
        "found":          False,
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
        # Documents (in the data itself) that this block never feeds scoring.
        "scoring_impact": "none",
        "relevance_note": None,
        "notes":          notes,
    }

    # Not a domain we'd meaningfully look up (internal / personal webmail /
    # disposable). Say so explicitly rather than showing an empty card.
    if not applicable:
        if recipient_type == "internal":
            notes.append(
                "Internal recipient — identity is authoritative from the "
                "directory; external business lookup does not apply."
            )
        elif recipient_type in ("webmail", "disposable"):
            notes.append(
                "Personal mailbox provider, not a company domain — business "
                "lookup would describe the mail host, not the recipient's "
                "employer, so it is skipped."
            )
        else:
            notes.append("Business lookup not applicable for this recipient type.")
        return base

    # Applicable, but no lookup dict was provided (provider not configured or
    # the runner chose not to call it). Keep the card, explain the gap.
    if not business_lookup:
        notes.append(
            "Recipient business context was not retrieved (company-data "
            "provider not configured or unavailable). No business profile "
            "to show — this does not affect the risk score."
        )
        return base

    base["looked_up"] = True
    found = bool(business_lookup.get("found"))
    base["found"] = found
    base["source"] = business_lookup.get("source") or "none"
    # Descriptive, self/third-party-sourced → medium at best; never "high".
    # Clamp here so the guarantee holds even if a future provider returns
    # "high" — this layer decides its own trust ceiling, not the provider.
    base["confidence"] = "medium" if business_lookup.get("confidence") == "medium" else "low"

    if not found:
        # "No business record anywhere" is meaningful colour for an external
        # corporate/suspicious destination — surfaced as a note, NOT a score.
        base["confidence"] = "low"
        if recipient_type == "suspicious":
            notes.append(
                "⚠ No business record found for this domain in the company "
                "database, which is consistent with the suspicious "
                "characteristics already flagged. (Corroborating context "
                "only — it does not change the risk score.)"
            )
        else:
            notes.append(
                "No business record found for this external domain. Absence "
                "of a company profile can itself be worth noting for an "
                "unfamiliar recipient. (Context only — non-scoring.)"
            )
        return base

    # Found — copy the descriptive fields through verbatim (already normalized
    # and humanized by CompanyEnrichment; nothing invented here).
    for k in (
        "name", "legal_name", "description", "industry", "business_type",
        "employee_range", "revenue", "country", "city", "website",
        "linkedin_url", "year_founded", "match_score",
    ):
        base[k] = business_lookup.get(k)
    base["industries"] = list(business_lookup.get("industries") or [])

    base["relevance_note"] = _business_relevance_note(base, keyword_results)
    notes.append(
        "Business profile is descriptive context from an external provider "
        "(confidence: {c}). It is NOT used in the risk score or the "
        "legitimacy verdict — company self-description can be gamed.".format(
            c=base["confidence"]
        )
    )
    return base


def _business_relevance_note(bc: dict, keyword_results: Optional[dict]) -> Optional[str]:
    """
    One soft sentence relating the recipient's business to the sensitive data
    types seen in the email. Deliberately non-committal and NON-SCORING — it
    helps the analyst ask "does it make sense to send THIS to THEM?", nothing
    more. Returns None when there isn't enough to say.
    """
    industry = bc.get("industry")
    name = bc.get("name")
    if not industry and not name:
        return None

    summary = (keyword_results or {}).get("summary") or {}
    sensitive_present = any(
        summary.get(k, 0) for k in ("critical_count", "high_count", "medium_count")
    )
    who = name or "the recipient"
    if industry:
        who = f"{who} ({industry})"

    if sensitive_present:
        return (
            f"Sensitive-data indicators are present in this email and the "
            f"recipient is {who}. Consider whether this data type is expected "
            f"to flow to a recipient in this line of business."
        )
    return (
        f"Recipient business context: {who}. No specific relevance concern "
        f"is asserted — provided for the analyst's judgement."
    )


def _clean_whois_value(val) -> Optional[str]:
    if not val:
        return None
    s = str(val).strip()
    if not s or s.lower() in (
        "unknown", "n/a", "na", "none", "lookup failed",
        "whois lookup failed", "redacted for privacy", "not registered",
    ):
        return None
    return s


def _clean_whois_org(val) -> Optional[str]:
    """WHOIS registrant orgs are frequently privacy proxies — filter those."""
    s = _clean_whois_value(val)
    if not s:
        return None
    low = s.lower()
    proxy_markers = (
        "privacy", "redacted", "whoisguard", "domains by proxy",
        "perfect privacy", "contact privacy", "data protected",
        "withheld", "not disclosed", "gdpr",
    )
    if any(p in low for p in proxy_markers):
        return None
    return s


# ──────────────────────────────────────────────────────────────────────────────
# Recipient legitimacy assessment  (Part 4)
#
# Five levels, evidence-based, no forced binary. Legitimacy describes how
# much we trust the *recipient endpoint / domain* — it is kept separate from
# the DLP exposure risk (a fully-legitimate recipient can still be a policy
# violation, e.g. confidential data to a personal Gmail).
# ──────────────────────────────────────────────────────────────────────────────

def assess_recipient_legitimacy(
    recipient_type: str,
    ioc_domain_hit: dict,
    domain_intel: dict,
    self_send_fuzzy: dict,
    prior_correspondence: dict,
    org_context: dict,
    to_domain: str,
    org_domain: str,
) -> dict:
    """
    Return an evidence-based legitimacy assessment.

    Returns
    -------
    dict:
        level       : one of LEGITIMACY_LEVELS
        confidence  : "high" | "medium" | "low"
        reasons     : list[str]   (evidence — never generic)
    """
    ioc_domain_hit = ioc_domain_hit or {}
    domain_intel = domain_intel or {}
    self_send_fuzzy = self_send_fuzzy or {}
    prior_correspondence = prior_correspondence or {}
    org_context = org_context or {}
    to_domain = (to_domain or "").lower()

    reasons: list[str] = []

    # 1. MALICIOUS — a confirmed threat-intel hit overrides everything.
    if ioc_domain_hit.get("is_malicious"):
        sources = ", ".join(ioc_domain_hit.get("matched_sources", [])) or "threat feed"
        score = ioc_domain_hit.get("reputation_score", 0)
        reasons.append(
            f"Recipient domain {to_domain} matched threat intelligence "
            f"({sources}) with reputation score {score}/100."
        )
        return {"level": "MALICIOUS", "confidence": "high", "reasons": reasons}

    # 2. LEGITIMATE — internal recipient, authoritative from our directory.
    if recipient_type == "internal" or to_domain == (org_domain or "").lower():
        reasons.append(
            "Recipient is inside the organization's own verified mail domain."
        )
        return {"level": "LEGITIMATE", "confidence": "high", "reasons": reasons}

    # 3. SUSPICIOUS — disposable, look-alike, brand-new, or self-send patterns.
    suspicious = False
    if recipient_type == "disposable":
        suspicious = True
        reasons.append(
            f"{to_domain} is a known disposable / throwaway mail provider."
        )
    if recipient_type == "suspicious":
        suspicious = True
        reasons.append(
            f"{to_domain} has structural traits of a randomly generated / "
            f"look-alike domain."
        )
    newly = is_newly_registered(domain_intel, 30)
    if newly:
        suspicious = True
        reasons.append(
            f"{to_domain} was registered very recently "
            f"({domain_intel.get('age_days')} days ago)."
        )
    if self_send_fuzzy.get("is_fuzzy_match"):
        suspicious = True
        reasons.append(
            f"Recipient local-part resembles the sender "
            f"(method: {self_send_fuzzy.get('method')}) — possible attempt to "
            f"move data to a personal account."
        )
    if suspicious:
        return {"level": "SUSPICIOUS", "confidence": "medium", "reasons": reasons}

    # 4. Personal webmail — the provider is legitimate, but it is not a
    #    business recipient. Trust the endpoint, flag the context.
    if recipient_type == "webmail":
        provider = org_context.get("organization") or "a personal webmail provider"
        reasons.append(
            f"{to_domain} is operated by {provider}, an established mailbox "
            f"provider — the domain itself is legitimate."
        )
        reasons.append(
            "However this is a personal mailbox, not a verified business "
            "recipient; treat the individual's identity as unconfirmed."
        )
        return {"level": "LIKELY_LEGITIMATE", "confidence": "medium", "reasons": reasons}

    # 5. External corporate domain — grade on age, WHOIS org, prior contact.
    age_days = domain_intel.get("age_days")
    has_org = bool(org_context.get("organization"))
    has_prior = prior_correspondence.get("has_prior")

    positive = 0
    if age_days is not None and age_days >= 730:      # 2+ years
        positive += 1
        reasons.append(
            f"{to_domain} is an established domain "
            f"({domain_intel.get('age_label', 'over 2 years old')})."
        )
    if has_org:
        positive += 1
        reasons.append(
            f"WHOIS lists a registrant organization "
            f"({org_context.get('organization')})."
        )
    if has_prior:
        positive += 1
        reasons.extend(
            f"Prior correspondence: {e}"
            for e in prior_correspondence.get("evidence", [])[:2]
        )

    if positive >= 2:
        return {"level": "LIKELY_LEGITIMATE", "confidence": "medium", "reasons": reasons}

    # Not enough evidence either way — be honest.
    if not reasons:
        reasons.append(
            f"No reputation hit, but also no corroborating evidence "
            f"(domain age, registrant organization or prior correspondence) "
            f"was available for {to_domain}."
        )
    return {"level": "UNKNOWN", "confidence": "low", "reasons": reasons}


# ──────────────────────────────────────────────────────────────────────────────
# Contextual DLP risk scoring  (Parts 5 & 6)
#
# A transparent, additive model. Every point added is recorded as a risk
# factor; every point removed is recorded as a mitigating factor. The final
# score, the band and the verdict are all derived from the same evidence, so
# the report can show the analyst exactly how the number was reached.
# ──────────────────────────────────────────────────────────────────────────────

def score_dlp_risk(
    enrichment: dict,
    legitimacy: dict,
    org_context: dict,
    prior_correspondence: dict,
) -> dict:
    """
    Combine sender, recipient, data and behavioural context into a single
    0-100 risk score with explicit risk_factors and mitigating_factors.

    Returns
    -------
    dict:
        score               : int 0-100
        band                : "critical" | "high" | "medium" | "low"
        verdict_level       : "ESCALATE" | "NEEDS_REVIEW" | "LIKELY_FP"
        risk_factors        : list[{factor, weight, detail}]
        mitigating_factors  : list[{factor, weight, detail}]
    """
    e = enrichment or {}
    legitimacy = legitimacy or {}
    prior_correspondence = prior_correspondence or {}

    risk: list[dict] = []
    mit: list[dict] = []

    def add_risk(factor, weight, detail):
        risk.append({"factor": factor, "weight": weight, "detail": detail})

    def add_mit(factor, weight, detail):
        mit.append({"factor": factor, "weight": weight, "detail": detail})

    recipient_type = e.get("recipient_type", "unknown")
    to_domain = e.get("to_domain", "")
    ioc_domain_hit = e.get("ioc_domain_hit") or {}
    ioc_ip_hits = e.get("ioc_ip_hits") or []
    domain_intel = e.get("domain_intel") or {}
    sender_identity = e.get("sender_identity") or {}
    kw = e.get("keyword_results") or {}
    kw_hits = kw.get("hits", {})
    fa = e.get("file_analysis") or {}
    dm = e.get("doc_metadata") or {}
    timing = e.get("timing") or {}

    ioc_malicious = bool(ioc_domain_hit.get("is_malicious")) or bool(ioc_ip_hits)

    # ── Recipient / destination risk ──────────────────────────────────────────
    if ioc_domain_hit.get("is_malicious"):
        add_risk("recipient_ioc", 60,
                 f"Recipient domain {to_domain} is on a threat feed "
                 f"(score {ioc_domain_hit.get('reputation_score', 0)}/100).")
    for _ in ioc_ip_hits:
        add_risk("routing_ip_ioc", 40,
                 "An IP in the mail routing path matched a threat feed.")

    if recipient_type == "disposable":
        add_risk("disposable_recipient", 35,
                 f"Data sent to a disposable/temporary address domain ({to_domain}).")
    elif recipient_type == "suspicious":
        add_risk("suspicious_recipient", 25,
                 f"Recipient domain {to_domain} looks randomly generated or look-alike.")
    elif recipient_type == "webmail":
        add_risk("personal_webmail", 12,
                 f"Organization data sent to a personal webmail address ({to_domain}).")

    age_days = domain_intel.get("age_days")
    if age_days is not None and age_days < 30:
        add_risk("newly_registered_domain", 30,
                 f"Recipient domain registered only {age_days} days ago.")
    elif age_days is not None and age_days < 180:
        add_risk("recent_domain", 15,
                 f"Recipient domain registered recently ({domain_intel.get('age_label')}).")

    # ── Behavioural risk ──────────────────────────────────────────────────────
    if e.get("self_send_exact"):
        add_risk("self_send_exact", 30,
                 "Sender and recipient are the same address (exfil to self).")
    elif (e.get("self_send_fuzzy") or {}).get("is_fuzzy_match"):
        add_risk("self_send_fuzzy", 20,
                 "Recipient local-part closely resembles the sender at a personal domain.")

    if e.get("has_bcc"):
        n = len(e.get("bcc_addresses", []))
        add_risk("bcc_recipients", 15, f"{n} hidden BCC recipient(s) detected.")

    if dm.get("modified_just_before_send"):
        add_risk("doc_modified_pre_send", 10,
                 f"Attached document modified {dm.get('modification_gap_mins')} "
                 f"minutes before sending.")

    if timing.get("is_after_hours"):
        add_risk("after_hours", 5,
                 f"Sent outside business hours ({timing.get('datetime_str', '')}).")
    if timing.get("is_weekend"):
        add_risk("weekend", 5, f"Sent on a weekend ({timing.get('day_of_week', '')}).")

    # ── Sender identity risk ──────────────────────────────────────────────────
    if sender_identity.get("found"):
        crit = sender_identity.get("criticality", "LOW")
        name = sender_identity.get("display_name", "Sender")
        if crit == "CRITICAL":
            add_risk("sender_critical_asset", 20,
                     f"{name} is a CRITICAL asset — impact of data loss is maximal.")
        elif crit == "HIGH":
            add_risk("sender_high_asset", 12,
                     f"{name} is a HIGH-criticality asset.")
        if sender_identity.get("mfa_enabled") is False:
            add_risk("sender_no_mfa", 8,
                     f"{name} has no MFA — elevated account-compromise risk.")
        if sender_identity.get("risk_level") == "high":
            add_risk("sender_ad_risk_high", 15,
                     f"corporate directory Identity Protection flags {name} as HIGH risk.")
        elif sender_identity.get("risk_level") == "medium":
            add_risk("sender_ad_risk_medium", 8,
                     f"corporate directory Identity Protection flags {name} as MEDIUM risk.")

    # ── Data sensitivity risk ─────────────────────────────────────────────────
    crit_kw = kw_hits.get("critical", [])
    high_kw = kw_hits.get("high", [])
    if crit_kw:
        w = min(24, 8 * len(crit_kw))
        add_risk("critical_keywords", w,
                 f"Highly sensitive keywords: {', '.join(h['keyword'] for h in crit_kw)}.")
    if high_kw:
        w = min(16, 4 * len(high_kw))
        add_risk("sensitive_keywords", w,
                 f"Financial/compliance keywords: "
                 f"{', '.join(h['keyword'] for h in high_kw[:5])}.")

    dlp_score = e.get("dlp_score")
    if dlp_score is not None:
        if dlp_score >= 90:
            add_risk("gateway_dlp_score", 20, f"Gateway DLP score {dlp_score}/100.")
        elif dlp_score >= 80:
            add_risk("gateway_dlp_score", 15, f"Gateway DLP score {dlp_score}/100.")
        elif dlp_score >= 60:
            add_risk("gateway_dlp_score", 8, f"Gateway DLP score {dlp_score}/100.")

    dlp_class = (e.get("dlp_class") or "").upper()
    if "RESTRICTED" in dlp_class:
        add_risk("dlp_classification", 12, f"Gateway DLP classification: {e.get('dlp_class')}.")
    elif "CONFIDENTIAL" in dlp_class:
        add_risk("dlp_classification", 8, f"Gateway DLP classification: {e.get('dlp_class')}.")

    highest_file = fa.get("highest_risk")
    if highest_file == "critical":
        add_risk("high_risk_files", 15, "Attachment(s) of a critical (bulk/archive) type.")
    elif highest_file == "high":
        add_risk("high_risk_files", 10, "Attachment(s) of a high-risk (structured data) type.")

    sensitive_files = [f["filename"] for f in fa.get("files", []) if f.get("sensitive_name")]
    if sensitive_files:
        add_risk("sensitive_filenames", min(12, 6 * len(sensitive_files)),
                 f"Attachment name(s) imply sensitive content: {', '.join(sensitive_files[:3])}.")

    if (fa.get("total_size_mb") or 0) > 10:
        add_risk("large_volume", 6, f"Large attachment volume ({fa.get('total_size_mb')} MB).")

    # ── Mitigating factors ────────────────────────────────────────────────────
    if prior_correspondence.get("has_prior"):
        add_mit("prior_correspondence", 20,
                "Part of an existing thread / ongoing relationship "
                f"({'; '.join(prior_correspondence.get('evidence', [])[:1])}).")

    level = legitimacy.get("level")
    if level == "LEGITIMATE":
        add_mit("recipient_legitimate", 25, "Recipient assessed LEGITIMATE (internal).")
    elif level == "LIKELY_LEGITIMATE":
        add_mit("recipient_likely_legit", 12, "Recipient assessed LIKELY_LEGITIMATE.")

    if recipient_type == "internal":
        add_mit("internal_recipient", 30, "Recipient is inside the organization.")

    if age_days is not None and age_days >= 730 and recipient_type == "corporate":
        add_mit("established_domain", 10,
                f"Established corporate domain ({domain_intel.get('age_label')}).")

    if sender_identity.get("mfa_enabled") is True:
        add_mit("sender_mfa", 3, "Sender account has MFA enabled.")

    if org_context.get("org_source") == "whois" and recipient_type == "corporate":
        add_mit("registrant_org_known", 6,
                f"Recipient domain has a verifiable registrant organization "
                f"({org_context.get('organization')}).")

    # ── Combine ───────────────────────────────────────────────────────────────
    raw = sum(f["weight"] for f in risk) - sum(f["weight"] for f in mit)
    score = max(0, min(100, raw))

    band = "low"
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            band = name
            break

    if ioc_malicious:
        verdict = "ESCALATE"
    elif band == "critical":
        verdict = "ESCALATE"
    elif band in ("high", "medium"):
        verdict = "NEEDS_REVIEW"
    else:
        verdict = "LIKELY_FP"

    risk.sort(key=lambda f: f["weight"], reverse=True)
    mit.sort(key=lambda f: f["weight"], reverse=True)

    return {
        "score": score,
        "band": band,
        "verdict_level": verdict,
        "risk_factors": risk,
        "mitigating_factors": mit,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Evidence assembly  (Part 8 evidence[] / used by narrative)
# ──────────────────────────────────────────────────────────────────────────────

def build_dlp_evidence(enrichment: dict, prior_correspondence: dict) -> list[dict]:
    """
    Assemble a flat list of observed facts with their source, so the report
    and narrative can cite concrete evidence rather than assertions.

    Each item: {"category", "observation", "source"}
    """
    e = enrichment or {}
    ev: list[dict] = []

    def add(cat, obs, src):
        if obs:
            ev.append({"category": cat, "observation": obs, "source": src})

    add("sender", e.get("sender"), "email_header:From")
    si = e.get("sender_identity") or {}
    if si.get("found"):
        add("sender_identity",
            f"{si.get('display_name')} — {si.get('department')} / "
            f"{si.get('job_title')} (criticality {si.get('criticality')}, "
            f"MFA {'on' if si.get('mfa_enabled') else 'off'})",
            "directory" + ("(mock)" if si.get("mock") else ""))

    add("recipient", f"{e.get('to_address')} ({e.get('recipient_type')})",
        "email_header:To")
    for cc in e.get("cc_addresses", []):
        add("recipient_cc", cc, "email_header:CC")
    for bcc in e.get("bcc_addresses", []):
        add("recipient_bcc", bcc, "email_header:BCC")

    di = e.get("domain_intel") or {}
    if di.get("age_days") is not None or di.get("registrar"):
        add("recipient_domain",
            f"registrar={di.get('registrar')}, age={di.get('age_label')}, "
            f"country={di.get('country')}",
            "whois")

    ioc = e.get("ioc_domain_hit") or {}
    if ioc.get("is_malicious"):
        add("threat_intel",
            f"{e.get('to_domain')} on {', '.join(ioc.get('matched_sources', []))} "
            f"(score {ioc.get('reputation_score')}/100)",
            "ioc_database")

    kw = (e.get("keyword_results") or {}).get("summary", {})
    if kw:
        add("data_sensitivity",
            f"sensitive keywords — critical:{kw.get('critical_count', 0)} "
            f"high:{kw.get('high_count', 0)} medium:{kw.get('medium_count', 0)}",
            "content_scan")

    if e.get("dlp_score") is not None:
        add("data_sensitivity",
            f"gateway DLP score {e.get('dlp_score')}/100, "
            f"classification {e.get('dlp_class')}",
            "email_header:X-DLP-*")

    fa = e.get("file_analysis") or {}
    for f in fa.get("files", []):
        add("attachment",
            f"{f.get('filename')} ({f.get('extension')}, "
            f"{f.get('size_bytes')} bytes, risk {f.get('risk')})",
            "mime_part")

    dm = e.get("doc_metadata") or {}
    if dm.get("author") or dm.get("company"):
        add("document_metadata",
            f"author={dm.get('author')}, company={dm.get('company')}, "
            f"modified={dm.get('modified')}",
            "email_header:X-Document-*")

    timing = e.get("timing") or {}
    if timing.get("datetime_str"):
        add("timing",
            f"sent {timing.get('datetime_str')} "
            f"(after_hours={timing.get('is_after_hours')}, "
            f"weekend={timing.get('is_weekend')})",
            "email_header:Date")

    for item in (prior_correspondence or {}).get("evidence", []):
        add("relationship", item, "email_header")

    return ev


# ──────────────────────────────────────────────────────────────────────────────
# Deterministic DLP narrative  (Part 7)
#
# Answers the 10 investigation questions in seven labelled sections, and
# strictly separates: Observed facts / Enrichment results / Inference /
# Recommendation. Works with no LLM at all; also used as the grounded
# description handed to the LLM so it cannot wander off the evidence.
# ──────────────────────────────────────────────────────────────────────────────

def build_dlp_narrative(
    enrichment: dict,
    org_context: dict,
    legitimacy: dict,
    risk: dict,
    prior_correspondence: dict,
) -> str:
    """Return a structured, fact-grounded analyst narrative (plain text)."""
    e = enrichment or {}
    si = e.get("sender_identity") or {}
    lines: list[str] = []

    sender = e.get("sender", "unknown sender")
    to_addr = e.get("to_address", "unknown recipient")
    subject = e.get("subject", "(no subject)")
    rtype = e.get("recipient_type", "unknown")

    # Executive Summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append(
        f"[Observed] {sender} sent an email titled \"{subject}\" to {to_addr} "
        f"({rtype})."
    )
    lines.append(
        f"[Risk] Contextual DLP risk score {risk.get('score')}/100 "
        f"({risk.get('band', 'low').upper()}) — verdict "
        f"{risk.get('verdict_level')}."
    )
    lines.append("")

    # Sender Context
    lines.append("SENDER CONTEXT")
    if si.get("found"):
        lines.append(
            f"[Enrichment] {si.get('display_name')} — {si.get('department')} / "
            f"{si.get('job_title')}; manager {si.get('manager')}; "
            f"criticality {si.get('criticality')}; "
            f"MFA {'enabled' if si.get('mfa_enabled') else 'NOT enabled'}; "
            f"AD risk {str(si.get('risk_level')).upper()}."
        )
    else:
        lines.append(
            "[Observed] Sender could not be resolved in the identity directory; "
            "treat sender attributes as unconfirmed."
        )
    lines.append("")

    # Recipient Context
    lines.append("RECIPIENT CONTEXT")
    org = org_context.get("organization") or "Unknown"
    lines.append(
        f"[Enrichment] Recipient domain {e.get('to_domain')} — category: "
        f"{org_context.get('category')}; organization: {org} "
        f"(source: {org_context.get('org_source')}, "
        f"confidence: {org_context.get('confidence')})."
    )
    if org_context.get("country") or org_context.get("age_label"):
        lines.append(
            f"[Enrichment] WHOIS: country={org_context.get('country') or 'Unknown'}, "
            f"age={org_context.get('age_label') or 'Unknown'}, "
            f"registrar={org_context.get('registrar') or 'Unknown'}."
        )
    lines.append(
        f"[Enrichment] Legitimacy: {legitimacy.get('level')} "
        f"(confidence {legitimacy.get('confidence')})."
    )
    for r in legitimacy.get("reasons", [])[:4]:
        lines.append(f"   - {r}")
    lines.append("")

    # Data Exposure
    lines.append("DATA EXPOSURE")
    kw = (e.get("keyword_results") or {}).get("summary", {})
    fa = e.get("file_analysis") or {}
    lines.append(
        f"[Observed] Sensitive-keyword hits — critical:{kw.get('critical_count', 0)}, "
        f"high:{kw.get('high_count', 0)}, medium:{kw.get('medium_count', 0)}."
    )
    if e.get("dlp_score") is not None:
        lines.append(
            f"[Observed] Gateway DLP score {e.get('dlp_score')}/100, "
            f"classification {e.get('dlp_class')}."
        )
    if fa.get("count"):
        names = ", ".join(f.get("filename") for f in fa.get("files", []))
        lines.append(
            f"[Observed] {fa.get('count')} attachment(s) "
            f"({fa.get('total_size_mb', 0)} MB, highest risk "
            f"{fa.get('highest_risk')}): {names}."
        )
    else:
        lines.append("[Observed] No attachments.")
    lines.append("")

    # Behavioral Context
    lines.append("BEHAVIORAL CONTEXT")
    beh = []
    if e.get("self_send_exact"):
        beh.append("exact self-send")
    elif (e.get("self_send_fuzzy") or {}).get("is_fuzzy_match"):
        beh.append("possible fuzzy self-send")
    if e.get("has_bcc"):
        beh.append(f"{len(e.get('bcc_addresses', []))} BCC recipient(s)")
    timing = e.get("timing") or {}
    if timing.get("is_after_hours"):
        beh.append("sent after hours")
    if timing.get("is_weekend"):
        beh.append("sent on a weekend")
    if (e.get("doc_metadata") or {}).get("modified_just_before_send"):
        beh.append("document modified just before send")
    if prior_correspondence.get("has_prior"):
        beh.append("existing correspondence thread")
    lines.append("[Observed] " + ("; ".join(beh) if beh else "no unusual behavioural signals."))
    lines.append("")

    # Risk Assessment
    lines.append("RISK ASSESSMENT")
    if risk.get("risk_factors"):
        lines.append("[Inference] Risk factors:")
        for f in risk["risk_factors"][:6]:
            lines.append(f"   + ({f['weight']}) {f['detail']}")
    if risk.get("mitigating_factors"):
        lines.append("[Inference] Mitigating factors:")
        for f in risk["mitigating_factors"][:6]:
            lines.append(f"   - ({f['weight']}) {f['detail']}")
    lines.append("")

    # Recommended Analyst Action
    lines.append("RECOMMENDED ANALYST ACTION")
    for step in recommend_dlp_actions(risk, legitimacy, e):
        lines.append(f"[Recommendation] {step}")

    return "\n".join(lines)


def build_dlp_llm_description(
    enrichment: dict,
    org_context: dict,
    legitimacy: dict,
    risk: dict,
    prior_correspondence: dict,
) -> str:
    """
    A compact, evidence-only description handed to the LLM. Contains the same
    facts as the deterministic narrative but formatted as an input brief, so
    the model has no room to invent details.
    """
    e = enrichment or {}
    si = e.get("sender_identity") or {}
    kw = (e.get("keyword_results") or {}).get("summary", {})
    fa = e.get("file_analysis") or {}
    parts = [
        "DLP EMAIL INVESTIGATION — internal to external.",
        f"Sender: {e.get('sender')} "
        + (f"({si.get('display_name')}, {si.get('department')}, "
           f"criticality {si.get('criticality')}, "
           f"MFA {'on' if si.get('mfa_enabled') else 'off'})"
           if si.get("found") else "(not found in directory)"),
        f"Recipient: {e.get('to_address')} — type {e.get('recipient_type')}, "
        f"organization {org_context.get('organization') or 'Unknown'} "
        f"(source {org_context.get('org_source')}), "
        f"legitimacy {legitimacy.get('level')}.",
        f"Subject: {e.get('subject')}",
        f"Data: keyword hits critical={kw.get('critical_count', 0)} "
        f"high={kw.get('high_count', 0)} medium={kw.get('medium_count', 0)}; "
        f"gateway DLP score={e.get('dlp_score')} class={e.get('dlp_class')}; "
        f"attachments={fa.get('count', 0)} highest_risk={fa.get('highest_risk')}.",
        f"Behaviour: self_send_exact={e.get('self_send_exact')}, "
        f"fuzzy={(e.get('self_send_fuzzy') or {}).get('is_fuzzy_match')}, "
        f"bcc={e.get('has_bcc')}, "
        f"prior_correspondence={prior_correspondence.get('has_prior')}.",
        f"Risk score: {risk.get('score')}/100 ({risk.get('band')}), "
        f"verdict {risk.get('verdict_level')}.",
    ]
    return "\n".join(parts)


def recommend_dlp_actions(risk: dict, legitimacy: dict, enrichment: dict) -> list[str]:
    """Deterministic next-step recommendations keyed off the verdict."""
    verdict = risk.get("verdict_level", "NEEDS_REVIEW")
    rtype = (enrichment or {}).get("recipient_type", "unknown")
    steps: list[str] = []

    if verdict == "ESCALATE":
        steps.append("Escalate to Tier-2 DLP/insider-risk review immediately.")
        if legitimacy.get("level") == "MALICIOUS":
            steps.append("Block the recipient domain and quarantine the message at the gateway.")
        steps.append("Contact the sender's manager to confirm whether this transfer was authorized.")
        steps.append("Preserve the message, attachments and mail logs as evidence.")
    elif verdict == "NEEDS_REVIEW":
        steps.append("Review within SLA and confirm business justification with the sender.")
        if rtype == "webmail":
            steps.append("Verify whether sending organization data to a personal mailbox is policy-permitted.")
        steps.append("Check the sender's recent DLP history for a pattern.")
    else:
        steps.append("Handle as low priority during normal shift.")
        steps.append("If confirmed to be routine business, tune the DLP rule / add an exception.")

    if not (enrichment or {}).get("sender_identity", {}).get("found"):
        steps.append("Resolve the sender against the identity directory to complete the picture.")
    return steps


# ──────────────────────────────────────────────────────────────────────────────
# DLP structured JSON report  (Part 8)
# ──────────────────────────────────────────────────────────────────────────────

DLP_REPORT_SCHEMA_VERSION = "1.0"


def build_dlp_report(
    alert_id: str,
    alert_meta: dict,
    enrichment: dict,
    org_context: dict,
    legitimacy: dict,
    risk: dict,
    prior_correspondence: dict,
    evidence: list,
    narrative: str,
    narrative_source: str,
    raw_email: str = "",
    business_context: dict | None = None,
) -> dict:
    """
    Assemble the deterministic, machine-readable DLP investigation report.

    The top level carries a `report_type` discriminator so the report server
    can pick the right template, plus a `summary`/`risk_signals` block that is
    key-compatible with the existing report consumers.

    `business_context` is optional descriptive-only recipient company context
    (see build_recipient_business_context). It is surfaced under `recipient`
    for the analyst but is NOT part of any scoring input — the risk block is
    computed entirely upstream from org_context/legitimacy, not from this.
    """
    e = enrichment or {}
    si = e.get("sender_identity") or {}
    di = e.get("domain_intel") or {}
    ioc = e.get("ioc_domain_hit") or {}
    fa = e.get("file_analysis") or {}
    kw = e.get("keyword_results") or {}
    dm = e.get("doc_metadata") or {}
    timing = e.get("timing") or {}

    return {
        "report_type": "dlp_email_investigation",
        "schema_version": DLP_REPORT_SCHEMA_VERSION,
        "alert_id": alert_id,

        "alert": {
            "id": alert_id,
            "title": alert_meta.get("title", "DLP Email Investigation"),
            "source": alert_meta.get("source"),
            "severity_label": alert_meta.get("severityLabel") or alert_meta.get("severity"),
            "created_at": alert_meta.get("_createdAt") or alert_meta.get("created_at"),
            "direction": "internal_to_external",
        },

        "sender": {
            "address": e.get("sender"),
            "domain": e.get("sender_domain"),
            "identity": si,
        },

        "recipient": {
            "address": e.get("to_address"),
            "domain": e.get("to_domain"),
            "type": e.get("recipient_type"),
            "cc": e.get("cc_addresses", []),
            "bcc": e.get("bcc_addresses", []),
            "has_bcc": e.get("has_bcc", False),
            "organization_context": org_context,
            "business_context": business_context or {"applicable": False, "looked_up": False, "found": False, "scoring_impact": "none", "notes": []},
            "domain_intel": di,
            "legitimacy": legitimacy,
        },

        "data_analysis": {
            "keyword_results": kw,
            "gateway_dlp_score": e.get("dlp_score"),
            "gateway_dlp_classification": e.get("dlp_class"),
            "attachments": e.get("attachments", []),
            "file_analysis": fa,
            "document_metadata": dm,
        },

        "behavioral_analysis": {
            "self_send_exact": e.get("self_send_exact", False),
            "self_send_fuzzy": e.get("self_send_fuzzy", {}),
            "prior_correspondence": prior_correspondence,
            "timing": timing,
        },

        "threat_intelligence": {
            "recipient_domain_ioc": ioc,
            "routing_ip_iocs": e.get("ioc_ip_hits", []),
            "auth_summary": e.get("auth_summary"),
            "received_ips": e.get("received_ips", []),
        },

        "risk_assessment": {
            "score": risk.get("score"),
            "band": risk.get("band"),
            "verdict_level": risk.get("verdict_level"),
            "risk_factors": risk.get("risk_factors", []),
            "mitigating_factors": risk.get("mitigating_factors", []),
        },

        "ai_analysis": {
            "narrative": narrative,
            "narrative_source": narrative_source,   # "llm" | "deterministic"
        },

        "evidence": evidence,

        "recommended_actions": recommend_dlp_actions(risk, legitimacy, e),

        # ── Back-compat / convenience keys (mirror phishing record shape) ──────
        "verdict_level": risk.get("verdict_level"),
        "summary": {
            "risk_level": risk.get("band"),
            "risk_score": risk.get("score"),
            "any_malicious": bool(ioc.get("is_malicious")) or bool(e.get("ioc_ip_hits")),
            "recipient_legitimacy": legitimacy.get("level"),
            "high_risk_identity": si.get("criticality") in ("CRITICAL", "HIGH"),
        },
        "risk_signals": e.get("risk_signals", []),
        "raw_email": raw_email or "",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Phishing helpers  (Parts 10 & 11)
#
# Compute real, per-alert risk signals / statistics / summary from the parsed
# email, and produce a grounded narrative (and a grounded LLM brief). These
# replace the two hardcoded signals and the missing summary.risk_level in the
# phishing flow.
# ──────────────────────────────────────────────────────────────────────────────

def compute_phishing_signals(parsed: dict, ioc_hits: list, whois_info: dict) -> list[dict]:
    """
    Build evidence-based phishing risk signals from parsed email data.
    Returns a list of {level, message}; empty if nothing notable.
    """
    parsed = parsed or {}
    signals: list[dict] = []

    spf = (parsed.get("spf") or "").lower()
    dkim = (parsed.get("dkim") or "").lower()
    dmarc = (parsed.get("dmarc") or "").lower()

    if spf == "fail":
        signals.append({"level": "high", "message": f"SPF failed for sender domain {parsed.get('from_domain')}"})
    if dmarc == "fail":
        signals.append({"level": "high", "message": f"DMARC failed for sender domain {parsed.get('from_domain')}"})
    if dkim == "fail":
        signals.append({"level": "medium", "message": "DKIM signature verification failed"})

    if parsed.get("spoofs_domain"):
        signals.append({
            "level": "critical",
            "message": f"Sender domain appears to impersonate the organization: {parsed.get('spoofs_domain')}",
        })
    if parsed.get("reply_to_mismatch"):
        signals.append({
            "level": "high",
            "message": f"Reply-To domain differs from From domain ({parsed.get('reply_to')})",
        })

    urgency = parsed.get("urgency_words") or []
    if len(urgency) >= 3:
        signals.append({
            "level": "high",
            "message": f"Multiple urgency/pressure cues ({len(urgency)}): {', '.join(urgency[:5])}",
        })
    elif urgency:
        signals.append({
            "level": "medium",
            "message": f"Urgency/pressure language present: {', '.join(urgency[:5])}",
        })

    for hit in ioc_hits or []:
        val = hit.get("value") if isinstance(hit, dict) else hit
        src = hit.get("source", "threat feed") if isinstance(hit, dict) else "threat feed"
        fam = hit.get("malware_family") if isinstance(hit, dict) else None
        fam_str = f" — {fam}" if fam and fam != "N/A" else ""
        signals.append({
            "level": "critical",
            "message": f"Indicator matched threat feed ({src}){fam_str}: {val}",
        })

    n_urls = len(parsed.get("urls") or [])
    if n_urls:
        signals.append({
            "level": "low",
            "message": f"{n_urls} URL(s) present in the message body",
        })

    if parsed.get("attachments"):
        names = ", ".join(a.get("filename", "?") for a in parsed["attachments"])
        signals.append({
            "level": "medium",
            "message": f"{len(parsed['attachments'])} attachment(s): {names}",
        })

    age_days = (whois_info or {}).get("age_days")
    if isinstance(age_days, int) and age_days < 90:
        signals.append({
            "level": "high",
            "message": f"Sender domain registered recently ({age_days} days ago)",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    signals.sort(key=lambda s: order.get(s["level"], 99))
    # Deduplicate by message
    seen, unique = set(), []
    for s in signals:
        if s["message"] not in seen:
            seen.add(s["message"])
            unique.append(s)
    return unique


def compute_phishing_summary(parsed: dict, ioc_hits: list, signals: list) -> dict:
    """
    Derive a real summary block (incl. a risk_level the template can use) from
    the actual signals — no static values.
    """
    parsed = parsed or {}
    levels = {s["level"] for s in (signals or [])}
    any_malicious = bool(ioc_hits) or "critical" in levels

    if "critical" in levels:
        risk_level = "critical"
    elif "high" in levels:
        risk_level = "high"
    elif "medium" in levels:
        risk_level = "medium"
    else:
        risk_level = "low"

    auth_pass = (
        (parsed.get("spf") == "pass")
        and (parsed.get("dmarc") == "pass")
        and (parsed.get("dkim") in ("pass", "none"))
    )

    return {
        "risk_level": risk_level,
        "any_malicious": any_malicious,
        "auth_pass": auth_pass,
        "url_count": len(parsed.get("urls") or []),
        "ioc_hit_count": len(ioc_hits or []),
        "signal_count": len(signals or []),
        "attachment_count": len(parsed.get("attachments") or []),
    }


def phishing_verdict_from_summary(summary: dict) -> str:
    """Map a phishing summary risk_level to a verdict level."""
    level = (summary or {}).get("risk_level", "low")
    if level in ("critical",):
        return "ESCALATE"
    if level in ("high", "medium"):
        return "NEEDS_REVIEW"
    return "LIKELY_FP"


def build_phishing_narrative(parsed: dict, signals: list, ioc_hits: list,
                             whois_info: dict, summary: dict) -> str:
    """
    Deterministic phishing narrative grounded strictly in the alert's own
    evidence. Used as a fallback when the LLM is unavailable and as the
    grounded brief handed to the LLM.
    """
    parsed = parsed or {}
    lines = ["EXTRACTED FROM EMAIL"]
    lines.append(f"- Sender: {parsed.get('from_address')} (domain {parsed.get('from_domain')})")
    lines.append(f"- Subject: {parsed.get('subject')}")
    lines.append(f"- Authentication: {parsed.get('auth_summary')}")
    urls = parsed.get("urls") or []
    if urls:
        lines.append(f"- URLs ({len(urls)}): " + ", ".join(urls[:5]))
    if parsed.get("received_ips"):
        lines.append(f"- External routing IPs: {', '.join(parsed['received_ips'])}")
    if whois_info and whois_info.get("Registrar"):
        lines.append(f"- Sender domain WHOIS: registrar {whois_info.get('Registrar')}, age {whois_info.get('Age')}")

    lines.append("")
    lines.append("RISK ASSESSMENT")
    if signals:
        for s in signals:
            lines.append(f"- [{s['level'].upper()}] {s['message']}")
    else:
        lines.append("- No significant risk signals detected.")

    lines.append("")
    lines.append("ANALYST SHOULD CHECK FIRST")
    if ioc_hits:
        lines.append("- Confirmed threat-feed match — treat as malicious; block indicators and hunt for other recipients.")
    if parsed.get("spoofs_domain"):
        lines.append("- Domain impersonation of the organization — verify with the apparent sender out-of-band.")
    if parsed.get("reply_to_mismatch"):
        lines.append("- Reply-To differs from From — inspect where replies would actually go.")
    if urls:
        lines.append("- Detonate/inspect the URL(s) in a sandbox before any user interaction.")
    if not (ioc_hits or parsed.get("spoofs_domain") or parsed.get("reply_to_mismatch") or urls):
        lines.append("- No high-signal indicators; confirm with the reporting user and close if benign.")

    return "\n".join(lines)


def build_phishing_llm_description(parsed: dict, whois_info: dict) -> str:
    """Compact, evidence-only brief for the phishing LLM prompt."""
    parsed = parsed or {}
    urls = parsed.get("urls") or []
    atts = parsed.get("attachments") or []
    return "\n".join([
        f"Sender: {parsed.get('from_address')} (domain {parsed.get('from_domain')})",
        f"Reply-To: {parsed.get('reply_to')} (mismatch={parsed.get('reply_to_mismatch')})",
        f"Subject: {parsed.get('subject')}",
        f"Authentication: {parsed.get('auth_summary')}",
        f"Spoofing indicator: {parsed.get('spoofs_domain')}",
        f"Urgency words: {', '.join(parsed.get('urgency_words', [])) or 'none'}",
        f"External routing IPs: {', '.join(parsed.get('received_ips', [])) or 'none'}",
        f"URLs ({len(urls)}): " + (", ".join(urls[:5]) or "none"),
        f"Attachments ({len(atts)}): " + (", ".join(a.get('filename', '?') for a in atts) or "none"),
        f"Sender domain WHOIS: registrar={ (whois_info or {}).get('Registrar') }, "
        f"age={ (whois_info or {}).get('Age') }",
    ])
