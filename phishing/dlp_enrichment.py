"""
phishing/dlp_enrichment.py
===========================
Enrichment pipeline for email DLP alerts.

Direction: Internal → External (opposite of phishing)
Question : "Is our data walking out the door?"

What this module adds on top of email_parser.py:

  Sender Context
    → corporate directory identity (name, dept, manager, criticality, MFA)
    → Historical DLP cases for this sender (recurrence)

  Recipient Analysis
    → Webmail / disposable domain detection
    → Domain intelligence (WHOIS age, registrar, country)
    → IOC check on recipient domain and IPs
    → First-contact flag (never emailed this domain before?)
    → Recipient count + BCC detection

  Self-Send Detection
    → Exact match (same address)
    → Fuzzy match (adele.vance ≈ adelevance92)

  Content Signals
    → Sensitive keyword scoring (subject weighted 2x body)
    → DLP classification tag from SIEM headers
    → SIEM DLP score from headers
    → File type risk scoring
    → Total attachment size

  Document Metadata
    → Author, last modified by, creation date, company field
    → Modification timing (modified just before send = suspicious)

  Timing Context
    → Business hours flag
    → After hours flag
    → Day of week

  Risk Signal Assembly
    → Produces structured risk_signals list
    → LLM narrative generation

Usage:
    from phishing.dlp_enrichment import DLPEnrichment
    from phishing.email_parser import EmailParser
    from enrichment.identity_lookup import IdentityLookup
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.llm_analyzer import LLMAnalyzer
    from database.db_manager import DBManager

    db  = DBManager()
    dlp = DLPEnrichment(
        ad_lookup  = IdentityLookup(mock_mode=True),
        ioc_lookup = IOCLookup(db),
        llm        = LLMAnalyzer(),
    )

    result = dlp.enrich_file("tests/sample_emails/dlp_internal_to_gmail.eml")
    result = dlp.enrich_alert(alert_dict)
"""

import logging
import os
import re
import socket
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── Webmail and disposable domains ────────────────────────────────────────────
WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.fr", "yahoo.co.uk",
    "hotmail.com", "hotmail.fr", "hotmail.co.uk",
    "outlook.com", "live.com", "live.fr",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "yandex.com", "yandex.ru",
    "mail.com", "aol.com", "gmx.com",
    "tutanota.com", "tutanota.de",
    "zoho.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com",
    "throwaway.email", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "guerrillamail.info", "spam4.me",
    "trashmail.com", "trashmail.me", "trashmail.at",
    "dispostable.com", "maildrop.cc", "yopmail.com",
    "quickdump.io", "temp-mail.org", "fakeinbox.com",
}

# ── Sensitive keywords ────────────────────────────────────────────────────────
# Subject keywords weighted 2x, body keywords 1x
SENSITIVE_KEYWORDS_CRITICAL = [
    "confidential", "internal only", "restricted", "top secret",
    "do not distribute", "not for distribution",
]

SENSITIVE_KEYWORDS_HIGH = [
    "swift", "iban", "bic", "account number", "routing number",
    "client list", "client portfolio", "salary", "payroll",
    "merger", "acquisition", "board", "quarterly results",
    "financial statements", "revenue", "profit", "loss",
    "audit", "compliance", "regulatory",
]

SENSITIVE_KEYWORDS_MEDIUM = [
    "personal data", "gdpr", "pii", "credit card",
    "passport", "identity", "social security",
    "password", "credentials", "private key",
]

# ── File type risk scores ─────────────────────────────────────────────────────
FILE_TYPE_RISK = {
    # Critical — bulk data exports
    "pst":  "critical",   # entire mailbox
    "zip":  "critical",   # archive hiding content
    "rar":  "critical",
    "7z":   "critical",
    "tar":  "critical",
    # High — structured data
    "xlsx": "high",       # financial spreadsheets
    "csv":  "high",       # raw data exports
    "db":   "high",       # database files
    "sql":  "high",
    "mdb":  "high",
    # Medium — documents
    "pdf":  "medium",
    "docx": "medium",
    "doc":  "medium",
    "pptx": "medium",
    # Low — general
    "txt":  "low",
    "png":  "low",
    "jpg":  "low",
}

# ── Business hours ────────────────────────────────────────────────────────────
BUSINESS_HOUR_START = 8   # 08:00
BUSINESS_HOUR_END   = 19  # 19:00

# ── WHOIS API ─────────────────────────────────────────────────────────────────
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")
WHOIS_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

socket.setdefaulttimeout(3)


class DLPEnrichment:
    """
    Enriches email DLP alerts with sender identity, recipient analysis,
    content signals, and risk scoring.

    Parameters
    ----------
    ad_lookup  : IdentityLookup instance
    ioc_lookup : IOCLookup instance
    llm        : LLMAnalyzer instance (optional)
    org_domain : str — organization email domain
    """

    def __init__(
        self,
        ad_lookup,
        ioc_lookup,
        llm=None,
        org_domain: str = "example-corp.com",
    ):
        self.ad_lookup  = ad_lookup
        self.ioc_lookup = ioc_lookup
        self.llm        = llm
        self.org_domain = org_domain.lower()

        # Import here to avoid circular imports
        from phishing.email_parser import EmailParser
        self.parser = EmailParser(org_domain=org_domain)

        logger.info("DLPEnrichment initialized")

    # ── Public API ────────────────────────────────────────────────────────────

    def enrich_file(self, path: str) -> dict:
        """
        Enrich a DLP alert from a .eml file on disk.
        Used for testing and the folder watcher flow.
        """
        parsed = self.parser.parse_file(path)
        return self._enrich(parsed, alert_id=Path(path).stem)

    def enrich_bytes(self, raw: bytes, alert_id: str = "unknown") -> dict:
        """
        Enrich a DLP alert from raw .eml bytes.
        Used when the email content comes from case management platform description field.
        """
        parsed = self.parser.parse_bytes(raw)
        return self._enrich(parsed, alert_id=alert_id)

    def enrich_alert(self, alert: dict) -> dict:
        """
        Enrich a case management platform alert dict tagged 'dlp-alert'.
        Reads .eml content from the description field.
        """
        alert_id    = alert.get("_id", "unknown")
        raw_content = alert.get("description", "")
        raw_bytes   = raw_content.encode("utf-8", errors="ignore")
        return self.enrich_bytes(raw_bytes, alert_id=alert_id)

    # ── Core enrichment ───────────────────────────────────────────────────────

    def _enrich(self, parsed: dict, alert_id: str) -> dict:
        """
        Run all DLP enrichment checks on a parsed email.
        Returns a structured enrichment record.
        """
        start = time.monotonic()

        sender       = parsed.get("from_address", "")
        sender_domain = parsed.get("from_domain", "")
        to_address   = parsed.get("to_address", "")
        to_domain    = self._extract_domain(to_address)
        subject      = parsed.get("subject", "")
        body         = parsed.get("body_text", "")
        attachments  = parsed.get("attachments", [])
        date_str     = parsed.get("date", "")
        raw_headers  = parsed.get("raw_headers", "")

        # ── Sender identity (corporate directory) ────────────────────────────────────────
        sender_identity = self.ad_lookup.lookup_email(sender)

        # ── Recipient analysis ────────────────────────────────────────────────
        recipient_type  = self._classify_recipient(to_domain)
        domain_intel    = self._whois_lookup(to_domain)
        ioc_domain_hit  = self.ioc_lookup.check("domain", to_domain)
        ioc_ip_hits     = [
            self.ioc_lookup.check("ip", ip)
            for ip in parsed.get("received_ips", [])
            if self.ioc_lookup.check("ip", ip).get("is_malicious")
        ]

        # ── Self-send detection ───────────────────────────────────────────────
        self_send_exact = parsed.get("is_self_send", False)
        self_send_fuzzy = self._fuzzy_self_send(sender, to_address)

        # ── BCC and recipient count ───────────────────────────────────────────
        cc_addresses  = self._extract_cc(raw_headers)
        bcc_addresses = self._extract_bcc(raw_headers)
        has_bcc       = len(bcc_addresses) > 0

        # ── Relationship / prior-correspondence context ───────────────────────
        # Evidence that this exchange is part of an existing business thread
        # (In-Reply-To / References / X-Prior-Correspondence). Shared helper so
        # the DLP and phishing flows classify relationships identically.
        from enrichment.report_common import detect_prior_correspondence
        prior_correspondence = detect_prior_correspondence(raw_headers)

        # ── Content signals ───────────────────────────────────────────────────
        keyword_results = self._score_keywords(subject, body)
        dlp_score       = self._extract_dlp_score(raw_headers)
        dlp_class       = self._extract_dlp_classification(raw_headers)

        # ── File analysis ─────────────────────────────────────────────────────
        file_analysis   = self._analyze_attachments(attachments)

        # ── Document metadata ─────────────────────────────────────────────────
        doc_metadata    = self._extract_doc_metadata(raw_headers, attachments)

        # ── Timing context ────────────────────────────────────────────────────
        timing          = self._analyze_timing(date_str)

        # ── Risk signals ──────────────────────────────────────────────────────
        risk_signals    = self._build_risk_signals(
            sender_identity = sender_identity,
            recipient_type  = recipient_type,
            domain_intel    = domain_intel,
            ioc_domain_hit  = ioc_domain_hit,
            ioc_ip_hits     = ioc_ip_hits,
            self_send_exact = self_send_exact,
            self_send_fuzzy = self_send_fuzzy,
            has_bcc         = has_bcc,
            keyword_results = keyword_results,
            dlp_score       = dlp_score,
            dlp_class       = dlp_class,
            file_analysis   = file_analysis,
            doc_metadata    = doc_metadata,
            timing          = timing,
            sender          = sender,
            to_domain       = to_domain,
            subject         = subject,
        )

        # ── Verdict level ─────────────────────────────────────────────────────
        verdict_level = self._determine_verdict(risk_signals)

        # ── LLM narrative ─────────────────────────────────────────────────────
        narrative = None
        if self.llm:
            narrative = self.llm.generate_narrative({
                "target_id":   alert_id,
                "title":       f"DLP Alert — {subject}",
                "description": self._build_llm_description(
                    parsed, sender_identity, recipient_type,
                    domain_intel, keyword_results, timing
                ),
                "risk_signals": risk_signals,
                "summary": {
                    "any_malicious":        ioc_domain_hit.get("is_malicious", False),
                    "high_risk_identity":   sender_identity.get("criticality") in ("CRITICAL", "HIGH"),
                    "max_reputation_score": ioc_domain_hit.get("reputation_score", 0),
                },
                "verdict_level": verdict_level,
            })

        duration = round(time.monotonic() - start, 2)
        logger.info(
            f"DLP enrichment complete for {alert_id} in {duration}s — "
            f"verdict: {verdict_level}, signals: {len(risk_signals)}"
        )

        return {
            # Identity
            "alert_id":         alert_id,
            "sender":           sender,
            "sender_domain":    sender_domain,
            "sender_identity":  sender_identity,
            "to_address":       to_address,
            "to_domain":        to_domain,
            "subject":          subject,
            "date":             date_str,

            # Recipient
            "recipient_type":   recipient_type,
            "domain_intel":     domain_intel,
            "ioc_domain_hit":   ioc_domain_hit,
            "ioc_ip_hits":      ioc_ip_hits,
            "cc_addresses":     cc_addresses,
            "bcc_addresses":    bcc_addresses,
            "has_bcc":          has_bcc,

            # Self-send
            "self_send_exact":  self_send_exact,
            "self_send_fuzzy":  self_send_fuzzy,

            # Relationship context
            "prior_correspondence": prior_correspondence,

            # Content
            "keyword_results":  keyword_results,
            "dlp_score":        dlp_score,
            "dlp_class":        dlp_class,

            # Files
            "file_analysis":    file_analysis,
            "attachments":      attachments,

            # Metadata
            "doc_metadata":     doc_metadata,

            # Timing
            "timing":           timing,

            # Auth
            "auth_summary":     parsed.get("auth_summary", ""),
            "received_ips":     parsed.get("received_ips", []),

            # Raw passthrough (for report evidence / relationship analysis)
            "raw_headers":      raw_headers,
            "body_text":        body,

            # Output
            "risk_signals":     risk_signals,
            "verdict_level":    verdict_level,
            "narrative":        narrative,
            "duration_secs":    duration,
        }

    # ── Recipient classification ──────────────────────────────────────────────

    def _classify_recipient(self, domain: str) -> str:
        """
        Classify recipient domain type.
        Returns: webmail | disposable | internal | corporate | unknown
        """
        if not domain:
            return "unknown"
        d = domain.lower()
        if d == self.org_domain:
            return "internal"
        if d in WEBMAIL_DOMAINS:
            return "webmail"
        if d in DISPOSABLE_DOMAINS:
            return "disposable"
        # Heuristic: random-looking domain strings
        if re.search(r"\d{4,}", d) or len(d.split(".")[0]) < 4:
            return "suspicious"
        return "corporate"

    # ── Self-send fuzzy detection ─────────────────────────────────────────────

    def _fuzzy_self_send(self, sender: str, recipient: str) -> dict:
        """
        Detect if the sender is likely emailing themselves at a
        personal address using username similarity.

        Returns dict with: is_fuzzy_match, similarity, method
        """
        if not sender or not recipient:
            return {"is_fuzzy_match": False, "similarity": 0, "method": None}

        sender_user    = sender.split("@")[0].lower()
        recipient_user = recipient.split("@")[0].lower()
        recipient_dom  = self._extract_domain(recipient)

        # Only check if recipient is personal/webmail
        if recipient_dom not in WEBMAIL_DOMAINS:
            return {"is_fuzzy_match": False, "similarity": 0, "method": None}

        # Normalize: remove dots, dashes, underscores, digits
        def normalize(s):
            return re.sub(r"[.\-_0-9]", "", s.lower())

        s_norm = normalize(sender_user)
        r_norm = normalize(recipient_user)

        # Exact match after normalization
        if s_norm == r_norm:
            return {
                "is_fuzzy_match": True,
                "similarity":     1.0,
                "method":         "normalized_exact",
                "sender_user":    sender_user,
                "recipient_user": recipient_user,
            }

        # One contains the other
        if s_norm in r_norm or r_norm in s_norm:
            return {
                "is_fuzzy_match": True,
                "similarity":     0.8,
                "method":         "substring_match",
                "sender_user":    sender_user,
                "recipient_user": recipient_user,
            }

        # Initials match (adele.vance → av)
        sender_initials = "".join(p[0] for p in sender_user.split(".") if p)
        if sender_initials and recipient_user.startswith(sender_initials):
            return {
                "is_fuzzy_match": True,
                "similarity":     0.6,
                "method":         "initials_match",
                "sender_user":    sender_user,
                "recipient_user": recipient_user,
            }

        return {"is_fuzzy_match": False, "similarity": 0, "method": None}

    # ── Keyword scoring ───────────────────────────────────────────────────────

    def _score_keywords(self, subject: str, body: str) -> dict:
        """
        Score sensitive keywords in subject (2x weight) and body (1x).
        Returns structured keyword hit results.
        """
        subject_lower = subject.lower()
        body_lower    = body.lower()

        hits = {
            "critical": [],
            "high":     [],
            "medium":   [],
        }

        for kw in SENSITIVE_KEYWORDS_CRITICAL:
            in_subject = kw in subject_lower
            in_body    = kw in body_lower
            if in_subject or in_body:
                hits["critical"].append({
                    "keyword":    kw,
                    "in_subject": in_subject,
                    "in_body":    in_body,
                    "weight":     2 if in_subject else 1,
                })

        for kw in SENSITIVE_KEYWORDS_HIGH:
            in_subject = kw in subject_lower
            in_body    = kw in body_lower
            if in_subject or in_body:
                hits["high"].append({
                    "keyword":    kw,
                    "in_subject": in_subject,
                    "in_body":    in_body,
                    "weight":     2 if in_subject else 1,
                })

        for kw in SENSITIVE_KEYWORDS_MEDIUM:
            in_subject = kw in subject_lower
            in_body    = kw in body_lower
            if in_subject or in_body:
                hits["medium"].append({
                    "keyword":    kw,
                    "in_subject": in_subject,
                    "in_body":    in_body,
                    "weight":     2 if in_subject else 1,
                })

        total_score = (
            sum(h["weight"] * 3 for h in hits["critical"]) +
            sum(h["weight"] * 2 for h in hits["high"]) +
            sum(h["weight"] * 1 for h in hits["medium"])
        )

        return {
            "hits":        hits,
            "total_score": total_score,
            "summary": {
                "critical_count": len(hits["critical"]),
                "high_count":     len(hits["high"]),
                "medium_count":   len(hits["medium"]),
            }
        }

    # ── File analysis ─────────────────────────────────────────────────────────

    def _analyze_attachments(self, attachments: list) -> dict:
        """
        Analyze attachments for risk signals.
        Returns file risk scores and total size.
        """
        if not attachments:
            return {
                "count":        0,
                "total_size":   0,
                "highest_risk": None,
                "files":        [],
            }

        files        = []
        total_size   = 0
        highest_risk = "low"

        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for att in attachments:
            filename  = att.get("filename", "")
            ext       = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            risk      = FILE_TYPE_RISK.get(ext, "low")
            size      = att.get("size_bytes", 0)
            total_size += size

            # Check if filename contains sensitive words
            fname_lower = filename.lower()
            sensitive_name = any(
                kw in fname_lower for kw in [
                    "confidential", "restricted", "salary", "payroll",
                    "client", "portfolio", "financial", "report",
                    "internal", "private", "secret", "export"
                ]
            )

            files.append({
                "filename":       filename,
                "extension":      ext,
                "risk":           risk,
                "size_bytes":     size,
                "sha256":         att.get("sha256"),
                "sensitive_name": sensitive_name,
            })

            if risk_order.get(risk, 0) > risk_order.get(highest_risk, 0):
                highest_risk = risk

        return {
            "count":        len(files),
            "total_size":   total_size,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "highest_risk": highest_risk,
            "files":        files,
        }

    # ── Document metadata ─────────────────────────────────────────────────────

    def _extract_doc_metadata(self, raw_headers: str, attachments: list) -> dict:
        """
        Extract document metadata from X-Document headers and attachments.
        In production these would come from parsing Office/PDF files directly.
        For now reads X-Document-* headers injected by Exchange DLP.
        """
        author        = self._header_value(raw_headers, "X-Document-Author")
        company       = self._header_value(raw_headers, "X-Document-Company")
        created_str   = self._header_value(raw_headers, "X-Document-Created")
        modified_str  = self._header_value(raw_headers, "X-Document-Modified")

        # Calculate modification-to-send gap
        modification_gap_mins = None
        if modified_str:
            try:
                modified_dt = datetime.fromisoformat(
                    modified_str.replace("Z", "+00:00")
                )
                now = datetime.now(timezone.utc)
                gap = (now - modified_dt.replace(tzinfo=timezone.utc)
                       if modified_dt.tzinfo is None
                       else now - modified_dt)
                modification_gap_mins = int(gap.total_seconds() / 60)
            except Exception:
                pass

        # Flag: modified very recently before send (within 30 mins)
        modified_just_before_send = (
            modification_gap_mins is not None
            and modification_gap_mins < 30
        )

        return {
            "author":                    author,
            "company":                   company,
            "created":                   created_str,
            "modified":                  modified_str,
            "modification_gap_mins":     modification_gap_mins,
            "modified_just_before_send": modified_just_before_send,
        }

    # ── Timing analysis ───────────────────────────────────────────────────────

    def _analyze_timing(self, date_str: str) -> dict:
        """Analyze the email send time for after-hours signals."""
        if not date_str:
            return {
                "is_after_hours": None,
                "is_weekend":     None,
                "hour":           None,
                "day_of_week":    None,
            }

        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_str)
            hour         = dt.hour
            day_of_week  = dt.strftime("%A")
            is_weekend   = dt.weekday() >= 5
            is_after_hours = (
                hour < BUSINESS_HOUR_START or hour >= BUSINESS_HOUR_END
            )

            return {
                "is_after_hours": is_after_hours,
                "is_weekend":     is_weekend,
                "hour":           hour,
                "day_of_week":    day_of_week,
                "datetime_str":   dt.strftime("%Y-%m-%d %H:%M %Z"),
            }
        except Exception:
            return {
                "is_after_hours": None,
                "is_weekend":     None,
                "hour":           None,
                "day_of_week":    None,
            }

    # ── WHOIS lookup ──────────────────────────────────────────────────────────

    def _whois_lookup(self, domain: str) -> dict:
        """
        Look up domain registration info.
        Returns registrar, creation date, age in days.
        """
        if not domain or not WHOISXML_API_KEY:
            return {
                "registrar":    "unknown",
                "created":      "unknown",
                "age_days":     None,
                "age_label":    "unknown",
                "country":      "unknown",
                "organization": None,
            }

        try:
            r = requests.get(
                WHOIS_URL,
                params={
                    "apiKey":       WHOISXML_API_KEY,
                    "domainName":   domain,
                    "outputFormat": "JSON",
                },
                timeout=10
            )
            if r.status_code != 200:
                return {"registrar": "lookup failed", "age_days": None,
                        "age_label": "unknown", "country": "unknown",
                        "organization": None}

            data    = r.json()
            record  = data.get("WhoisRecord", {})
            age_days = record.get("estimatedDomainAge")

            age_label = "unknown"
            if age_days is not None:
                if age_days < 30:
                    age_label = f"{age_days} days ⚠️ very new"
                elif age_days < 365:
                    age_label = f"{age_days // 30} months"
                else:
                    age_label = f"{age_days // 365} years"

            # Registrant organization / country can appear either at the top
            # level or nested under registrant / registryData.registrant.
            organization = self._whois_registrant_field(record, "organization")
            country      = self._whois_registrant_field(record, "country")

            return {
                "registrar":    record.get("registrarName", "unknown"),
                "created":      record.get("createdDateNormalized", "unknown"),
                "age_days":     age_days,
                "age_label":    age_label,
                "country":      country or "unknown",
                "organization": organization,   # None if not disclosed / redacted
            }
        except Exception as exc:
            logger.warning(f"WHOIS lookup failed for {domain}: {exc}")
            return {"registrar": "lookup failed", "age_days": None,
                    "age_label": "unknown", "country": "unknown",
                    "organization": None}

    @staticmethod
    def _whois_registrant_field(record: dict, field: str) -> Optional[str]:
        """
        Pull a registrant field (e.g. 'organization', 'country') from the
        several places WhoisXML may place it, without inventing a value.
        """
        # Top-level convenience keys (registrantOrganization / registrantCountry)
        cap = "registrant" + field.capitalize()
        val = record.get(cap)
        if val:
            return str(val).strip()
        # Nested registrant objects
        for container in (record.get("registrant"),
                          (record.get("registryData") or {}).get("registrant")):
            if isinstance(container, dict) and container.get(field):
                return str(container[field]).strip()
        return None

    # ── Risk signal builder ───────────────────────────────────────────────────

    def _build_risk_signals(self, **kwargs) -> list[dict]:
        """
        Build structured risk signals from all enrichment results.
        Each signal has: level (critical/high/medium/low), message
        """
        signals = []
        si      = kwargs.get("sender_identity", {})
        timing  = kwargs.get("timing", {})
        kw      = kwargs.get("keyword_results", {})
        fa      = kwargs.get("file_analysis", {})
        dm      = kwargs.get("doc_metadata", {})
        ioc_d   = kwargs.get("ioc_domain_hit", {})

        # ── Recipient signals ─────────────────────────────────────────────────
        rtype   = kwargs.get("recipient_type", "unknown")
        domain  = kwargs.get("to_domain", "")
        subject = kwargs.get("subject", "")

        if rtype == "disposable":
            signals.append({
                "level":   "critical",
                "message": f"Email sent to disposable/temporary address domain: {domain}"
            })
        elif rtype == "webmail":
            signals.append({
                "level":   "high",
                "message": f"Email sent to personal webmail address: {domain}"
            })
        elif rtype == "suspicious":
            signals.append({
                "level":   "high",
                "message": f"Recipient domain looks suspicious or randomly generated: {domain}"
            })

        # ── Self-send signals ─────────────────────────────────────────────────
        if kwargs.get("self_send_exact"):
            signals.append({
                "level":   "critical",
                "message": "Self-send detected — sender and recipient are the same address"
            })
        elif kwargs.get("self_send_fuzzy", {}).get("is_fuzzy_match"):
            fsf = kwargs["self_send_fuzzy"]
            signals.append({
                "level":   "high",
                "message": (
                    f"Possible self-send — sender '{fsf['sender_user']}' resembles "
                    f"recipient '{fsf['recipient_user']}' at personal webmail "
                    f"(method: {fsf['method']})"
                )
            })

        # ── BCC signals ───────────────────────────────────────────────────────
        if kwargs.get("has_bcc"):
            signals.append({
                "level":   "high",
                "message": f"BCC recipients detected — {len(kwargs.get('bcc_addresses', []))} hidden recipient(s)"
            })

        # ── IOC signals ───────────────────────────────────────────────────────
        if ioc_d.get("is_malicious"):
            signals.append({
                "level":   "critical",
                "message": (
                    f"Recipient domain {domain} matched IOC feed "
                    f"({', '.join(ioc_d.get('matched_sources', []))}) — "
                    f"score {ioc_d.get('reputation_score', 0)}/100"
                )
            })

        for hit in kwargs.get("ioc_ip_hits", []):
            signals.append({
                "level":   "critical",
                "message": f"IP in email routing matched IOC feed: {hit.get('matched_sources', [])}"
            })

        # ── Sender identity signals ───────────────────────────────────────────
        if si.get("found"):
            criticality = si.get("criticality", "LOW")
            name        = si.get("display_name", "Unknown")
            dept        = si.get("department", "")

            if criticality == "CRITICAL":
                signals.append({
                    "level":   "critical",
                    "message": f"{name} ({dept}) is a CRITICAL asset — exfiltration impact is maximum"
                })
            elif criticality == "HIGH":
                signals.append({
                    "level":   "high",
                    "message": f"{name} ({dept}) is a HIGH criticality asset"
                })

            if not si.get("mfa_enabled"):
                signals.append({
                    "level":   "medium",
                    "message": f"{name} has no MFA — account compromise risk is elevated"
                })

            risk_level = si.get("risk_level", "none")
            if risk_level in ("high", "medium"):
                signals.append({
                    "level":   "high",
                    "message": f"corporate directory Identity Protection risk: {risk_level.upper()} for {name}"
                })

        # ── Keyword signals ───────────────────────────────────────────────────
        kw_hits = kw.get("hits", {})
        if kw_hits.get("critical"):
            words = [h["keyword"] for h in kw_hits["critical"]]
            signals.append({
                "level":   "critical",
                "message": f"Highly sensitive keywords detected: {', '.join(words)}"
            })
        if kw_hits.get("high"):
            words = [h["keyword"] for h in kw_hits["high"][:5]]
            signals.append({
                "level":   "high",
                "message": f"Sensitive financial/compliance keywords: {', '.join(words)}"
            })

        # ── DLP score signal ──────────────────────────────────────────────────
        dlp_score = kwargs.get("dlp_score")
        dlp_class = kwargs.get("dlp_class")
        if dlp_score and dlp_score >= 80:
            signals.append({
                "level":   "high",
                "message": f"SIEM DLP score: {dlp_score}/100 — high confidence data loss"
            })
        if dlp_class:
            signals.append({
                "level":   "medium",
                "message": f"SIEM DLP classification: {dlp_class}"
            })

        # ── File signals ──────────────────────────────────────────────────────
        if fa.get("highest_risk") in ("critical", "high"):
            risky = [
                f["filename"] for f in fa.get("files", [])
                if f["risk"] in ("critical", "high")
            ]
            signals.append({
                "level":   fa["highest_risk"],
                "message": f"High-risk file types in attachment(s): {', '.join(risky)}"
            })

        for f in fa.get("files", []):
            if f.get("sensitive_name"):
                signals.append({
                    "level":   "high",
                    "message": f"Attachment filename suggests sensitive content: {f['filename']}"
                })

        if fa.get("total_size_mb", 0) > 10:
            signals.append({
                "level":   "medium",
                "message": f"Large attachment volume: {fa['total_size_mb']} MB total"
            })

        # ── Document metadata signals ─────────────────────────────────────────
        if dm.get("modified_just_before_send"):
            signals.append({
                "level":   "high",
                "message": (
                    f"Document modified {dm.get('modification_gap_mins')} minutes "
                    f"before send — possible last-minute data preparation"
                )
            })

        if dm.get("company") and dm["company"].lower() != self.org_domain.split(".")[0].lower():
            signals.append({
                "level":   "medium",
                "message": f"Document company metadata '{dm['company']}' differs from sender org"
            })

        # ── Timing signals ────────────────────────────────────────────────────
        if timing.get("is_after_hours"):
            signals.append({
                "level":   "medium",
                "message": f"Email sent outside business hours: {timing.get('datetime_str', '')}"
            })

        if timing.get("is_weekend"):
            signals.append({
                "level":   "medium",
                "message": f"Email sent on a weekend: {timing.get('day_of_week', '')}"
            })

        # ── Domain age signal ─────────────────────────────────────────────────
        di      = kwargs.get("domain_intel", {})
        age_days = di.get("age_days")
        if age_days is not None and age_days < 30:
            signals.append({
                "level":   "critical",
                "message": f"Recipient domain {domain} registered only {age_days} days ago"
            })
        elif age_days is not None and age_days < 180:
            signals.append({
                "level":   "high",
                "message": f"Recipient domain {domain} registered recently: {di.get('age_label')}"
            })

        # Sort: critical first
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        signals.sort(key=lambda s: order.get(s["level"], 99))

        # Deduplicate
        seen, unique = set(), []
        for s in signals:
            if s["message"] not in seen:
                seen.add(s["message"])
                unique.append(s)

        return unique

    # ── Verdict determination ─────────────────────────────────────────────────

    def _determine_verdict(self, signals: list[dict]) -> str:
        """
        Determine overall verdict level from risk signals.
        Does NOT auto-close — analyst makes final decision.
        """
        levels = {s["level"] for s in signals}
        if "critical" in levels:
            return "ESCALATE"
        if "high" in levels:
            return "NEEDS_REVIEW"
        if "medium" in levels:
            return "NEEDS_REVIEW"
        return "LIKELY_FP"

    # ── LLM description builder ───────────────────────────────────────────────

    def _build_llm_description(
        self, parsed, sender_identity, recipient_type,
        domain_intel, keyword_results, timing
    ) -> str:
        """Build a rich description for the LLM prompt."""
        si   = sender_identity
        name = si.get("display_name", "Unknown") if si.get("found") else parsed.get("from_address")
        dept = si.get("department", "Unknown") if si.get("found") else ""
        mgr  = si.get("manager", "Unknown") if si.get("found") else ""

        kw_summary = ""
        hits = keyword_results.get("hits", {})
        all_kw = (
            [h["keyword"] for h in hits.get("critical", [])] +
            [h["keyword"] for h in hits.get("high", [])]
        )
        if all_kw:
            kw_summary = f"Sensitive keywords: {', '.join(all_kw[:8])}"

        atts = parsed.get("attachments", [])
        att_summary = ""
        if atts:
            att_summary = f"Attachments: {', '.join(a['filename'] for a in atts)}"

        return (
            f"DLP ALERT — Internal to External Email\n"
            f"Sender: {name} ({dept}) — Manager: {mgr}\n"
            f"From: {parsed.get('from_address')}\n"
            f"To: {parsed.get('to_address')} ({recipient_type})\n"
            f"Subject: {parsed.get('subject')}\n"
            f"Sent: {timing.get('datetime_str', parsed.get('date', ''))}\n"
            f"{att_summary}\n"
            f"{kw_summary}\n\n"
            f"Email body:\n{parsed.get('body_text', '')[:800]}"
        )

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(address: str) -> str:
        if not address or "@" not in address:
            return address or ""
        return address.split("@")[-1].lower().strip()

    @staticmethod
    def _extract_dlp_score(raw_headers: str) -> Optional[int]:
        match = re.search(r"X-DLP-Score:\s*(\d+)", raw_headers, re.IGNORECASE)
        return int(match.group(1)) if match else None

    @staticmethod
    def _extract_dlp_classification(raw_headers: str) -> Optional[str]:
        match = re.search(r"X-DLP-Classification:\s*(.+)", raw_headers, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _extract_cc(raw_headers: str) -> list[str]:
        match = re.search(r"^CC:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE)
        if not match:
            return []
        return [a.strip() for a in match.group(1).split(",") if a.strip()]

    @staticmethod
    def _extract_bcc(raw_headers: str) -> list[str]:
        match = re.search(r"^BCC:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE)
        if not match:
            return []
        return [a.strip() for a in match.group(1).split(",") if a.strip()]

    @staticmethod
    def _header_value(raw_headers: str, header_name: str) -> Optional[str]:
        match = re.search(
            rf"^{re.escape(header_name)}:\s*(.+)$",
            raw_headers, re.IGNORECASE | re.MULTILINE
        )
        return match.group(1).strip() if match else None


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from enrichment.identity_lookup import IdentityLookup
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.llm_analyzer import LLMAnalyzer
    from database.db_manager import DBManager

    db  = DBManager()
    dlp = DLPEnrichment(
        ad_lookup  = IdentityLookup(mock_mode=True),
        ioc_lookup = IOCLookup(db),
        llm        = LLMAnalyzer(),
    )

    test_files = [
        ("tests/sample_emails/dlp_internal_to_gmail.eml",    "Self-send to Gmail"),
        ("tests/sample_emails/dlp_confidential_external.eml","Client data external"),
        ("tests/sample_emails/dlp_legitimate_vendor.eml",    "Legitimate vendor (FP)"),
    ]

    for path, label in test_files:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
        try:
            result = dlp.enrich_file(path)
        except FileNotFoundError:
            print(f"  ⚠ File not found: {path}")
            continue

        print(f"  Sender       : {result['sender']}")
        print(f"  Recipient    : {result['to_address']} ({result['recipient_type']})")
        print(f"  Self-send    : exact={result['self_send_exact']} "
              f"fuzzy={result['self_send_fuzzy'].get('is_fuzzy_match')}")
        print(f"  DLP Score    : {result['dlp_score']} | Class: {result['dlp_class']}")
        print(f"  Keywords     : {result['keyword_results']['summary']}")
        print(f"  Files        : {result['file_analysis']['count']} "
              f"(highest risk: {result['file_analysis']['highest_risk']})")
        print(f"  After hours  : {result['timing'].get('is_after_hours')} "
              f"({result['timing'].get('datetime_str', '')})")
        print(f"  Verdict      : {result['verdict_level']}")
        print(f"  Risk signals : {len(result['risk_signals'])}")
        for sig in result["risk_signals"]:
            emoji = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🟢"}.get(sig["level"], "⚪")
            print(f"    {emoji} [{sig['level'].upper()}] {sig['message']}")

        if result.get("narrative"):
            print(f"\n  🤖 AI Narrative:")
            print(f"  {result['narrative'][:300]}...")