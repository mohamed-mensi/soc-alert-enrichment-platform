"""
phishing/email_parser.py
=========================
Parses .eml files and extracts structured data for enrichment.

Used by both the phishing flow and the DLP flow.

What it extracts:
  - Headers: From, To, Subject, Date, Message-ID, Reply-To
  - Authentication: SPF, DKIM, DMARC results from headers
  - Routing: all IPs found in Received headers
  - Body: plain text content, HTML content
  - URLs: all links found in body and HTML
  - Attachments: filename, content-type, SHA256 hash
  - Derived signals: urgency score, spoofing indicators

Usage:
    from phishing.email_parser import EmailParser

    parser = EmailParser()
    result = parser.parse_file("tests/sample_emails/obvious_phishing.eml")
    # or from raw bytes:
    result = parser.parse_bytes(eml_bytes)

    result = {
        "from_address":   "security-alert@microsoft-account-verify.com",
        "from_domain":    "microsoft-account-verify.com",
        "to_address":     "adele.vance@example-corp.com",
        "subject":        "[URGENT] Your Microsoft Account Will Be Suspended",
        "date":           "2026-07-07T02:14:33+00:00",
        "message_id":     "<1234567890.abc@microsoft-account-verify.com>",
        "reply_to":       None,
        "spf":            "fail",
        "dkim":           "none",
        "dmarc":          "fail",
        "auth_summary":   "SPF:fail DKIM:none DMARC:fail",
        "received_ips":   ["185.220.101.45"],
        "body_text":      "Dear Microsoft Account User...",
        "body_html":      "<html>...",
        "urls":           ["http://microsoft-account-verify.com/verify?token=abc123"],
        "url_domains":    ["microsoft-account-verify.com"],
        "attachments":    [],
        "urgency_score":  3,
        "urgency_words":  ["URGENT", "SUSPENDED", "immediately"],
        "is_self_send":   False,
        "spoofs_domain":  None,
        "reply_to_mismatch": False,
        "raw_headers":    "...",
    }
"""

import email
import email.policy
import hashlib
import logging
import re
from email import message_from_bytes, message_from_string
from email.utils import parseaddr, getaddresses
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Urgency keywords ──────────────────────────────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "verify", "expire",
    "action required", "confirm now", "click here", "limited time",
    "account locked", "unusual activity", "security alert",
    "final notice", "last warning", "unauthorized access",
    "validate", "24 hours", "48 hours", "will be closed",
]

# ── Known webmail domains (for DLP self-send detection) ──────────────────────
WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
    "outlook.com", "live.com", "icloud.com", "protonmail.com",
    "yandex.com", "mail.com", "aol.com", "gmx.com", "tutanota.com",
}

# ── Org domain (for spoofing detection) ──────────────────────────────────────
ORG_DOMAIN = "example-corp.com"
ORG_DOMAIN_VARIANTS = [
    "example-corp-group.com", "exаmple-corp.com", "0xample-corp.com",
    "examplecorp.com", "example.corp.com",
]


class EmailParser:
    """
    Parses .eml files into structured enrichment data.

    Parameters
    ----------
    org_domain : str
        The organization's email domain — used for spoofing detection.
    """

    def __init__(self, org_domain: str = ORG_DOMAIN):
        self.org_domain = org_domain.lower()

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_file(self, path: str) -> dict:
        """
        Parse an .eml file from disk.

        Parameters
        ----------
        path : str — path to the .eml file

        Returns
        -------
        dict — structured email data
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Email file not found: {path}")

        raw = file_path.read_bytes()
        logger.debug(f"Parsing email file: {path} ({len(raw)} bytes)")
        return self.parse_bytes(raw)

    def parse_bytes(self, raw: bytes) -> dict:
        """
        Parse raw .eml bytes.

        Parameters
        ----------
        raw : bytes — raw email content

        Returns
        -------
        dict — structured email data
        """
        try:
            msg = message_from_bytes(raw, policy=email.policy.default)
        except Exception:
            # Fallback for malformed emails
            msg = message_from_string(raw.decode("utf-8", errors="replace"))

        return self._extract(msg, raw)

    # ── Core extraction ───────────────────────────────────────────────────────

    def _extract(self, msg, raw: bytes) -> dict:
        """Extract all useful fields from a parsed email message."""

        # ── Basic headers ─────────────────────────────────────────────────────
        from_raw     = msg.get("From", "")
        to_raw       = msg.get("To", "")
        reply_to_raw = msg.get("Reply-To", "")

        from_name, from_address = parseaddr(from_raw)
        from_address = from_address.lower().strip()
        from_domain  = self._extract_domain(from_address)

        to_address = parseaddr(to_raw)[1].lower().strip()
        reply_to   = parseaddr(reply_to_raw)[1].lower().strip() or None

        subject    = str(msg.get("Subject", ""))
        date       = str(msg.get("Date", ""))
        message_id = str(msg.get("Message-ID", ""))

        # ── Authentication ────────────────────────────────────────────────────
        auth_results = msg.get("Authentication-Results", "")
        spf, dkim, dmarc = self._parse_auth_results(auth_results)

        # ── Received IPs ──────────────────────────────────────────────────────
        received_headers = msg.get_all("Received") or []
        received_ips     = self._extract_received_ips(received_headers)

        # ── Body ──────────────────────────────────────────────────────────────
        body_text, body_html = self._extract_body(msg)

        # ── URLs ──────────────────────────────────────────────────────────────
        urls        = self._extract_urls(body_text, body_html)
        url_domains = list({self._extract_domain(u) for u in urls if u})

        # ── Attachments ───────────────────────────────────────────────────────
        attachments = self._extract_attachments(msg)

        # ── Derived signals ───────────────────────────────────────────────────
        full_text      = f"{subject} {body_text}".lower()
        urgency_words  = [w for w in URGENCY_KEYWORDS if w in full_text]
        urgency_score  = len(urgency_words)

        is_self_send        = self._detect_self_send(from_address, to_address)
        spoofs_domain       = self._detect_spoofing(from_address, from_domain)
        reply_to_mismatch   = self._detect_reply_to_mismatch(
            from_domain, reply_to
        )
        is_webmail_recipient = self._extract_domain(to_address) in WEBMAIL_DOMAINS

        # ── Auth summary ──────────────────────────────────────────────────────
        auth_summary = f"SPF:{spf} DKIM:{dkim} DMARC:{dmarc}"

        result = {
            # Identity
            "from_name":     from_name,
            "from_address":  from_address,
            "from_domain":   from_domain,
            "to_address":    to_address,
            "reply_to":      reply_to,
            "subject":       subject,
            "date":          date,
            "message_id":    message_id,

            # Authentication
            "spf":           spf,
            "dkim":          dkim,
            "dmarc":         dmarc,
            "auth_summary":  auth_summary,
            "auth_pass":     all(r == "pass" for r in [spf, dkim, dmarc]),

            # Routing
            "received_ips":  received_ips,

            # Content
            "body_text":     body_text[:3000] if body_text else "",
            "body_html":     body_html[:3000] if body_html else "",
            "urls":          urls,
            "url_domains":   url_domains,
            "attachments":   attachments,

            # Derived signals
            "urgency_score":         urgency_score,
            "urgency_words":         urgency_words,
            "is_self_send":          is_self_send,
            "spoofs_domain":         spoofs_domain,
            "reply_to_mismatch":     reply_to_mismatch,
            "is_webmail_recipient":  is_webmail_recipient,

            # Raw
            "raw_headers":   self._extract_raw_headers(msg),
            "size_bytes":    len(raw),
        }

        logger.info(
            f"Parsed email: from={from_address} "
            f"spf={spf} dkim={dkim} dmarc={dmarc} "
            f"urls={len(urls)} attachments={len(attachments)} "
            f"urgency={urgency_score}"
        )

        return result

    # ── Authentication parsing ────────────────────────────────────────────────

    def _parse_auth_results(self, header: str) -> tuple[str, str, str]:
        """
        Parse Authentication-Results header into SPF, DKIM, DMARC results.
        Returns (spf, dkim, dmarc) as lowercase strings.
        """
        header = header.lower()

        def extract(protocol: str) -> str:
            pattern = rf"{protocol}=(\w+)"
            match   = re.search(pattern, header)
            return match.group(1) if match else "none"

        spf   = extract("spf")
        dkim  = extract("dkim")
        dmarc = extract("dmarc")

        return spf, dkim, dmarc

    # ── IP extraction ─────────────────────────────────────────────────────────

    def _extract_received_ips(self, received_headers: list) -> list[str]:
        """
        Extract all IPs from Received headers.
        Filters out private/loopback addresses.
        """
        ip_pattern = re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        )
        private_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0."
        )

        ips = []
        for header in received_headers:
            for ip in ip_pattern.findall(str(header)):
                if not any(ip.startswith(p) for p in private_prefixes):
                    if ip not in ips:
                        ips.append(ip)
        return ips

    # ── Body extraction ───────────────────────────────────────────────────────

    def _extract_body(self, msg) -> tuple[str, str]:
        """Extract plain text and HTML body from a message."""
        text_parts = []
        html_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get("Content-Disposition", ""))
                if "attachment" in cd:
                    continue
                if ct == "text/plain":
                    text_parts.append(
                        part.get_content() if hasattr(part, "get_content")
                        else part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace"
                        )
                    )
                elif ct == "text/html":
                    html_parts.append(
                        part.get_content() if hasattr(part, "get_content")
                        else part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace"
                        )
                    )
        else:
            ct = msg.get_content_type()
            payload = (
                msg.get_content() if hasattr(msg, "get_content")
                else msg.get_payload(decode=True)
            )
            if isinstance(payload, bytes):
                payload = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
            if ct == "text/plain":
                text_parts.append(payload or "")
            elif ct == "text/html":
                html_parts.append(payload or "")

        return "\n".join(text_parts), "\n".join(html_parts)

    # ── URL extraction ────────────────────────────────────────────────────────

    def _extract_urls(self, text: str, html: str) -> list[str]:
        """Extract all URLs from plain text and HTML body."""
        url_pattern = re.compile(
            r"https?://[^\s<>\"')\]]+",
            re.IGNORECASE
        )
        href_pattern = re.compile(
            r'href=["\']?(https?://[^"\'>\s]+)',
            re.IGNORECASE
        )

        urls = []
        for url in url_pattern.findall(text or ""):
            url = url.rstrip(".,;)")
            if url not in urls:
                urls.append(url)

        for url in href_pattern.findall(html or ""):
            url = url.rstrip(".,;)")
            if url not in urls:
                urls.append(url)

        return urls

    # ── Attachment extraction ─────────────────────────────────────────────────

    def _extract_attachments(self, msg) -> list[dict]:
        """
        Extract attachment metadata including SHA256 hash.
        Does not decode or execute attachment content.
        """
        attachments = []

        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" not in cd:
                continue

            filename = part.get_filename() or "unknown"
            ct       = part.get_content_type()

            try:
                payload = part.get_payload(decode=True)
                size    = len(payload) if payload else 0
                sha256  = (
                    hashlib.sha256(payload).hexdigest()
                    if payload else None
                )
            except Exception:
                size   = 0
                sha256 = None

            attachments.append({
                "filename":     filename,
                "content_type": ct,
                "size_bytes":   size,
                "sha256":       sha256,
            })

        return attachments

    # ── Derived signal helpers ────────────────────────────────────────────────

    def _detect_self_send(self, from_address: str, to_address: str) -> bool:
        """Return True if sender and recipient are the same address."""
        return bool(from_address and from_address == to_address)

    def _detect_spoofing(
        self, from_address: str, from_domain: str
    ) -> Optional[str]:
        """
        Return the spoofed domain name if the sender domain appears to
        impersonate the organization, otherwise None.

        Checks:
        - Known lookalike variants of the org domain
        - Unicode/homoglyph substitutions
        - Subdomain abuse (e.g. example-corp.com.malicious.com)
        """
        if not from_domain:
            return None

        fd = from_domain.lower()
        od = self.org_domain.lower()

        # Direct variants
        for variant in ORG_DOMAIN_VARIANTS:
            if fd == variant.lower():
                return od

        # Subdomain abuse: malicious.com contains our domain as subdomain
        if od in fd and fd != od:
            return od

        # Unicode normalization check — catch Cyrillic lookalikes
        try:
            normalized = from_domain.encode("ascii", errors="ignore").decode()
            if normalized.lower() != from_domain.lower():
                # Contains non-ASCII — possible homoglyph attack
                return f"possible homoglyph of {od}"
        except Exception:
            pass

        return None

    def _detect_reply_to_mismatch(
        self, from_domain: str, reply_to: Optional[str]
    ) -> bool:
        """
        Return True if Reply-To domain differs from From domain.
        Common in phishing — sender spoofs a legitimate address but
        wants replies to go to their controlled mailbox.
        """
        if not reply_to or not from_domain:
            return False
        reply_domain = self._extract_domain(reply_to)
        return reply_domain != from_domain.lower()

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(address: str) -> str:
        """Extract the domain part from an email address or URL."""
        if not address:
            return ""
        if "@" in address:
            return address.split("@")[-1].lower().strip()
        try:
            parsed = urlparse(address)
            return parsed.hostname.lower() if parsed.hostname else ""
        except Exception:
            return ""

    @staticmethod
    def _extract_raw_headers(msg) -> str:
        """Return the raw headers as a string for display in case management platform."""
        headers = []
        for key, val in msg.items():
            headers.append(f"{key}: {val}")
        return "\n".join(headers)


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = EmailParser()

    test_files = [
        ("tests/sample_emails/obvious_phishing.eml",  "Obvious Phishing"),
        ("tests/sample_emails/lookalike_domain.eml",  "Lookalike Domain BEC"),
        ("tests/sample_emails/legitimate_fp.eml",     "Legitimate Invoice (FP)"),
    ]

    for path, label in test_files:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")

        try:
            result = parser.parse_file(path)
        except FileNotFoundError:
            print(f"  ⚠ File not found: {path}")
            continue

        print(f"  From        : {result['from_address']}")
        print(f"  From domain : {result['from_domain']}")
        print(f"  Subject     : {result['subject'][:60]}")
        print(f"  Auth        : {result['auth_summary']}")
        print(f"  Received IPs: {result['received_ips']}")
        print(f"  URLs found  : {len(result['urls'])}")
        for url in result['urls'][:3]:
            print(f"    → {url[:70]}")
        print(f"  Attachments : {len(result['attachments'])}")
        for att in result['attachments']:
            print(f"    → {att['filename']} ({att['content_type']}) "
                  f"sha256={att['sha256'][:16] if att['sha256'] else 'N/A'}...")
        print(f"  Urgency     : {result['urgency_score']} "
              f"({result['urgency_words'][:3]})")
        print(f"  Self-send   : {result['is_self_send']}")
        print(f"  Spoofing    : {result['spoofs_domain']}")
        print(f"  Reply-To mismatch: {result['reply_to_mismatch']}")