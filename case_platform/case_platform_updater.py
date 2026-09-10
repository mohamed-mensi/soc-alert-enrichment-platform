"""
hive/case_platform_updater.py
=====================
Writes enrichment results back onto case management platform alert and case observables.

NEW: Everything goes into the Summary field - no comments.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

DEFAULT_CASE_PLATFORM_URL = "http://localhost:9000"
REQUEST_TIMEOUT = 30

# Verdict → tag mapping
VERDICT_TAGS = {
    "ESCALATE": ["verdict:escalate", "requires-action"],
    "NEEDS_REVIEW": ["verdict:needs-review", "review-required"],
    "LIKELY_FP": ["verdict:likely-fp", "low-priority"],
}

# Severity labels for the report header
SEVERITY_EMOJI = {
    "ESCALATE": "🔴",
    "NEEDS_REVIEW": "🟡",
    "LIKELY_FP": "🟢",
}


class CasePlatformUpdater:
    """
    Writes enrichment results back onto case management platform alerts and cases.
    Everything goes into the Summary field.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.url = (url or os.getenv("CASE_PLATFORM_URL", DEFAULT_CASE_PLATFORM_URL)).rstrip("/")
        self.api_key = api_key or os.getenv("CASE_PLATFORM_API_KEY")

        if not self.api_key:
            raise ValueError("CASE_PLATFORM_API_KEY not set in .env")

        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        logger.info(f"CasePlatformUpdater initialized — {self.url}")

    # ── Public API ────────────────────────────────────────────────────────────

    def update_alert(
        self,
        alert_id: str,
        enrichments: list[dict],
        verdict: str,
        verdict_reasons: list[str],
        narrative: Optional[str] = None,
    ):
        """
        Write enrichment results onto an alert.
        Everything goes into the Summary field - no comments.
        """
        logger.info(f"Updating alert {alert_id} — verdict: {verdict}")

        # Step 1 — Update each observable (tags + ioc flag)
        obs_success = 0
        for enrichment in enrichments:
            obs_id = enrichment.get("observable_id")
            if not obs_id:
                continue
            try:
                self._update_observable(obs_id, enrichment)
                obs_success += 1
            except Exception as exc:
                logger.warning(
                    f"Failed to update observable {obs_id} "
                    f"on alert {alert_id}: {exc}"
                )

        # Step 2 — Build and write COMPLETE report to Summary field
        try:
            summary = self._build_complete_summary(
                enrichments, 
                verdict, 
                verdict_reasons, 
                narrative
            )
            self._patch(f"/api/v1/alert/{alert_id}", {"summary": summary})
        except Exception as exc:
            logger.warning(f"Failed to update summary for alert {alert_id}: {exc}")

        # Step 3 — Tag the alert itself with the verdict
        try:
            verdict_tags = VERDICT_TAGS.get(verdict, []) + ["enriched"]
            self._tag_alert(alert_id, verdict_tags)
        except Exception as exc:
            logger.warning(f"Failed to tag alert {alert_id}: {exc}")

        logger.info(
            f"Alert {alert_id} updated — "
            f"{obs_success}/{len(enrichments)} observables enriched, "
            f"summary updated"
        )

    def update_case(
        self,
        case_id: str,
        enrichments: list[dict],
        verdict: str,
        verdict_reasons: list[str],
        narrative: Optional[str] = None,
    ):
        """
        Write enrichment results onto a case.
        Everything goes into the Summary field - no comments.
        """
        logger.info(f"Updating case {case_id} — verdict: {verdict}")

        # Step 1 — Update each observable
        obs_success = 0
        for enrichment in enrichments:
            obs_id = enrichment.get("observable_id")
            if not obs_id:
                continue
            try:
                self._update_observable(obs_id, enrichment)
                obs_success += 1
            except Exception as exc:
                logger.warning(
                    f"Failed to update observable {obs_id} "
                    f"on case {case_id}: {exc}"
                )

        # Step 2 — Build and write COMPLETE report to Summary field
        try:
            summary = self._build_complete_summary(
                enrichments, 
                verdict, 
                verdict_reasons, 
                narrative
            )
            self._patch(f"/api/v1/case/{case_id}", {"summary": summary})
        except Exception as exc:
            logger.warning(f"Failed to update summary for case {case_id}: {exc}")

        # Step 3 — Tag the case
        try:
            verdict_tags = VERDICT_TAGS.get(verdict, []) + ["enriched"]
            self._tag_case(case_id, verdict_tags)
        except Exception as exc:
            logger.warning(f"Failed to tag case {case_id}: {exc}")

        logger.info(
            f"Case {case_id} updated — "
            f"{obs_success}/{len(enrichments)} observables enriched, "
            f"summary updated"
        )

    # ── Observable update ─────────────────────────────────────────────────────

    def _update_observable(self, obs_id: str, enrichment: dict):
        """Update a single observable with enrichment tags and ioc flag."""
        tags = self._build_observable_tags(enrichment)
        is_malicious = enrichment.get("is_malicious", False)

        body = {
            "tags": tags,
            "ioc": is_malicious,
        }

        if is_malicious:
            body["sighted"] = True

        self._patch(f"/api/v1/observable/{obs_id}", body)
        logger.debug(f"Observable {obs_id} updated — tags: {tags}")

    def _build_observable_tags(self, enrichment: dict) -> list[str]:
        """Build the tag list to attach to an observable."""
        tags = ["enriched"]

        # Reputation
        if enrichment.get("is_malicious"):
            tags.append("malicious")
            for family in (enrichment.get("malware_families") or []):
                tags.append(f"malware:{family.lower()}")
            for source in (enrichment.get("matched_sources") or []):
                tags.append(f"feed:{source}")
        else:
            tags.append("clean")

        # Geo
        country = enrichment.get("geo_country")
        if country:
            tags.append(f"geo:{country.lower().replace(' ', '-')}")
        if enrichment.get("is_tor_exit"):
            tags.append("tor-exit")
        if enrichment.get("is_vpn"):
            tags.append("vpn")

        # Identity
        dept = enrichment.get("ad_department")
        if dept:
            tags.append(f"dept:{dept.lower().replace(' ', '-')}")

        criticality = enrichment.get("ad_criticality")
        if criticality:
            tags.append(f"criticality:{criticality.lower()}")

        if enrichment.get("ad_mfa_enabled") is False:
            tags.append("no-mfa")

        if enrichment.get("ad_risk_level") in ("medium", "high"):
            tags.append(f"ad-risk:{enrichment['ad_risk_level']}")

        # Recurrence
        if (enrichment.get("recurrence_count") or 0) > 0:
            tags.append("recurring")

        return sorted(set(tags))

    # ─── COMPLETE SUMMARY BUILDER ────────────────────────────────────────────

    def _build_complete_summary(
        self,
        enrichments: list[dict],
        verdict: str,
        verdict_reasons: list[str],
        narrative: Optional[str] = None,
    ) -> str:
        """
        Build the COMPLETE enrichment report for the Summary field.
        This replaces ALL comments - everything is here.
        """
        emoji = SEVERITY_EMOJI.get(verdict, "⚪")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        
        lines = []
        
        # ─── HEADER ──────────────────────────────────────────────────────────
        lines.append(f"# {emoji} {verdict.replace('_', ' ')}")
        lines.append("")
        lines.append(f"*Enriched automatically by SOC Enrichment Platform — {now}*")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # ─── AI TRIAGE SUMMARY ──────────────────────────────────────────────
        if narrative:
            lines.append("## 🤖 AI Triage Summary")
            lines.append("*Local LLM (phi3) — for guidance only, final decision by analyst*")
            lines.append("")
            lines.append(narrative)
            lines.append("")
            lines.append("---")
            lines.append("")
        
        # ─── KEY FINDINGS ────────────────────────────────────────────────────
        lines.append("## 🚨 Key Findings")
        lines.append("")
        
        malicious = [e for e in enrichments if e.get("is_malicious")]
        identities = [e for e in enrichments if e.get("ad_display_name")]
        
        if malicious:
            lines.append(f"**{len(malicious)} Malicious Observable(s)**")
            for e in malicious:
                value = e.get("observable_value", "unknown")
                obs_type = e.get("observable_type", "unknown")
                score = e.get("reputation_score", 0)
                sources = ", ".join(e.get("matched_sources", ["Unknown"])[:2])
                families = ", ".join(e.get("malware_families", ["Unknown"])[:2])
                lines.append(f"- 🔴 `{obs_type}` **{value}** — MALICIOUS (score: {score}, {sources})")
                if families:
                    lines.append(f"  - Malware: {families}")
            lines.append("")
        
        if identities:
            lines.append(f"**{len(identities)} Identity Enrichment(s)**")
            for e in identities:
                name = e.get("ad_display_name", "Unknown")
                dept = e.get("ad_department", "Unknown")
                mfa = "✅ Enabled" if e.get("ad_mfa_enabled") else "❌ DISABLED"
                criticality = e.get("ad_criticality", "Unknown")
                lines.append(f"- 👤 **{name}** ({dept})")
                lines.append(f"  - MFA: {mfa}")
                lines.append(f"  - Criticality: {criticality}")
                if e.get("ad_risk_level") in ("high", "medium"):
                    lines.append(f"  - corporate directory Risk: {e.get('ad_risk_level').upper()}")
            lines.append("")
        
        # ─── VERDICT REASONS ────────────────────────────────────────────────
        lines.append("## 📋 Verdict Reasons")
        lines.append("")
        if verdict_reasons:
            for reason in verdict_reasons[:5]:
                lines.append(f"- {reason}")
        else:
            lines.append("- No specific reasons provided")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # ─── DETAILED OBSERVABLE TABLE ──────────────────────────────────────
        lines.append("## 📊 Observable Enrichment Details")
        lines.append("")
        lines.append("| Type | Value | Status | Key Details |")
        lines.append("|------|-------|--------|-------------|")
        
        for e in enrichments:
            obs_type = e.get("observable_type", "unknown")
            obs_value = e.get("observable_value", "unknown")
            
            if e.get("is_malicious"):
                status = "🚨 MALICIOUS"
            elif e.get("ad_display_name"):
                status = "👤 IDENTITY"
            else:
                status = "✅ CLEAN"
            
            details = []
            if e.get("ad_display_name"):
                details.append(f"User: {e.get('ad_display_name')}")
            if e.get("ad_department"):
                details.append(f"Dept: {e.get('ad_department')}")
            if e.get("malware_families"):
                details.append(f"Malware: {', '.join(e.get('malware_families', [])[:2])}")
            if e.get("reputation_score", 0) > 0:
                details.append(f"Score: {e.get('reputation_score')}")
            if e.get("geo_country"):
                details.append(f"Location: {e.get('geo_country')}")
            
            details_str = ", ".join(details[:3])
            if not details_str:
                details_str = "No enrichment"
            
            lines.append(f"| {obs_type} | {obs_value} | {status} | {details_str} |")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # ─── RECOMMENDED ACTIONS ─────────────────────────────────────────────
        lines.append("## 🎯 Recommended Actions")
        lines.append("")
        
        if verdict == "ESCALATE":
            lines.append("1. ⚠️ **Escalate immediately** to Tier 2/3 SOC analyst")
            lines.append("2. 📞 Contact affected user's manager to verify activity")
            lines.append("3. 🔒 Consider account lockout if unauthorized")
            lines.append("4. 📊 Review EDR and network logs for lateral movement")
            lines.append("5. 📝 Document findings in case management platform case notes")
        elif verdict == "NEEDS_REVIEW":
            lines.append("1. 🔍 **Investigate within 1-2 hours**")
            lines.append("2. 📋 Check with user about the activity")
            lines.append("3. 📊 Review endpoint and network logs")
            lines.append("4. 🔄 Check if this matches known false positive pattern")
            lines.append("5. 📝 Document findings and close or escalate")
        else:  # LIKELY_FP
            lines.append("1. ✅ **Review during normal shift**")
            lines.append("2. 📋 Verify if this is expected behavior")
            lines.append("3. 🔄 Update whitelist/exception list if confirmed FP")
            lines.append("4. 📊 Check if this rule needs tuning")
            lines.append("5. 🔒 Close alert with FP reason")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # ─── FOOTER ──────────────────────────────────────────────────────────
        lines.append("*SOC Enrichment Platform — Example Corp Tunis*")
        lines.append(f"*Report generated: {now}*")
        
        return "\n".join(lines)

    # ─── TAG HELPERS ──────────────────────────────────────────────────────────

    def _tag_alert(self, alert_id: str, tags: list[str]):
        """Add tags to an alert (merges with existing tags)."""
        response = self._get(f"/api/v1/alert/{alert_id}")
        existing = response.get("tags", [])
        merged = sorted(set(existing + tags))
        self._patch(f"/api/v1/alert/{alert_id}", {"tags": merged})

    def _tag_case(self, case_id: str, tags: list[str]):
        """Add tags to a case (merges with existing tags)."""
        response = self._get(f"/api/v1/case/{case_id}")
        existing = response.get("tags", [])
        merged = sorted(set(existing + tags))
        self._patch(f"/api/v1/case/{case_id}", {"tags": merged})

    # ─── HTTP HELPERS ─────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        url = f"{self.url}{path}"
        response = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self.url}{path}"
        response = requests.post(
            url, headers=self.headers, json=body, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def _patch(self, path: str, body: dict) -> dict:
        url = f"{self.url}{path}"
        response = requests.patch(
            url, headers=self.headers, json=body, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        if response.content:
            return response.json()
        return {}