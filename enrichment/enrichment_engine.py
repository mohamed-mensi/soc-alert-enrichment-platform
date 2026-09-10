"""
enrichment/enrichment_engine.py
=================================
Orchestrates the full enrichment pipeline:
  1. Polls case management platform for new alerts and cases
  2. Partitions observables by type
  3. Routes each observable to the correct enrichment source
  4. Assembles enrichment payloads
  5. Writes results back to case management platform via case_platform_updater

Design rules:
  - Internal IPs + emails  → corporate directory identity lookup only
  - External IPs, hashes, URLs, domains → IOC reputation only
  - No auto-verdict — analyst decides based on enrichment context
  - Risk signals surfaced explicitly in the report

Usage:
    from enrichment.enrichment_engine import EnrichmentEngine
    from case_platform.case_platform_client import CasePlatformClient
    from case_platform.case_platform_updater import CasePlatformUpdater
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.identity_lookup import IdentityLookup
    from database.db_manager import DBManager

    db     = DBManager()
    engine = EnrichmentEngine(
        case_platform_client = CasePlatformClient(),
        case_platform_updater = CasePlatformUpdater(),
        ioc_lookup  = IOCLookup(db),
        ad_lookup   = IdentityLookup(mock_mode=True),
    )
    engine.run_and_update()
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enrichment import llm_analyzer
from enrichment.ip_utils import extract_ips_from_observables

logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """
    Ties together CasePlatformClient, IOCLookup, IdentityLookup, and CasePlatformUpdater
    into one enrichment pass over new alerts and cases.

    Parameters
    ----------
    case_platform_client  : CasePlatformClient
    case_platform_updater : CasePlatformUpdater  (optional — if None, dry-run mode)
    ioc_lookup   : IOCLookup
    ad_lookup    : IdentityLookup
    """

    def __init__(self, case_platform_client, ioc_lookup, ad_lookup,
             case_platform_updater=None, llm_analyzer=None):
        self.case_platform_client  = case_platform_client
        self.case_platform_updater = case_platform_updater
        self.ioc_lookup   = ioc_lookup
        self.ad_lookup    = ad_lookup
        self.llm_analyzer = llm_analyzer

    # ── Public API ────────────────────────────────────────────────────────────

    def run_once(self) -> list[dict]:
        records = []
        records.extend(self._process_new_alerts())
        records.extend(self._process_new_cases())

        if self.case_platform_updater and records:
            for record in records:
                try:
                    self._write_back(record)  # ← was: self.case_platform_updater.update_alert(record)
                except Exception as exc:
                    logger.error(f"Failed to write enrichment for {record.get('target_id')}: {exc}")

        return records

    def run_and_update(self) -> list[dict]:
        """
        Full pipeline: enrich all new alerts/cases AND write
        results back to case management platform via case_platform_updater.

        Returns the enrichment records for inspection.
        """
        records = self.run_once()

        if not self.case_platform_updater:
            logger.warning("No case_platform_updater configured — skipping write-back")
            return records

        for record in records:
            try:
                self._write_back(record)
            except Exception as exc:
                logger.error(
                    f"Failed to write back enrichment for "
                    f"{record['target_type']} {record['target_id']}: {exc}"
                )

        return records

    # ── Alerts / cases ────────────────────────────────────────────────────────

    def _process_new_alerts(self) -> list[dict]:
        alerts  = self.case_platform_client.get_new_alerts()
        records = []
        for alert in alerts:
            try:
                observables = self.case_platform_client.get_alert_observables(alert["_id"])
                records.append(self._enrich_target("alert", alert, observables))
            except Exception as exc:
                logger.error(f"Failed to enrich alert {alert.get('_id')}: {exc}")
        return records

    def _process_new_cases(self) -> list[dict]:
        cases   = self.case_platform_client.get_new_cases()
        records = []
        for case in cases:
            try:
                observables = self.case_platform_client.get_case_observables(case["_id"])
                records.append(self._enrich_target("case", case, observables))
            except Exception as exc:
                logger.error(f"Failed to enrich case {case.get('_id')}: {exc}")
        return records

    # ── Core enrichment ───────────────────────────────────────────────────────

    def _enrich_target(
        self, target_type: str, target: dict, observables: list[dict]
    ) -> dict:
        """
        Partition one alert/case's observables and enrich each one
        through the correct source, then assemble a single record.
        """
        target_id = target.get("_id")
        title     = target.get("title")

        partitioned = extract_ips_from_observables(observables)

        # Identity enrichment — internal IPs and emails only
        identity_results = []
        for obs in partitioned["internal_ips"]:
            identity_results.append(self._enrich_identity(obs, "ip"))
        for obs in partitioned["emails"]:
            identity_results.append(self._enrich_identity(obs, "mail"))

        # Reputation enrichment — external IPs, hashes, URLs, domains only
        reputation_results = []
        for bucket in ("external_ips", "hashes", "urls", "domains"):
            for obs in partitioned[bucket]:
                reputation_results.append(self._enrich_reputation(obs))

        # Unhandled types
        unhandled = [
            {"dataType": o.get("dataType"), "data": o.get("data")}
            for o in partitioned["other"]
        ]
        if unhandled:
            logger.warning(
                f"{target_type} {target_id}: {len(unhandled)} observable(s) "
                f"with unhandled dataType — {unhandled}"
            )

        summary      = self._build_summary(identity_results, reputation_results)
        risk_signals = self._build_risk_signals(identity_results, reputation_results)

        record = {
            "target_type":          target_type,
            "target_id":            target_id,
            "title":                title,
            "severity_label":       target.get("severityLabel"),
            "created_at":           target.get("_createdAt"),
            "identity":             identity_results,
            "reputation":           reputation_results,
            "unhandled_observables": unhandled,
            "summary":              summary,
            "risk_signals":         risk_signals,
        }

        logger.info(
            f"Enriched {target_type} {target_id} — "
            f"{len(identity_results)} identity, "
            f"{len(reputation_results)} reputation, "
            f"malicious={summary['any_malicious']}, "
            f"signals={len(risk_signals)}"
        )


        
        narrative = None
        if self.llm_analyzer:
            narrative = self.llm_analyzer.generate_narrative({
                **record,
                "description":  target.get("description", ""),
                "verdict_level": self._signals_to_level(risk_signals),
            })
        record["narrative"] = narrative

        return record

    def _enrich_identity(self, obs: dict, obs_type: str) -> dict:
        """Look up an internal IP or email observable via corporate directory."""
        value  = obs.get("data", "")
        result = self.ad_lookup.lookup_observable(obs_type, value)
        return {"observable": obs, "identity": result}

    def _enrich_reputation(self, obs: dict) -> dict:
        """Look up an external IP, hash, URL, or domain via IOC DB."""
        obs_type = obs.get("dataType", "")
        value    = obs.get("data", "")
        result   = self.ioc_lookup.check(obs_type, value)
        return {"observable": obs, "reputation": result}

    # ── Risk signals ──────────────────────────────────────────────────────────

    def _build_risk_signals(
        self,
        identity_results: list[dict],
        reputation_results: list[dict],
    ) -> list[dict]:
        """
        Build a list of explicit risk signals from enrichment results.
        These replace the auto-verdict — analyst sees signals and decides.

        Each signal has:
            level   : "critical" | "high" | "medium" | "low"
            message : human-readable explanation
        """
        signals = []

        # ── Reputation signals ────────────────────────────────────────────────
        for r in reputation_results:
            rep = r["reputation"]
            obs = r["observable"]
            val = obs.get("data", "")

            if not rep["is_malicious"]:
                continue

            families = rep.get("malware_families") or []
            sources  = rep.get("matched_sources")  or []
            score    = rep.get("reputation_score", 0)
            severity = rep.get("severity", "high")

            family_str = f" ({', '.join(families)})" if families else ""
            source_str = ", ".join(sources)

            signals.append({
                "level":   "critical" if severity == "critical" else "high",
                "message": (
                    f"{obs.get('dataType', 'observable').upper()} {val} matched "
                    f"{source_str}{family_str} — score {score}/100"
                )
            })

        # ── Identity signals ──────────────────────────────────────────────────
        for r in identity_results:
            identity = r["identity"]
            obs      = r["observable"]

            if not identity.get("found"):
                continue

            name        = identity.get("display_name", "Unknown")
            dept        = identity.get("department", "")
            criticality = identity.get("criticality", "LOW")
            risk_level  = identity.get("risk_level", "none")

            # High criticality asset
            if criticality in ("CRITICAL", "HIGH"):
                signals.append({
                    "level":   "high" if criticality == "HIGH" else "critical",
                    "message": (
                        f"{name} ({dept}) — "
                        f"{criticality} criticality asset"
                    )
                })

            # No MFA
            if identity.get("mfa_enabled") is False:
                signals.append({
                    "level":   "high",
                    "message": f"{name} has no MFA registered"
                })

            # corporate directory risk level
            if risk_level in ("high", "medium"):
                signals.append({
                    "level":   "high" if risk_level == "high" else "medium",
                    "message": (
                        f"corporate directory Identity Protection risk: "
                        f"{risk_level.upper()} for {name}"
                    )
                })

            # Privileged groups
            groups = identity.get("groups") or []
            priv_groups = [
                g for g in groups
                if any(kw in g.lower() for kw in
                       ("admin", "domain", "controller", "erp", "finance"))
            ]
            if priv_groups:
                signals.append({
                    "level":   "medium",
                    "message": (
                        f"{name} is member of privileged groups: "
                        f"{', '.join(priv_groups)}"
                    )
                })


        # Deduplicate by message
        seen = set()
        unique_signals = []
        for s in signals:
            if s["message"] not in seen:
                seen.add(s["message"])
                unique_signals.append(s)
        signals = unique_signals
        # Sort signals: critical first, then high, medium, low
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        signals.sort(key=lambda s: order.get(s["level"], 99))

        return signals

    @staticmethod
    def _build_summary(
        identity_results: list[dict],
        reputation_results: list[dict],
    ) -> dict:
        """Roll up per-observable results into a quick top-level summary."""
        any_malicious = any(
            r["reputation"]["is_malicious"] for r in reputation_results
        )
        max_reputation_score = max(
            (r["reputation"]["reputation_score"] for r in reputation_results),
            default=0,
        )
        high_risk_identity = any(
            r["identity"]["found"] and (
                r["identity"].get("risk_level") in ("high", "medium")
                or r["identity"].get("criticality") in ("CRITICAL", "HIGH")
            )
            for r in identity_results
        )
        return {
            "any_malicious":        any_malicious,
            "max_reputation_score": max_reputation_score,
            "high_risk_identity":   high_risk_identity,
            "identity_count":       len(identity_results),
            "reputation_count":     len(reputation_results),
        }

    # ── Write-back ────────────────────────────────────────────────────────────

    def _write_back(self, record: dict):
        """
        Convert an enrichment record into case_platform_updater payloads
        and write enrichment back to case management platform.
        """
        target_type = record["target_type"]
        target_id   = record["target_id"]
        risk_signals = record.get("risk_signals", [])

        # Build one payload per observable
        payloads = self._build_updater_payloads(record)

        if not payloads:
            logger.debug(f"No payloads to write for {target_type} {target_id}")
            return

        # Build risk signal summary for the report
        signal_reasons = [s["message"] for s in risk_signals]
        if not signal_reasons:
            signal_reasons = ["No significant risk signals detected"]

        narrative    = record.get("narrative")
        signal_reasons = [s["message"] for s in risk_signals]
        if not signal_reasons:
            signal_reasons = ["No significant risk signals detected"]

        if target_type == "alert":
            self.case_platform_updater.update_alert(
                alert_id        = target_id,
                enrichments     = payloads,
                verdict         = self._signals_to_level(risk_signals),
                verdict_reasons = signal_reasons,
                narrative       = narrative,
            )
        else:
            self.case_platform_updater.update_case(
                case_id         = target_id,
                enrichments     = payloads,
                verdict         = self._signals_to_level(risk_signals),
                verdict_reasons = signal_reasons,
                narrative       = narrative,
            )

        logger.info(
            f"Written enrichment to {target_type} {target_id} — "
            f"{len(payloads)} observable(s), {len(risk_signals)} signal(s)"
        )

    def _build_updater_payloads(self, record: dict) -> list[dict]:
        """
        Translate enrichment engine output format into the flat payload
        dicts that case_platform_updater.update_alert() / update_case() expect.
        """
        payloads = []

        # Identity results
        for r in record["identity"]:
            obs      = r["observable"]
            identity = r["identity"]

            payload = {
                "observable_id":    obs.get("_id"),
                "observable_type":  obs.get("dataType"),
                "observable_value": obs.get("data"),
                # Identity fields
                "ad_display_name":   identity.get("display_name"),
                "ad_department":     identity.get("department"),
                "ad_job_title":      identity.get("job_title"),
                "ad_manager":        identity.get("manager"),
                "ad_employee_type":  identity.get("employee_type"),
                "ad_account_enabled": identity.get("account_enabled"),
                "ad_mfa_enabled":    identity.get("mfa_enabled"),
                "ad_risk_level":     identity.get("risk_level"),
                "ad_groups":         identity.get("groups", []),
                "ad_criticality":    identity.get("criticality"),
                # No reputation for internal/identity observables
                "is_malicious":      False,
                "reputation_score":  0,
                "matched_sources":   [],
                "malware_families":  [],
                "threat_actors":     [],
                "recurrence_count":  0,
            }
            payloads.append(payload)

        # Reputation results
        for r in record["reputation"]:
            obs = r["observable"]
            rep = r["reputation"]

            payload = {
                "observable_id":    obs.get("_id"),
                "observable_type":  obs.get("dataType"),
                "observable_value": obs.get("data"),
                # No identity for external/reputation observables
                "ad_display_name":  None,
                "ad_department":    None,
                "ad_job_title":     None,
                "ad_manager":       None,
                "ad_criticality":   None,
                "ad_mfa_enabled":   None,
                "ad_risk_level":    "none",
                "ad_groups":        [],
                # Reputation fields
                "is_malicious":     rep.get("is_malicious", False),
                "reputation_score": rep.get("reputation_score", 0),
                "matched_sources":  rep.get("matched_sources", []),
                "malware_families": rep.get("malware_families", []),
                "threat_actors":    rep.get("threat_actors", []),
                "recurrence_count": 0,
            }
            payloads.append(payload)

        return payloads

    @staticmethod
    def _signals_to_level(signals: list[dict]) -> str:
        """
        Convert risk signals into a display level for the report header.
        This is NOT an auto-verdict — it's just a visual indicator
        to help the analyst prioritize. Final decision is theirs.
        """
        if not signals:
            return "LIKELY_FP"
        levels = {s["level"] for s in signals}
        if "critical" in levels:
            return "ESCALATE"
        if "high" in levels:
            return "NEEDS_REVIEW"
        return "LIKELY_FP"


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from case_platform.case_platform_client import CasePlatformClient
    from case_platform.case_platform_updater import CasePlatformUpdater
    from enrichment.ioc_lookup import IOCLookup
    from enrichment.identity_lookup import IdentityLookup
    from database.db_manager import DBManager

    db     = DBManager()
    engine = EnrichmentEngine(
        case_platform_client  = CasePlatformClient(),
        case_platform_updater = CasePlatformUpdater(),
        ioc_lookup   = IOCLookup(db),
        ad_lookup    = IdentityLookup(mock_mode=True),
    )

    engine.case_platform_client.reset_alert_timestamp(0)
    engine.case_platform_client.reset_case_timestamp(0)

    print("\nRunning full pipeline (enrich + write back to case management platform)...\n")
    records = engine.run_and_update()

    print(f"\n{len(records)} record(s) enriched and written to case management platform")
    print("=" * 60)

    for rec in records:
        print(f"\n[{rec['target_type']}] {rec['target_id']} — {rec['title']}")
        print(f"  Any malicious    : {rec['summary']['any_malicious']}")
        print(f"  High risk identity: {rec['summary']['high_risk_identity']}")
        print(f"  Risk signals     : {len(rec['risk_signals'])}")
        for sig in rec["risk_signals"]:
            emoji = "🔴" if sig["level"] == "critical" else "🟡" if sig["level"] == "high" else "🟠"
            print(f"    {emoji} [{sig['level'].upper()}] {sig['message']}")

    print(f"\n✅ Done — check alerts in case management platform UI")
    print(f"   → http://localhost:9000 (login as analyst@example.local)")