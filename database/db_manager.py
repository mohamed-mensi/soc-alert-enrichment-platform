"""
database/db_manager.py
======================
Central database access layer for the SOC Enrichment Platform.

Responsibilities:
- Initialize and migrate the SQLite schema
- Provide typed methods for IOC insert / upsert / query
- Manage enrichment cache (read, write, expiry)
- Record feed run history
- Store and query case history for recurrence detection and FP metrics

All public methods are safe to call from multiple threads —
SQLite WAL mode handles concurrent reads; writes are serialized
via a threading.Lock.

Usage:
    from database.db_manager import DBManager

    db = DBManager()                        # uses default path from config
    db = DBManager("data/ioc_database.db") # explicit path

    db.upsert_ioc({...})
    results = db.lookup_ioc("ip", "185.220.101.45")
    db.set_cache("ip", "1.2.3.4", payload)
    cached = db.get_cache("ip", "1.2.3.4")
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default paths
_ROOT        = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "database" / "schema.sql"
_DEFAULT_DB  = _ROOT / "data" / "ioc_database.db"

# How long enrichment cache entries are valid
CACHE_TTL_HOURS = 4


class DBManager:
    """
    Thread-safe SQLite wrapper for the SOC Enrichment Platform.

    Parameters
    ----------
    db_path : str or Path, optional
        Path to the SQLite database file.
        Defaults to data/ioc_database.db relative to project root.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._local = threading.local()  # per-thread connections

        self._init_schema()
        logger.info(f"DBManager initialized — {self.db_path}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a per-thread connection, creating it if needed."""
        if not getattr(self._local, "conn", None):
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row        # dict-like rows
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    @property
    def _conn(self) -> sqlite3.Connection:
        return self._connect()

    def _init_schema(self):
        """Create tables from schema.sql if they don't exist."""
        if not _SCHEMA_PATH.exists():
            raise FileNotFoundError(f"Schema file not found: {_SCHEMA_PATH}")
        schema = _SCHEMA_PATH.read_text()
        with self._lock:
            self._conn.executescript(schema)
            self._conn.commit()
        logger.debug("Schema initialized")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _expires(hours: int = CACHE_TTL_HOURS) -> str:
        dt = datetime.now(timezone.utc) + timedelta(hours=hours)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------
    # IOC methods
    # ------------------------------------------------------------------

    def upsert_ioc(self, ioc: dict) -> bool:
    
        required = {"type", "value", "source"}
        missing = required - ioc.keys()
        if missing:
            raise ValueError(f"IOC missing required fields: {missing}")
    
        tags = json.dumps(ioc.get("tags", []))
        raw  = json.dumps(ioc.get("raw", {}))
        now  = self._now()
        clean_value = ioc["value"].strip().lower()
    
        sql_insert = """
            INSERT INTO iocs (
                type, value, source, source_id,
                malware_family, threat_actor, campaign,
                tags, confidence, severity,
                first_seen, last_seen, expires_at,
                raw, created_at, updated_at
            ) VALUES (
                :type, :value, :source, :source_id,
                :malware_family, :threat_actor, :campaign,
                :tags, :confidence, :severity,
                :first_seen, :last_seen, :expires_at,
                :raw, :now, :now
            )
            ON CONFLICT(type, value, source) DO UPDATE SET
                last_seen       = excluded.last_seen,
                malware_family  = excluded.malware_family,
                threat_actor    = excluded.threat_actor,
                tags            = excluded.tags,
                confidence      = excluded.confidence,
                severity        = excluded.severity,
                raw             = excluded.raw,
                updated_at      = :now
        """
        params = {
            "type":           ioc["type"],
            "value":          clean_value,
            "source":         ioc["source"],
            "source_id":      ioc.get("source_id"),
            "malware_family": ioc.get("malware_family"),
            "threat_actor":   ioc.get("threat_actor"),
            "campaign":       ioc.get("campaign"),
            "tags":           tags,
            "confidence":     ioc.get("confidence", "medium"),
            "severity":       ioc.get("severity", "high"),
            "first_seen":     ioc.get("first_seen"),
            "last_seen":      ioc.get("last_seen", now),
            "expires_at":     ioc.get("expires_at"),
            "raw":            raw,
            "now":            now,
        }
    
        with self._lock:
            # Explicit existence check BEFORE the upsert — this is the
            # actual fix. lastrowid after an ON CONFLICT DO UPDATE is not
            # a trustworthy signal of which branch fired.
            existing = self._conn.execute(
                "SELECT 1 FROM iocs WHERE type = ? AND value = ? AND source = ?",
                (ioc["type"], clean_value, ioc["source"])
            ).fetchone()
            was_new = existing is None
    
            self._conn.execute(sql_insert, params)
            self._conn.commit()
            return was_new

    def lookup_ioc(self, ioc_type: str, value: str) -> list[dict]:
        """
        Check whether a value exists in the IOC database.

        Parameters
        ----------
        ioc_type : str   — "ip", "url", "hash", "domain", "email"
        value    : str   — the observable value to look up

        Returns
        -------
        list[dict] : matching rows (empty list = not found = clean)
        """
        sql = """
            SELECT id, type, value, source, malware_family, threat_actor,
                   tags, confidence, severity, first_seen, last_seen
            FROM iocs
            WHERE type = ? AND value = ?
            ORDER BY severity DESC, last_seen DESC
        """
        cursor = self._conn.execute(sql, (ioc_type, value.strip().lower()))
        rows = [dict(r) for r in cursor.fetchall()]

        # Deserialize JSON fields
        for row in rows:
            if row.get("tags"):
                try:
                    row["tags"] = json.loads(row["tags"])
                except (json.JSONDecodeError, TypeError):
                    row["tags"] = []
        return rows

    def is_malicious(self, ioc_type: str, value: str) -> bool:
        """Quick boolean check — True if the value exists in the IOC DB."""
        return len(self.lookup_ioc(ioc_type, value)) > 0

    def get_ioc_count(self, source: Optional[str] = None) -> int:
        """Return total IOC count, optionally filtered by source."""
        if source:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE source = ?", (source,)
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM iocs")
        return cursor.fetchone()[0]

    def get_recent_iocs(self, hours: int = 24, limit: int = 100) -> list[dict]:
        """Return IOCs added or updated in the last N hours."""
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).strftime("%Y-%m-%d %H:%M:%S")
        sql = """
            SELECT type, value, source, malware_family, severity, last_seen
            FROM iocs
            WHERE updated_at >= ?
            ORDER BY updated_at DESC
            LIMIT ?
        """
        cursor = self._conn.execute(sql, (since, limit))
        return [dict(r) for r in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Feed run tracking
    # ------------------------------------------------------------------

    def record_feed_run(
        self,
        source: str,
        status: str,
        iocs_fetched: int = 0,
        iocs_new: int = 0,
        iocs_updated: int = 0,
        error_message: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        started_at: Optional[str] = None,
    ) -> int:
        """
        Record a completed feed collection run.

        Returns the inserted row id.
        """
        sql = """
            INSERT INTO feed_runs (
                source, status, iocs_fetched, iocs_new, iocs_updated,
                error_message, duration_seconds, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        now = self._now()
        with self._lock:
            cursor = self._conn.execute(sql, (
                source, status, iocs_fetched, iocs_new, iocs_updated,
                error_message, duration_seconds,
                started_at or now, now
            ))
            self._conn.commit()
        return cursor.lastrowid

    def get_feed_health(self) -> list[dict]:
        """
        Return the latest run status for each feed source.
        Used by the dashboard feed health panel.
        """
        sql = """
            SELECT source, status, iocs_fetched, iocs_new,
                   duration_seconds, completed_at, error_message
            FROM feed_runs
            WHERE id IN (
                SELECT MAX(id) FROM feed_runs GROUP BY source
            )
            ORDER BY source
        """
        cursor = self._conn.execute(sql)
        return [dict(r) for r in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Enrichment cache
    # ------------------------------------------------------------------

    def get_cache(self, observable_type: str, observable_value: str) -> Optional[dict]:
        """
        Return cached enrichment for an observable, or None if
        the cache is empty or expired.
        """
        sql = """
            SELECT *
            FROM enrichment_cache
            WHERE observable_type = ?
              AND observable_value = ?
              AND expires_at > ?
        """
        cursor = self._conn.execute(
            sql, (observable_type, observable_value.lower(), self._now())
        )
        row = cursor.fetchone()
        if not row:
            return None

        result = dict(row)
        # Deserialize JSON fields
        for field in ("ad_groups", "matched_sources", "malware_families",
                      "threat_actors", "full_payload"):
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return result

    def set_cache(
        self,
        observable_type: str,
        observable_value: str,
        payload: dict,
        ttl_hours: int = CACHE_TTL_HOURS,
    ):
        """
        Store enrichment results in the cache.

        Parameters
        ----------
        observable_type  : "ip" | "url" | "hash" | "domain"
        observable_value : the actual observable (e.g. "185.220.101.45")
        payload          : enrichment result dict from enrichment_engine
        ttl_hours        : how long to keep this cache entry valid
        """
        def _json(val):
            return json.dumps(val) if isinstance(val, (list, dict)) else val

        sql = """
            INSERT INTO enrichment_cache (
                observable_type, observable_value,
                ad_display_name, ad_department, ad_job_title, ad_manager,
                ad_employee_type, ad_account_enabled, ad_mfa_enabled,
                ad_groups, ad_risk_level, ad_criticality,
                is_malicious, reputation_score,
                matched_sources, malware_families, threat_actors,
                geo_country, geo_city, is_tor_exit, is_vpn,
                full_payload, created_at, expires_at
            ) VALUES (
                :obs_type, :obs_value,
                :ad_display_name, :ad_department, :ad_job_title, :ad_manager,
                :ad_employee_type, :ad_account_enabled, :ad_mfa_enabled,
                :ad_groups, :ad_risk_level, :ad_criticality,
                :is_malicious, :reputation_score,
                :matched_sources, :malware_families, :threat_actors,
                :geo_country, :geo_city, :is_tor_exit, :is_vpn,
                :full_payload, :now, :expires_at
            )
            ON CONFLICT(observable_type, observable_value) DO UPDATE SET
                ad_display_name    = excluded.ad_display_name,
                ad_department      = excluded.ad_department,
                ad_job_title       = excluded.ad_job_title,
                ad_manager         = excluded.ad_manager,
                ad_employee_type   = excluded.ad_employee_type,
                ad_account_enabled = excluded.ad_account_enabled,
                ad_mfa_enabled     = excluded.ad_mfa_enabled,
                ad_groups          = excluded.ad_groups,
                ad_risk_level      = excluded.ad_risk_level,
                ad_criticality     = excluded.ad_criticality,
                is_malicious       = excluded.is_malicious,
                reputation_score   = excluded.reputation_score,
                matched_sources    = excluded.matched_sources,
                malware_families   = excluded.malware_families,
                threat_actors      = excluded.threat_actors,
                geo_country        = excluded.geo_country,
                geo_city           = excluded.geo_city,
                is_tor_exit        = excluded.is_tor_exit,
                is_vpn             = excluded.is_vpn,
                full_payload       = excluded.full_payload,
                expires_at         = excluded.expires_at
        """
        with self._lock:
            self._conn.execute(sql, {
                "obs_type":          observable_type,
                "obs_value":         observable_value.lower(),
                "ad_display_name":   payload.get("ad_display_name"),
                "ad_department":     payload.get("ad_department"),
                "ad_job_title":      payload.get("ad_job_title"),
                "ad_manager":        payload.get("ad_manager"),
                "ad_employee_type":  payload.get("ad_employee_type"),
                "ad_account_enabled":int(payload.get("ad_account_enabled", 1)),
                "ad_mfa_enabled":    int(payload.get("ad_mfa_enabled", 0)),
                "ad_groups":         _json(payload.get("ad_groups", [])),
                "ad_risk_level":     payload.get("ad_risk_level"),
                "ad_criticality":    payload.get("ad_criticality"),
                "is_malicious":      int(payload.get("is_malicious", 0)),
                "reputation_score":  payload.get("reputation_score", 0),
                "matched_sources":   _json(payload.get("matched_sources", [])),
                "malware_families":  _json(payload.get("malware_families", [])),
                "threat_actors":     _json(payload.get("threat_actors", [])),
                "geo_country":       payload.get("geo_country"),
                "geo_city":          payload.get("geo_city"),
                "is_tor_exit":       int(payload.get("is_tor_exit", 0)),
                "is_vpn":            int(payload.get("is_vpn", 0)),
                "full_payload":      _json(payload),
                "now":               self._now(),
                "expires_at":        self._expires(ttl_hours),
            })
            self._conn.commit()

    def invalidate_cache(self, observable_type: str, observable_value: str):
        """Force-expire a cache entry."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM enrichment_cache WHERE observable_type=? AND observable_value=?",
                (observable_type, observable_value.lower())
            )
            self._conn.commit()

    def purge_expired_cache(self) -> int:
        """Delete all expired cache entries. Returns count deleted."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM enrichment_cache WHERE expires_at <= ?", (self._now(),)
            )
            self._conn.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Case history — recurrence detection + FP metrics
    # ------------------------------------------------------------------

    def record_case(self, case: dict[str, Any]):
        """
        Store or update a case management platform case outcome.

        Parameters
        ----------
        case : dict
            Must contain: platform_case_id
            Key fields:   rule_name, source_ip, destination_ip,
                          user_email, verdict, closed_at,
                          triage_time_mins, resolution_time_mins
        """
        sql = """
            INSERT INTO case_history (
                platform_case_id, platform_alert_id, rule_name, rule_id,
                source_ip, destination_ip, user_email, device_name,
                verdict, closed_by, escalated_to,
                alert_created_at, case_created_at,
                first_action_at, closed_at,
                triage_time_mins, resolution_time_mins,
                mitre_technique, mitre_tactic
            ) VALUES (
                :platform_case_id, :platform_alert_id, :rule_name, :rule_id,
                :source_ip, :destination_ip, :user_email, :device_name,
                :verdict, :closed_by, :escalated_to,
                :alert_created_at, :case_created_at,
                :first_action_at, :closed_at,
                :triage_time_mins, :resolution_time_mins,
                :mitre_technique, :mitre_tactic
            )
            ON CONFLICT(platform_case_id) DO UPDATE SET
                verdict              = excluded.verdict,
                closed_by            = excluded.closed_by,
                escalated_to         = excluded.escalated_to,
                first_action_at      = excluded.first_action_at,
                closed_at            = excluded.closed_at,
                triage_time_mins     = excluded.triage_time_mins,
                resolution_time_mins = excluded.resolution_time_mins
        """
        with self._lock:
            self._conn.execute(sql, {
                "platform_case_id":        case["platform_case_id"],
                "platform_alert_id":       case.get("platform_alert_id"),
                "rule_name":           case.get("rule_name"),
                "rule_id":             case.get("rule_id"),
                "source_ip":           case.get("source_ip"),
                "destination_ip":      case.get("destination_ip"),
                "user_email":          case.get("user_email"),
                "device_name":         case.get("device_name"),
                "verdict":             case.get("verdict"),
                "closed_by":           case.get("closed_by"),
                "escalated_to":        case.get("escalated_to"),
                "alert_created_at":    case.get("alert_created_at"),
                "case_created_at":     case.get("case_created_at"),
                "first_action_at":     case.get("first_action_at"),
                "closed_at":           case.get("closed_at"),
                "triage_time_mins":    case.get("triage_time_mins"),
                "resolution_time_mins":case.get("resolution_time_mins"),
                "mitre_technique":     case.get("mitre_technique"),
                "mitre_tactic":        case.get("mitre_tactic"),
            })
            self._conn.commit()

    def get_recurrence(
        self,
        rule_name: Optional[str] = None,
        user_email: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 10,
    ) -> list[dict]:
        """
        Find past cases matching any of the given identifiers.
        Used by enrichment_engine to detect repeat offenders.

        At least one parameter must be provided.
        """
        if not any([rule_name, user_email, source_ip]):
            raise ValueError("Provide at least one filter parameter")

        conditions, params = [], []
        if rule_name:
            conditions.append("rule_name = ?")
            params.append(rule_name)
        if user_email:
            conditions.append("user_email = ?")
            params.append(user_email.lower())
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)

        where = " OR ".join(conditions)
        sql = f"""
            SELECT platform_case_id, rule_name, source_ip, user_email,
                   verdict, closed_at, triage_time_mins
            FROM case_history
            WHERE {where}
            ORDER BY closed_at DESC
            LIMIT ?
        """
        cursor = self._conn.execute(sql, params + [limit])
        return [dict(r) for r in cursor.fetchall()]

    def get_fp_rate_by_rule(self, days: int = 30) -> list[dict]:
        """
        Calculate FP rate per rule over the last N days.
        Used by the FP dashboard.

        Returns
        -------
        list[dict] with keys:
            rule_name, total_cases, fp_count, tp_count,
            fp_rate_pct, avg_triage_time_mins
        """
        since = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).strftime("%Y-%m-%d %H:%M:%S")

        sql = """
            SELECT
                rule_name,
                COUNT(*)                                            AS total_cases,
                SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END) AS fp_count,
                SUM(CASE WHEN verdict = 'true_positive'  THEN 1 ELSE 0 END) AS tp_count,
                SUM(CASE WHEN verdict = 'escalated'      THEN 1 ELSE 0 END) AS escalated_count,
                ROUND(
                    100.0 * SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END)
                    / COUNT(*), 1
                )                                                   AS fp_rate_pct,
                ROUND(AVG(triage_time_mins), 1)                    AS avg_triage_time_mins
            FROM case_history
            WHERE closed_at >= ?
              AND rule_name IS NOT NULL
              AND verdict IS NOT NULL
            GROUP BY rule_name
            ORDER BY fp_rate_pct DESC
        """
        cursor = self._conn.execute(sql, (since,))
        return [dict(r) for r in cursor.fetchall()]

    def get_noisy_rules(self, fp_threshold_pct: float = 60.0, days: int = 30) -> list[dict]:
        """
        Return rules currently exceeding the FP threshold.
        Used by the dashboard proactive watchlist.
        """
        all_rules = self.get_fp_rate_by_rule(days=days)
        return [r for r in all_rules if (r["fp_rate_pct"] or 0) >= fp_threshold_pct]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def close(self):
        """Close the current thread's connection."""
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None

    def __repr__(self):
        return f"DBManager(db_path={self.db_path})"