-- =============================================================
-- SOC Enrichment Platform — IOC Database Schema
-- Example Corp Tunis — Mohamed Mensi — June 2026
-- =============================================================
-- Tables:
--   iocs              → normalized IOC records from all feeds
--   feed_runs         → feed collection history and health
--   enrichment_cache  → cached enrichment results per observable
--   case_history      → historical case outcomes per rule/user/asset
-- =============================================================



-- -------------------------------------------------------------
-- 1. IOCs
-- Stores all indicators of compromise from all feed sources.
-- UNIQUE on (type, value, source) — same IOC from same source
-- is updated in place rather than duplicated.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,

    -- What the IOC is
    type             TEXT NOT NULL CHECK(type IN ('ip', 'url', 'hash', 'domain', 'email')),
    value            TEXT NOT NULL,

    -- Where it came from
    source           TEXT NOT NULL, -- abusech_feodo | abusech_urlhaus | abusech_threatfox | otx | misp
    source_id        TEXT,          -- original ID in the source feed (for deduplication)

    -- Threat context
    malware_family   TEXT,          -- Emotet, TrickBot, QakBot, AgentTesla ...
    threat_actor     TEXT,          -- FIN7, Lazarus, Carbanak ...
    campaign         TEXT,
    tags             TEXT,          -- JSON array: ["c2", "banking", "emotet"]
    confidence       TEXT CHECK(confidence IN ('high', 'medium', 'low')),
    severity         TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),

    -- Temporal fields
    first_seen       TEXT,          -- ISO 8601
    last_seen        TEXT,          -- ISO 8601 — updated on each feed refresh
    expires_at       TEXT,          -- optional TTL from source

    -- Raw feed response for traceability
    raw              TEXT,          -- JSON blob of original feed record

    -- Housekeeping
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(type, value, source)
);

-- Index for fast observable lookups during enrichment
CREATE INDEX IF NOT EXISTS idx_iocs_value      ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen  ON iocs(last_seen);
CREATE INDEX IF NOT EXISTS idx_iocs_source     ON iocs(source);

-- -------------------------------------------------------------
-- 2. FEED RUNS
-- Tracks every feed collection attempt — success, failure,
-- how many IOCs were pulled, how long it took.
-- Used by the dashboard to show feed health.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feed_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source           TEXT NOT NULL,
    status           TEXT NOT NULL CHECK(status IN ('success', 'failed', 'partial')),
    iocs_fetched     INTEGER DEFAULT 0,
    iocs_new         INTEGER DEFAULT 0,   -- net new IOCs added
    iocs_updated     INTEGER DEFAULT 0,   -- existing IOCs refreshed
    error_message    TEXT,                -- populated on failure
    duration_seconds REAL,
    started_at       TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_feed_runs_source ON feed_runs(source);
CREATE INDEX IF NOT EXISTS idx_feed_runs_status ON feed_runs(status);

-- -------------------------------------------------------------
-- 3. ENRICHMENT CACHE
-- Caches enrichment results per observable value so the same
-- IP/domain/hash is not re-enriched on every case.
-- TTL-based: cache entries older than X hours are ignored.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrichment_cache (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    observable_type  TEXT NOT NULL,   -- ip | url | hash | domain
    observable_value TEXT NOT NULL,

    -- Identity enrichment (corporate directory)
    ad_display_name  TEXT,
    ad_department    TEXT,
    ad_job_title     TEXT,
    ad_manager       TEXT,
    ad_employee_type TEXT,            -- Member | Guest | ServiceAccount
    ad_account_enabled INTEGER,       -- 0 or 1
    ad_mfa_enabled   INTEGER,         -- 0 or 1
    ad_groups        TEXT,            -- JSON array of group names
    ad_risk_level    TEXT,            -- none | low | medium | high (Identity Protection)
    ad_criticality   TEXT,            -- CRITICAL | HIGH | MEDIUM | LOW (derived)

    -- Reputation enrichment (IOC feeds)
    is_malicious     INTEGER DEFAULT 0,  -- 0 or 1
    reputation_score INTEGER,            -- 0-100
    matched_sources  TEXT,               -- JSON array: ["abusech_feodo", "otx"]
    malware_families TEXT,               -- JSON array: ["Emotet", "TrickBot"]
    threat_actors    TEXT,               -- JSON array

    -- Location context
    geo_country      TEXT,
    geo_city         TEXT,
    is_tor_exit      INTEGER DEFAULT 0,
    is_vpn           INTEGER DEFAULT 0,

    -- Full enrichment payload for writing back to case management platform
    full_payload     TEXT,            -- JSON blob

    -- Cache management
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at       TEXT NOT NULL,   -- datetime('now', '+4 hours') typically

    UNIQUE(observable_type, observable_value)
);

CREATE INDEX IF NOT EXISTS idx_cache_observable ON enrichment_cache(observable_type, observable_value);
CREATE INDEX IF NOT EXISTS idx_cache_expires    ON enrichment_cache(expires_at);

-- -------------------------------------------------------------
-- 4. CASE HISTORY
-- Records outcomes of case management platform cases for:
--   a) Recurrence detection (same rule/user/asset fired before?)
--   b) FP dashboard metrics (FP rate per rule over time)
-- Populated by polling case management platform for closed cases.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,

    -- case management platform identifiers
    platform_case_id     TEXT NOT NULL UNIQUE,
    platform_alert_id    TEXT,
    rule_name        TEXT,             -- SIEM correlation rule name
    rule_id          TEXT,             -- SIEM rule ID if available

    -- Observables involved
    source_ip        TEXT,
    destination_ip   TEXT,
    user_email       TEXT,
    device_name      TEXT,

    -- Outcome
    verdict          TEXT CHECK(verdict IN ('true_positive', 'false_positive', 'escalated', 'undetermined')),
    closed_by        TEXT,            -- analyst username
    escalated_to     TEXT,            -- tier level if escalated

    -- Timing (for MTTD / MTTR metrics)
    alert_created_at  TEXT,
    case_created_at   TEXT,
    first_action_at   TEXT,           -- when analyst first touched it
    closed_at         TEXT,
    triage_time_mins  REAL,           -- first_action - case_created
    resolution_time_mins REAL,        -- closed - case_created

    -- MITRE ATT&CK
    mitre_technique  TEXT,            -- T1078
    mitre_tactic     TEXT,            -- Initial Access

    -- Housekeeping
    recorded_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_history_rule       ON case_history(rule_name);
CREATE INDEX IF NOT EXISTS idx_history_user       ON case_history(user_email);
CREATE INDEX IF NOT EXISTS idx_history_source_ip  ON case_history(source_ip);
CREATE INDEX IF NOT EXISTS idx_history_dest_ip    ON case_history(destination_ip);
CREATE INDEX IF NOT EXISTS idx_history_verdict    ON case_history(verdict);
CREATE INDEX IF NOT EXISTS idx_history_closed_at  ON case_history(closed_at);