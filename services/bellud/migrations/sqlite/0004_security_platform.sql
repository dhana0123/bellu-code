-- Security platform schema (bellu-wiz-security-platform, task 2.1).
-- Extends the unused finding table (Requirement 3.15) and adds the issue, scan,
-- rule, runtime, gap and audit tables. finding_event is append-only (3.12).
-- Every table carries workspace_id.

ALTER TABLE finding ADD COLUMN category TEXT NOT NULL DEFAULT 'code_and_dependencies';
ALTER TABLE finding ADD COLUMN rule_id TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN title TEXT NOT NULL DEFAULT '' CHECK (length(title) <= 256);
ALTER TABLE finding ADD COLUMN description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 8192);
ALTER TABLE finding ADD COLUMN severity TEXT NOT NULL DEFAULT 'info'
  CHECK (severity IN ('critical','high','medium','low','info'));
ALTER TABLE finding ADD COLUMN status TEXT NOT NULL DEFAULT 'open'
  CHECK (status IN ('open','in_progress','resolved','ignored','accepted_risk'));
ALTER TABLE finding ADD COLUMN asset_id TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN evidence_refs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_refs));
ALTER TABLE finding ADD COLUMN first_seen TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN last_seen TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN resolved_at TEXT;
ALTER TABLE finding ADD COLUMN source TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN rule_pack_version TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1;
ALTER TABLE finding ADD COLUMN risk_score REAL CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100));
ALTER TABLE finding ADD COLUMN unmapped_severity INTEGER NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN snooze_reason TEXT CHECK (snooze_reason IS NULL OR length(snooze_reason) <= 1024);
ALTER TABLE finding ADD COLUMN snooze_until TEXT;
CREATE INDEX finding_list_idx   ON finding (workspace_id, severity, status, last_seen DESC, id);
CREATE INDEX finding_cat_idx    ON finding (workspace_id, category, status, severity);
CREATE INDEX finding_asset_idx  ON finding (workspace_id, asset_id, source, status);
CREATE INDEX finding_snooze_idx ON finding (workspace_id, snooze_until) WHERE snooze_until IS NOT NULL;

CREATE TABLE finding_event (            -- append-only (3.12)
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  at TEXT NOT NULL, actor TEXT NOT NULL,           -- user id, 'system', or scanner name
  prev_status TEXT, new_status TEXT NOT NULL, reason TEXT
);
CREATE TRIGGER finding_event_no_update BEFORE UPDATE ON finding_event BEGIN SELECT RAISE(ABORT,'finding_event is append-only'); END;
CREATE TRIGGER finding_event_no_delete BEFORE DELETE ON finding_event BEGIN SELECT RAISE(ABORT,'finding_event is append-only'); END;

CREATE TABLE issue (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
  rule_id TEXT NOT NULL, title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  risk_score REAL NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  status TEXT NOT NULL CHECK (status IN ('open','resolved','ignored')),
  category TEXT NOT NULL, path TEXT NOT NULL CHECK (json_valid(path)),
  includes_inferred INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX issue_list_idx ON issue (workspace_id, status, risk_score DESC, updated_at DESC);
CREATE INDEX issue_cat_idx  ON issue (workspace_id, category, status, risk_score DESC);
CREATE TABLE issue_finding (
  workspace_id TEXT NOT NULL, issue_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  PRIMARY KEY (workspace_id, issue_id, finding_id)
) WITHOUT ROWID;                         -- 1..500 members enforced in issues.Store

CREATE TABLE scan_job (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('sbom','vulnerability','misconfiguration','secret','posture','data_classification','ai_inventory')),
  target_type TEXT NOT NULL, target_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','cancelled','skipped_unchanged')),
  reason TEXT, queued_at TEXT NOT NULL, started_at TEXT, ended_at TEXT,
  created_count INTEGER NOT NULL DEFAULT 0, updated_count INTEGER NOT NULL DEFAULT 0, resolved_count INTEGER NOT NULL DEFAULT 0,
  content_digest TEXT, scanner_versions TEXT NOT NULL DEFAULT '{}', rule_pack_versions TEXT NOT NULL DEFAULT '{}',
  duration_ms INTEGER                       -- recorded even when a performance target is missed (22.9)
);
CREATE INDEX scan_job_queue_idx  ON scan_job (workspace_id, status, queued_at);
CREATE INDEX scan_job_target_idx ON scan_job (workspace_id, target_type, target_id, kind, status, ended_at DESC);
CREATE TABLE scan_schedule (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, kind TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
  interval_s INTEGER NOT NULL CHECK (interval_s BETWEEN 900 AND 2592000), next_at TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  UNIQUE (workspace_id, kind, target_type, target_id)
);
CREATE TABLE scanner_error (               -- Scanner_Error_Row
  seq INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL,
  job_id TEXT, at TEXT NOT NULL, input TEXT NOT NULL, cause TEXT NOT NULL
);
CREATE TABLE sbom_snapshot (               -- last good SBOM per asset (5.12, 5.15)
  workspace_id TEXT NOT NULL, asset_id TEXT NOT NULL, content_digest TEXT NOT NULL,
  packages_json BLOB NOT NULL, package_count INTEGER NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, asset_id)
) WITHOUT ROWID;

CREATE TABLE rule_pack_state (
  workspace_id TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  severity_override TEXT, PRIMARY KEY (workspace_id, pack_id)
) WITHOUT ROWID;
CREATE TABLE rule_override (
  workspace_id TEXT NOT NULL, pack_id TEXT NOT NULL, rule_id TEXT NOT NULL,
  enabled INTEGER, severity_override TEXT,                 -- NULL = inherit from pack (10.8)
  PRIMARY KEY (workspace_id, pack_id, rule_id)
) WITHOUT ROWID;
CREATE TABLE posture_eval (                -- feeds compliance (10.9) and error reporting (10.15)
  workspace_id TEXT NOT NULL, pack_id TEXT NOT NULL, rule_id TEXT NOT NULL, entity_id TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('pass','fail','error')), error TEXT, pack_version TEXT NOT NULL, evaluated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, pack_id, rule_id, entity_id)
) WITHOUT ROWID;

CREATE TABLE runtime_event (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, ts TEXT NOT NULL, type TEXT NOT NULL,
  node TEXT, namespace TEXT, pod TEXT, container_id TEXT, process_path TEXT, args TEXT, user TEXT, unavailable TEXT NOT NULL DEFAULT '[]',
  size_bytes INTEGER NOT NULL
);
CREATE INDEX runtime_event_ts_idx ON runtime_event (workspace_id, ts);
CREATE TABLE runtime_sensor (workspace_id TEXT NOT NULL, node TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, drops TEXT NOT NULL DEFAULT '{}',
  rejected_total INTEGER NOT NULL DEFAULT 0, seen_at TEXT NOT NULL, PRIMARY KEY (workspace_id, node)) WITHOUT ROWID;

CREATE TABLE collector_gap (               -- missing_data (11.11, 13.12, 14.8, 14.13)
  workspace_id TEXT NOT NULL, connector TEXT NOT NULL, resource_type TEXT NOT NULL, scope TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('missing_permission','rate_limited','failed_call')),
  detail TEXT, run_at TEXT NOT NULL, PRIMARY KEY (workspace_id, connector, resource_type, scope)
) WITHOUT ROWID;
CREATE TABLE cve_gap_state (workspace_id TEXT NOT NULL, cause TEXT, at TEXT, PRIMARY KEY (workspace_id)) WITHOUT ROWID;
CREATE TABLE secret_verify_audit (         -- 9.11; also copied to `audit`
  seq INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, provider TEXT NOT NULL, fingerprint TEXT NOT NULL,
  at TEXT NOT NULL, result TEXT NOT NULL CHECK (result IN ('live','not_live','unverified'))
);
