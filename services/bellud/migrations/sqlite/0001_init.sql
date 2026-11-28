-- Migration 0001: core per-workspace system-of-record schema.
-- Every table except meta carries workspace_id NOT NULL.

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE stable_entity (
  workspace_id    TEXT NOT NULL,
  stable_id       TEXT NOT NULL,
  graph           TEXT NOT NULL CHECK (graph IN ('code','cve','unified')),
  kind            TEXT NOT NULL,
  attrs           TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  source_revision TEXT NOT NULL,
  valid_from      TEXT NOT NULL,
  valid_until     TEXT,
  PRIMARY KEY (workspace_id, stable_id, valid_from),
  CONSTRAINT valid_interval CHECK (valid_until IS NULL OR valid_from <= valid_until)
) WITHOUT ROWID;

CREATE TABLE evidence (
  workspace_id    TEXT NOT NULL,
  id              TEXT NOT NULL,
  kind            TEXT NOT NULL,
  content         BLOB NOT NULL CHECK (length(content) <= 8192),
  content_sha256  BLOB NOT NULL CHECK (length(content_sha256) = 32),
  locator         TEXT NOT NULL,
  trust           TEXT NOT NULL CHECK (trust IN ('trusted_source','derived','untrusted_text')),
  event_time      TEXT,
  recorded_at     TEXT NOT NULL,
  observed_at     TEXT NOT NULL,
  source_revision TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
) WITHOUT ROWID;

CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TABLE evidence_status (
  workspace_id TEXT NOT NULL,
  evidence_id  TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('corrupt','suspected_injection')),
  noted_at     TEXT NOT NULL,
  PRIMARY KEY (workspace_id, evidence_id, status)
) WITHOUT ROWID;

CREATE TABLE relation (
  workspace_id    TEXT NOT NULL,
  id              TEXT NOT NULL,
  type            TEXT NOT NULL,
  from_id         TEXT NOT NULL,
  to_id           TEXT NOT NULL,
  state           TEXT NOT NULL CHECK (state IN ('hypothesis','candidate','confirmed','retracted')),
  confidence      REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  method          TEXT NOT NULL,
  event_time      TEXT,
  recorded_at     TEXT NOT NULL,
  valid_from      TEXT NOT NULL,
  valid_until     TEXT,
  observed_at     TEXT NOT NULL,
  source_revision TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id, valid_from),
  CONSTRAINT llm_never_confirmed CHECK (NOT (method = 'llm' AND state = 'confirmed')),
  CONSTRAINT valid_interval CHECK (valid_until IS NULL OR valid_from <= valid_until)
) WITHOUT ROWID;

CREATE INDEX relation_from ON relation (workspace_id, from_id) WHERE state IN ('confirmed','candidate');
CREATE INDEX relation_to   ON relation (workspace_id, to_id)   WHERE state IN ('confirmed','candidate');

CREATE TRIGGER relation_state_transitions BEFORE UPDATE OF state ON relation
WHEN NOT (
     (OLD.state = 'hypothesis' AND NEW.state IN ('candidate','retracted'))
  OR (OLD.state = 'candidate'  AND NEW.state IN ('confirmed','retracted'))
  OR (OLD.state = 'confirmed'  AND NEW.state = 'retracted')
  OR (OLD.state = NEW.state))
BEGIN SELECT RAISE(ABORT, 'illegal relation state transition'); END;

CREATE TRIGGER relation_needs_evidence BEFORE UPDATE OF state ON relation
WHEN NEW.state IN ('candidate','confirmed')
  AND NOT (OLD.state = 'hypothesis' AND NEW.state = 'confirmed') -- illegal; relation_state_transitions reports it
  AND NOT EXISTS (
  SELECT 1 FROM relation_evidence re
  WHERE re.workspace_id = NEW.workspace_id AND re.relation_id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'relation requires evidence'); END;

CREATE TABLE relation_evidence (
  workspace_id TEXT NOT NULL,
  relation_id  TEXT NOT NULL,
  evidence_id  TEXT NOT NULL,
  PRIMARY KEY (workspace_id, relation_id, evidence_id)
) WITHOUT ROWID;

CREATE TABLE embedding (
  workspace_id    TEXT NOT NULL,
  stable_id       TEXT NOT NULL,
  model           TEXT NOT NULL,
  source_revision TEXT NOT NULL,
  dim             INTEGER NOT NULL CHECK (dim > 0),
  vec             BLOB NOT NULL CHECK (length(vec) = dim * 4),
  PRIMARY KEY (workspace_id, stable_id, model)
) WITHOUT ROWID;

CREATE TABLE finding (
  id              TEXT PRIMARY KEY,
  workspace_id    TEXT NOT NULL,
  kind            TEXT NOT NULL,
  body            TEXT NOT NULL CHECK (json_valid(body)),
  revisions       TEXT NOT NULL,
  cve_snapshot_id TEXT,
  verdict         TEXT,
  created_at      TEXT NOT NULL
);

CREATE TABLE agent_run (
  id              TEXT PRIMARY KEY,
  workspace_id    TEXT NOT NULL,
  agent           TEXT NOT NULL,
  plan            TEXT,
  plan_level      INTEGER CHECK (plan_level IN (1,2)),
  planning_rounds INTEGER NOT NULL CHECK (planning_rounds BETWEEN 1 AND 2),
  token_usage     TEXT,
  started_at      TEXT,
  finished_at     TEXT
);

CREATE TABLE audit (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  at           TEXT NOT NULL,
  actor_kind   TEXT NOT NULL,
  action       TEXT NOT NULL,
  subject      TEXT NOT NULL,
  detail       TEXT
);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;

CREATE TABLE retrieval_cache (
  workspace_id TEXT NOT NULL,
  key          TEXT NOT NULL,
  selection    TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, key)
) WITHOUT ROWID;

CREATE TABLE cve_update_state (
  workspace_id    TEXT NOT NULL,
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  snapshot_id     TEXT,
  built_at        TEXT,
  installed_at    TEXT,
  last_check_at   TEXT,
  last_etag       TEXT,
  delta_chain_len INTEGER NOT NULL DEFAULT 0,
  source          TEXT
);

CREATE VIRTUAL TABLE fts_text USING fts5(
  stable_id UNINDEXED, workspace_id UNINDEXED, body,
  tokenize = 'unicode61 remove_diacritics 2'
);
