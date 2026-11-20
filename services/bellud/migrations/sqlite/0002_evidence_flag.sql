-- Migration 0002: per-evidence flags that cannot live on the append-only evidence row.

CREATE TABLE evidence_flag (
  workspace_id TEXT NOT NULL,
  evidence_id  TEXT NOT NULL,
  truncated    INTEGER NOT NULL CHECK (truncated IN (0,1)),
  PRIMARY KEY (workspace_id, evidence_id)
) WITHOUT ROWID;

CREATE TRIGGER evidence_flag_no_update BEFORE UPDATE ON evidence_flag
BEGIN SELECT RAISE(ABORT, 'evidence flag is append-only'); END;
CREATE TRIGGER evidence_flag_no_delete BEFORE DELETE ON evidence_flag
BEGIN SELECT RAISE(ABORT, 'evidence flag is append-only'); END;
