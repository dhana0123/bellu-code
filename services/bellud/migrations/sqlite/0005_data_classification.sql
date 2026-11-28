-- Data_Classifier results per data store entity (Requirement 13.3). Kept out of
-- the graph: a "dataclass" collector asserting an aws_resource entity would keep
-- it alive after the cloud collector retires it.
CREATE TABLE data_classification (
  workspace_id TEXT NOT NULL, entity_id TEXT NOT NULL, account_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  classes TEXT NOT NULL,                     -- JSON array from pii, financial, health, credentials, none
  match_counts TEXT NOT NULL DEFAULT '{}',   -- sampling: class -> count (task 27.3), never content
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, entity_id)
) WITHOUT ROWID;
CREATE INDEX data_classification_account_idx ON data_classification (workspace_id, account_id);
