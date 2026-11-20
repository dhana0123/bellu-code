-- SyncStatus reports the schema version of the installed CVE snapshot.
ALTER TABLE cve_update_state ADD COLUMN schema_version INTEGER;
