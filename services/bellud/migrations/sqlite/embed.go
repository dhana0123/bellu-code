// Package sqlitemigrations embeds the numbered SQLite migration files
// (NNNN_name.sql) applied by internal/store/sqlite.
package sqlitemigrations

import "embed"

// FS holds the migration files. Non-migration files are ignored by the runner.
//
//go:embed *
var FS embed.FS
