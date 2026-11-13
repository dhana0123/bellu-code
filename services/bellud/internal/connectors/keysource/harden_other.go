//go:build !linux

package keysource

// SetNotDumpable is a no-op where PR_SET_DUMPABLE does not exist.
func SetNotDumpable() error { return nil }
