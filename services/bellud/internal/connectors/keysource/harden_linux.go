//go:build linux

package keysource

import "golang.org/x/sys/unix"

// SetNotDumpable sets PR_SET_DUMPABLE=0 so the process memory is not readable
// through ptrace or core dumps.
func SetNotDumpable() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
