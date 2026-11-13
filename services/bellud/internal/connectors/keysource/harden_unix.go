//go:build unix

package keysource

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Lock pins b in RAM so the key is not swapped out. Failure (for example
// RLIMIT_MEMLOCK) is reported; callers may continue without it.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// Unlock releases a Lock.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

func ownedByCurrentUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Getuid()
}
