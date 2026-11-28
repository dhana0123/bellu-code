//go:build !unix

package keysource

import "os"

// Lock is a no-op where mlock is unavailable.
func Lock([]byte) error { return nil }

// Unlock is a no-op where mlock is unavailable.
func Unlock([]byte) error { return nil }

func ownedByCurrentUser(os.FileInfo) bool { return true }
