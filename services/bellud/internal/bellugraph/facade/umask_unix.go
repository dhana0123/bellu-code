//go:build !windows

package facade

import "syscall"

// setUmask sets the process umask and returns the previous one.
func setUmask(m int) int { return syscall.Umask(m) }
