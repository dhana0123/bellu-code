//go:build unix

package runtimeevents

import "syscall"

func setUmask(m int) int { return syscall.Umask(m) }
