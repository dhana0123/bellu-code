//go:build windows

package tschild

import (
	"os"
	"syscall"
)

// procAttr: Windows has no POSIX process groups; no special attributes.
func procAttr() *syscall.SysProcAttr { return nil }

// killProcessGroup kills only the child process on Windows.
func killProcessGroup(p *os.Process) { _ = p.Kill() }
