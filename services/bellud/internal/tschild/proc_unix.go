//go:build !windows

package tschild

import (
	"os"
	"syscall"
)

// procAttr places the child in its own process group.
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// killProcessGroup SIGKILLs the child's group, falling back to the process.
func killProcessGroup(p *os.Process) {
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		_ = p.Kill()
	}
}
