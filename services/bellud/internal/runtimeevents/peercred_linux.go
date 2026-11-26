//go:build linux

package runtimeevents

import (
	"net"
	"syscall"
)

// peerUID returns the effective uid of the process on the other end (SO_PEERCRED).
func peerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	uid, found := 0, false
	_ = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			uid, found = int(cred.Uid), true
		}
	})
	return uid, found
}
