//go:build !linux

package runtimeevents

import "net"

// peerUID is unavailable off Linux, so every Unix-socket peer is rejected.
func peerUID(net.Conn) (int, bool) { return 0, false }
