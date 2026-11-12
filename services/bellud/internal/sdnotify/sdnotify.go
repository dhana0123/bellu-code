// Package sdnotify sends systemd readiness notifications using only the standard library.
package sdnotify

import (
	"net"
	"os"
)

// Ready sends READY=1 to $NOTIFY_SOCKET. It is a no-op (false, nil) when the variable is unset.
func Ready() (bool, error) { return Notify("READY=1") }

// Notify sends state to the socket named by $NOTIFY_SOCKET.
func Notify(state string) (bool, error) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return false, nil
	}
	if addr[0] == '@' { // abstract socket
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}
