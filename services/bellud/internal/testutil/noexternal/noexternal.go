// Package noexternal fails tests that try to reach a non-loopback network
// destination, proving the product works offline.
package noexternal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var (
	mu         sync.Mutex
	violations []string
)

// Control is a net.Dialer.Control hook. It rejects any connection whose
// resolved destination is not loopback and names the address in the error.
// Unix-domain sockets are allowed.
func Control(network, address string, _ syscall.RawConn) error {
	if strings.HasPrefix(network, "unix") {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	mu.Lock()
	violations = append(violations, address)
	mu.Unlock()
	return fmt.Errorf("noexternal: blocked non-loopback %s connection to %s", network, address)
}

// Dialer returns a dialer guarded by Control.
func Dialer() *net.Dialer { return &net.Dialer{Control: Control} }

// Violations returns the destinations blocked so far.
func Violations() []string {
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), violations...)
}

// Install guards http.DefaultTransport and net.DefaultResolver (DNS to a
// remote server is also blocked). It returns a function that restores them.
func Install() (restore func()) {
	d := Dialer()
	oldRes := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
	}
	var oldTr *http.Transport
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		oldTr = tr
		clone := tr.Clone()
		clone.DialContext = d.DialContext
		clone.Proxy = nil
		http.DefaultTransport = clone
	}
	return func() {
		net.DefaultResolver = oldRes
		if oldTr != nil {
			http.DefaultTransport = oldTr
		}
	}
}

// Main is for use from TestMain: `func TestMain(m *testing.M) { noexternal.Main(m) }`.
// It installs the guard, runs the tests and exits non-zero if any external
// connection was attempted, even when the code under test swallowed the error.
func Main(m *testing.M) {
	restore := Install()
	code := m.Run()
	restore()
	if v := Violations(); len(v) > 0 && code == 0 {
		fmt.Fprintf(os.Stderr, "noexternal: external connections attempted: %v\n", v)
		code = 1
	}
	os.Exit(code)
}
