//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

const (
	dialTimeout  = 5 * time.Second
	writeTimeout = 5 * time.Second
	keyFileName  = "runtime.key"
)

// wireTypes maps the sensor's event types to the wire names (Requirement 15.3).
var wireTypes = map[string]string{
	TypeProcessExec:        wire.TypeProcessExec,
	TypeNetConnect:         wire.TypeNetworkConnect,
	TypeFileWriteSensitive: wire.TypeFileWrite,
	TypeShellInContainer:   wire.TypeShellSpawn,
	TypePrivChange:         wire.TypePrivilegeChange,
	TypeContainerEscape:    wire.TypeContainerEscape,
}

// ToWire converts a sensor event to its wire form. The second result is false for
// unknown types, which the server would reject.
func ToWire(e Event) (wire.Event, bool) {
	t, ok := wireTypes[e.Type]
	if !ok {
		return wire.Event{}, false
	}
	args := e.Args
	if t == wire.TypeNetworkConnect {
		args = connectArgs(args)
	}
	return wire.Event{
		TS: e.TS, Type: t, Node: e.Node, Namespace: e.Namespace, Pod: e.Pod,
		ContainerID: e.ContainerID, ProcessPath: e.ProcessPath, Args: args,
		User: e.User, Unavailable: e.Unavailable,
	}, true
}

// connectArgs makes network_connect args one of "ip", "ip:port" or "dst=ip:port",
// the forms the server parses. Anything else becomes "dst=<value>" so a bad value is
// visible rather than silently shaped like an address.
func connectArgs(a string) string {
	a = strings.TrimSpace(a)
	h := a
	if host, _, err := net.SplitHostPort(a); err == nil {
		h = host
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil || strings.HasPrefix(a, "dst=") {
		return a
	}
	return "dst=" + a
}

// Transport is the sensor's connection to bellud.
type Transport struct {
	Network, Addr string // "unix" + socket path, or "tcp" + host:port
	TLS           *tls.Config
	Workspace     string
	Node          string
	Key           []byte // HMAC key; used on the Unix socket only
	Now           func() time.Time

	mu   sync.Mutex
	conn net.Conn
}

// LoadKey reads <dataDir>/workspaces/<workspace>/runtime.key.
func LoadKey(workspaceDir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(workspaceDir, keyFileName))
	if err != nil {
		return nil, fmt.Errorf("read runtime key: %w", err)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return nil, errors.New("runtime key is empty")
	}
	return b, nil
}

// TLSConfig builds a client config from PEM files (workspace-CA client certificate).
func TLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificates in " + caFile)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13}, nil
}

// connect dials and sends the hello. The caller holds t.mu.
func (t *Transport) connect() error {
	d := net.Dialer{Timeout: dialTimeout}
	var c net.Conn
	var err error
	if t.TLS != nil {
		c, err = (&tls.Dialer{NetDialer: &d, Config: t.TLS}).DialContext(context.Background(), t.Network, t.Addr)
	} else {
		c, err = d.DialContext(context.Background(), t.Network, t.Addr)
	}
	if err != nil {
		return err
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	h, err := wire.Marshal(wire.NewHello(t.Key, t.Workspace, t.Node, now()))
	if err == nil {
		_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err = c.Write(h)
	}
	if err != nil {
		c.Close()
		return err
	}
	t.conn = c
	return nil
}

func (t *Transport) write(f wire.Frame) error {
	b, err := wire.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > wire.MaxFrameBytes {
		return nil // cannot be delivered; do not block the queue
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		if err := t.connect(); err != nil {
			return err
		}
	}
	_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := t.conn.Write(b); err != nil {
		t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

// Send writes one event. Unknown types are discarded.
func (t *Transport) Send(e Event) error {
	w, ok := ToWire(e)
	if !ok {
		return nil
	}
	if w.Node == "" {
		w.Node = t.Node
	}
	return t.write(wire.Frame{Kind: wire.KindEvent, Event: &w})
}

// SendStatus writes a status frame. drops is keyed by sensor type and converted to wire names.
func (t *Transport) SendStatus(pf Preflight, drops map[string]uint64) error {
	st := wire.Status{Status: pf.Status, Reason: pf.Reason}
	if len(drops) > 0 {
		st.Drops = map[string]int64{}
		for k, v := range drops {
			if w, ok := wireTypes[k]; ok {
				k = w
			}
			st.Drops[k] += int64(v)
		}
	}
	return t.write(wire.Frame{Kind: wire.KindStatus, Status: &st})
}

// Close closes the connection.
func (t *Transport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}
