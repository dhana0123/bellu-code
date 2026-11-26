// Package runtimeevents receives runtime events from sensors, authenticates
// the sender and stores events in the bounded runtime_event table.
//
// Unix socket: mode 0600, SO_PEERCRED uid must equal the server uid, and the
// first frame must be a hello with a valid per-workspace HMAC. Remote nodes
// connect over mutual TLS. An unauthenticated sender is disconnected, nothing
// is stored or passed to OnEvent, and the rejected counter is incremented.
package runtimeevents

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

// SocketPath returns $XDG_RUNTIME_DIR/bellucode/runtime.sock, or "" when the
// runtime dir is unset.
func SocketPath(getenv func(string) string) string {
	d := getenv("XDG_RUNTIME_DIR")
	if d == "" {
		return ""
	}
	return filepath.Join(d, "bellucode", "runtime.sock")
}

const (
	maxSkew   = 5 * time.Minute
	helloWait = 10 * time.Second
)

var validTypes = map[string]bool{
	wire.TypeProcessExec: true, wire.TypeNetworkConnect: true, wire.TypeFileWrite: true,
	wire.TypeShellSpawn: true, wire.TypePrivilegeChange: true, wire.TypeContainerEscape: true,
}

// Config configures a Server.
type Config struct {
	Store       *sqlite.Store
	WorkspaceID string
	// Key is the per-workspace HMAC token for Unix-socket senders.
	Key []byte
	// UID is the uid allowed on the Unix socket; default os.Getuid().
	UID int
	// OnEvent is called after an event is stored (rules hook). Optional.
	OnEvent func(wire.Event)
	Now     func() time.Time
}

// Server ingests runtime events.
type Server struct {
	cfg      Config
	rejected atomic.Int64
	mu       sync.Mutex
	ln       []net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// New returns a Server. Key must be non-empty.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.WorkspaceID == "" || len(cfg.Key) == 0 {
		return nil, errors.New("runtimeevents: store, workspace and key are required")
	}
	if cfg.UID == 0 {
		cfg.UID = os.Getuid()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, conns: map[net.Conn]struct{}{}}, nil
}

// Rejected is runtime_rejected_total.
func (s *Server) Rejected() int64 { return s.rejected.Load() }

// ListenUnix creates the socket (dir 0700, socket 0600) and serves it in the background.
func (s *Server) ListenUnix(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(path)
	old := setUmask(0o177)
	ln, err := net.Listen("unix", path)
	setUmask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.serve(ln, false)
	return nil
}

// ListenTLS serves remote nodes; the config must require and verify client certificates.
func (s *Server) ListenTLS(addr string, cfg *tls.Config) error {
	if cfg == nil || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("runtimeevents: TLS config must set ClientAuth to RequireAndVerifyClientCert")
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	s.serve(ln, true)
	return nil
}

// Close stops listeners and connections and waits for handlers.
func (s *Server) Close() {
	s.mu.Lock()
	for _, l := range s.ln {
		l.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) serve(ln net.Listener, remote bool) {
	s.mu.Lock()
	s.ln = append(s.ln, ln)
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[c] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { s.mu.Lock(); delete(s.conns, c); s.mu.Unlock(); c.Close() }()
				s.handle(c, remote)
			}()
		}
	}()
}

func (s *Server) reject() { s.rejected.Add(1) }

func (s *Server) handle(c net.Conn, remote bool) {
	ctx := context.Background()
	if !remote {
		if uid, ok := peerUID(c); !ok || uid != s.cfg.UID {
			s.reject()
			return
		}
	}
	r := bufio.NewReaderSize(c, 4096)
	_ = c.SetReadDeadline(s.cfg.Now().Add(helloWait))
	var first wire.Frame
	if !readFrame(r, &first) || first.Kind != wire.KindHello || first.Hello == nil || !s.helloOK(first.Hello, remote) {
		s.reject()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	node := first.Hello.Node
	for {
		var f wire.Frame
		if !readFrame(r, &f) {
			return
		}
		switch {
		case f.Kind == wire.KindEvent && f.Event != nil:
			ev := *f.Event
			ev.Node = node
			if s.valid(&ev) {
				if s.store(ctx, ev) == nil && s.cfg.OnEvent != nil {
					s.cfg.OnEvent(ev)
				}
			}
		case f.Kind == wire.KindStatus && f.Status != nil:
			_ = s.saveStatus(ctx, node, *f.Status)
		}
	}
}

// readFrame reads one line; false on EOF, overlong line or bad JSON.
func readFrame(r *bufio.Reader, f *wire.Frame) bool {
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) > wire.MaxFrameBytes {
		return false
	}
	return json.Unmarshal(line, f) == nil
}

func (s *Server) helloOK(h *wire.Hello, remote bool) bool {
	if h.Workspace != s.cfg.WorkspaceID || h.Node == "" || len(h.Node) > 253 {
		return false
	}
	if remote { // the verified client certificate is the credential
		return true
	}
	if d := s.cfg.Now().Sub(time.Unix(h.TS, 0)); d > maxSkew || d < -maxSkew {
		return false
	}
	got, err := hex.DecodeString(h.MAC)
	if err != nil {
		return false
	}
	want, _ := hex.DecodeString(wire.Sign(s.cfg.Key, h.Workspace, h.Node, h.TS))
	return hmac.Equal(got, want)
}

func (s *Server) valid(e *wire.Event) bool {
	if !validTypes[e.Type] {
		return false
	}
	if e.TS.IsZero() {
		e.TS = s.cfg.Now()
	}
	if r := []rune(e.Args); len(r) > wire.MaxArgsChars {
		e.Args = string(r[:wire.MaxArgsChars])
	}
	return true
}

func (s *Server) store(ctx context.Context, e wire.Event) error {
	un, _ := json.Marshal(append([]string{}, e.Unavailable...))
	size := len(e.Type) + len(e.Node) + len(e.Namespace) + len(e.Pod) + len(e.ContainerID) +
		len(e.ProcessPath) + len(e.Args) + len(e.User) + len(un) + 32
	return s.cfg.Store.Write(ctx, s.cfg.WorkspaceID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO runtime_event
 (workspace_id, ts, type, node, namespace, pod, container_id, process_path, args, user, unavailable, size_bytes)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, s.cfg.WorkspaceID, e.TS.UTC().Format(time.RFC3339Nano), e.Type, e.Node,
			e.Namespace, e.Pod, e.ContainerID, e.ProcessPath, e.Args, e.User, string(un), size)
		return err
	})
}

func (s *Server) saveStatus(ctx context.Context, node string, st wire.Status) error {
	if st.Status != wire.StatusOK && st.Status != wire.StatusUnsupported {
		return errors.New("runtimeevents: unknown status")
	}
	drops, _ := json.Marshal(st.Drops)
	if st.Drops == nil {
		drops = []byte("{}")
	}
	return s.cfg.Store.Write(ctx, s.cfg.WorkspaceID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO runtime_sensor (workspace_id, node, status, reason, drops, rejected_total, seen_at)
 VALUES (?,?,?,?,?,?,?)
 ON CONFLICT(workspace_id, node) DO UPDATE SET status=excluded.status, reason=excluded.reason,
  drops=excluded.drops, rejected_total=excluded.rejected_total, seen_at=excluded.seen_at`,
			s.cfg.WorkspaceID, node, st.Status, st.Reason, string(drops), s.rejected.Load(), s.cfg.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}
