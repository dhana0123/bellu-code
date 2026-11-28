package runtimeevents

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func setup(t *testing.T) (*Server, *sqlite.Store, string) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(Config{Store: db, WorkspaceID: "ws1", Key: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	sock := filepath.Join(t.TempDir(), "rt", "runtime.sock")
	if err := s.ListenUnix(sock); err != nil {
		t.Fatal(err)
	}
	return s, db, sock
}

func send(t *testing.T, sock string, frames ...wire.Frame) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, f := range frames {
		b, _ := wire.Marshal(f)
		c.Write(b)
	}
	c.Write([]byte("\n"))
	buf := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(buf) // wait for server close or deadline
}

func count(t *testing.T, db *sqlite.Store, q string) int {
	t.Helper()
	var n int
	if err := db.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ev() wire.Frame {
	return wire.Frame{Kind: wire.KindEvent, Event: &wire.Event{Type: wire.TypeShellSpawn, ProcessPath: "/bin/sh", Unavailable: []string{"pod"}}}
}

func TestAuthenticatedEventStored(t *testing.T) {
	s, db, sock := setup(t)
	got := make(chan wire.Event, 1)
	s.cfg.OnEvent = func(e wire.Event) { got <- e }
	send(t, sock, wire.NewHello([]byte("secret"), "ws1", "n1", time.Now()), ev(),
		wire.Frame{Kind: wire.KindStatus, Status: &wire.Status{Status: wire.StatusUnsupported, Reason: "btf_missing"}})
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("event not delivered")
	}
	if n := count(t, db, "SELECT count(*) FROM runtime_event WHERE node='n1' AND size_bytes>0"); n != 1 {
		t.Fatalf("events=%d", n)
	}
	time.Sleep(100 * time.Millisecond)
	if n := count(t, db, "SELECT count(*) FROM runtime_sensor WHERE node='n1' AND reason='btf_missing'"); n != 1 {
		t.Fatalf("sensor rows=%d", n)
	}
	if s.Rejected() != 0 {
		t.Fatal("unexpected rejection")
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	bad := map[string][]wire.Frame{
		"no hello": {ev()},
		"bad mac":  {wire.NewHello([]byte("wrong"), "ws1", "n1", time.Now()), ev()},
		"other ws": {wire.NewHello([]byte("secret"), "ws2", "n1", time.Now()), ev()},
		"stale":    {wire.NewHello([]byte("secret"), "ws1", "n1", time.Now().Add(-time.Hour)), ev()},
	}
	for name, frames := range bad {
		t.Run(name, func(t *testing.T) {
			s, db, sock := setup(t)
			called := false
			s.cfg.OnEvent = func(wire.Event) { called = true }
			send(t, sock, frames...)
			if s.Rejected() != 1 {
				t.Fatalf("rejected=%d", s.Rejected())
			}
			if n := count(t, db, "SELECT count(*) FROM runtime_event"); n != 0 || called {
				t.Fatalf("stored=%d called=%v", n, called)
			}
		})
	}
}

func TestPeerUIDMismatchRejected(t *testing.T) {
	s, db, sock := setup(t)
	s.cfg.UID = s.cfg.UID + 1
	send(t, sock, wire.NewHello([]byte("secret"), "ws1", "n1", time.Now()), ev())
	if s.Rejected() != 1 || count(t, db, "SELECT count(*) FROM runtime_event") != 0 {
		t.Fatal("uid mismatch accepted")
	}
}
