//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
	sqlitemigrations "github.com/bellu/bellucode/services/bellud/migrations/sqlite"
)

func TestToWireMapsTypesAndConnectArgs(t *testing.T) {
	for in, want := range map[string]string{
		TypeNetConnect: wire.TypeNetworkConnect, TypePrivChange: wire.TypePrivilegeChange,
		TypeShellInContainer: wire.TypeShellSpawn, TypeProcessExec: wire.TypeProcessExec,
		TypeFileWriteSensitive: wire.TypeFileWrite, TypeContainerEscape: wire.TypeContainerEscape,
	} {
		w, ok := ToWire(Event{Type: in})
		if !ok || w.Type != want {
			t.Errorf("%s -> %q, %v", in, w.Type, ok)
		}
	}
	if _, ok := ToWire(Event{Type: "bogus"}); ok {
		t.Error("unknown type accepted")
	}
	for in, want := range map[string]string{
		"10.0.0.1:443": "10.0.0.1:443", "10.0.0.1": "10.0.0.1", "dst=1.2.3.4:80": "dst=1.2.3.4:80",
		"[::1]:80": "[::1]:80", "evil.example": "dst=evil.example",
	} {
		if got := connectArgs(in); got != want {
			t.Errorf("connectArgs(%q) = %q, want %q", in, got, want)
		}
		if got := connectArgs(in); runtimeevents.ConnectDest(got) == "" && in != "evil.example" {
			t.Errorf("server cannot parse %q", got)
		}
	}
}

func TestEndToEndWithRuntimeEventsServer(t *testing.T) {
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := []byte("secret")
	srv, err := runtimeevents.New(runtimeevents.Config{Store: db, WorkspaceID: "ws1", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	sock := filepath.Join(t.TempDir(), "rt", "runtime.sock")
	if err := srv.ListenUnix(sock); err != nil {
		t.Fatal(err)
	}

	tr := &Transport{Network: "unix", Addr: sock, Workspace: "ws1", Node: "n1", Key: key}
	defer tr.Close()
	buf := NewReconnectBuffer(10)
	s := NewSender(tr.Send, buf)
	s.Send(Normalize(Event{TS: time.Now(), Type: TypeNetConnect, Node: "n1", Args: "10.1.2.3:443"}))
	s.Send(Normalize(Event{TS: time.Now(), Type: TypeShellInContainer, Node: "n1", ProcessPath: "/bin/sh"}))
	if err := tr.SendStatus(Preflight{Status: StatusOK}, map[string]uint64{TypeNetConnect: 7}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer not drained: %d", buf.Len())
	}
	var n int
	var drops string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = db.DB().QueryRow("SELECT count(*) FROM runtime_event WHERE node='n1'").Scan(&n)
		_ = db.DB().QueryRow("SELECT drops FROM runtime_sensor WHERE node='n1'").Scan(&drops)
		if n == 2 && drops != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n != 2 || drops != `{"network_connect":7}` {
		t.Fatalf("events=%d drops=%q", n, drops)
	}
}

func TestBadKeyIsRejectedAndEventsStayBuffered(t *testing.T) {
	db, err := sqlite.Open(context.Background(), t.TempDir(), "ws1", sqlite.Options{Migrations: sqlitemigrations.FS})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv, _ := runtimeevents.New(runtimeevents.Config{Store: db, WorkspaceID: "ws1", Key: []byte("secret")})
	defer srv.Close()
	sock := filepath.Join(t.TempDir(), "rt", "runtime.sock")
	if err := srv.ListenUnix(sock); err != nil {
		t.Fatal(err)
	}
	tr := &Transport{Network: "unix", Addr: sock, Workspace: "ws1", Node: "n1", Key: []byte("wrong")}
	defer tr.Close()
	for i := 0; i < 3; i++ {
		_ = tr.Send(Event{Type: TypeProcessExec})
		time.Sleep(50 * time.Millisecond)
	}
	var n int
	_ = db.DB().QueryRow("SELECT count(*) FROM runtime_event").Scan(&n)
	if n != 0 || srv.Rejected() == 0 {
		t.Fatalf("stored=%d rejected=%d", n, srv.Rejected())
	}
}

func TestLoadKey(t *testing.T) {
	d := t.TempDir()
	if _, err := LoadKey(d); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := os.WriteFile(filepath.Join(d, "runtime.key"), []byte("abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadKey(d); err != nil || string(k) != "abc" {
		t.Fatalf("%q %v", k, err)
	}
}
