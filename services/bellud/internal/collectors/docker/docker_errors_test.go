package docker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755); os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

// A stale socket file with no listener behind it means Docker is absent.
func TestConnectionRefusedIsAbsent(t *testing.T) {
	sock := shortSock(t)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	b, err := New(WithSocket(sock)).Collect(context.Background())
	if err != nil || b.Collector != "docker" || len(b.Entities) != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}

func TestSocketPermissionDenied(t *testing.T) {
	sock := shortSock(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(sock, os.O_RDWR, 0); err == nil { // running as root
		f.Close()
		t.Skip("permissions not enforced")
	}
	b, err := New(WithSocket(sock)).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "permission denied") || len(b.Entities) != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}

func TestStatPermissionDenied(t *testing.T) {
	sock := shortSock(t)
	dir := filepath.Dir(sock)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); err == nil {
		t.Skip("permissions not enforced")
	}
	_, err := New(WithSocket(sock)).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("got %v", err)
	}
}

func TestNon200IsError(t *testing.T) {
	sock := shortSock(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	b, err := New(WithSocket(sock)).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 500") || len(b.Entities) != 0 {
		t.Fatalf("got %+v, %v", b, err)
	}
}
