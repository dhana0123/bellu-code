package noexternal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoopbackAllowed(t *testing.T) {
	restore := Install()
	defer restore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback request failed: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatalf("body = %q", b)
	}
}

func TestNonLoopbackBlockedWithAddress(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1; Control rejects before any packet is sent.
	_, err := Dialer().DialContext(context.Background(), "tcp", "192.0.2.1:443")
	if err == nil {
		t.Fatal("expected dial to fail")
	}
	if !strings.Contains(err.Error(), "192.0.2.1:443") {
		t.Fatalf("error should name the address: %v", err)
	}
	found := false
	for _, v := range Violations() {
		found = found || v == "192.0.2.1:443"
	}
	if !found {
		t.Fatalf("violation not recorded: %v", Violations())
	}
}

func TestHTTPDefaultTransportBlocked(t *testing.T) {
	restore := Install()
	defer restore()
	_, err := http.Get("http://192.0.2.1:80/")
	if err == nil || !strings.Contains(err.Error(), "192.0.2.1:80") {
		t.Fatalf("expected blocked error naming address, got %v", err)
	}
}
