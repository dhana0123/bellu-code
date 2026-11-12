// Command stubchild is a tiny stand-in for the TS server used by supervisor tests.
//
// STUB_MODE: ok (default), hang (never ready, ignores stdin), crash (exit 1 at once),
// crashafter (ready, then exit after STUB_LIVE_MS), leak (ok, but prints the password).
// STUB_LOG: file that receives one unix-nano line per start.
// STUB_MARKER: file written when stdin reaches EOF (the ownership lease closing).
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	if p := os.Getenv("STUB_LOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, time.Now().UnixNano())
			f.Close()
		}
	}
	mode := os.Getenv("STUB_MODE")
	pw := os.Getenv("BELLUCODE_PASSWORD")
	switch mode {
	case "hang":
		time.Sleep(time.Hour) // select{} would die on Go's deadlock detector
	case "crash":
		fmt.Fprintln(os.Stderr, "stub crashing")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "bellucode" || p != pw || pw == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	go http.Serve(ln, mux)

	fmt.Printf("{\"url\":\"http://%s\"}\n", ln.Addr())
	if mode == "leak" {
		fmt.Println("stdout leak " + pw)
		fmt.Fprintln(os.Stderr, "stderr leak "+pw)
	}
	if mode == "crashafter" {
		ms, _ := strconv.Atoi(os.Getenv("STUB_LIVE_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	if p := os.Getenv("STUB_MARKER"); p != "" {
		_ = os.WriteFile(p, []byte("eof"), 0o644)
	}
}
