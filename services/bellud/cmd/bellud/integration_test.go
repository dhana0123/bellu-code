package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testPassword = "itest-password"

var bellud string // path of the binary built by TestMain

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	flagShort := false
	for _, a := range os.Args[1:] {
		if a == "-test.short" || a == "-test.short=true" {
			flagShort = true
		}
	}
	if !flagShort {
		dir, err := os.MkdirTemp("", "bellud-itest")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		bellud = filepath.Join(dir, "bellud")
		goBin := "go"
		if p, err := exec.LookPath("go"); err != nil {
			goBin = "/usr/local/go/bin/go"
		} else {
			goBin = p
		}
		if out, err := exec.Command(goBin, "build", "-o", bellud, ".").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
			return 1
		}
	}
	return m.Run()
}

type instance struct {
	cmd    *exec.Cmd
	base   string
	notify chan string
	logs   *bytes.Buffer
}

func startBellud(t *testing.T) *instance {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	if _, err := findBun(); err != nil {
		t.Skip("bun not available: ", err)
	}
	repo := os.Getenv("BELLUCODE_REPO")
	if repo == "" {
		// The test runs in services/bellud/cmd/bellud; the repo root is four levels up.
		if wd, err := os.Getwd(); err == nil {
			repo = filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))
		}
	}

	home := t.TempDir()
	// Pick a free port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	sockDir, err := os.MkdirTemp("", "ns")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "n.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	notify := make(chan string, 8)
	go func() {
		buf := make([]byte, 256)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			notify <- string(buf[:n])
		}
	}()

	logs := &bytes.Buffer{}
	cmd := exec.Command(bellud, "serve", "--hostname", "127.0.0.1", "--port", strconv.Itoa(port))
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"XDG_STATE_HOME="+filepath.Join(home, ".local", "state"),
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"BELLUCODE_DISABLE_MODELS_FETCH=1",
		"BELLUCODE_PASSWORD="+testPassword,
		"BELLUCODE_REPO="+repo,
		"NOTIFY_SOCKET="+sock,
		"PATH="+os.Getenv("PATH")+":/home/ubuntu/.bun/bin",
	)
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	inst := &instance{cmd: cmd, base: "http://127.0.0.1:" + strconv.Itoa(port), notify: notify, logs: logs}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("bellud logs:\n%s", logs.String())
		}
	})
	return inst
}

func (i *instance) get(path string, withAuth bool) (*http.Response, error) {
	req, _ := http.NewRequest("GET", i.base+path, nil)
	if withAuth {
		req.SetBasicAuth("bellucode", testPassword)
	}
	return (&http.Client{Timeout: 10 * time.Second}).Do(req)
}

// waitInfo polls /api/info until it returns 200.
func (i *instance) waitInfo(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	last := "no response"
	for time.Now().Before(deadline) {
		resp, err := i.get("/api/info", true)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("/api/info not 200 within %s (last: %s)\nlogs:\n%s", within, last, i.logs.String())
}

// childPIDs returns direct children of pid by scanning /proc.
func childPIDs(pid int) []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		rest := s[strings.LastIndex(s, ")")+2:]
		f := strings.Fields(rest)
		if len(f) > 1 {
			if pp, _ := strconv.Atoi(f[1]); pp == pid {
				out = append(out, p)
			}
		}
	}
	return out
}

func TestIntegrationInfoAuthAndReady(t *testing.T) {
	inst := startBellud(t)

	// READY=1 is sent exactly once after bind.
	select {
	case msg := <-inst.notify:
		if msg != "READY=1" {
			t.Fatalf("notify = %q, want READY=1", msg)
		}
	case <-time.After(90 * time.Second):
		t.Fatalf("no READY=1\nlogs:\n%s", inst.logs.String())
	}

	inst.waitInfo(t, 90*time.Second)

	// No credentials: 401 with Basic challenge.
	resp, err := inst.get("/api/info", false)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("unauthenticated: status %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	// Wrong password: 401.
	req, _ := http.NewRequest("GET", inst.base+"/api/info", nil)
	req.SetBasicAuth("bellucode", "wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong password: status %d", resp.StatusCode)
	}

	// Authenticated request is proxied to the TS child.
	resp, err = inst.get("/api/info", true)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("authenticated: status %d body %q", resp.StatusCode, body)
	}

	// The internal child credential must not leak to the client.
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), "internal") {
		t.Fatal("leaked internal credential header")
	}

	// No second READY=1.
	select {
	case msg := <-inst.notify:
		t.Fatalf("unexpected extra notify %q", msg)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestIntegrationSSEChildKillAndRecovery(t *testing.T) {
	inst := startBellud(t)
	inst.waitInfo(t, 90*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", inst.base+"/api/event", nil)
	req.SetBasicAuth("bellucode", testPassword)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("event status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type %q", ct)
	}

	// Drain the stream in the background; record how it ends.
	ended := make(chan error, 1)
	go func() {
		r := bufio.NewReader(resp.Body)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				ended <- err
				return
			}
		}
	}()

	kids := childPIDs(inst.cmd.Process.Pid)
	if len(kids) == 0 {
		t.Fatal("bellud has no child process")
	}
	for _, p := range kids {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}

	select {
	case err := <-ended:
		t.Logf("stream ended: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("SSE stream did not close after child was killed")
	}

	// bellud itself must still be alive and the child must come back.
	if err := inst.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("bellud died: %v", err)
	}
	inst.waitInfo(t, 90*time.Second)
}
