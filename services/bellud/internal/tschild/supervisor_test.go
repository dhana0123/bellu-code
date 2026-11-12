package tschild

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var stubBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tschild-stub")
	if err != nil {
		panic(err)
	}
	stubBin = filepath.Join(dir, "stubchild")
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = "/usr/local/go/bin/go"
	}
	if out, err := exec.Command(goBin, "build", "-o", stubBin, "./testdata/stubchild").CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("build stub child: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type harness struct {
	sup    *Supervisor
	out    *syncBuf
	logs   *syncBuf
	log    string
	marker string
}

func newHarness(t *testing.T, env map[string]string, tweak func(*Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{out: &syncBuf{}, logs: &syncBuf{}, log: filepath.Join(dir, "starts"), marker: filepath.Join(dir, "eof")}
	e := map[string]string{"STUB_LOG": h.log, "STUB_MARKER": h.marker}
	for k, v := range env {
		e[k] = v
	}
	cfg := Config{
		Command:      []string{stubBin},
		Env:          e,
		StartTimeout: 5 * time.Second,
		StopGrace:    2 * time.Second,
		Out:          h.out,
		Logger:       log.New(h.logs, "", 0),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	h.sup = New(cfg)
	if err := h.sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.sup.Stop(ctx)
	})
	return h
}

func (h *harness) starts() []time.Time {
	b, _ := os.ReadFile(h.log)
	var ts []time.Time
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.ParseInt(f, 10, 64); err == nil {
			ts = append(ts, time.Unix(0, n))
		}
	}
	return ts
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSupervisorReadyAndLeaseClose(t *testing.T) {
	h := newHarness(t, nil, nil)
	waitFor(t, 5*time.Second, "ready", func() bool { return h.sup.Current() != nil })
	c := h.sup.Current()
	if h.sup.State() != StateRunning {
		t.Fatalf("state = %s", h.sup.State())
	}
	if c.URL.Hostname() != "127.0.0.1" {
		t.Fatalf("url = %s", c.URL)
	}
	// The child only answers 200 when OPENCODE_PASSWORD matches the credential we hold.
	req, _ := http.NewRequest(http.MethodGet, c.URL.String()+"/api/info", nil)
	req.SetBasicAuth(Username, c.Password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("authenticated request: %v %v", resp, err)
	}
	resp.Body.Close()

	if _, err := os.Stat(h.marker); err == nil {
		t.Fatal("lease closed while child running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.sup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.marker); err != nil {
		t.Fatalf("child did not see stdin EOF on shutdown: %v", err)
	}
	if h.sup.Current() != nil || h.sup.State() != StateStopped {
		t.Fatalf("after stop: current=%v state=%s", h.sup.Current(), h.sup.State())
	}
}

func TestSupervisorStartTimeoutKillsAndRetries(t *testing.T) {
	h := newHarness(t, map[string]string{"STUB_MODE": "hang"}, func(c *Config) {
		c.StartTimeout = 300 * time.Millisecond
		c.StopGrace = 200 * time.Millisecond
	})
	waitFor(t, 5*time.Second, "second attempt", func() bool { return len(h.starts()) >= 2 })
	if h.sup.Current() != nil {
		t.Fatal("hung child must not be ready")
	}
	err := h.sup.LastError()
	if err == nil || !strings.Contains(err.Error(), "readiness") {
		t.Fatalf("last error = %v", err)
	}
	if gap := h.starts()[1].Sub(h.starts()[0]); gap < 300*time.Millisecond+minBackoff-50*time.Millisecond {
		t.Fatalf("retry came too early: %s\n%s\n%s", gap, h.logs.String(), h.out.String())
	}
}

func TestSupervisorCrashBackoffDoubles(t *testing.T) {
	h := newHarness(t, map[string]string{"STUB_MODE": "crash"}, func(c *Config) {
		c.StableAfter = time.Minute
		c.DegradedAfter = 100
	})
	waitFor(t, 8*time.Second, "three starts", func() bool { return len(h.starts()) >= 3 })
	s := h.starts()
	g1, g2 := s[1].Sub(s[0]), s[2].Sub(s[1])
	if g1 < 450*time.Millisecond || g1 > 900*time.Millisecond {
		t.Fatalf("first gap = %s, want about 500ms", g1)
	}
	if g2 < 950*time.Millisecond || g2 > 1600*time.Millisecond {
		t.Fatalf("second gap = %s, want about 1s", g2)
	}
	if h.sup.Current() != nil {
		t.Fatal("crashing child must not be ready")
	}
}

func TestSupervisorBackoffResetsAfterStableRun(t *testing.T) {
	h := newHarness(t, map[string]string{"STUB_MODE": "crashafter", "STUB_LIVE_MS": "400"}, func(c *Config) {
		c.StableAfter = 200 * time.Millisecond
	})
	waitFor(t, 8*time.Second, "three starts", func() bool { return len(h.starts()) >= 3 })
	s := h.starts()
	// Each run lives ~400ms and is stable, so the delay stays at 500ms (about 900ms per cycle).
	// Without the reset the second gap would be about 1.4s.
	if g2 := s[2].Sub(s[1]); g2 > 1150*time.Millisecond {
		t.Fatalf("backoff not reset: second gap = %s", g2)
	}
	if h.sup.State() == StateDegraded {
		t.Fatal("stable runs must not degrade")
	}
}

func TestSupervisorNeverLogsCredential(t *testing.T) {
	h := newHarness(t, map[string]string{"STUB_MODE": "leak"}, nil)
	waitFor(t, 5*time.Second, "ready", func() bool { return h.sup.Current() != nil })
	pw := h.sup.Current().Password
	waitFor(t, 5*time.Second, "relayed leak lines", func() bool {
		return strings.Contains(h.out.String(), "stderr leak") && strings.Contains(h.out.String(), "stdout leak")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.sup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	all := h.out.String() + h.logs.String() + strings.Join(h.sup.LastStderr(), "\n")
	if strings.Contains(all, pw) {
		t.Fatalf("credential leaked into logs: %q", all)
	}
	if !strings.Contains(all, "[REDACTED]") {
		t.Fatalf("expected redaction marker in %q", all)
	}
}
