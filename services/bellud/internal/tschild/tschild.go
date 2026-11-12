// Package tschild supervises the TypeScript core as a loopback-only child process.
//
// Readiness: the real server prints {"url": ...} only in --stdio mode (default mode prints
// "server listening on <url>"). --stdio is also the mode that treats stdin EOF as the end of
// the ownership lease and removes the password from the environment seen by tools, so the
// default command uses it. The parser accepts both line forms.
package tschild

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/logx"
)

// State is the supervisor lifecycle state.
type State string

const (
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateDegraded State = "degraded"
	StateStopped  State = "stopped"
)

const (
	// Username is the Basic-auth username the TS server expects (compatibility name).
	Username = "opencode"
	// PasswordEnv is the child env var carrying the internal credential (compatibility name).
	PasswordEnv = "OPENCODE_PASSWORD"

	minBackoff = 500 * time.Millisecond
	maxBackoff = 15 * time.Second
)

// passwordEnvNames are stripped from the inherited environment so the external secret never reaches the child.
var passwordEnvNames = []string{"OPENCODE_PASSWORD", "OPENCODE_SERVER_PASSWORD", "BELLUCODE_PASSWORD"}

// Child describes a started, probed child.
type Child struct {
	URL      *url.URL
	Password string // internal credential, never logged
}

// Config configures a Supervisor.
type Config struct {
	// Command defaults to bun run src/index.ts serve --stdio --hostname 127.0.0.1 --port 0.
	Command []string
	// Dir is the child working directory (packages/cli).
	Dir string
	// Env holds extra child env entries (e.g. OPENCODE_CONFIG_CONTENT). Password entries are ignored.
	Env map[string]string
	// BaseEnv is the inherited environment ("K=V"); defaults to os.Environ().
	BaseEnv []string

	StartTimeout time.Duration // default 30s
	StopGrace    time.Duration // default 5s
	// StableAfter is how long a child must stay up for the failure count and backoff to reset. Default 10s.
	StableAfter time.Duration
	// DegradedAfter is the consecutive failure count that sets StateDegraded. Default 3.
	DegradedAfter int
	// StderrLines is how many recent stderr lines are kept for diagnostics. Default 50.
	StderrLines int

	Out    io.Writer // relay target for child stdout/stderr; default os.Stderr
	Logger *log.Logger
}

// DefaultCommand is the command used when Config.Command is empty.
func DefaultCommand() []string {
	return []string{"bun", "run", "src/index.ts", "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"}
}

// Supervisor starts, watches, restarts and stops the child.
type Supervisor struct {
	cfg Config

	mu       sync.Mutex
	current  *Child
	state    State
	lastErr  error
	stderr   []string
	curStdin io.Closer
	curProc  *os.Process

	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a Supervisor with defaults applied.
func New(cfg Config) *Supervisor {
	if len(cfg.Command) == 0 {
		cfg.Command = DefaultCommand()
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 30 * time.Second
	}
	if cfg.StopGrace <= 0 {
		cfg.StopGrace = 5 * time.Second
	}
	if cfg.StableAfter <= 0 {
		cfg.StableAfter = 10 * time.Second
	}
	if cfg.DegradedAfter <= 0 {
		cfg.DegradedAfter = 3
	}
	if cfg.StderrLines <= 0 {
		cfg.StderrLines = 50
	}
	if cfg.Out == nil {
		cfg.Out = os.Stderr
	}
	if cfg.Logger == nil {
		cfg.Logger = logx.New(os.Stderr)
	}
	if cfg.BaseEnv == nil {
		cfg.BaseEnv = os.Environ()
	}
	return &Supervisor{cfg: cfg, state: StateStopped}
}

// Start launches the restart loop and returns immediately; use Current to observe readiness.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("tschild: already started")
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.state = StateStarting
	go s.loop(loopCtx)
	return nil
}

// Current returns the ready child, or nil while starting, restarting or stopped.
func (s *Supervisor) Current() *Child {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// State returns the lifecycle state.
func (s *Supervisor) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// LastError returns the most recent start or exit error.
func (s *Supervisor) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// LastStderr returns the most recent child stderr lines (credentials redacted).
func (s *Supervisor) LastStderr() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stderr...)
}

// Stop ends the restart loop, closes the child's stdin lease, waits for the grace period, then kills.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		s.mu.Lock()
		if s.curProc != nil {
			killGroup(s.curProc)
		}
		s.mu.Unlock()
		return ctx.Err()
	}
	return nil
}

func (s *Supervisor) loop(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.current, s.state = nil, StateStopped
		s.mu.Unlock()
		close(s.done)
	}()
	delay := minBackoff
	failures := 0
	for ctx.Err() == nil {
		began := time.Now()
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(began) >= s.cfg.StableAfter {
			failures, delay = 0, minBackoff
		}
		failures++
		s.mu.Lock()
		s.lastErr = err
		if failures >= s.cfg.DegradedAfter {
			s.state = StateDegraded
		} else {
			s.state = StateStarting
		}
		s.mu.Unlock()
		s.cfg.Logger.Printf("ts child exited (%v); restart in %s", err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxBackoff)
	}
}

// runOnce starts one child, waits for readiness, publishes it, and blocks until it exits or ctx ends.
func (s *Supervisor) runOnce(ctx context.Context) error {
	password, err := GeneratePassword()
	if err != nil {
		return err
	}
	cmd := exec.Command(s.cfg.Command[0], s.cfg.Command[1:]...)
	cmd.Dir = s.cfg.Dir
	cmd.Env = s.buildEnv(password)
	cmd.SysProcAttr = procAttr()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ts child: %w", err)
	}
	s.mu.Lock()
	s.curStdin, s.curProc = stdin, cmd.Process
	s.mu.Unlock()

	ready := make(chan string, 1)
	var pipes sync.WaitGroup
	pipes.Add(2)
	go func() {
		defer pipes.Done()
		s.pumpStdout(stdout, password, ready)
	}()
	go func() {
		defer pipes.Done()
		s.pumpStderr(stderr, password)
	}()
	// exited is closed (not sent on) so every waiter observes the exit; the result is in waitRes.
	exited := make(chan struct{})
	var waitRes error
	go func() {
		pipes.Wait() // os/exec requires reads to finish before Wait
		waitRes = cmd.Wait()
		close(exited)
	}()

	child, err := s.awaitReady(ctx, ready, exited, password)
	if err != nil {
		s.terminate(cmd.Process, stdin, exited)
		return err
	}
	s.mu.Lock()
	s.current, s.state = child, StateRunning
	s.mu.Unlock()

	var waitErr error
	select {
	case <-exited:
		waitErr = waitRes
		if waitErr == nil {
			waitErr = errors.New("ts child exited")
		}
	case <-ctx.Done():
		s.terminate(cmd.Process, stdin, exited)
	}
	s.mu.Lock()
	s.current, s.curStdin, s.curProc = nil, nil, nil
	s.mu.Unlock()
	return waitErr
}

func (s *Supervisor) awaitReady(ctx context.Context, ready <-chan string, exited <-chan struct{}, password string) (*Child, error) {
	tctx, cancel := context.WithTimeout(ctx, s.cfg.StartTimeout)
	defer cancel()
	var raw string
	select {
	case raw = <-ready:
	case <-exited:
		return nil, errors.New("ts child exited before readiness")
	case <-tctx.Done():
		return nil, fmt.Errorf("ts child readiness: %w", tctx.Err())
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("ts child reported invalid url %q", raw)
	}
	if err := probe(tctx, u, password, exited); err != nil {
		return nil, err
	}
	return &Child{URL: u, Password: password}, nil
}

// probe polls GET /api/info (server.info) with the internal credential until 200.
func probe(ctx context.Context, base *url.URL, password string, exited <-chan struct{}) error {
	target := base.ResolveReference(&url.URL{Path: "/api/info"}).String()
	client := &http.Client{Timeout: 3 * time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(Username, password)
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ts child probe: %w", ctx.Err())
		case <-exited:
			return errors.New("ts child exited during probe")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// terminate closes the stdin lease, waits for the grace period, then kills the process group.
func (s *Supervisor) terminate(p *os.Process, stdin io.Closer, exited <-chan struct{}) {
	_ = stdin.Close()
	select {
	case <-exited:
		return
	case <-time.After(s.cfg.StopGrace):
	}
	killGroup(p)
	<-exited
}

func killGroup(p *os.Process) { killProcessGroup(p) }

func (s *Supervisor) pumpStdout(r io.Reader, password string, ready chan<- string) {
	relay := logx.NewRelay(redactWriter{s.cfg.Out, password})
	defer relay.Flush()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	found := false
	for sc.Scan() {
		line := sc.Text()
		if !found {
			if u, ok := ParseReady(line); ok {
				found = true
				ready <- u
				continue // readiness line is protocol, not log output
			}
		}
		if strings.HasPrefix(line, "server password ") {
			continue // default mode echoes a generated password; never relay it
		}
		_, _ = relay.Write([]byte(line + "\n"))
	}
}

func (s *Supervisor) pumpStderr(r io.Reader, password string) {
	relay := logx.NewRelay(redactWriter{s.cfg.Out, password})
	defer relay.Flush()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.ReplaceAll(sc.Text(), password, "[REDACTED]")
		s.mu.Lock()
		s.stderr = append(s.stderr, line)
		if n := len(s.stderr) - s.cfg.StderrLines; n > 0 {
			s.stderr = s.stderr[n:]
		}
		s.mu.Unlock()
		_, _ = relay.Write([]byte(line + "\n"))
	}
}

// buildEnv inherits BaseEnv minus external password variables, adds cfg.Env, then sets the internal credential last.
func (s *Supervisor) buildEnv(password string) []string {
	skip := map[string]bool{}
	for _, n := range passwordEnvNames {
		skip[n] = true
	}
	env := make([]string, 0, len(s.cfg.BaseEnv)+len(s.cfg.Env)+1)
	for _, kv := range s.cfg.BaseEnv {
		k, _, _ := strings.Cut(kv, "=")
		if skip[k] {
			continue
		}
		if _, over := s.cfg.Env[k]; over {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range s.cfg.Env {
		if skip[k] {
			continue
		}
		env = append(env, k+"="+v)
	}
	return append(env, PasswordEnv+"="+password)
}

// GeneratePassword returns a fresh 32-byte base64url internal credential.
func GeneratePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseReady extracts the server URL from a stdout line. It accepts the --stdio form
// {"url":"http://..."} and the default-mode form "server listening on http://...".
func ParseReady(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var v struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &v) == nil && v.URL != "" {
			return v.URL, true
		}
		return "", false
	}
	if rest, ok := strings.CutPrefix(line, "server listening on "); ok {
		if rest = strings.TrimSpace(rest); rest != "" {
			return rest, true
		}
	}
	return "", false
}

// redactWriter masks the internal credential in relayed output.
type redactWriter struct {
	w        io.Writer
	password string
}

func (r redactWriter) Write(p []byte) (int, error) {
	if r.password == "" || !bytes.Contains(p, []byte(r.password)) {
		return r.w.Write(p)
	}
	_, err := r.w.Write(bytes.ReplaceAll(p, []byte(r.password), []byte("[REDACTED]")))
	return len(p), err
}
