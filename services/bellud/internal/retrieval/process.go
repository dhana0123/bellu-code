package retrieval

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ProcessConfig describes the retrieval subprocess.
type ProcessConfig struct {
	Python     string // interpreter, default python3
	ServiceDir string // services/retrieval
	SocketPath string // Unix socket
	BelluDB    string
	GraphDB    string
}

// Process is a running retrieval subprocess.
type Process struct {
	cmd    *exec.Cmd
	Client *Client
}

// Start launches the service on a Unix socket with a fresh per-run token. The
// environment is built from scratch: it carries the token, the socket and the
// two database paths, and no connector vault path, key or credential.
func Start(ctx context.Context, cfg ProcessConfig) (*Process, error) {
	tok, err := NewToken()
	if err != nil {
		return nil, err
	}
	py := cfg.Python
	if py == "" {
		py = "python3"
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		return nil, err
	}
	cmd := exec.Command(py, "-m", "retrieval_service")
	cmd.Dir = cfg.ServiceDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"BELLU_RETRIEVAL_TOKEN=" + tok,
		"BELLU_RETRIEVAL_SOCKET=" + cfg.SocketPath,
		"BELLU_DB=" + cfg.BelluDB,
		"BELLU_GRAPH_DB=" + cfg.GraphDB,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("retrieval: start: %w", err)
	}
	p := &Process{cmd: cmd, Client: NewUnix(cfg.SocketPath, tok)}
	if err := p.Client.WaitReady(ctx, 10*time.Second); err != nil {
		p.Stop()
		return nil, fmt.Errorf("retrieval: not ready: %w", err)
	}
	return p, nil
}

// Stop kills the subprocess.
func (p *Process) Stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}
