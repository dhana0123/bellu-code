//go:build linux

// Command bellu-sensor is the Linux runtime sensor. It is disabled by default and never started by bellud.
// Only this binary may import github.com/cilium/ebpf (Requirement 19.11).
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cveupdate"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents"
	"github.com/bellu/bellucode/services/bellud/internal/store/sqlite"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	tr, rate, err := configure(os.Args[1:], os.Getenv)
	if err != nil {
		log.Error("sensor configuration failed", "error", err)
		os.Exit(2)
	}
	defer tr.Close()
	if err := run(ctx, log, &BPFSource{}, tr, rate); err != nil {
		log.Error("sensor failed", "error", err)
		os.Exit(1)
	}
}

// configure builds the transport from flags. By default the sensor uses the local
// Unix socket with the workspace key; --tls-addr selects mutual TLS for remote nodes.
func configure(args []string, getenv func(string) string) (*Transport, int, error) {
	fs := flag.NewFlagSet("bellu-sensor", flag.ContinueOnError)
	var (
		dataDir = fs.String("data-dir", "", "bellud data directory (default ~/.local/share/bellucode)")
		socket  = fs.String("socket", "", "Unix socket path (default $XDG_RUNTIME_DIR/bellucode/runtime.sock)")
		tlsAddr = fs.String("tls-addr", "", "host:port of bellud for mutual TLS (remote nodes)")
		cert    = fs.String("tls-cert", "", "client certificate PEM")
		key     = fs.String("tls-key", "", "client key PEM")
		ca      = fs.String("tls-ca", "", "workspace CA PEM")
		sname   = fs.String("tls-server-name", "", "expected server name")
		node    = fs.String("node", "", "node name (default hostname)")
		rate    = fs.Int("rate", 0, "events per second, 100..50000 (default 2000)")
	)
	if err := fs.Parse(args); err != nil {
		return nil, 0, err
	}
	if *node == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, 0, err
		}
		*node = h
	}
	t := &Transport{Workspace: cveupdate.CLIWorkspace, Node: *node}
	if *tlsAddr != "" {
		cfg, err := TLSConfig(*cert, *key, *ca, *sname)
		if err != nil {
			return nil, 0, err
		}
		t.Network, t.Addr, t.TLS = "tcp", *tlsAddr, cfg
		return t, *rate, nil
	}
	if *dataDir == "" {
		d, err := config.DataDir()
		if err != nil {
			return nil, 0, err
		}
		*dataDir = d
	}
	wsDir, err := sqlite.WorkspaceDir(*dataDir, cveupdate.CLIWorkspace)
	if err != nil {
		return nil, 0, err
	}
	k, err := LoadKey(wsDir)
	if err != nil {
		return nil, 0, err
	}
	if *socket == "" {
		*socket = runtimeevents.SocketPath(getenv)
	}
	if *socket == "" {
		return nil, 0, errors.New("no socket path: set --socket or XDG_RUNTIME_DIR")
	}
	t.Network, t.Addr, t.Key = "unix", filepath.Clean(*socket), k
	return t, *rate, nil
}

// run performs the preflight, reports its status to bellud, and (when supported)
// streams rate-limited events through the reconnect buffer.
func run(ctx context.Context, log *slog.Logger, src EventSource, tr *Transport, rate int) error {
	pf, err := RunPreflight()
	if err != nil {
		return err
	}
	log.Info("preflight", "status", pf.Status, "reason", pf.Reason)
	if err := tr.SendStatus(pf, nil); err != nil {
		log.Warn("status not delivered; will retry", "error", err)
		go retryStatus(ctx, tr, pf)
	}
	if pf.Status != StatusOK || src == nil {
		<-ctx.Done()
		return nil
	}
	lim := NewLimiter(rate)
	sender := NewSender(tr.Send, NewReconnectBuffer(0))
	go sender.Retry(ctx)
	go lim.Run(ctx, sender.Send, func(d map[string]uint64) {
		if err := tr.SendStatus(pf, d); err != nil {
			log.Warn("drop report not delivered", "error", err)
		}
	})
	return src.Start(ctx, func(e Event) {
		if e.Node == "" {
			e.Node = tr.Node
		}
		lim.Offer(Normalize(e))
	})
}

func retryStatus(ctx context.Context, tr *Transport, pf Preflight) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if tr.SendStatus(pf, nil) == nil {
				return
			}
		}
	}
}
