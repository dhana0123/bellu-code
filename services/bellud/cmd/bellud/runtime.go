package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cveupdate"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents"
)

// runtimeFlag guards the runtime event ingest socket.
const runtimeFlag = "security_runtime"

// runtimeKeyFile is the per-workspace HMAC token (0600) the sensor reads.
const runtimeKeyFile = "runtime.key"

// openRuntime starts the runtime event ingest on the local Unix socket. It needs
// the findings database; a disabled flag, a missing runtime dir or any failure
// yields nil and serving continues.
func openRuntime(logger interface{ Println(...any) }, getenv func(string) string, fnd *findingsWiring) *runtimeHandle {
	if fnd == nil || !config.FeatureEnabled(getenv, runtimeFlag, false) {
		return nil
	}
	sock := runtimeevents.SocketPath(getenv)
	if sock == "" {
		logger.Println("warning: runtime events unavailable: XDG_RUNTIME_DIR is not set")
		return nil
	}
	keyPath := filepath.Join(fnd.db.Dir(), runtimeKeyFile)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		b := make([]byte, 32)
		if _, err = rand.Read(b); err == nil {
			key = []byte(hex.EncodeToString(b))
			err = os.WriteFile(keyPath, key, 0o600)
		}
	}
	if err != nil {
		logger.Println("warning: runtime events unavailable:", err)
		return nil
	}
	srv, err := runtimeevents.New(runtimeevents.Config{Store: fnd.db, WorkspaceID: cveupdate.CLIWorkspace, Key: []byte(strings.TrimSpace(string(key))),
		OnEvent: func() func(wire.Event) {
			rules := runtimeevents.RuleHook(cveupdate.CLIWorkspace, fnd.store, func(err error) { logger.Println("warning: runtime rule:", err) })
			obs := runtimeevents.ObservedHook(func() func(batch.Batch) error { return fnd.ingest(context.Background()) },
				func(err error) { logger.Println("warning: observed_connection:", err) })
			return func(e wire.Event) { rules(e); obs(e) }
		}()})
	if err == nil {
		err = srv.ListenUnix(sock)
	}
	if err != nil {
		logger.Println("warning: runtime events unavailable:", err)
		return nil
	}
	return &runtimeHandle{Server: srv, jan: runtimeevents.StartJanitor(runtimeevents.JanitorConfig{
		Store: fnd.db, WorkspaceID: cveupdate.CLIWorkspace,
		RetentionDays: envInt(getenv, "BELLUCODE_RUNTIME_RETENTION_DAYS"),
		MaxBytes:      int64(envInt(getenv, "BELLUCODE_RUNTIME_MAX_MB")) << 20,
	})}
}

// runtimeHandle stops the janitor before closing the server.
type runtimeHandle struct {
	*runtimeevents.Server
	jan *runtimeevents.Janitor
}

func (h *runtimeHandle) Close() {
	h.jan.Stop()
	h.Server.Close()
}

func envInt(getenv func(string) string, k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(getenv(k)))
	return n
}
