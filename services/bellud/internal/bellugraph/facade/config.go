// Package facade is the bellud-owned adapter over the in-process Bellu Graph
// Engine (internal/bellugraph/internal/bge). It opens and supervises the
// store, resolves callers, audits operator writes and converts engine types at
// the boundary; only this package (and the thin internal/graph re-export)
// touches the engine packages.
package facade

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Environment variable names.
const (
	EnvEnabled    = "BELLU_GRAPH_ENABLED"
	EnvDir        = "BELLU_GRAPH_DIR"
	EnvOTLPListen = "BELLU_GRAPH_OTLP_LISTEN"
	EnvRetention  = "BELLU_GRAPH_RETENTION"
	EnvLogLevel   = "BELLU_GRAPH_LOG_LEVEL"
)

// Config is the graph engine configuration.
type Config struct {
	Enabled    bool
	Dir        string        // default ~/.local/share/bellucode/graph, created 0700
	Retention  time.Duration // 0 = keep forever
	OTLPListen string        // "" disables the OTLP listener (default)
	LogLevel   slog.Level
	MCPToken   string // bearer for the MCP endpoint; a non-empty value is an implicit RoleWrite grant
	// Grants maps bearer tokens to roles in addition to MCPToken.
	Grants []Grant

	// Logger receives engine logs. Nil means slog.Default().
	Logger *slog.Logger
	// MCPExtras, when set, is called by MCPHandler with the MCP server after
	// the built-in tools are registered, so callers can add read-only tools.
	MCPExtras func(*mcp.Server)
	// OpenTimeout bounds Open; zero means 5s.
	OpenTimeout time.Duration
}

// ConfigError reports an unparsable environment variable and names it.
type ConfigError struct {
	Var   string
	Value string
	Msg   string
}

// RegistryVar is the ConfigError.Var of a failed schema registry merge. Msg
// then holds every failure.
const RegistryVar = "graph schema registry"

func (e *ConfigError) Error() string {
	if e.Var == RegistryVar {
		return e.Var + ": " + e.Msg
	}
	return fmt.Sprintf("%s: invalid value %q: %s", e.Var, e.Value, e.Msg)
}

// DefaultDir returns ~/.local/share/bellucode/graph.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving default graph dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "bellucode", "graph"), nil
}

// LoadConfig reads the BELLU_GRAPH_* variables via getenv. defaultEnabled is
// the build default (on in dev, off in release); an explicit value wins.
// Every unparsable variable is reported; the joined error names each one.
func LoadConfig(getenv func(string) string, defaultEnabled bool) (Config, error) {
	cfg := Config{Enabled: defaultEnabled, LogLevel: slog.LevelInfo}
	var errs []error

	if v := strings.TrimSpace(getenv(EnvEnabled)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, &ConfigError{EnvEnabled, v, "want a boolean (true/false)"})
		} else {
			cfg.Enabled = b
		}
	}
	if v := getenv(EnvDir); strings.TrimSpace(v) != "" {
		cfg.Dir = v
	} else if d, err := DefaultDir(); err != nil {
		errs = append(errs, &ConfigError{EnvDir, "", err.Error()})
	} else {
		cfg.Dir = d
	}
	if v := strings.TrimSpace(getenv(EnvRetention)); v != "" {
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			errs = append(errs, &ConfigError{EnvRetention, v, "want a duration such as 720h"})
		case d < 0:
			errs = append(errs, &ConfigError{EnvRetention, v, "must not be negative"})
		default:
			cfg.Retention = d
		}
	}
	if v := strings.TrimSpace(getenv(EnvOTLPListen)); v != "" {
		if err := validHostPort(v); err != nil {
			errs = append(errs, &ConfigError{EnvOTLPListen, v, "want host:port"})
		} else {
			cfg.OTLPListen = v
		}
	}
	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
		switch v {
		case "debug":
			cfg.LogLevel = slog.LevelDebug
		case "info":
			cfg.LogLevel = slog.LevelInfo
		case "warn":
			cfg.LogLevel = slog.LevelWarn
		case "error":
			cfg.LogLevel = slog.LevelError
		default:
			errs = append(errs, &ConfigError{EnvLogLevel, v, "want one of debug, info, warn, error"})
		}
	}
	return cfg, errors.Join(errs...)
}

func validHostPort(s string) error {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("bad port %q", port)
	}
	return nil
}
