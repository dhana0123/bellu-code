// Package config reads bellud configuration from the environment.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

const (
	DefaultHostname = "127.0.0.1"
	DefaultPort     = 4096
)

// Config is the resolved bellud configuration.
type Config struct {
	Password string
	Hostname string
	Port     int
	CORS     string
	WebDist  string
}

// Load reads configuration through getenv (use os.Getenv in production).
// Only BELLUCODE_* names are read, plus the legacy OPENCODE_PASSWORD fallback.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Password: getenv("BELLUCODE_PASSWORD"),
		Hostname: getenv("BELLUCODE_HOSTNAME"),
		Port:     DefaultPort,
		CORS:     getenv("BELLUCODE_CORS"),
		WebDist:  getenv("BELLUCODE_WEB_DIST"),
	}
	if c.Password == "" {
		c.Password = getenv("OPENCODE_PASSWORD") // (legacy name from before the rebrand)
	}
	if c.Hostname == "" {
		c.Hostname = DefaultHostname
	}
	if raw := getenv("BELLUCODE_PORT"); raw != "" {
		p, err := strconv.Atoi(raw)
		if err != nil || p < 0 || p > 65535 {
			return c, fmt.Errorf("invalid BELLUCODE_PORT %q", raw)
		}
		c.Port = p
	}
	return c, nil
}

// LoadEnv loads configuration from the process environment.
func LoadEnv() (Config, error) { return Load(os.Getenv) }

// Addr returns host:port for listening.
func (c Config) Addr() string {
	return net.JoinHostPort(c.Hostname, strconv.Itoa(c.Port))
}

// Warnings returns non-fatal configuration warnings.
func (c Config) Warnings() []string {
	if c.Password == "" && !isLoopback(c.Hostname) {
		return []string{fmt.Sprintf("hostname %q is not loopback and no password is set; the server is unauthenticated", c.Hostname)}
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ConfigDir returns ~/.config/bellucode.
func ConfigDir() (string, error) { return homeJoin(".config", "bellucode") }

// DataDir returns ~/.local/share/bellucode.
func DataDir() (string, error) { return homeJoin(".local", "share", "bellucode") }

func homeJoin(parts ...string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{home}, parts...)...), nil
}
