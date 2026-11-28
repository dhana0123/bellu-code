// Package secretscan is the secret scanner adapter. It runs the embedded
// Gitleaks library (never an external process, never TruffleHog) over a
// working tree and reports one Finding per detection. A Finding carries a
// salted fingerprint and a short prefix of the secret, never the secret
// (Requirements 9.1, 9.3, 9.4, 9.7, 9.9, 9.13).
package secretscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"

	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

const (
	// MaxFileSize is the largest file scanned; bigger files are skipped.
	MaxFileSize = 1 << 20
	// SaltFile is the per-workspace salt file inside the workspace directory.
	SaltFile = "secretscan.salt"
	// MinPrefixValueLen is the shortest value for which a prefix is stored.
	MinPrefixValueLen = 12
	// MaxPrefixLen is the longest stored prefix, in characters.
	MaxPrefixLen = 4

	maxExcerpt = 200
)

// DefaultSkipDirs are never descended into.
var DefaultSkipDirs = map[string]bool{"node_modules": true, ".git": true, "dist": true}

// Options configure an Engine.
type Options struct {
	// WorkspaceDir holds the per-workspace salt. When empty a fixed built-in
	// salt is used, which keeps fingerprints stable but not workspace-unique.
	WorkspaceDir string
	// ConfigPath is an optional custom Gitleaks config merged over the
	// default rules. A missing, unreadable or invalid file fails New.
	ConfigPath string
}

// Hit is one detection. It holds no secret value.
type Hit struct {
	RuleID      string
	File        string
	Line        int // 1-based
	Commit      string
	Fingerprint string
	Prefix      string
	Excerpt     string // redacted
}

// Engine wraps one Gitleaks detector.
type Engine struct {
	det  *detect.Detector
	salt []byte
}

var defaultSalt = sha256.Sum256([]byte("bellud-secretscan-default-salt"))

// New builds the engine. It fails, naming the file, when the custom config
// cannot be used, so no scan starts with a half-applied config.
func New(o Options) (*Engine, error) {
	salt, err := loadSalt(o.WorkspaceDir)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(o.ConfigPath)
	if err != nil {
		return nil, err
	}
	return &Engine{det: detect.NewDetector(cfg), salt: salt}, nil
}

func loadSalt(dir string) ([]byte, error) {
	if dir == "" {
		return defaultSalt[:], nil
	}
	p := filepath.Join(dir, SaltFile)
	b, err := os.ReadFile(p)
	if err == nil && len(b) >= 16 {
		return b, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("secretscan: salt file %q: %w", p, err)
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("secretscan: salt: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secretscan: salt file %q: %w", p, err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("secretscan: salt file %q: %w", p, err)
	}
	return b, nil
}

func loadConfig(path string) (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if path == "" {
		if err := v.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
			return config.Config{}, fmt.Errorf("secretscan: default config: %w", err)
		}
	} else {
		raw, err := os.ReadFile(path)
		if err != nil {
			return config.Config{}, fmt.Errorf("secretscan: custom config %q: %w", path, err)
		}
		if err := v.ReadConfig(bytes.NewReader(raw)); err != nil {
			return config.Config{}, fmt.Errorf("secretscan: custom config %q: invalid: %w", path, err)
		}
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("secretscan: config %q: invalid: %w", path, err)
	}
	if path != "" && vc.Extend.Path == "" && vc.Extend.URL == "" {
		vc.Extend.UseDefault = true // merge over the default rules
	}
	cfg, err := translate(vc)
	if err != nil {
		return config.Config{}, fmt.Errorf("secretscan: custom config %q: invalid: %w", path, err)
	}
	return cfg, nil
}

// translate turns a regexp panic of Gitleaks' Translate into an error.
func translate(vc config.ViperConfig) (cfg config.Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return vc.Translate()
}

// Fingerprint is hex(sha256(salt || value)).
func (e *Engine) Fingerprint(value string) string {
	h := sha256.New()
	h.Write(e.salt)
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// Prefix returns at most the first four characters of value, and nothing when
// value is shorter than twelve characters.
func Prefix(value string) string {
	r := []rune(value)
	if len(r) < MinPrefixValueLen {
		return ""
	}
	return string(r[:MaxPrefixLen])
}

// ScanContent scans one file's content. name is reported as Hit.File. The
// Gitleaks Secret, Match, Line and Fragment fields are cleared as soon as the
// fingerprint and the redacted excerpt exist.
func (e *Engine) ScanContent(ctx context.Context, name string, content []byte) []Hit {
	fs := e.det.DetectContext(ctx, detect.Fragment{Raw: string(content), FilePath: name})
	out := make([]Hit, 0, len(fs))
	for _, f := range fs {
		h := Hit{RuleID: f.RuleID, File: f.File, Line: f.StartLine + 1, Commit: f.Commit}
		h.Fingerprint = e.Fingerprint(f.Secret)
		h.Prefix = Prefix(f.Secret)
		line := f.Line
		if line == "" {
			line = f.Match
		}
		for _, s := range []string{f.Secret, f.Match} {
			if s != "" {
				line = strings.ReplaceAll(line, s, "[REDACTED]")
			}
		}
		f.Secret, f.Match, f.Line, f.Fragment = "", "", "", nil
		line = strings.TrimSpace(line)
		if len(line) > maxExcerpt {
			line = line[:maxExcerpt]
		}
		if red, err := redact.Text(line); err == nil {
			h.Excerpt = red
		} else {
			h.Excerpt = redact.FailedPlaceholder
		}
		out = append(out, h)
	}
	return out
}

// Walk calls fn for each regular, non-binary file of at most MaxFileSize bytes
// under root. The root itself is always entered whatever its name. Unreadable
// entries are skipped.
func Walk(ctx context.Context, root string, skip map[string]bool, fn func(path string, content []byte)) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if b, ok := readText(p); ok {
			fn(p, b)
		}
		return nil
	})
}

func readText(p string) ([]byte, bool) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > MaxFileSize {
		return nil, false
	}
	br := bufio.NewReaderSize(f, 64<<10)
	head, _ := br.Peek(8000)
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, false
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(br); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}
