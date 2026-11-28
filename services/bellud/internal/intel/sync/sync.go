// Package sync downloads, verifies, and imports the signed intel corpus.
//
// The only outbound request is a GET of the latest.json pointer and a GET of
// the bundle it names. Neither carries a body, query string, cookie, or any
// identifier. A local bundle path is imported without touching the network.
package sync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	gosync "sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/intel/bundle"
	"github.com/bellu/bellucode/services/bellud/internal/intel/store"
)

// Sync states reported by Status.
const (
	StateNotConfigured = "not_configured"
	StateDisabled      = "disabled"
	StateIdle          = "idle"
	StateSyncing       = "syncing"
	StateOK            = "ok"
	StateError         = "error"
)

// Failure kinds recorded in the store's last_error.
const (
	ErrPointerUnreachable = "pointer_unreachable"
	ErrPointerInvalid     = "pointer_invalid"
	ErrDownloadFailed     = "download_failed"
	ErrDownloadCorrupt    = "download_corrupt"
	ErrVerificationFailed = "verification_failed"
	ErrImportFailed       = "import_failed"
)

const (
	defaultInterval   = 24 * time.Hour
	defaultFirstDelay = 30 * time.Second
	defaultRetryDelay = time.Hour
	jitterFraction    = 0.10
	pointerTimeout    = 15 * time.Second
	downloadTimeout   = 10 * time.Minute
	maxPointerBytes   = 1 << 20
)

// Config configures a Syncer. Zero durations take the design defaults.
type Config struct {
	// URL is the latest.json pointer URL. Empty means not configured.
	URL string
	// LocalBundle is a .tar.zst path. When set it is used instead of URL and
	// the network is never touched.
	LocalBundle string
	// Key is the pinned ed25519 public key. Nil disables sync.
	Key ed25519.PublicKey
	// Version is the bellud version used in the User-Agent.
	Version string
	// HTTPClient overrides the client (tests). Its Jar is ignored and it must
	// not add headers.
	HTTPClient *http.Client

	Interval   time.Duration // default 24h
	FirstDelay time.Duration // default 30s
	RetryDelay time.Duration // default 1h
	// Rand returns a value in [0,1) for the jitter. Default math/rand.
	Rand func() float64
}

// Status is the sync state shown by the intel status route.
type Status struct {
	State        string    `json:"state"`
	Version      string    `json:"version"`
	Records      int       `json:"records"`
	LastSyncedAt time.Time `json:"last_synced_at"`
	LastError    string    `json:"last_error"`
}

// Syncer keeps the intel store current.
type Syncer struct {
	cfg        Config
	store      *store.Store
	onImported func()
	now        func() time.Time
	client     *http.Client

	run gosync.Mutex // one RunOnce at a time

	mu       gosync.Mutex
	syncing  bool
	lastFail bool
	// local bundle identity of the last successful import
	localMod  time.Time
	localSize int64
	localSeen bool
}

// New returns a Syncer. onImported may be nil.
func New(cfg Config, st *store.Store, onImported func()) *Syncer {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.FirstDelay <= 0 {
		cfg.FirstDelay = defaultFirstDelay
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = defaultRetryDelay
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	c := &http.Client{}
	if cfg.HTTPClient != nil {
		cp := *cfg.HTTPClient
		cp.Jar = nil
		c = &cp
	}
	return &Syncer{cfg: cfg, store: st, onImported: onImported, now: time.Now, client: c}
}

func (s *Syncer) configured() bool { return s.cfg.URL != "" || s.cfg.LocalBundle != "" }

// Run is the schedule loop. It returns when ctx is done.
func (s *Syncer) Run(ctx context.Context) {
	if !s.configured() || len(s.cfg.Key) != ed25519.PublicKeySize {
		return
	}
	delay := s.cfg.FirstDelay
	for {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := s.RunOnce(ctx); err != nil {
			delay = s.cfg.RetryDelay
		} else {
			delay = s.cfg.Interval + time.Duration(s.cfg.Rand()*jitterFraction*float64(s.cfg.Interval))
		}
	}
}

// RunOnce performs one sync. A nil return means the corpus is current, either
// because it was imported or because nothing changed. Failures are recorded in
// the store, the previous corpus stays active, and the error is returned.
func (s *Syncer) RunOnce(ctx context.Context) error {
	if !s.configured() {
		return nil
	}
	if len(s.cfg.Key) != ed25519.PublicKeySize {
		return errors.New("disabled: no pinned key")
	}
	s.run.Lock()
	defer s.run.Unlock()
	s.setSyncing(true)
	imported, err := s.runLocked(ctx)
	s.mu.Lock()
	s.syncing = false
	s.lastFail = err != nil
	s.mu.Unlock()
	if err != nil {
		_ = s.store.RecordError(err.Error())
		return err
	}
	if imported && s.onImported != nil {
		s.onImported()
	}
	return nil
}

func (s *Syncer) setSyncing(v bool) {
	s.mu.Lock()
	s.syncing = v
	s.mu.Unlock()
}

func (s *Syncer) runLocked(ctx context.Context) (bool, error) {
	if s.cfg.LocalBundle != "" {
		return s.importLocal(ctx)
	}
	return s.syncRemote(ctx)
}

func (s *Syncer) importLocal(ctx context.Context) (bool, error) {
	fi, err := os.Stat(s.cfg.LocalBundle)
	if err != nil {
		return false, fmt.Errorf("%s: %v", ErrDownloadFailed, err)
	}
	s.mu.Lock()
	same := s.localSeen && fi.ModTime().Equal(s.localMod) && fi.Size() == s.localSize
	s.mu.Unlock()
	if same {
		return false, nil
	}
	f, err := os.Open(s.cfg.LocalBundle)
	if err != nil {
		return false, fmt.Errorf("%s: %v", ErrDownloadFailed, err)
	}
	defer f.Close()
	if err := s.verifyAndImport(ctx, f, store.ImportInfo{}); err != nil {
		return false, err
	}
	s.mu.Lock()
	s.localSeen, s.localMod, s.localSize = true, fi.ModTime(), fi.Size()
	s.mu.Unlock()
	return true, nil
}

func (s *Syncer) syncRemote(ctx context.Context) (bool, error) {
	pointerURL, err := url.Parse(s.cfg.URL)
	if err != nil || !allowedURL(pointerURL) {
		return false, fmt.Errorf("%s: url", ErrPointerUnreachable)
	}
	meta, err := s.store.Meta()
	if err != nil {
		return false, fmt.Errorf("%s: %v", ErrPointerUnreachable, err)
	}
	body, etag, notModified, err := s.fetchPointer(ctx, pointerURL, meta.ETag)
	if err != nil {
		return false, err
	}
	if notModified {
		return false, nil
	}
	p, err := bundle.ParsePointer(body)
	if err != nil {
		return false, err // already prefixed pointer_invalid
	}
	if meta.Active() && p.Version == meta.Version {
		return false, nil
	}
	bu, err := pointerURL.Parse(p.BundleURL)
	if err != nil || !allowedURL(bu) {
		return false, fmt.Errorf("%s: bundle_url", ErrPointerInvalid)
	}
	tmp, err := s.download(ctx, bu, p)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	info := store.ImportInfo{Version: p.Version, CreatedAt: p.CreatedAt, ETag: etag}
	if err := s.verifyAndImport(ctx, tmp, info); err != nil {
		return false, err
	}
	return true, nil
}

// allowedURL accepts https, or http on a loopback host.
func allowedURL(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		ip := net.ParseIP(h)
		return h == "localhost" || (ip != nil && ip.IsLoopback())
	}
	return false
}

func (s *Syncer) newRequest(ctx context.Context, u *url.URL, accept string) (*http.Request, error) {
	u2 := *u
	u2.RawQuery, u2.Fragment, u2.User = "", "", nil
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u2.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bellud/"+s.cfg.Version)
	req.Header.Set("Accept", accept)
	return req, nil
}

func (s *Syncer) fetchPointer(ctx context.Context, u *url.URL, etag string) (body []byte, newETag string, notModified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, pointerTimeout)
	defer cancel()
	req, err := s.newRequest(ctx, u, "application/json")
	if err != nil {
		return nil, "", false, fmt.Errorf("%s: %v", ErrPointerUnreachable, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("%s: %v", ErrPointerUnreachable, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, "", true, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, "", false, fmt.Errorf("%s: status %d", ErrPointerUnreachable, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxPointerBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("%s: %v", ErrPointerUnreachable, err)
	}
	if len(b) > maxPointerBytes {
		return nil, "", false, fmt.Errorf("%s: too large", ErrPointerInvalid)
	}
	return b, resp.Header.Get("ETag"), false, nil
}

// download fetches the bundle into a temp file, rewound for reading. The
// caller closes and removes it.
func (s *Syncer) download(ctx context.Context, u *url.URL, p bundle.Pointer) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := s.newRequest(ctx, u, "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDownloadFailed, err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDownloadFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: status %d", ErrDownloadFailed, resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "bellu-intel-*.tar.zst")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", ErrDownloadFailed, err)
	}
	fail := func(e error) (*os.File, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, e
	}
	h := sha256.New()
	// One byte past the declared size detects an oversized body.
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, p.BundleSize+1))
	if err != nil {
		return fail(fmt.Errorf("%s: %v", ErrDownloadFailed, err))
	}
	if n < p.BundleSize {
		return fail(fmt.Errorf("%s: got %d of %d bytes", ErrDownloadFailed, n, p.BundleSize))
	}
	if n > p.BundleSize {
		return fail(fmt.Errorf("%s: larger than bundle_size", ErrDownloadCorrupt))
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), p.BundleSHA256) {
		return fail(fmt.Errorf("%s: sha256 mismatch", ErrDownloadCorrupt))
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("%s: %v", ErrDownloadFailed, err))
	}
	return tmp, nil
}

func (s *Syncer) verifyAndImport(ctx context.Context, r io.Reader, info store.ImportInfo) error {
	v, err := bundle.Verify(r, s.cfg.Key)
	if err != nil {
		return fmt.Errorf("%s: %v", ErrVerificationFailed, err)
	}
	if info.Version == "" {
		info.Version = fmt.Sprintf("local-%d", v.Manifest.Version)
		if t, perr := time.Parse(time.RFC3339, v.Manifest.CreatedAt); perr == nil {
			info.CreatedAt = t.UTC()
			info.Version = "local-" + info.CreatedAt.Format("20060102T150405Z")
		}
	}
	if err := s.store.Replace(ctx, info, bytes.NewReader(v.JSONL)); err != nil {
		return fmt.Errorf("%s: %v", ErrImportFailed, err)
	}
	return nil
}

// Status reports the corpus and sync state.
func (s *Syncer) Status() Status {
	st := Status{State: StateNotConfigured}
	if m, err := s.store.Meta(); err == nil {
		st.Version, st.Records, st.LastSyncedAt, st.LastError = m.Version, m.Records, m.SyncedAt, m.LastError
		if !m.Active() {
			st.Version, st.Records = "", 0
		}
		s.mu.Lock()
		syncing, failed := s.syncing, s.lastFail
		s.mu.Unlock()
		switch {
		case !s.configured():
			st.State = StateNotConfigured
		case len(s.cfg.Key) != ed25519.PublicKeySize:
			st.State = StateDisabled
			st.LastError = "disabled: no pinned key"
		case syncing:
			st.State = StateSyncing
		case failed || m.LastError != "":
			st.State = StateError
		case m.Active():
			st.State = StateOK
		default:
			st.State = StateIdle
		}
	}
	return st
}
