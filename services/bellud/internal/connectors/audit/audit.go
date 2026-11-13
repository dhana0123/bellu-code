// Package audit implements the append-only, hash-chained connector audit log.
//
// Files live in one directory (mode 0700) as audit-YYYY-MM-DD.jsonl (mode 0600),
// one JSON object per line, opened with O_APPEND and fsynced before Append
// returns. The package exposes no update or delete of individual entries;
// only whole day files outside the retention window are removed by Prune.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Event types (design: Audit).
const (
	EventConnect                 = "connect"
	EventTest                    = "test"
	EventDisconnect              = "disconnect"
	EventRotate                  = "rotate"
	EventCredentialRelease       = "credential_release"
	EventCollect                 = "collect"
	EventBlockedOperation        = "blocked_operation"
	EventPermissionChange        = "permission_change"
	EventStatusChange            = "status_change"
	EventRejectedTransition      = "rejected_transition"
	EventCredentialOptionIgnored = "credential_option_ignored"
	EventScopeDenied             = "scope_denied"
	EventDecryptFailed           = "decrypt_failed"
	EventVaultForget             = "vault_forget"
	EventMasterKeyRotate         = "master_key_rotate"
	// EventPluginPrefix prefixes all plugin events (plugin_*).
	EventPluginPrefix = "plugin_"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeBlocked = "blocked"
)

// Actors. A Plugin_Connector id is also a valid actor.
const (
	ActorUser   = "user"
	ActorSystem = "system"
)

// Retention bounds and defaults.
const (
	MinRetentionDays     = 1
	MaxRetentionDays     = 365
	DefaultRetentionDays = 90
	// PageSize is the number of entries per page.
	PageSize = 50

	maxDetailEntries = 32
	maxDetailLen     = 512
	fileMode         = 0o600
	dirMode          = 0o700
	filePrefix       = "audit-"
	fileSuffix       = ".jsonl"
	dateLayout       = "2006-01-02"
	tsLayout         = "2006-01-02T15:04:05.000Z"
)

// Errors.
var (
	ErrInvalidRetention = errors.New("audit: retention must be between 1 and 365 days")
	ErrInvalidEntry     = errors.New("audit: invalid entry")
	ErrInvalidCursor    = errors.New("audit: invalid cursor")
	ErrClosed           = errors.New("audit: log closed")
)

// Entry is one audit record. TS is serialized as UTC with millisecond precision.
type Entry struct {
	Seq          uint64
	TS           time.Time
	ConnectionID string
	ConnectorID  string
	Event        string
	Outcome      string // success|failure|blocked
	Actor        string // user|system|<plugin connector id>
	Detail       map[string]string
	Prev         string // "sha256:<hex>" of the previous line, "" for the first entry
}

type wireEntry struct {
	Seq          uint64            `json:"seq"`
	TS           string            `json:"ts"`
	ConnectionID string            `json:"connectionId"`
	ConnectorID  string            `json:"connectorId"`
	Event        string            `json:"event"`
	Outcome      string            `json:"outcome"`
	Actor        string            `json:"actor"`
	Detail       map[string]string `json:"detail,omitempty"`
	Prev         string            `json:"prev"`
}

// MarshalJSON writes the wire form with a UTC millisecond timestamp.
func (e Entry) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireEntry{
		Seq: e.Seq, TS: e.TS.UTC().Format(tsLayout),
		ConnectionID: e.ConnectionID, ConnectorID: e.ConnectorID,
		Event: e.Event, Outcome: e.Outcome, Actor: e.Actor,
		Detail: e.Detail, Prev: e.Prev,
	})
}

// UnmarshalJSON parses the wire form.
func (e *Entry) UnmarshalJSON(b []byte) error {
	var w wireEntry
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	ts, err := time.Parse(tsLayout, w.TS)
	if err != nil {
		return fmt.Errorf("audit: bad ts: %w", err)
	}
	*e = Entry{
		Seq: w.Seq, TS: ts.UTC(), ConnectionID: w.ConnectionID, ConnectorID: w.ConnectorID,
		Event: w.Event, Outcome: w.Outcome, Actor: w.Actor, Detail: w.Detail, Prev: w.Prev,
	}
	return nil
}

// Page is one page of List results, newest first. NextCursor is empty on the last page.
type Page struct {
	Entries    []Entry
	NextCursor string
}

// Log is the audit log contract. There is intentionally no update or delete API.
type Log interface {
	Append(ctx context.Context, e Entry) error
	List(connID string, cursor string, limit int) (Page, error)
	Prune(now time.Time, retentionDays int) error
}

// Options configures a FileLog.
type Options struct {
	// RetentionDays defaults to DefaultRetentionDays; must be within 1–365.
	RetentionDays int
	// Now defaults to time.Now.
	Now func() time.Time
	// Sanitize, if set, is applied to every Detail key and value (e.g. the
	// Secret_Redactor). Entries never carry credentials, this is defense in depth.
	Sanitize func(string) string
}

// FileLog is the file-backed Log.
type FileLog struct {
	dir      string
	now      func() time.Time
	sanitize func(string) string

	mu        sync.Mutex
	retention int
	seq       uint64
	prev      string
	closed    bool
}

var _ Log = (*FileLog)(nil)

// Open creates (0700) or opens the audit directory and restores the chain head.
func Open(dir string, opt Options) (*FileLog, error) {
	if opt.RetentionDays == 0 {
		opt.RetentionDays = DefaultRetentionDays
	}
	if err := validRetention(opt.RetentionDays); err != nil {
		return nil, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("audit: chmod dir: %w", err)
	}
	l := &FileLog{dir: dir, now: opt.Now, sanitize: opt.Sanitize, retention: opt.RetentionDays}
	if err := l.restoreHead(); err != nil {
		return nil, err
	}
	return l, nil
}

func validRetention(d int) error {
	if d < MinRetentionDays || d > MaxRetentionDays {
		return ErrInvalidRetention
	}
	return nil
}

// SetRetention changes the retention window (1–365 days).
func (l *FileLog) SetRetention(days int) error {
	if err := validRetention(days); err != nil {
		return err
	}
	l.mu.Lock()
	l.retention = days
	l.mu.Unlock()
	return nil
}

// Retention returns the current retention in days.
func (l *FileLog) Retention() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retention
}

// Run prunes immediately and then every 24 h until ctx is done.
func (l *FileLog) Run(ctx context.Context) {
	_ = l.Prune(l.now(), l.Retention())
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = l.Prune(l.now(), l.Retention())
		}
	}
}

// Close makes further Appends fail.
func (l *FileLog) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// files returns day files sorted ascending by name (= by date).
func (l *FileLog) files() ([]string, error) {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if _, ok := fileDay(e.Name()); ok {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func fileDay(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileSuffix) {
		return time.Time{}, false
	}
	d, err := time.Parse(dateLayout, strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileSuffix))
	return d, err == nil
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines [][]byte
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		b, err := r.ReadBytes('\n')
		if len(b) > 0 && b[len(b)-1] == '\n' {
			if t := bytes.TrimRight(b, "\r\n"); len(t) > 0 {
				lines = append(lines, t)
			}
		}
		if err != nil {
			break
		}
	}
	return lines, nil
}

func (l *FileLog) restoreHead() error {
	names, err := l.files()
	if err != nil {
		return fmt.Errorf("audit: read dir: %w", err)
	}
	for i := len(names) - 1; i >= 0; i-- {
		lines, err := readLines(filepath.Join(l.dir, names[i]))
		if err != nil {
			return fmt.Errorf("audit: read %s: %w", names[i], err)
		}
		for j := len(lines) - 1; j >= 0; j-- {
			var e Entry
			if json.Unmarshal(lines[j], &e) == nil {
				l.seq = e.Seq
				l.prev = hashLine(lines[j])
				return nil
			}
		}
	}
	return nil
}

func (l *FileLog) clean(s string) string {
	if l.sanitize != nil {
		s = l.sanitize(s)
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxDetailLen {
		s = string([]rune(s)[:maxDetailLen])
	}
	return s
}

func validEvent(ev string) bool {
	switch ev {
	case EventConnect, EventTest, EventDisconnect, EventRotate, EventCredentialRelease,
		EventCollect, EventBlockedOperation, EventPermissionChange, EventStatusChange,
		EventRejectedTransition, EventCredentialOptionIgnored, EventScopeDenied,
		EventDecryptFailed, EventVaultForget, EventMasterKeyRotate:
		return true
	}
	return strings.HasPrefix(ev, EventPluginPrefix) && len(ev) > len(EventPluginPrefix)
}

// Append validates, chains, writes and fsyncs one entry. Seq, TS (if zero) and
// Prev are assigned by the log; caller-provided Seq and Prev are ignored.
func (l *FileLog) Append(ctx context.Context, e Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch {
	case !validEvent(e.Event):
		return fmt.Errorf("%w: event %q", ErrInvalidEntry, e.Event)
	case e.Outcome != OutcomeSuccess && e.Outcome != OutcomeFailure && e.Outcome != OutcomeBlocked:
		return fmt.Errorf("%w: outcome %q", ErrInvalidEntry, e.Outcome)
	case e.Actor == "":
		return fmt.Errorf("%w: actor required", ErrInvalidEntry)
	case len(e.Detail) > maxDetailEntries:
		return fmt.Errorf("%w: too many detail entries", ErrInvalidEntry)
	}
	e.ConnectionID = l.clean(e.ConnectionID)
	e.ConnectorID = l.clean(e.ConnectorID)
	e.Actor = l.clean(e.Actor)
	if len(e.Detail) > 0 {
		d := make(map[string]string, len(e.Detail))
		for k, v := range e.Detail {
			d[l.clean(k)] = l.clean(v)
		}
		e.Detail = d
	} else {
		e.Detail = nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if e.TS.IsZero() {
		e.TS = l.now()
	}
	e.TS = e.TS.UTC().Truncate(time.Millisecond)
	e.Seq = l.seq + 1
	e.Prev = l.prev

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	path := filepath.Join(l.dir, filePrefix+e.TS.Format(dateLayout)+fileSuffix)
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("audit: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("audit: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: close: %w", err)
	}
	if statErr != nil {
		syncDir(l.dir)
	}
	l.seq = e.Seq
	l.prev = hashLine(line)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// List returns entries of connID (all connections if empty) newest first,
// within the retention window. cursor is the opaque NextCursor of the previous
// page ("" for the first). limit <= 0 or > PageSize means PageSize.
func (l *FileLog) List(connID string, cursor string, limit int) (Page, error) {
	if limit <= 0 || limit > PageSize {
		limit = PageSize
	}
	before := uint64(0) // 0 = no upper bound
	if cursor != "" {
		n, err := strconv.ParseUint(cursor, 10, 64)
		if err != nil || n == 0 {
			return Page{}, ErrInvalidCursor
		}
		before = n
	}
	l.mu.Lock()
	days := l.retention
	l.mu.Unlock()
	cutoff := l.now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	names, err := l.files()
	if err != nil {
		return Page{}, fmt.Errorf("audit: read dir: %w", err)
	}
	var page Page
	for i := len(names) - 1; i >= 0; i-- {
		day, _ := fileDay(names[i])
		if !day.Add(24 * time.Hour).After(cutoff) {
			break // whole file older than the window; all earlier files are too
		}
		lines, err := readLines(filepath.Join(l.dir, names[i]))
		if err != nil {
			return Page{}, fmt.Errorf("audit: read %s: %w", names[i], err)
		}
		for j := len(lines) - 1; j >= 0; j-- {
			var e Entry
			if json.Unmarshal(lines[j], &e) != nil {
				continue
			}
			if (before != 0 && e.Seq >= before) || e.TS.Before(cutoff) {
				continue
			}
			if connID != "" && e.ConnectionID != connID {
				continue
			}
			if len(page.Entries) == limit {
				page.NextCursor = strconv.FormatUint(page.Entries[limit-1].Seq, 10)
				return page, nil
			}
			page.Entries = append(page.Entries, e)
		}
	}
	return page, nil
}

// Prune deletes whole day files that end at or before now-retentionDays.
// retentionDays outside 1–365 is rejected and nothing is deleted.
func (l *FileLog) Prune(now time.Time, retentionDays int) error {
	if err := validRetention(retentionDays); err != nil {
		return err
	}
	cutoff := now.UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	l.mu.Lock()
	defer l.mu.Unlock()
	names, err := l.files()
	if err != nil {
		return fmt.Errorf("audit: read dir: %w", err)
	}
	var firstErr error
	for _, n := range names {
		day, _ := fileDay(n)
		if day.Add(24 * time.Hour).After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(l.dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("audit: prune %s: %w", n, err)
		}
	}
	syncDir(l.dir)
	return firstErr
}
