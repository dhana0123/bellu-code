package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 13, 7, 54, 52, 0, time.UTC)

func TestOpenCreatesDefaultWithModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "connectors")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot()
	if st.Settings.AuditRetentionDays != 90 || st.Settings.DefaultIntervalSec != 900 {
		t.Fatalf("defaults: %+v", st.Settings)
	}
	di, _ := os.Stat(dir)
	fi, _ := os.Stat(filepath.Join(dir, FileName))
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes dir=%v file=%v", di.Mode().Perm(), fi.Mode().Perm())
	}
}

func TestConnectionDefaultsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	c := NewConnection("cn_1", "aws", "prod", s.Snapshot().Settings, now)
	if c.AllowAgentLiveReads || c.RotationIntervalDays != 90 || c.IntervalSec != 900 {
		t.Fatalf("defaults: %+v", c)
	}
	if err := s.AddConnection(c); err != nil {
		t.Fatal(err)
	}
	re, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := re.Connection("cn_1")
	if !ok || got.Alias != "prod" || !got.CreatedAt.Equal(now) {
		t.Fatalf("reload: %+v ok=%v", got, ok)
	}
}

func TestAliasRules(t *testing.T) {
	s, _ := Open(t.TempDir())
	if err := s.AddConnection(NewConnection("a", "aws", "dup", s.Snapshot().Settings, now)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, connector, alias string
		ok                     bool
	}{
		{"empty", "aws", "", false},
		{"41 chars", "aws", string(make([]rune, 41)) + "x", false},
		{"40 chars", "aws", "abcdefghijabcdefghijabcdefghijabcdefghij", true},
		{"duplicate", "aws", "dup", false},
		{"same alias other connector", "github", "dup", true},
	}
	for i, tc := range cases {
		err := s.AddConnection(NewConnection("n"+string(rune('a'+i)), tc.connector, tc.alias, s.Snapshot().Settings, now))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.name, err)
		}
	}
}

func TestRemovedAliasCanBeReused(t *testing.T) {
	s, _ := Open(t.TempDir())
	_ = s.AddConnection(NewConnection("a", "aws", "x", s.Snapshot().Settings, now))
	_ = s.UpdateConnection("a", func(c *Connection) error { c.Removed = true; return nil })
	if err := s.AddConnection(NewConnection("b", "aws", "x", s.Snapshot().Settings, now)); err != nil {
		t.Fatal(err)
	}
}

func TestIntervalAndRangesKeepPreviousValue(t *testing.T) {
	s, _ := Open(t.TempDir())
	_ = s.AddConnection(NewConnection("a", "aws", "x", s.Snapshot().Settings, now))
	for _, sec := range []int{0, 59, 90, 86460} {
		err := s.UpdateConnection("a", func(c *Connection) error { c.IntervalSec = sec; return nil })
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "intervalSec" {
			t.Errorf("interval %d: %v", sec, err)
		}
	}
	if c, _ := s.Connection("a"); c.IntervalSec != 900 {
		t.Fatalf("interval changed: %d", c.IntervalSec)
	}
	for _, sec := range []int{60, 86400} {
		if err := ValidateInterval(sec); err != nil {
			t.Errorf("interval %d: %v", sec, err)
		}
	}
	if ValidateRotationDays(0) == nil || ValidateRotationDays(366) == nil || ValidateRotationDays(365) != nil {
		t.Error("rotation bounds")
	}
	if err := s.SetSettings(Settings{AuditRetentionDays: 0, DefaultIntervalSec: 900}); err == nil {
		t.Error("retention 0 accepted")
	}
	if s.Snapshot().Settings.AuditRetentionDays != 90 {
		t.Error("retention changed after rejection")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	st := Default()
	c := NewConnection("cn_1", "github", "org", st.Settings, now)
	c.LastSync = &LastSync{Status: "ok", EndedAt: &now, Entities: 3}
	st.Connections = append(st.Connections, c)
	st.Scopes = append(st.Scopes, Scope{Principal: "agent"})
	st.Plugins = append(st.Plugins, Plugin{ID: "p", PinnedVersion: "1.2.0"})
	raw, err := Encode(st)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Encode(back)
	if string(raw) != string(again) {
		t.Fatalf("round trip differs:\n%s\n%s", raw, again)
	}
}
