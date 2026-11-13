package store

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// rapid runs 100 checks per property by default.
func genConnection(t *rapid.T, label, alias string) Connection {
	c := Connection{
		ID:                   rapid.StringN(1, 12, -1).Draw(t, label+"id"),
		ConnectorID:          rapid.SampledFrom([]string{"aws", "github"}).Draw(t, label+"connector"),
		Alias:                alias,
		AuthConfigID:         rapid.String().Draw(t, label+"auth"),
		Method:               rapid.String().Draw(t, label+"method"),
		Status:               rapid.SampledFrom([]string{"ACTIVE", "PAUSED", "ERROR", "EXPIRED"}).Draw(t, label+"status"),
		StatusReason:         rapid.String().Draw(t, label+"reason"),
		AccountLabel:         rapid.String().Draw(t, label+"acct"),
		ExternalIDRef:        rapid.String().Draw(t, label+"ext"),
		Selection:            Selection{Regions: rapid.SliceOf(rapid.String()).Draw(t, label+"regions"), Repos: rapid.SliceOf(rapid.String()).Draw(t, label+"repos")},
		IntervalSec:          60 * rapid.IntRange(1, 1440).Draw(t, label+"interval"),
		AllowAgentLiveReads:  rapid.Bool().Draw(t, label+"live"),
		RotationIntervalDays: rapid.IntRange(MinRotationDays, MaxRotationDays).Draw(t, label+"rot"),
		PermissionCheck:      rapid.SampledFrom([]string{"", PermissionOK, PermissionExcess, PermissionUnverifiable}).Draw(t, label+"perm"),
		Removed:              rapid.Bool().Draw(t, label+"removed"),
		CreatedAt:            time.Unix(rapid.Int64Range(0, 4e9).Draw(t, label+"created"), int64(rapid.IntRange(0, 999999999).Draw(t, label+"ns"))).UTC(),
	}
	optTime := func(name string) *time.Time {
		if !rapid.Bool().Draw(t, label+name+"set") {
			return nil
		}
		v := time.Unix(rapid.Int64Range(0, 4e9).Draw(t, label+name), 0).UTC()
		return &v
	}
	c.CredentialCreatedAt = optTime("ccreated")
	c.CredentialExpiresAt = optTime("cexpires")
	c.LastPermissionCheck = optTime("lpc")
	if rapid.Bool().Draw(t, label+"lastsync") {
		c.LastSync = &LastSync{
			Status:   rapid.String().Draw(t, label+"lsstatus"),
			EndedAt:  optTime("lsended"),
			Entities: rapid.IntRange(0, 1e6).Draw(t, label+"lsentities"),
			Partial:  rapid.SliceOf(rapid.String()).Draw(t, label+"lspartial"),
		}
	}
	return c
}

func genState(t *rapid.T) State {
	st := Default()
	st.Settings = Settings{
		AuditRetentionDays: rapid.IntRange(MinRetentionDays, MaxRetentionDays).Draw(t, "retention"),
		DefaultIntervalSec: 60 * rapid.IntRange(1, 1440).Draw(t, "defInterval"),
	}
	aliases := rapid.SliceOfNDistinct(rapid.StringN(1, MaxAliasLen, -1), 0, 5, func(s string) string { return s }).Draw(t, "aliases")
	for i, a := range aliases {
		st.Connections = append(st.Connections, genConnection(t, "conn"+string(rune('a'+i)), a))
	}
	for i := range rapid.IntRange(0, 3).Draw(t, "nAuth") {
		_ = i
		st.AuthConfigs = append(st.AuthConfigs, AuthConfig{
			ID:          rapid.String().Draw(t, "acid"),
			ConnectorID: rapid.String().Draw(t, "acconn"),
			Name:        rapid.String().Draw(t, "acname"),
			Builtin:     rapid.Bool().Draw(t, "acbuiltin"),
			Method:      rapid.String().Draw(t, "acmethod"),
			Scopes:      rapid.SliceOf(rapid.String()).Draw(t, "acscopes"),
			Settings:    rapid.MapOf(rapid.String(), rapid.String()).Draw(t, "acsettings"),
		})
	}
	for range rapid.IntRange(0, 3).Draw(t, "nScope") {
		st.Scopes = append(st.Scopes, Scope{
			Principal:   rapid.String().Draw(t, "principal"),
			Connectors:  rapid.SliceOf(rapid.String()).Draw(t, "sconnectors"),
			Connections: rapid.SliceOf(rapid.String()).Draw(t, "sconnections"),
			Operations:  rapid.MapOf(rapid.String(), rapid.SliceOf(rapid.String())).Draw(t, "sops"),
		})
	}
	for range rapid.IntRange(0, 3).Draw(t, "nPlugin") {
		st.Plugins = append(st.Plugins, Plugin{
			ID:                   rapid.String().Draw(t, "pid"),
			PinnedVersion:        rapid.String().Draw(t, "pver"),
			ConfirmedPermissions: rapid.SliceOf(rapid.String()).Draw(t, "pperm"),
			ConfirmedHosts:       rapid.SliceOf(rapid.String()).Draw(t, "phosts"),
			Signed:               rapid.Bool().Draw(t, "psigned"),
		})
	}
	normalize(&st)
	return st
}

// Feature: cloud-connectors, Property 13: Account alias validation
//
// **Validates: Requirements 1.13, 1.15**
func TestPropertyAccountAliasValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Small alphabet makes collisions with existing aliases likely.
		alias := rapid.OneOf(
			rapid.StringOfN(rapid.SampledFrom([]rune("ab")), 0, 3, -1),
			rapid.StringN(0, 60, -1),
		).Draw(t, "alias")
		connectors := []string{"aws", "github"}
		existing := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Connection {
			return Connection{
				ID:          rapid.SampledFrom([]string{"c1", "c2", "c3", "c4"}).Draw(t, "id"),
				ConnectorID: rapid.SampledFrom(connectors).Draw(t, "connector"),
				Alias:       rapid.OneOf(rapid.Just(alias), rapid.StringOfN(rapid.SampledFrom([]rune("ab")), 1, 3, -1)).Draw(t, "ealias"),
				Removed:     rapid.Bool().Draw(t, "removed"),
			}
		}), 0, 6).Draw(t, "existing")
		connector := rapid.SampledFrom(connectors).Draw(t, "target")
		selfID := rapid.SampledFrom([]string{"", "c1", "c2", "c3", "c4"}).Draw(t, "self")

		// Independent oracle.
		n := utf8.RuneCountInString(alias)
		want := n >= 1 && n <= 40
		for _, c := range existing {
			if c.ConnectorID == connector && !c.Removed && c.ID != selfID && c.Alias == alias {
				want = false
			}
		}

		err := ValidateAlias(alias, connector, selfID, existing)
		if (err == nil) != want {
			t.Fatalf("alias %q (%d runes): err=%v want accepted=%v", alias, n, err, want)
		}
		if err != nil {
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != "alias" {
				t.Fatalf("rejection must name the alias field, got %v", err)
			}
		}
	})
}

// Feature: cloud-connectors, Property 13: Account alias validation
// (store level: a rejected rename keeps the previous alias, in memory and on disk)
//
// **Validates: Requirements 1.13, 1.15**
func TestPropertyAliasRejectionKeepsPreviousAlias(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, cleanup := tempDir(t)
		defer cleanup()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(s.AddConnection(NewConnection("a", "aws", "first", s.Snapshot().Settings, now)))
		must(s.AddConnection(NewConnection("b", "aws", "second", s.Snapshot().Settings, now)))

		alias := rapid.OneOf(rapid.SampledFrom([]string{"first", "second", ""}), rapid.StringN(0, 60, -1)).Draw(t, "alias")
		n := utf8.RuneCountInString(alias)
		want := n >= 1 && n <= 40 && alias != "first" // "first" is used by connection "a"

		err = s.UpdateConnection("b", func(c *Connection) error { c.Alias = alias; return nil })
		if (err == nil) != want {
			t.Fatalf("rename to %q: err=%v want accepted=%v", alias, err, want)
		}
		expected := "second"
		if want {
			expected = alias
		}
		if got, _ := s.Connection("b"); got.Alias != expected {
			t.Fatalf("alias = %q, want %q", got.Alias, expected)
		}
		reopened, err := Open(dir)
		must(err)
		if got, _ := reopened.Connection("b"); got.Alias != expected {
			t.Fatalf("persisted alias = %q, want %q", got.Alias, expected)
		}
	})
}

// Feature: cloud-connectors, Property 14: Bounded settings validators
//
// **Validates: Requirements 7.10, 9.6, 9.10**
func TestPropertyBoundedSettingsValidators(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.OneOf(
			rapid.IntRange(-10, 400),
			rapid.IntRange(0, 100000),
			rapid.SampledFrom([]int{0, 59, 60, 61, 120, 86340, 86400, 86401, 86460}),
		).Draw(t, "value")

		check := func(name string, err error, accepted bool, field string) {
			if (err == nil) != accepted {
				t.Fatalf("%s(%d): err=%v want accepted=%v", name, v, err, accepted)
			}
			if err != nil {
				var fe *FieldError
				if !errors.As(err, &fe) || fe.Field != field || fe.Message == "" {
					t.Fatalf("%s(%d): rejection must name field %q and range, got %v", name, v, field, err)
				}
			}
		}
		check("interval", ValidateInterval(v), v >= 60 && v <= 86400 && v%60 == 0, "intervalSec")
		check("rotation", ValidateRotationDays(v), v >= 1 && v <= 365, "rotationIntervalDays")
		check("retention", ValidateRetentionDays(v), v >= 1 && v <= 365, "audit_retention_days")
	})
}

// Feature: cloud-connectors, Property 14: Bounded settings validators
// (store level: a rejected value keeps the previous value in memory and on disk)
//
// **Validates: Requirements 7.10, 9.6, 9.10**
func TestPropertyRejectedSettingKeepsPreviousValue(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, cleanup := tempDir(t)
		defer cleanup()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AddConnection(NewConnection("a", "aws", "x", s.Snapshot().Settings, now)); err != nil {
			t.Fatal(err)
		}
		before := s.Snapshot()
		v := rapid.OneOf(rapid.IntRange(-5, 500), rapid.IntRange(0, 100000)).Draw(t, "value")
		field := rapid.SampledFrom([]string{"interval", "rotation", "retention"}).Draw(t, "field")

		var accepted bool
		switch field {
		case "interval":
			accepted = v >= 60 && v <= 86400 && v%60 == 0
			err = s.UpdateConnection("a", func(c *Connection) error { c.IntervalSec = v; return nil })
		case "rotation":
			accepted = v >= 1 && v <= 365
			err = s.UpdateConnection("a", func(c *Connection) error { c.RotationIntervalDays = v; return nil })
		default:
			accepted = v >= 1 && v <= 365
			err = s.SetSettings(Settings{AuditRetentionDays: v, DefaultIntervalSec: before.Settings.DefaultIntervalSec})
		}
		if (err == nil) != accepted {
			t.Fatalf("%s=%d: err=%v want accepted=%v", field, v, err, accepted)
		}
		if !accepted {
			if !reflect.DeepEqual(s.Snapshot(), before) {
				t.Fatalf("%s=%d rejected but in-memory state changed", field, v)
			}
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reopened.Snapshot(), before) {
				t.Fatalf("%s=%d rejected but persisted state changed", field, v)
			}
		}
	})
}

// Feature: cloud-connectors, Property 9: Manifest and state serialization round trip (state document part)
//
// **Validates: Requirements 7.10, 9.6, 9.10**
func TestPropertyStateRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := genState(t)
		raw, err := Encode(st)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode of encoded valid state: %v", err)
		}
		if !reflect.DeepEqual(got, st) {
			t.Fatalf("round trip differs:\n got %+v\nwant %+v", got, st)
		}
		again, err := Encode(got)
		if err != nil || string(again) != string(raw) {
			t.Fatalf("re-encoding is not stable (err=%v)", err)
		}
	})
}

// Feature: cloud-connectors, Property 9: Manifest and state serialization round trip (state document part)
// (persisted through the Store: reopening yields the same document)
//
// **Validates: Requirements 7.10, 9.6, 9.10**
func TestPropertyStatePersistRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := genState(t)
		dir, cleanup := tempDir(t)
		defer cleanup()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Update(func(cur *State) error { *cur = st; return nil }); err != nil {
			t.Fatalf("update with valid state: %v", err)
		}
		reopened, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reopened.Snapshot(), st) {
			t.Fatalf("persisted state differs from stored state")
		}
	})
}

func tempDir(t *rapid.T) (string, func()) {
	dir, err := os.MkdirTemp("", "store-prop-")
	if err != nil {
		t.Fatal(err)
	}
	return dir, func() { os.RemoveAll(dir) }
}
