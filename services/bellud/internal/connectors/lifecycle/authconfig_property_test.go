package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// stepVault fails the nth Put and/or the nth Delete (1-based, 0 never).
type stepVault struct {
	*mgrVault
	puts, deletes        int
	failPutAt, failDelAt int
}

func (v *stepVault) Put(ctx context.Context, ref vault.Ref, c string, s []byte, exp time.Time) error {
	v.puts++
	if v.failPutAt == v.puts {
		return errors.New("vault down")
	}
	return v.mgrVault.Put(ctx, ref, c, s, exp)
}

func (v *stepVault) Delete(ctx context.Context, ref vault.Ref) error {
	v.deletes++
	if v.failDelAt == v.deletes {
		return errors.New("vault down")
	}
	return v.mgrVault.Delete(ctx, ref)
}

func (v *stepVault) snapshot() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := []string{}
	for r, s := range v.data {
		out = append(out, fmt.Sprintf("%v=%s", r, s))
	}
	slices.Sort(out)
	return out
}

var propSecretSlots = []string{"privateKey", "passphrase"}

func newPropFix(t *testing.T) (*AuthConfigService, *store.Store, *stepVault, *mgrAudit) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	if err := reg.Register(manifest.Manifest{
		ID: "gh", Version: "1.0.0", Name: "gh", Icon: "gh",
		AuthMethods: []manifest.AuthMethod{
			{ID: "pat", Name: "PAT", Enabled: true},
			{ID: "github_app", Name: "App", Enabled: true},
		},
		Permissions: []manifest.Permission{{Name: "contents:read", ReadOnly: true}, {Name: "metadata:read", ReadOnly: true}},
		Operations:  []manifest.Operation{{Name: "GET /x", Class: manifest.ClassRead, Method: "GET", Host: "api.example.com", Path: "/x"}},
		Egress:      []string{"api.example.com"},
		Entities:    []string{"thing"},
	}); err != nil {
		t.Fatal(err)
	}
	v := &stepVault{mgrVault: &mgrVault{data: map[vault.Ref]string{}}}
	a := &mgrAudit{}
	n := 0
	svc := NewAuthConfigService(AuthConfigServiceConfig{
		Store: st, Vault: v, Audit: a, Registry: reg,
		Methods: map[string]MethodSpec{"github_app": {Required: []string{"appId"}, Secrets: propSecretSlots}},
		NewID:   func() string { n++; return fmt.Sprintf("ac%d", n) },
	})
	return svc, st, v, a
}

type propInput struct {
	in      CreateAuthConfigInput
	valid   bool
	fields  []string // offenders that must be named (field-class)
	scopes  []string // out-of-set scopes that must be named
	atLimit bool
}

func genPropInput(t *rapid.T, taken []string, custom int) propInput {
	name := rapid.OneOf(
		rapid.SampledFrom(taken),
		rapid.StringN(0, 12, -1),
		rapid.StringOfN(rapid.RuneFrom([]rune("abcé界")), 38, 42, -1),
		rapid.Just("\xff\xfe"),
		rapid.Just(""),
	).Draw(t, "name")
	method := rapid.SampledFrom([]string{"github_app", "github_app", "github_app", "pat", "nope"}).Draw(t, "method")
	scopes := rapid.SliceOfN(rapid.SampledFrom([]string{"contents:read", "metadata:read", "admin:org", "repo"}), 0, 4).Draw(t, "scopes")
	settings := map[string]string{}
	if rapid.Bool().Draw(t, "hasAppID") {
		settings["appId"] = "42"
	}
	if rapid.IntRange(0, 9).Draw(t, "slotsKey") == 0 {
		settings[SettingSecretSlots] = "x"
	}
	secrets := map[string][]byte{}
	for _, s := range append(slices.Clone(propSecretSlots), "bogus") {
		switch rapid.IntRange(0, 5).Draw(t, "sec_"+s) {
		case 0:
			secrets[s] = []byte{}
		case 1:
			// absent
		default:
			if s != "bogus" {
				secrets[s] = []byte("secret-" + s + "-0123456789abcdef")
			}
		}
	}
	if rapid.IntRange(0, 9).Draw(t, "bogus") == 0 {
		secrets["bogus"] = []byte("secret-bogus-0123456789abcdef")
	}

	// Bias toward well-formed input so the success, rollback and delete paths
	// are exercised often, not only rejections.
	if rapid.IntRange(0, 2).Draw(t, "wellFormed") > 0 {
		name = fmt.Sprintf("good-%s", rapid.StringOfN(rapid.RuneFrom([]rune("abcé界")), 1, 30, -1).Draw(t, "goodName"))
		method = "github_app"
		scopes = rapid.SliceOfN(rapid.SampledFrom([]string{"contents:read", "metadata:read"}), 1, 3).Draw(t, "goodScopes")
		settings = map[string]string{"appId": "42"}
		secrets = map[string][]byte{
			"privateKey": []byte("secret-privateKey-0123456789"), "passphrase": []byte("secret-passphrase-0123456789"),
		}
	}

	p := propInput{in: CreateAuthConfigInput{
		ConnectorID: "gh", Name: name, Method: method, Scopes: scopes, Settings: settings, Secrets: secrets,
	}}
	// Independent oracle of Req 13.2, 13.3, 13.4, 13.7.
	if n := utf8.RuneCountInString(name); n < 1 || n > MaxAuthConfigName || !utf8.ValidString(name) || slices.Contains(taken, name) {
		p.fields = append(p.fields, "name")
	}
	if method != "github_app" && method != "pat" {
		p.fields = append(p.fields, "method")
	}
	for k := range secrets {
		if method != "github_app" || !slices.Contains(propSecretSlots, k) {
			p.fields = append(p.fields, "secrets."+k)
		}
	}
	if method == "github_app" {
		if settings["appId"] == "" {
			p.fields = append(p.fields, "settings.appId")
		}
		for _, s := range propSecretSlots {
			if len(secrets[s]) == 0 {
				p.fields = append(p.fields, "secrets."+s)
			}
		}
	}
	if _, ok := settings[SettingSecretSlots]; ok {
		p.fields = append(p.fields, "settings."+SettingSecretSlots)
	}
	if len(scopes) == 0 {
		p.fields = append(p.fields, "scopes")
	}
	for _, sc := range scopes {
		if sc != "contents:read" && sc != "metadata:read" && !slices.Contains(p.scopes, sc) {
			p.scopes = append(p.scopes, sc)
		}
	}
	p.atLimit = custom >= MaxCustomAuthConfigs
	p.valid = len(p.fields) == 0 && len(p.scopes) == 0 && !p.atLimit
	return p
}

func authConfigIDs(st *store.Store) []string {
	out := []string{}
	for _, a := range st.Snapshot().AuthConfigs {
		if a.Builtin {
			continue // Create lazily materializes the default; it is not a custom config.
		}
		out = append(out, a.ID)
	}
	return out
}

func wantSecretSlots(in CreateAuthConfigInput) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range in.Secrets {
			if !yield(k) {
				return
			}
		}
	})
}

// Feature: cloud-connectors, Property 15: Auth_Config validation and lifecycle
// Validates: Requirements 13.2, 13.3, 13.4, 13.6, 13.7, 13.8, 13.9
func TestPropertyAuthConfigValidationAndLifecycle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		svc, st, v, a := newPropFix(t)
		ctx := context.Background()

		// The default config exists (and is listed) before or after; either way
		// its name is taken (Req 13.3).
		if rapid.Bool().Draw(rt, "ensureDefaults") {
			if err := svc.EnsureDefaults(); err != nil {
				rt.Fatal(err)
			}
		}
		taken := []string{DefaultAuthConfigName}
		pre := rapid.IntRange(0, MaxCustomAuthConfigs).Draw(rt, "preexisting")
		for i := 0; i < pre; i++ {
			name := fmt.Sprintf("pre%d", i)
			in := CreateAuthConfigInput{
				ConnectorID: "gh", Name: name, Method: "github_app", Scopes: []string{"contents:read"},
				Settings: map[string]string{"appId": "1"},
				Secrets: map[string][]byte{
					"privateKey": []byte("pre-private-0123456789"), "passphrase": []byte("pre-passphr-0123456789"),
				},
			}
			if _, err := svc.Create(ctx, in); err != nil {
				rt.Fatalf("seed create: %v", err)
			}
			taken = append(taken, name)
		}

		p := genPropInput(rt, taken, pre)
		failPut := 0
		auditFail := false
		if p.valid {
			switch rapid.IntRange(0, 2).Draw(rt, "failKind") {
			case 1:
				failPut = rapid.IntRange(1, len(p.in.Secrets)+0).Draw(rt, "failPutAt")
			case 2:
				auditFail = true
			}
		}
		beforeIDs, beforeVault := authConfigIDs(st), v.snapshot()
		v.puts, v.failPutAt = 0, failPut
		a.mu.Lock()
		a.fail = auditFail
		a.mu.Unlock()
		wantSlots := wantSecretSlots(p.in)
		in := p.in
		cfg, err := svc.Create(ctx, in)
		a.mu.Lock()
		a.fail = false
		a.mu.Unlock()
		v.failPutAt = 0

		switch {
		case !p.valid:
			var te *Error
			if !errors.As(err, &te) {
				rt.Fatalf("invalid input accepted or wrong error: %v", err)
			}
			if p.atLimit {
				if len(te.Offenders) != 1 || te.Offenders[0] != "limit" {
					rt.Fatalf("limit offenders = %v", te.Offenders)
				}
			} else {
				for _, f := range append(slices.Clone(p.fields), prefixAll("scope:", p.scopes)...) {
					if len(p.fields) > 0 && !slices.Contains(te.Offenders, f) {
						rt.Fatalf("offender %q not named in %v", f, te.Offenders)
					}
				}
				if len(p.fields) == 0 {
					for _, sc := range p.scopes {
						if !slices.Contains(te.Offenders, sc) {
							rt.Fatalf("scope %q not named in %v", sc, te.Offenders)
						}
					}
				}
			}
			if !slices.Equal(beforeIDs, authConfigIDs(st)) || !slices.Equal(beforeVault, v.snapshot()) || v.puts != 0 {
				rt.Fatal("rejection must store nothing")
			}
			return
		case failPut > 0 || auditFail:
			if err == nil {
				rt.Fatal("injected failure not surfaced")
			}
			if strings.Contains(err.Error(), "secret-") {
				rt.Fatalf("error leaks secret: %v", err)
			}
			if !slices.Equal(beforeIDs, authConfigIDs(st)) || !slices.Equal(beforeVault, v.snapshot()) {
				rt.Fatalf("orphan after failure: configs %v vault %v", authConfigIDs(st), v.snapshot())
			}
			return
		}
		if err != nil {
			rt.Fatalf("valid input rejected: %v", err)
		}
		if cfg.Builtin || cfg.Name != p.in.Name {
			rt.Fatalf("cfg = %+v", cfg)
		}
		for _, s := range wantSlots {
			if _, ok := v.get(authConfigRef(cfg.ID, s)); !ok {
				rt.Fatalf("secret %s missing from vault", s)
			}
		}
		raw, _ := store.Encode(st.Snapshot())
		if strings.Contains(string(raw), "secret-") {
			rt.Fatal("secret leaked into state")
		}

		// Deletion: in-use rejection with the exact count, then vault failure
		// at every delete step, then success.
		using := rapid.IntRange(0, 3).Draw(rt, "using")
		removed := rapid.IntRange(0, 2).Draw(rt, "removed")
		for i := 0; i < using+removed; i++ {
			c := store.NewConnection(fmt.Sprintf("c%d", i), "gh", fmt.Sprintf("al%d", i), st.Snapshot().Settings, svc.now())
			c.AuthConfigID, c.Removed = cfg.ID, i >= using
			if err := st.AddConnection(c); err != nil {
				rt.Fatal(err)
			}
		}
		stored := authConfigIDs(st)
		vaultBefore := v.snapshot()
		if using > 0 {
			var te *Error
			err := svc.Delete(ctx, cfg.ID)
			if !errors.As(err, &te) || te.InUse != using {
				rt.Fatalf("in-use delete: want count %d, got %#v", using, err)
			}
			if !slices.Equal(stored, authConfigIDs(st)) || !slices.Equal(vaultBefore, v.snapshot()) {
				rt.Fatal("rejected delete changed state")
			}
			return
		}
		failDel := rapid.IntRange(0, len(wantSlots)).Draw(rt, "failDelAt")
		v.deletes, v.failDelAt = 0, failDel
		err = svc.Delete(ctx, cfg.ID)
		v.failDelAt = 0
		if failDel > 0 {
			if err == nil {
				rt.Fatal("delete vault failure not surfaced")
			}
			// Tombstoned: the config is hidden and unusable (no usable partial
			// config), and the vault failure is reported as vault_unavailable.
			var te *Error
			if !errors.As(err, &te) || te.Code != CodeVaultUnavailable {
				rt.Fatalf("want vault_unavailable, got %v", err)
			}
			tomb := false
			for _, c := range st.Snapshot().AuthConfigs {
				if c.ID == cfg.ID {
					tomb = c.Deleting
				}
			}
			if !tomb {
				rt.Fatal("failed delete must leave the config tombstoned")
			}
			// List also retries cleanup; keep the vault failing so the
			// tombstone must be hidden by List itself.
			v.deletes, v.failDelAt = 0, 1
			listed, lerr := svc.List("gh")
			v.failDelAt = 0
			if lerr != nil {
				rt.Fatal(lerr)
			}
			for _, c := range listed {
				if c.ID == cfg.ID {
					rt.Fatal("tombstoned config still listed")
				}
			}
			if !slices.ContainsFunc(st.Snapshot().AuthConfigs, func(c store.AuthConfig) bool { return c.ID == cfg.ID && c.Deleting }) {
				rt.Fatal("tombstone must survive a failing cleanup retry")
			}
			// Cleanup is retried on the next EnsureDefaults; nothing orphaned.
			if err := svc.EnsureDefaults(); err != nil {
				rt.Fatal(err)
			}
			if slices.Contains(authConfigIDs(st), cfg.ID) {
				rt.Fatal("tombstone not cleaned up on retry")
			}
			for _, s := range wantSlots {
				if _, ok := v.get(authConfigRef(cfg.ID, s)); ok {
					rt.Fatalf("orphan secret %q after resumed delete", s)
				}
			}
			return
		}
		if err != nil {
			rt.Fatalf("delete: %v", err)
		}
		if slices.Contains(authConfigIDs(st), cfg.ID) {
			rt.Fatal("config not removed")
		}
		for _, s := range wantSlots {
			if _, ok := v.get(authConfigRef(cfg.ID, s)); ok {
				rt.Fatalf("orphan secret %q after delete", s)
			}
		}
	})
}
