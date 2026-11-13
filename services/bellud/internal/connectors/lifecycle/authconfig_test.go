package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// acVault fails the nth Put or any Delete on demand.
type acVault struct {
	*mgrVault
	puts      int
	failPutAt int // 1-based; 0 never
}

func (v *acVault) Put(ctx context.Context, ref vault.Ref, c string, secret []byte, exp time.Time) error {
	v.puts++
	if v.failPutAt == v.puts {
		return errors.New("vault down")
	}
	return v.mgrVault.Put(ctx, ref, c, secret, exp)
}

type acFix struct {
	svc *AuthConfigService
	st  *store.Store
	v   *acVault
	a   *mgrAudit
}

func newAcFix(t *testing.T) *acFix {
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
	f := &acFix{st: st, v: &acVault{mgrVault: &mgrVault{data: map[vault.Ref]string{}}}, a: &mgrAudit{}}
	n := 0
	f.svc = NewAuthConfigService(AuthConfigServiceConfig{
		Store: st, Vault: f.v, Audit: f.a, Registry: reg,
		NewID: func() string { n++; return fmt.Sprintf("ac%d", n) },
	})
	return f
}

func appInput(name string) CreateAuthConfigInput {
	return CreateAuthConfigInput{
		ConnectorID: "gh", Name: name, Method: "github_app", Scopes: []string{"contents:read"},
		Settings: map[string]string{"appId": "42"},
		Secrets:  map[string][]byte{"privateKey": []byte("PRIVATE-KEY-VALUE-0001")},
	}
}

func (f *acFix) customCount() int {
	n := 0
	for _, a := range f.st.Snapshot().AuthConfigs {
		if !a.Builtin {
			n++
		}
	}
	return n
}

func TestAuthConfigDefaultIsListedFirstAndImmutable(t *testing.T) {
	f := newAcFix(t)
	if _, err := f.svc.Create(context.Background(), appInput("mine")); err != nil {
		t.Fatal(err)
	}
	list, err := f.svc.List("gh")
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	d := list[0]
	if !d.Builtin || d.Name != "default" || strings.Join(d.Scopes, ",") != "contents:read,metadata:read" {
		t.Fatalf("default = %+v", d)
	}
	if d.Settings[SettingAppRef] != "builtin:gh" {
		t.Fatalf("default settings = %v", d.Settings)
	}
	// Listing again does not duplicate the default.
	if list, _ = f.svc.List("gh"); len(list) != 2 {
		t.Fatalf("default duplicated: %d", len(list))
	}
	err = f.svc.Delete(context.Background(), d.ID)
	if codeOf(t, err) != CodeForbidden {
		t.Fatalf("delete default: %v", err)
	}
}

func TestAuthConfigCreateStoresSecretOnlyInVault(t *testing.T) {
	f := newAcFix(t)
	cfg, err := f.svc.Create(context.Background(), appInput("mine"))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := f.v.get(authConfigRef(cfg.ID, "privateKey")); !ok || s != "PRIVATE-KEY-VALUE-0001" {
		t.Fatal("secret not in vault")
	}
	raw, _ := store.Encode(f.st.Snapshot())
	if strings.Contains(string(raw), "PRIVATE-KEY-VALUE") {
		t.Fatal("secret leaked into state")
	}
	if f.a.count(audit.EventConnect) != 1 {
		t.Fatal("create not audited")
	}
}

func TestAuthConfigRejectsInvalidInputNamingEachField(t *testing.T) {
	f := newAcFix(t)
	if _, err := f.svc.Create(context.Background(), appInput("dup")); err != nil {
		t.Fatal(err)
	}
	puts := f.v.puts
	bad := CreateAuthConfigInput{ConnectorID: "gh", Name: "dup", Method: "github_app", Scopes: []string{"contents:read", "contents:write"}}
	var te *Error
	err := func() error { _, err := f.svc.Create(context.Background(), bad); return err }()
	if !errors.As(err, &te) || te.Code != CodeValidationFailed {
		t.Fatalf("err = %v", err)
	}
	want := []string{"name", "settings.appId", "secrets.privateKey", "scope:contents:write"}
	if strings.Join(te.Offenders, ",") != strings.Join(want, ",") {
		t.Fatalf("offenders = %v", te.Offenders)
	}
	if f.v.puts != puts || f.customCount() != 1 {
		t.Fatal("rejected config must store nothing")
	}
	for _, name := range []string{"", strings.Repeat("x", 41)} {
		in := appInput(name)
		if _, err := f.svc.Create(context.Background(), in); codeOf(t, err) != CodeValidationFailed {
			t.Fatalf("name %q accepted", name)
		}
	}
	in := appInput("noscopes")
	in.Scopes = nil
	if _, err := f.svc.Create(context.Background(), in); codeOf(t, err) != CodeValidationFailed {
		t.Fatal("empty scopes accepted")
	}
	in = appInput("pat-method")
	in.Method = "unknown"
	if _, err := f.svc.Create(context.Background(), in); codeOf(t, err) != CodeValidationFailed {
		t.Fatal("unsupported method accepted")
	}
}

func TestAuthConfigScopeOutsideReadSetNamesOffenders(t *testing.T) {
	f := newAcFix(t)
	in := appInput("wide")
	in.Scopes = []string{"contents:read", "admin:org", "repo"}
	_, err := f.svc.Create(context.Background(), in)
	var te *Error
	if !errors.As(err, &te) || te.Code != CodeScopeDenied || strings.Join(te.Offenders, ",") != "admin:org,repo" {
		t.Fatalf("err = %#v", err)
	}
	if _, ok := f.v.get(authConfigRef("ac1", "privateKey")); ok || f.customCount() != 0 {
		t.Fatal("nothing may be stored")
	}
}

func TestAuthConfigLimitOfTen(t *testing.T) {
	f := newAcFix(t)
	for i := 0; i < MaxCustomAuthConfigs; i++ {
		if _, err := f.svc.Create(context.Background(), appInput(fmt.Sprintf("c%d", i))); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	_, err := f.svc.Create(context.Background(), appInput("eleventh"))
	var te *Error
	if !errors.As(err, &te) || te.Code != CodeValidationFailed || len(te.Offenders) != 1 || te.Offenders[0] != "limit" {
		t.Fatalf("err = %v", err)
	}
	if f.customCount() != 10 {
		t.Fatal("limit exceeded")
	}
}

func TestAuthConfigVaultFailureLeavesNoOrphan(t *testing.T) {
	f := newAcFix(t)
	svc := NewAuthConfigService(AuthConfigServiceConfig{
		Store: f.st, Vault: f.v, Audit: f.a, Registry: f.svc.cfg.Registry,
		Methods: map[string]MethodSpec{"github_app": {Required: []string{"appId"}, Secrets: []string{"a", "b"}}},
		NewID:   func() string { return "acX" },
	})
	in := appInput("two")
	in.Secrets = map[string][]byte{"a": []byte("secret-a-000000001"), "b": []byte("secret-b-000000002")}
	f.v.failPutAt = 2
	_, err := svc.Create(context.Background(), in)
	var te *Error
	if !errors.As(err, &te) || te.Code != CodeVaultUnavailable || strings.Contains(te.Message, "secret-") {
		t.Fatalf("err = %v", err)
	}
	if len(f.v.data) != 0 || f.customCount() != 0 {
		t.Fatalf("orphans: vault=%d configs=%d", len(f.v.data), f.customCount())
	}
}

func TestAuthConfigAuditFailureRollsBackSecrets(t *testing.T) {
	f := newAcFix(t)
	f.a.fail = true
	_, err := f.svc.Create(context.Background(), appInput("mine"))
	if codeOf(t, err) != CodeAuditFailed {
		t.Fatalf("err = %v", err)
	}
	if len(f.v.data) != 0 || f.customCount() != 0 {
		t.Fatal("rollback incomplete")
	}
}

func TestAuthConfigDeleteInUseReportsCount(t *testing.T) {
	f := newAcFix(t)
	cfg, err := f.svc.Create(context.Background(), appInput("mine"))
	if err != nil {
		t.Fatal(err)
	}
	for i, removed := range []bool{false, false, true} {
		c := store.NewConnection(fmt.Sprintf("c%d", i), "gh", fmt.Sprintf("a%d", i), f.st.Snapshot().Settings, f.svc.now())
		c.AuthConfigID, c.Removed = cfg.ID, removed
		if err := f.st.AddConnection(c); err != nil {
			t.Fatal(err)
		}
	}
	err = f.svc.Delete(context.Background(), cfg.ID)
	var te *Error
	if !errors.As(err, &te) || te.InUse != 2 || !strings.Contains(te.Message, "2") {
		t.Fatalf("err = %#v", err)
	}
	if _, ok := f.v.get(authConfigRef(cfg.ID, "privateKey")); !ok || f.customCount() != 1 {
		t.Fatal("config or secret changed")
	}
}

func TestAuthConfigDeleteUnused(t *testing.T) {
	f := newAcFix(t)
	cfg, err := f.svc.Create(context.Background(), appInput("mine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.v.data) != 0 || f.customCount() != 0 {
		t.Fatal("not removed")
	}
	if f.a.count(audit.EventDisconnect) != 1 {
		t.Fatal("delete not audited")
	}
}

func TestAuthConfigDeleteVaultFailureKeepsConfig(t *testing.T) {
	f := newAcFix(t)
	cfg, err := f.svc.Create(context.Background(), appInput("mine"))
	if err != nil {
		t.Fatal(err)
	}
	f.v.deleteErr = errors.New("vault down")
	err = f.svc.Delete(context.Background(), cfg.ID)
	if codeOf(t, err) != CodeVaultUnavailable {
		t.Fatalf("err = %v", err)
	}
	if f.customCount() != 1 {
		t.Fatal("config must be kept")
	}
	if _, ok := f.v.get(authConfigRef(cfg.ID, "privateKey")); !ok {
		t.Fatal("secret must be kept")
	}
}
