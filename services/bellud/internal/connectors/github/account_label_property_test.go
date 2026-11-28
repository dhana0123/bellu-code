package github

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

type labelVault struct {
	mu   sync.Mutex
	data map[vault.Ref]string
}

func (v *labelVault) Put(_ context.Context, ref vault.Ref, _ string, secret []byte, _ time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data[ref] = string(secret)
	return nil
}

func (v *labelVault) Delete(_ context.Context, ref vault.Ref) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.data, ref)
	return nil
}

func (v *labelVault) Use(_ context.Context, ref vault.Ref, fn func([]byte) error) error {
	v.mu.Lock()
	s, ok := v.data[ref]
	v.mu.Unlock()
	if !ok {
		return vault.ErrNotFound
	}
	return fn([]byte(s))
}

type labelAudit struct{}

func (labelAudit) Append(context.Context, audit.Entry) error    { return nil }
func (labelAudit) List(string, string, int) (audit.Page, error) { return audit.Page{}, nil }
func (labelAudit) Prune(time.Time, int) error                   { return nil }

type labelClients struct{ rt http.RoundTripper }

func (c labelClients) HTTPClient(broker.ConnectionRef, string) *http.Client {
	return &http.Client{Transport: c.rt}
}

type labelSup struct{}

func (labelSup) Start(store.Connection)                {}
func (labelSup) Stop(context.Context, string) error    { return nil }
func (labelSup) SyncNow(context.Context, string) error { return nil }

type labelForget struct{}

func (labelForget) Forget(string) {}

type labelIngest struct{}

func (labelIngest) Apply(context.Context, graph.Batch) (graph.Receipt, error) {
	return graph.Receipt{}, nil
}

type labelEngine struct{ graph.Engine }

func (labelEngine) Ingest() graph.Ingest { return labelIngest{} }

// Feature: github-app-signin, Property 18: The account label equals the login GitHub returned
//
// For any login string returned by GET /user for the token, a verified
// Connection records exactly that login as its account label and
// permission_check unverifiable with the required message.
//
// **Validates: Requirements 6.2, 6.3**
func TestProperty18AccountLabelEqualsLogin(t *testing.T) {
	if UnverifiableMessage != "Permissions can't be verified; write requests are still blocked by the allowlist" {
		t.Fatalf("UnverifiableMessage = %q", UnverifiableMessage)
	}
	rapid.Check(t, func(rt *rapid.T) {
		login := rapid.String().Draw(rt, "login")
		rtp := &countingRT{routes: func(r *http.Request) (int, string, http.Header) {
			switch r.URL.Path {
			case "/user":
				b, _ := json.Marshal(map[string]string{"login": login})
				return 200, string(b), nil
			case "/user/installations":
				return 200, `{"total_count":0,"installations":[]}`, nil
			}
			return 404, `{}`, nil
		}}
		st, err := store.Open(t.TempDir())
		if err != nil {
			rt.Fatal(err)
		}
		reg := registry.New()
		if err := reg.Register(Manifest("Iv1.testclient")); err != nil {
			rt.Fatal(err)
		}
		if err := lifecycle.NewAuthConfigService(lifecycle.AuthConfigServiceConfig{
			Store: st, Registry: reg, Vault: &labelVault{data: map[vault.Ref]string{}},
		}).EnsureDefaults(); err != nil {
			rt.Fatal(err)
		}
		m := lifecycle.NewManager(lifecycle.Config{
			Store: st, Vault: &labelVault{data: map[vault.Ref]string{}}, Audit: labelAudit{},
			Registry: reg, Clients: labelClients{rt: rtp}, Engine: labelEngine{},
			Runner: labelForget{}, Supervisor: labelSup{},
		})
		m.RegisterProvider(ConnectorID, NewProvider(ProviderConfig{}))
		conn, err := m.Create(context.Background(), lifecycle.CreateInput{
			ConnectorID: ConnectorID, Alias: "gh", Method: MethodDevice,
			AuthConfigID: lifecycle.DefaultAuthConfigID(ConnectorID),
			Credential:   lifecycle.CredentialInput{Secret: []byte("ghu_" + "abcdef0123456789")},
		})
		if err != nil {
			rt.Fatalf("create: %v", err)
		}
		got, ok := st.Connection(conn.ID)
		if !ok {
			rt.Fatal("connection not stored")
		}
		if got.AccountLabel != login {
			rt.Fatalf("label = %q, want %q", got.AccountLabel, login)
		}
		if got.PermissionCheck != store.PermissionUnverifiable {
			rt.Fatalf("permission check = %q", got.PermissionCheck)
		}
	})
}
