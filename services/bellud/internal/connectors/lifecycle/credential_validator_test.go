package lifecycle

import (
	"context"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// prefixProvider mimics the GitHub provider: it rejects non-"ok_" secrets.
type prefixProvider struct{ *mgrProvider }

func (prefixProvider) ValidateCredential(s []byte) error {
	if !strings.HasPrefix(string(s), "ok_") {
		return NewError(CodeValidationFailed, "Classic tokens are not supported", nil)
	}
	return nil
}

// Validates: Requirements 4.2 (manager path).
func TestCredentialValidatorRejectsBeforeAnyStep(t *testing.T) {
	f := newMgrFix(t)
	f.m.RegisterProvider("ex", prefixProvider{f.p})
	ctx := context.Background()
	bad := "ghp_supersecretvalue"

	check := func(err error) {
		t.Helper()
		if codeOf(t, err) != CodeValidationFailed {
			t.Fatalf("code: %v", err)
		}
		if strings.Contains(err.Error(), bad) {
			t.Fatal("error echoes secret")
		}
	}
	_, err := f.m.Create(ctx, CreateInput{ConnectorID: "ex", Alias: "a", Method: "token", Credential: CredentialInput{Secret: []byte(bad)}})
	check(err)
	if n := len(f.st.Snapshot().Connections); n != 0 || len(f.v.data) != 0 || len(f.a.entries) != 0 {
		t.Fatalf("create left state: conns=%d vault=%d audit=%d", n, len(f.v.data), len(f.a.entries))
	}

	c := f.create(t, "good", "ok_token")
	before := len(f.a.entries)
	check(f.m.Rotate(ctx, c.ID, CredentialInput{Secret: []byte(bad)}))
	check(f.m.Reconnect(ctx, c.ID, CredentialInput{Secret: []byte(bad)}))
	got, _ := f.st.Connection(c.ID)
	if got.Status != string(StatusActive) || len(f.a.entries) != before || f.v.data[credRef(c.ID)] != "ok_token" {
		t.Fatalf("rotate/reconnect changed state: %+v", got)
	}
	_ = store.Connection{}
}
