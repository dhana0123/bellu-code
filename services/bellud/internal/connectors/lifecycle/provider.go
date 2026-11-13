package lifecycle

import (
	"context"
	"net/http"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Identity is what a provider reports for a verified credential.
type Identity struct {
	// AccountLabel is a non-secret label such as an account id or login.
	AccountLabel string
	// ExpiresAt is the credential expiry when the provider knows it (zero otherwise).
	ExpiresAt time.Time
}

// PermissionReport is the result of a permission check.
type PermissionReport struct {
	// WriteOffenders names every write permission the credential holds.
	WriteOffenders []string
	// Unverifiable is true when the check could not be completed
	// (for example a best-effort simulation that was denied).
	Unverifiable bool
}

// Descriptor tells the manager how the broker should reach one connection.
type Descriptor struct {
	Auth     broker.AuthKind
	APIHost  string
	BasePath string
	// Host replaces {host} in manifest host patterns (GitHub Enterprise Server).
	Host string
}

// Call is the input to Verify, CheckPermissions and Refresh. Client is built on
// the broker, so every request it sends passes the policy transport.
type Call struct {
	Connection store.Connection
	Ref        broker.ConnectionRef
	Client     *http.Client
}

// Provider is the provider-neutral surface of one connector. Failures should be
// returned as *Error; other errors are classified from the broker's typed errors.
type Provider interface {
	// Verify checks the identity of the credential.
	Verify(ctx context.Context, c Call) (Identity, error)
	// CheckPermissions lists write permissions held by the credential.
	CheckPermissions(ctx context.Context, c Call) (PermissionReport, error)
	// Refresh renews a session credential and returns its new expiry.
	Refresh(ctx context.Context, c Call) (time.Time, error)
	// Collector builds the collector run for an ACTIVE connection.
	Collector(conn store.Connection, ref broker.ConnectionRef) collectors.Collector
	// Describe returns the broker routing of a connection.
	Describe(conn store.Connection) Descriptor
}

// CredentialValidator is an optional Provider extension. The manager calls it
// before any audit, store or vault step in Create, Reconnect and Rotate.
type CredentialValidator interface {
	ValidateCredential(secret []byte) error
}
