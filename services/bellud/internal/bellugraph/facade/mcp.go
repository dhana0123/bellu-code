package facade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/errs"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/bge/mcpserver"
)

const (
	auditFileName   = "audit.jsonl"
	maxMCPBodyBytes = 4 << 20
	toolAnnotate    = "annotate_entity"
	// frontDoorIdentity is recorded when the facade is not asked to verify a
	// token itself (bellud's front door already did).
	frontDoorIdentity = "front-door"
)

// MCPTools are the MCP tool names the Facade serves.
var MCPTools = []string{
	"describe_schema", "describe_type", "find_entities", "get_entity",
	"annotate_entity", "get_neighbors", "find_path", "impact_of",
	"entity_history", "recent_changes", "graph_diff", "telemetry_keys",
	"slice", "attack_paths", "blast_radius", "reachable_vulns",
}

// AuditRecord is one audited operator write.
type AuditRecord struct {
	Time     time.Time `json:"time"`
	Identity string    `json:"identity"` // token identity, never the token
	Action   string    `json:"action"`
	EntityID string    `json:"entity_id"`
}

// AuditSink durably records an AuditRecord. A returned error blocks the write.
type AuditSink interface {
	Write(AuditRecord) error
}

// fileAudit appends JSON lines to a 0600 file and syncs each record.
type fileAudit struct {
	mu sync.Mutex
	f  *os.File
}

func openFileAudit(dir string) (*fileAudit, error) {
	f, err := os.OpenFile(filepath.Join(dir, auditFileName), os.O_WRONLY|os.O_APPEND|os.O_CREATE, fileMode)
	if err != nil {
		return nil, err
	}
	return &fileAudit{f: f}, nil
}

func (a *fileAudit) Write(r AuditRecord) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		return err
	}
	return a.f.Sync()
}

func (a *fileAudit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}

// TokenIdentity derives a stable, non-reversible identity for a bearer token.
func TokenIdentity(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(sum[:6])
}

func bearerToken(h string) (string, bool) {
	const p = "bearer "
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return strings.TrimSpace(h[len(p):]), true
}

func tokenEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

var errUnauthorized = errors.New("unauthorized")

// resolveCaller determines who is calling, in this order: a Caller already on
// the request context (set by bellud's front door); else the bearer token
// matched in constant time against the configured grants (Config.MCPToken is
// an implicit write grant); else, when no grants are configured, the front
// door is trusted and the caller is a write-role "front-door" identity.
func (e *engine) resolveCaller(r *http.Request) (Caller, error) {
	if c, ok := CallerFrom(r.Context()); ok {
		if c.Identity == "" {
			c.Identity = frontDoorIdentity
		}
		return c, nil
	}
	grants := e.cfg.Grants
	if e.cfg.MCPToken != "" {
		grants = append(append([]Grant(nil), grants...), Grant{Token: e.cfg.MCPToken, Role: RoleWrite})
	}
	if len(grants) == 0 {
		return Caller{Role: RoleWrite, Identity: frontDoorIdentity}, nil
	}
	got, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return Caller{}, errUnauthorized
	}
	var match *Grant
	for i := range grants { // no early exit: every grant is compared
		if tokenEqual(got, grants[i].Token) && match == nil {
			match = &grants[i]
		}
	}
	if match == nil {
		return Caller{}, errUnauthorized
	}
	return Caller{Role: match.Role, Identity: TokenIdentity(match.Token)}, nil
}

// authorizeIngest is the OTLP receiver's authorizer: the caller must be
// resolvable and allowed to ingest.
func (e *engine) authorizeIngest(r *http.Request) error {
	c, err := e.resolveCaller(r)
	if err != nil {
		return err
	}
	if !c.Role.Allows(RoleIngest) {
		return errs.Forbidden
	}
	return nil
}

// MCPHandler serves the MCP tools over Streamable HTTP. It wraps the engine's
// MCP handler with readiness (503 graph_unavailable), caller resolution (401
// with a Bearer challenge when a token is required and missing or wrong) and
// a 4 MiB request body limit (413). annotate_entity is audited before it is
// applied.
func (e *engine) MCPHandler() http.Handler {
	if e.State().Kind != StateReady {
		return UnavailableHandler(e.State().Reason)
	}
	srv, err := mcpserver.New(mcpserver.Config{
		Core:     e.stack,
		Annotate: e.annotateAudited,
		CallerRole: func(ctx context.Context) string {
			c, _ := CallerFrom(ctx)
			return string(c.Role)
		},
	})
	if err != nil {
		e.log.Error("mcp server unavailable", "err", err)
		return UnavailableHandler(err.Error())
	}
	if e.cfg.MCPExtras != nil {
		e.cfg.MCPExtras(srv.MCP())
	}
	inner := srv.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.State().Kind != StateReady {
			UnavailableHandler(e.State().Reason).ServeHTTP(w, r)
			return
		}
		caller, err := e.resolveCaller(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="bellu-graph"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(WithCaller(r.Context(), caller))
		if r.Method == http.MethodPost && r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBodyBytes+1))
			if err != nil || len(body) > maxMCPBodyBytes {
				http.Error(w, "request body unreadable or too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		inner.ServeHTTP(w, r)
	})
}

// annotateAudited is the only path to Core.Annotate. It checks the caller's
// role, writes (and syncs) the audit record, and only then applies the
// annotation; when the audit write fails nothing is applied.
func (e *engine) annotateAudited(ctx context.Context, id string, set map[string]string, unset []string) error {
	caller, ok := CallerFrom(ctx)
	if !ok {
		caller = Caller{Role: RoleWrite, Identity: frontDoorIdentity}
	}
	if !caller.Role.Allows(RoleWrite) {
		return fmt.Errorf("%w: annotating needs the write role", ErrForbidden)
	}
	if caller.Identity == "" {
		caller.Identity = frontDoorIdentity
	}
	sink := e.audit
	if sink == nil {
		return errors.New("annotation not applied: audit sink unavailable")
	}
	rec := AuditRecord{Time: time.Now().UTC(), Identity: caller.Identity, Action: toolAnnotate, EntityID: id}
	if err := sink.Write(rec); err != nil {
		e.log.Error("audit write failed; annotation not applied", "err", err)
		return fmt.Errorf("annotation not applied: audit record could not be written: %w", err)
	}
	_, err := e.stack.Annotate(ctx, id, set, unset, caller.Identity)
	return err
}
