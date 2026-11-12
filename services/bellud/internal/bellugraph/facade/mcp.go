package facade

import (
	"bytes"
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

	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/bellugraph/internal/mcp"
)

const (
	auditFileName   = "audit.jsonl"
	maxMCPBodyBytes = 4 << 20
	toolAnnotate    = "annotate_entity"
	// frontDoorIdentity is recorded when the facade is not asked to verify a
	// token itself (bellud's front door already did).
	frontDoorIdentity = "front-door"
)

// MCPTools are the upstream MCP tool names, unchanged.
var MCPTools = []string{
	"describe_schema", "describe_type", "find_entities", "get_entity",
	"annotate_entity", "get_neighbors", "find_path", "impact_of",
	"entity_history", "recent_changes", "graph_diff", "telemetry_keys",
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

// MCPHandler serves the upstream MCP tools over Streamable HTTP. When
// Config.MCPToken is set the handler verifies the bearer token in constant
// time; otherwise it relies on the caller's front door. annotate_entity is
// audited before it is applied.
func (e *engine) MCPHandler() http.Handler {
	if e.State().Kind != StateReady {
		return UnavailableHandler(e.State().Reason)
	}
	st := e.stack
	inner := mcp.New(st.Graph, st.Store).
		SetTenant(st.Tenant).
		SetCadence(st.Engine).
		SetAnnotations(st.Annotations).
		HTTPHandler()
	token := e.cfg.MCPToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := frontDoorIdentity
		if token != "" {
			got, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok || !tokenEqual(got, token) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="bellu-graph"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			identity = TokenIdentity(token)
		}
		ctx := auth.WithWritable(r.Context(), true)
		r = r.WithContext(ctx)
		if r.Method == http.MethodPost && r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBodyBytes+1))
			if err != nil || len(body) > maxMCPBodyBytes {
				http.Error(w, "request body unreadable or too large", http.StatusRequestEntityTooLarge)
				return
			}
			if rid, err := e.auditAnnotations(body, identity); err != nil {
				writeAuditFailure(w, rid, err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		inner.ServeHTTP(w, r)
	})
}

type rpcCall struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string `json:"name"`
		Arguments struct {
			EntityID string `json:"entity_id"`
		} `json:"arguments"`
	} `json:"params"`
}

// auditAnnotations writes an audit record for every annotate_entity call in a
// JSON-RPC body, before any of them is applied. On failure it returns the id
// of the offending request (nil for a batch) and nothing has been applied.
func (e *engine) auditAnnotations(body []byte, identity string) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	var calls []rpcCall
	if len(trimmed) > 0 && trimmed[0] == '[' {
		_ = json.Unmarshal(trimmed, &calls)
	} else {
		var c rpcCall
		if json.Unmarshal(trimmed, &c) == nil {
			calls = append(calls, c)
		}
	}
	batch := len(trimmed) > 0 && trimmed[0] == '['
	for _, c := range calls {
		if c.Method != "tools/call" || c.Params.Name != toolAnnotate {
			continue
		}
		rec := AuditRecord{Time: time.Now().UTC(), Identity: identity, Action: toolAnnotate, EntityID: c.Params.Arguments.EntityID}
		sink := e.audit
		if sink == nil {
			return rpcID(c, batch), errors.New("audit sink unavailable")
		}
		if err := sink.Write(rec); err != nil {
			e.log.Error("audit write failed; annotation not applied", "err", err)
			return rpcID(c, batch), err
		}
	}
	return nil, nil
}

func rpcID(c rpcCall, batch bool) json.RawMessage {
	if batch {
		return nil
	}
	return c.ID
}

func writeAuditFailure(w http.ResponseWriter, id json.RawMessage, cause error) {
	w.Header().Set("Content-Type", "application/json")
	msg := fmt.Sprintf("annotation not applied: audit record could not be written: %v", cause)
	if len(id) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32603, "message": msg}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": msg}}},
	})
}
