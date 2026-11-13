package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	svc "github.com/bellu/bellucode/services/bellud/internal/connectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/scope"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Prefix is the route prefix; handlers register full paths, so mount at "/".
const Prefix = "/api/experimental/connectors"

// Route describes one registered route. Name is the protocol identifier suffix
// (`experimental.connectors.<Name>`).
type Route struct {
	Name    string
	Method  string
	Pattern string // path below Prefix, ServeMux syntax
	// Credential marks a credential-bearing write (Req 6.14, 6.15).
	Credential bool
	// Body is the route's body schema; nil for routes without a body.
	body func(map[string]any) (any, []string)
	// known are the route's own top-level body fields.
	known map[string]bool
}

var routeTable = []Route{
	{Name: "status", Method: "GET", Pattern: "/status"},
	{Name: "catalog", Method: "GET", Pattern: "/catalog"},
	{Name: "listConnections", Method: "GET", Pattern: "/connections"},
	{Name: "createConnection", Method: "POST", Pattern: "/connections", Credential: true, body: parseCreate,
		known: fields("alias", "connectorId", "authConfigId", "method", "params", "credential", "intervalSec")},
	{Name: "getConnection", Method: "GET", Pattern: "/connections/{id}"},
	{Name: "updateConnection", Method: "PATCH", Pattern: "/connections/{id}", body: parseUpdate,
		known: fields("alias", "intervalSec", "allowAgentLiveReads", "selection", "rotationIntervalDays")},
	{Name: "deleteConnection", Method: "DELETE", Pattern: "/connections/{id}"},
	{Name: "testConnection", Method: "POST", Pattern: "/connections/{id}/test"},
	{Name: "syncConnection", Method: "POST", Pattern: "/connections/{id}/sync"},
	{Name: "pauseConnection", Method: "POST", Pattern: "/connections/{id}/pause"},
	{Name: "resumeConnection", Method: "POST", Pattern: "/connections/{id}/resume"},
	{Name: "reconnectConnection", Method: "POST", Pattern: "/connections/{id}/reconnect", Credential: true,
		body: parseReplace, known: fields("credential")},
	{Name: "rotateCredential", Method: "POST", Pattern: "/connections/{id}/rotate", Credential: true,
		body: parseReplace, known: fields("credential")},
	{Name: "listAudit", Method: "GET", Pattern: "/connections/{id}/audit"},
	{Name: "listAuthConfigs", Method: "GET", Pattern: "/connectors/{cid}/auth-configs"},
	{Name: "createAuthConfig", Method: "POST", Pattern: "/connectors/{cid}/auth-configs", Credential: true,
		body: parseCreateAuthConfig, known: fields("name", "method", "scopes", "settings", "secrets")},
	{Name: "deleteAuthConfig", Method: "DELETE", Pattern: "/auth-configs/{id}"},
	{Name: "awsSetup", Method: "POST", Pattern: "/aws/setup", body: parseAwsSetup, known: fields("alias")},
	{Name: "listGithubRepos", Method: "GET", Pattern: "/connections/{id}/github/repos"},
	{Name: "getScope", Method: "GET", Pattern: "/scopes/{principal}"},
	{Name: "putScope", Method: "PUT", Pattern: "/scopes/{principal}", body: parseScope,
		known: fields("connectors", "connections", "operations")},
	{Name: "unlockVault", Method: "POST", Pattern: "/vault/unlock", body: parseUnlock, known: fields("passphrase")},
	{Name: "rotateMasterKey", Method: "POST", Pattern: "/vault/rotate"},
	{Name: "forgetAll", Method: "POST", Pattern: "/vault/forget"},
}

func fields(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Routes lists every route the handler registers. The no-token-export scan
// enumerates it to prove each route is exercised (Req 15.7).
func Routes() []Route { return append([]Route(nil), routeTable...) }

// APIConfig configures NewAPI.
type APIConfig struct {
	Service *svc.Service
	// Scope serves getScope and putScope. Share the instance the connector MCP
	// broker consults so a Put is visible at once; nil builds a private one.
	Scope *scope.Service
	// Role names the caller role of an authenticated request ("user" for the
	// Bellu Code web client). Nil means every request is "user"; a request whose
	// role is not "user" can never write a credential.
	Role func(*http.Request) string
	// AllowedHosts adds host names (no port) to localhost, 127.0.0.1 and ::1.
	AllowedHosts []string
}

// Handler serves the connector HTTP API.
type Handler struct {
	svc   *svc.Service
	scope *scope.Service
	role  func(*http.Request) string
	hosts []string
	mux   *http.ServeMux
}

// call is the per-request state handed to a route function.
type call struct {
	id   string
	role string
	in   any
}

type routeFunc func(w http.ResponseWriter, r *http.Request, c *call)

// NewAPI returns the API handler. Disabled services answer 404 on every route.
func NewAPI(cfg APIConfig) *Handler {
	h := &Handler{svc: cfg.Service, scope: cfg.Scope, role: cfg.Role, mux: http.NewServeMux()}
	if h.scope == nil && cfg.Service.Enabled() {
		h.scope = scope.New(cfg.Service.Store(), cfg.Service.Registry(), nil)
	}
	for _, x := range cfg.AllowedHosts {
		h.hosts = append(h.hosts, strings.ToLower(x))
	}
	fns := map[string]routeFunc{
		"status":           h.status,
		"catalog":          h.catalog,
		"listConnections":  h.listConnections,
		"createConnection": h.createConnection,
		"getConnection":    h.getConnection,
		"updateConnection": h.updateConnection,
		"deleteConnection": h.deleteConnection,

		"testConnection":      h.testConnection,
		"syncConnection":      h.syncConnection,
		"pauseConnection":     h.pauseConnection,
		"resumeConnection":    h.resumeConnection,
		"reconnectConnection": h.reconnectConnection,
		"rotateCredential":    h.rotateCredential,
		"listAudit":           h.listAudit,
		"listAuthConfigs":     h.listAuthConfigs,
		"createAuthConfig":    h.createAuthConfig,
		"deleteAuthConfig":    h.deleteAuthConfig,
		"awsSetup":            h.awsSetup,
		"listGithubRepos":     h.listGithubRepos,
		"getScope":            h.getScope,
		"putScope":            h.putScope,
		"unlockVault":         h.unlockVault,
		"rotateMasterKey":     h.rotateMasterKey,
		"forgetAll":           h.forgetAll,
	}
	for _, rt := range routeTable {
		fn, ok := fns[rt.Name]
		if !ok {
			panic("connectors api: no handler for route " + rt.Name)
		}
		h.mux.HandleFunc(rt.Method+" "+Prefix+rt.Pattern, h.wrap(rt, fn))
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(&redactingWriter{ResponseWriter: w, red: h.redact}, r)
}

func (h *Handler) redact(s string) string {
	if h.svc == nil || h.svc.Redactor() == nil {
		return s
	}
	return h.svc.Redactor().String(s)
}

// redactingWriter passes every response body through the Secret_Redactor
// (Req 6.16), the last line of defence behind the masked wire types.
type redactingWriter struct {
	http.ResponseWriter
	red func(string) string
}

func (w *redactingWriter) Write(b []byte) (int, error) {
	out := w.red(string(b))
	if _, err := w.ResponseWriter.Write([]byte(out)); err != nil {
		return 0, err
	}
	return len(b), nil
}

// wrap applies the request guards in the order of the design: flag, fetch
// metadata, credential-write guard, body limit, schema validation.
func (h *Handler) wrap(rt Route, fn routeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.svc == nil || !h.svc.Enabled() {
			writeNotFound(w, "not found")
			return
		}
		c := &call{id: r.PathValue("id"), role: RoleUser}
		if h.role != nil {
			c.role = h.role(r)
		}
		if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
			h.reject(r, c, "cross_site")
			h.writeForbidden(w)
			return
		}
		if rt.Credential {
			if reason := h.guardReason(r, c.role); reason != "" {
				h.reject(r, c, reason)
				h.writeForbidden(w)
				return
			}
		}
		var obj map[string]any
		if rt.body != nil {
			var ok bool
			if obj, ok = h.readBody(w, r); !ok {
				return
			}
		}
		h.auditOptions(r, c, obj, rt.known)
		if rt.body != nil {
			in, bad := rt.body(obj)
			if len(bad) > 0 {
				h.writeErr(w, h.invalid("request body failed validation", bad...))
				return
			}
			c.in = in
		}
		fn(w, r, c)
	}
}

// readBody enforces the 1 MiB limit before parsing and decodes one JSON object.
// Failures are written and reported as ok=false; messages never echo input.
func (h *Handler) readBody(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	tooLarge := func() {
		h.writeErr(w, lifecycle.NewError(lifecycle.CodePayloadTooLarge, "request body exceeds 1 MiB", nil))
	}
	if r.ContentLength > maxBody {
		tooLarge()
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		h.writeErr(w, h.invalid("request body could not be read", "body"))
		return nil, false
	}
	if len(raw) > maxBody {
		tooLarge()
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil || dec.More() {
		h.writeErr(w, h.invalid("request body is not a JSON object", "body"))
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		h.writeErr(w, h.invalid("request body is not a JSON object", "body"))
		return nil, false
	}
	return obj, true
}

func (h *Handler) invalid(msg string, fields ...string) *lifecycle.Error {
	red := h.redactor()
	return lifecycle.NewError(lifecycle.CodeValidationFailed, msg, red).WithOffenders(fields, red)
}

func (h *Handler) redactor() lifecycle.Redactor {
	if h.svc == nil || h.svc.Redactor() == nil {
		return nil
	}
	return h.svc.Redactor()
}

// reject audits a refused request (Req 6.15). Nothing from the request body is recorded.
func (h *Handler) reject(r *http.Request, c *call, reason string) {
	h.appendAudit(r.Context(), audit.Entry{
		ConnectionID: c.id, Event: audit.EventBlockedOperation, Outcome: audit.OutcomeBlocked,
		Actor:  actorOf(c.role),
		Detail: map[string]string{"role": c.role, "reason": reason, "method": r.Method, "route": r.Pattern},
	})
}

// auditOptions records each ignored credential-requesting option (Req 15.3).
// The option is otherwise ignored, so the response is the same masked one.
func (h *Handler) auditOptions(r *http.Request, c *call, body map[string]any, known map[string]bool) {
	for _, opt := range credentialOptions(r, body, known) {
		h.appendAudit(r.Context(), audit.Entry{
			ConnectionID: c.id, Event: audit.EventCredentialOptionIgnored, Outcome: audit.OutcomeBlocked,
			Actor:  actorOf(c.role),
			Detail: map[string]string{"role": c.role, "option": opt, "route": r.Pattern},
		})
	}
}

func (h *Handler) appendAudit(ctx context.Context, e audit.Entry) {
	l := h.svc.Audit()
	if l == nil {
		return
	}
	if e.ConnectorID == "" && e.ConnectionID != "" {
		if conn, ok := h.svc.Connection(e.ConnectionID); ok {
			e.ConnectorID = conn.ConnectorID
		}
	}
	// An audit failure must not turn a rejection into an acceptance.
	_ = l.Append(context.WithoutCancel(ctx), e)
}

func actorOf(role string) string {
	if role == "" {
		return "unauthenticated"
	}
	return role
}

// ---- routes ----

func (h *Handler) status(w http.ResponseWriter, _ *http.Request, _ *call) {
	st := h.svc.Status()
	if st.Warnings == nil {
		st.Warnings = []string{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handler) catalog(w http.ResponseWriter, _ *http.Request, _ *call) {
	ms := h.svc.Catalog()
	items := make([]manifest.Manifest, 0, len(ms))
	for _, m := range ms {
		items = append(items, normalizeManifest(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) listConnections(w http.ResponseWriter, _ *http.Request, _ *call) {
	conns := h.svc.Connections()
	items := make([]store.Connection, 0, len(conns))
	for _, c := range conns {
		items = append(items, normalizeConnection(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createConnection(w http.ResponseWriter, r *http.Request, c *call) {
	in := c.in.(createInput)
	conn, err := h.svc.Create(r.Context(), svc.CreateInput{
		ConnectorID: in.ConnectorID, Alias: in.Alias, AuthConfigID: in.AuthConfigID, Method: in.Method,
		Params: in.Params, Credential: in.Credential, IntervalSec: in.IntervalSec,
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, normalizeConnection(conn))
}

func (h *Handler) getConnection(w http.ResponseWriter, _ *http.Request, c *call) {
	conn, ok := h.svc.Connection(c.id)
	if !ok {
		writeNotFound(w, "connection not found")
		return
	}
	writeJSON(w, http.StatusOK, normalizeConnection(conn))
}

func (h *Handler) updateConnection(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.svc.Connection(c.id); !ok {
		writeNotFound(w, "connection not found")
		return
	}
	in := c.in.(updateInput)
	err := h.svc.Update(r.Context(), c.id, lifecycle.ConnectionPatch{
		Alias: in.Alias, IntervalSec: in.IntervalSec, AllowAgentLiveReads: in.AllowAgentLiveReads,
		RotationIntervalDays: in.RotationIntervalDays, Selection: in.Selection,
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	conn, ok := h.svc.Connection(c.id)
	if !ok {
		writeNotFound(w, "connection not found")
		return
	}
	writeJSON(w, http.StatusOK, normalizeConnection(conn))
}

func (h *Handler) deleteConnection(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.svc.Connection(c.id); !ok {
		writeNotFound(w, "connection not found")
		return
	}
	if err := h.svc.Disconnect(r.Context(), c.id); err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- remaining routes ----

// connection answers 404 for an unknown connection.
func (h *Handler) connection(w http.ResponseWriter, c *call) (store.Connection, bool) {
	conn, ok := h.svc.Connection(c.id)
	if !ok {
		writeNotFound(w, "connection not found")
	}
	return conn, ok
}

func (h *Handler) writeConnection(w http.ResponseWriter, c *call) {
	conn, ok := h.connection(w, c)
	if ok {
		writeJSON(w, http.StatusOK, normalizeConnection(conn))
	}
}

func (h *Handler) testConnection(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	res, err := h.svc.TestDetail(r.Context(), c.id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	check := res.Report.Permission
	if check == "" {
		check = store.PermissionOK
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "accountLabel": res.Report.AccountLabel, "permissionCheck": check,
		"offenders": []string{}, "warnings": res.Warnings,
	})
}

func (h *Handler) syncConnection(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	if err := h.svc.SyncNow(r.Context(), c.id); err != nil {
		h.writeErr(w, err)
		return
	}
	conn, ok := h.connection(w, c)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"started": true, "connection": normalizeConnection(conn)})
}

func (h *Handler) pauseConnection(w http.ResponseWriter, r *http.Request, c *call) {
	h.transition(w, r, c, h.svc.Pause)
}

func (h *Handler) resumeConnection(w http.ResponseWriter, r *http.Request, c *call) {
	h.transition(w, r, c, h.svc.Resume)
}

func (h *Handler) transition(w http.ResponseWriter, r *http.Request, c *call, fn func(context.Context, string) error) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	if err := fn(r.Context(), c.id); err != nil {
		h.writeErr(w, err)
		return
	}
	h.writeConnection(w, c)
}

func (h *Handler) reconnectConnection(w http.ResponseWriter, r *http.Request, c *call) {
	h.replace(w, r, c, h.svc.Reconnect)
}

func (h *Handler) rotateCredential(w http.ResponseWriter, r *http.Request, c *call) {
	h.replace(w, r, c, h.svc.Rotate)
}

func (h *Handler) replace(w http.ResponseWriter, r *http.Request, c *call, fn func(context.Context, string, map[string]string) error) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	if err := fn(r.Context(), c.id, c.in.(replaceInput).Credential); err != nil {
		h.writeErr(w, err)
		return
	}
	h.writeConnection(w, c)
}

// auditPageSize is the fixed page size of listAudit.
const auditPageSize = 50

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	page, err := h.svc.ListAudit(c.id, r.URL.Query().Get("cursor"), auditPageSize)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	items := page.Entries
	if items == nil {
		items = []audit.Entry{}
	}
	out := map[string]any{"items": items}
	if page.NextCursor != "" {
		out["nextCursor"] = page.NextCursor
	}
	writeJSON(w, http.StatusOK, out)
}

func normalizeAuthConfig(a store.AuthConfig) store.AuthConfig {
	if a.Scopes == nil {
		a.Scopes = []string{}
	}
	if a.Settings == nil {
		a.Settings = map[string]string{}
	}
	return a
}

func (h *Handler) listAuthConfigs(w http.ResponseWriter, r *http.Request, _ *call) {
	list, err := h.svc.AuthConfigs(r.PathValue("cid"))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	items := make([]store.AuthConfig, 0, len(list))
	for _, a := range list {
		items = append(items, normalizeAuthConfig(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createAuthConfig(w http.ResponseWriter, r *http.Request, c *call) {
	in := c.in.(authConfigInput)
	secrets := make(map[string][]byte, len(in.Secrets))
	for k, v := range in.Secrets {
		secrets[k] = []byte(v)
	}
	ac, err := h.svc.CreateAuthConfig(r.Context(), lifecycle.CreateAuthConfigInput{
		ConnectorID: r.PathValue("cid"), Name: in.Name, Method: in.Method,
		Scopes: in.Scopes, Settings: in.Settings, Secrets: secrets,
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, normalizeAuthConfig(ac))
}

func (h *Handler) deleteAuthConfig(w http.ResponseWriter, r *http.Request, _ *call) {
	if err := h.svc.DeleteAuthConfig(r.Context(), r.PathValue("id")); err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) awsSetup(w http.ResponseWriter, r *http.Request, c *call) {
	res, err := h.svc.AWSSetup(r.Context(), c.in.(awsSetupInput).Alias)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	out := map[string]any{"externalId": res.ExternalID, "cloudFormation": res.CloudFormation, "terraform": res.Terraform}
	if res.Principal != "" {
		out["principal"] = res.Principal
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) listGithubRepos(w http.ResponseWriter, r *http.Request, c *call) {
	if _, ok := h.connection(w, c); !ok {
		return
	}
	repos, err := h.svc.GithubRepos(r.Context(), c.id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	items := make([]map[string]any, 0, len(repos))
	for _, rp := range repos {
		items = append(items, map[string]any{"fullName": rp.FullName, "private": rp.Private})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func normalizeScope(sc store.Scope) store.Scope {
	if sc.Connectors == nil {
		sc.Connectors = []string{}
	}
	if sc.Connections == nil {
		sc.Connections = []string{}
	}
	ops := make(map[string][]string, len(sc.Operations))
	for k, v := range sc.Operations {
		if v == nil {
			v = []string{}
		}
		ops[k] = v
	}
	sc.Operations = ops
	return sc
}

func (h *Handler) getScope(w http.ResponseWriter, r *http.Request, _ *call) {
	writeJSON(w, http.StatusOK, normalizeScope(h.scope.Get(r.PathValue("principal"))))
}

func (h *Handler) putScope(w http.ResponseWriter, r *http.Request, c *call) {
	principal := r.PathValue("principal")
	in := c.in.(store.Scope)
	in.Principal = principal
	if err := h.scope.Put(principal, in); err != nil {
		var ve *scope.ValidationError
		if errors.As(err, &ve) {
			name := ve.Field
			if ve.Operation != "" {
				name = ve.Operation
			}
			h.writeErr(w, h.invalid("scope failed validation", name))
			return
		}
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, normalizeScope(h.scope.Get(principal)))
}

func (h *Handler) unlockVault(w http.ResponseWriter, r *http.Request, c *call) {
	if err := h.svc.Unlock(r.Context(), []byte(c.in.(unlockInput).Passphrase)); err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) rotateMasterKey(w http.ResponseWriter, r *http.Request, _ *call) {
	if err := h.svc.RotateMasterKey(r.Context()); err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) forgetAll(w http.ResponseWriter, r *http.Request, _ *call) {
	if err := h.svc.ForgetAll(r.Context()); err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- wire helpers ----

// normalizeConnection turns nil slices into empty ones so the JSON matches the
// Effect schema (arrays, never null). store.Connection carries no credential.
func normalizeConnection(c store.Connection) store.Connection {
	if c.Selection.Regions == nil {
		c.Selection.Regions = []string{}
	}
	if c.Selection.Repos == nil {
		c.Selection.Repos = []string{}
	}
	if c.LastSync != nil {
		ls := *c.LastSync
		if ls.Partial == nil {
			ls.Partial = []string{}
		}
		c.LastSync = &ls
	}
	return c
}

func normalizeManifest(m manifest.Manifest) manifest.Manifest {
	if m.AuthMethods == nil {
		m.AuthMethods = []manifest.AuthMethod{}
	}
	if m.Permissions == nil {
		m.Permissions = []manifest.Permission{}
	}
	if m.Operations == nil {
		m.Operations = []manifest.Operation{}
	}
	if m.Egress == nil {
		m.Egress = []string{}
	}
	if m.Entities == nil {
		m.Entities = []string{}
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeNotFound(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusNotFound, map[string]string{"_tag": "NotFoundError", "message": msg})
}

func (h *Handler) writeForbidden(w http.ResponseWriter) {
	h.writeErr(w, lifecycle.NewError(lifecycle.CodeForbidden, "request is not permitted", nil))
}

// connectorError is the ConnectorError wire body of packages/protocol.
type connectorError struct {
	Tag       string   `json:"_tag"`
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	Offenders []string `json:"offenders,omitempty"`
	InUse     int      `json:"inUse,omitempty"`
}

// writeErr maps a service error to its wire form. Typed lifecycle errors keep
// their credential-free message (`settings.connectors.error.<code>` on the
// client); anything else becomes a generic internal error whose text is not
// echoed, because untyped errors can carry request data.
func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	var le *lifecycle.Error
	switch {
	case errors.As(err, &le):
		switch le.Code {
		case lifecycle.CodeRunInProgress:
			writeJSON(w, http.StatusConflict, map[string]string{"_tag": "ConflictError", "message": le.Message, "resource": "connection"})
			return
		}
		status := http.StatusBadRequest
		switch le.Code {
		case lifecycle.CodeForbidden:
			status = http.StatusForbidden
		case lifecycle.CodePayloadTooLarge:
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, connectorError{Tag: "ConnectorError", Code: string(le.Code), Message: le.Message, Offenders: le.Offenders, InUse: le.InUse})
	case errors.Is(err, svc.ErrDisabled), errors.Is(err, store.ErrNotFound):
		writeNotFound(w, "not found")
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"_tag": "UnknownError", "message": "internal error"})
	}
}
