package deviceflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/manifest"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/redactor"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/registry"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// Limits.
const (
	// MaxPending is the maximum number of concurrent pending authorizations.
	MaxPending = 8
	// Retention is how long a terminal entry stays readable.
	Retention = 2 * time.Minute

	maxResponse       = 16 << 10
	requestTimeout    = 15 * time.Second
	connectTimeout    = 60 * time.Second
	defaultCodeExpiry = 900 * time.Second
	maxRetryAfterSec  = 3600
)

// Phases of the device_authorization audit event.
const (
	PhaseStarted   = "started"
	PhaseConnected = "connected"
	PhaseDenied    = "denied"
	PhaseExpired   = "expired"
	PhaseCancelled = "cancelled"
	PhaseFailed    = "failed"
)

// Status values reported by Status.
const (
	StatusPending   = "pending"
	StatusConnected = "connected"
	StatusExpired   = "expired"
	StatusDenied    = "denied"
	StatusFailed    = "failed"
)

// ErrNotFound is returned for an unknown, removed or cancelled authorization id.
var ErrNotFound = errors.New("deviceflow: authorization not found")

// Spec is read from the manifest's enabled "device" auth method.
type Spec struct {
	DeviceCodeURL, TokenURL *url.URL // tenant placeholders already resolved
	ClientID                string
	Scopes                  []string
	TokenGrant              string // grant_type of the token request
	KeepRefresh             bool   // decode and keep refresh_token
}

// Clients builds policy-enforcing clients. *broker.Broker satisfies it.
type Clients interface {
	HTTPClient(ref broker.ConnectionRef, caller string) *http.Client
}

// StartInput describes one authorization.
type StartInput struct {
	ConnectorID string
	Alias       string // empty when ReconnectID is set
	ReconnectID string
	// Tenant fills the {tenant} placeholder of the manifest URLs. Empty uses the
	// manifest tenant, then manifest.DefaultTenant.
	Tenant string
}

// Authorization is the start response. It never carries the device code.
type Authorization struct {
	ID          string
	UserCode    string
	VerifyURI   string
	ExpiresAt   time.Time
	IntervalSec int
}

// State is the status response.
type State struct {
	Status        string
	ExpiresAt     time.Time
	IntervalSec   int
	Connection    *store.Connection // only when connected
	ErrorCode     lifecycle.Code
	RetryAfterSec int
}

// ConnectRequest hands a received token to the connector layer.
type ConnectRequest struct {
	ConnectorID, Alias, ReconnectID string
	Token                           []byte    // owned by the callee, zeroed after use
	RefreshToken                    []byte    // owned by the callee; nil when none was kept
	ExpiresAt                       time.Time // zero when the provider sent no expires_in
}

// Config wires the Service.
type Config struct {
	Clients  Clients
	Registry registry.Registry
	Audit    audit.Log
	Redactor *redactor.Redactor
	Store    *store.Store
	// PreRef builds the pre-connection ref for a connector.
	PreRef func(connectorID, authID string) (broker.ConnectionRef, error)
	// Connect turns a received token into a Connection (new or reconnect).
	Connect func(ctx context.Context, req ConnectRequest) (store.Connection, error)
	// Abandon deletes a Connection created by this flow.
	Abandon func(ctx context.Context, connectionID string) error
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
}

type entryState int

const (
	statePending entryState = iota
	stateConnecting
	stateConnected
	stateExpired
	stateDenied
	stateFailed
	stateCancelled
)

type entry struct {
	id, connectorID, alias string
	reconnectID            string
	userCode, verifyURI    string
	expiresAt              time.Time
	cancel                 context.CancelFunc

	mu            sync.Mutex
	deviceCode    []byte // memory only, zeroed on any terminal state
	releaseDevice func()
	interval      time.Duration
	state         entryState
	errCode       lifecycle.Code
	retryAfterSec int
	conn          *store.Connection
	removeAt      time.Time
}

// Service runs device authorizations. It is safe for concurrent use.
type Service struct {
	cfg  Config
	root context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	entries map[string]*entry
}

// New builds a Service.
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	root, stop := context.WithCancel(context.Background())
	return &Service{cfg: cfg, root: root, stop: stop, entries: map[string]*entry{}}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Start requests a device code and begins polling. A strict audit entry is
// written before anything is sent to GitHub.
func (s *Service) Start(ctx context.Context, in StartInput) (Authorization, error) {
	spec, err := s.spec(in.ConnectorID, in.Tenant)
	if err != nil {
		return Authorization{}, err
	}
	alias, err := s.checkTarget(in)
	if err != nil {
		return Authorization{}, err
	}
	e := &entry{id: newID(), connectorID: in.ConnectorID, alias: alias, reconnectID: in.ReconnectID}
	if err := s.reserve(e); err != nil {
		return Authorization{}, err
	}
	if err := s.record(ctx, e, PhaseStarted, audit.OutcomeSuccess); err != nil {
		s.drop(e)
		return Authorization{}, lifecycle.NewError(lifecycle.CodeAuditFailed, "audit log is unavailable", s.cfg.Redactor)
	}
	client, err := s.client(e)
	if err != nil {
		s.failStart(e)
		return Authorization{}, err
	}
	dc, interval, err := s.requestCode(ctx, client, spec)
	if err != nil {
		s.failStart(e)
		return Authorization{}, err
	}
	if err := s.checkVerifyURI(e, dc); err != nil {
		clear(dc.deviceCode)
		s.failStart(e)
		return Authorization{}, err
	}
	pctx, cancel := context.WithCancel(s.root)
	now := s.cfg.Now()
	e.mu.Lock()
	e.deviceCode, e.releaseDevice = dc.deviceCode, dc.release
	e.userCode, e.verifyURI = dc.userCode, dc.verifyURI
	e.expiresAt = now.Add(dc.expiresIn)
	e.interval = interval
	e.cancel = cancel
	e.mu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		s.finish(e, stateCancelled, "", 0, PhaseCancelled)
		return Authorization{}, ErrNotFound
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go s.run(pctx, e, spec, client)
	return Authorization{ID: e.id, UserCode: e.userCode, VerifyURI: e.verifyURI, ExpiresAt: e.expiresAt, IntervalSec: int(interval / time.Second)}, nil
}

// Status returns the state of an authorization.
func (s *Service) Status(id string) (State, error) {
	e, ok := s.lookup(id)
	if !ok {
		return State{}, ErrNotFound
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := State{ErrorCode: e.errCode, RetryAfterSec: e.retryAfterSec}
	switch e.state {
	case statePending, stateConnecting:
		st.Status, st.ExpiresAt, st.IntervalSec = StatusPending, e.expiresAt, int(e.interval/time.Second)
	case stateConnected:
		st.Status = StatusConnected
		if e.conn != nil {
			c := *e.conn
			if cur, ok := s.cfg.Store.Connection(c.ID); ok {
				c = cur
			}
			st.Connection = &c
		}
	case stateExpired:
		st.Status = StatusExpired
	case stateDenied:
		st.Status = StatusDenied
	default:
		st.Status = StatusFailed
	}
	return st, nil
}

// Cancel stops an authorization. A Connection created by it is abandoned only
// when its selection is still empty and the flow is not a reconnect.
func (s *Service) Cancel(ctx context.Context, id string) error {
	e, ok := s.lookup(id)
	if !ok {
		return ErrNotFound
	}
	e.mu.Lock()
	switch e.state {
	case statePending, stateConnecting:
		// A connecting goroutine abandons the Connection when Connect returns.
		e.state = stateCancelled
		s.zeroLocked(e)
		e.mu.Unlock()
		e.cancelPoll()
	case stateConnected:
		conn := e.conn
		if e.reconnectID != "" || conn == nil || !s.selectionEmpty(conn.ID) {
			e.mu.Unlock()
			return nil
		}
		e.state = stateCancelled
		e.mu.Unlock()
		_ = s.cfg.Abandon(ctx, conn.ID)
	default:
		e.state = stateCancelled
		e.mu.Unlock()
	}
	s.drop(e)
	_ = s.record(ctx, e, PhaseCancelled, audit.OutcomeSuccess)
	return nil
}

// Close cancels every poll and waits for the goroutines (bounded by ctx).
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	all := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, e)
	}
	s.mu.Unlock()

	for _, e := range all {
		e.mu.Lock()
		if e.state == statePending || e.state == stateConnecting {
			e.state = stateCancelled
			s.zeroLocked(e)
		}
		e.mu.Unlock()
		e.cancelPoll()
	}
	s.stop()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *entry) cancelPoll() {
	if e.cancel != nil {
		e.cancel()
	}
}

// ---- start helpers ----

func (s *Service) spec(connectorID, tenant string) (Spec, error) {
	reg, ok := s.cfg.Registry.Get(connectorID)
	if !ok {
		return Spec{}, s.invalid("unknown connector", "connectorId")
	}
	for _, m := range reg.Manifest.AuthMethods {
		if m.ID != manifest.MethodDevice || !m.Enabled || m.Device == nil {
			continue
		}
		if tenant == "" {
			tenant = m.Device.Tenant
		}
		if tenant == "" {
			tenant = manifest.DefaultTenant
		}
		if !manifest.ValidTenant(tenant) {
			return Spec{}, s.invalid("tenant is invalid", "tenant")
		}
		dc, err1 := url.Parse(strings.ReplaceAll(m.Device.DeviceCodeURL, manifest.TenantPlaceholder, tenant))
		tk, err2 := url.Parse(strings.ReplaceAll(m.Device.TokenURL, manifest.TenantPlaceholder, tenant))
		if err1 != nil || err2 != nil {
			break
		}
		grant := m.Device.TokenGrant
		if grant == "" {
			grant = manifest.DefaultTokenGrant
		}
		return Spec{DeviceCodeURL: dc, TokenURL: tk, ClientID: m.Device.ClientID, Scopes: m.Device.Scopes,
			TokenGrant: grant, KeepRefresh: m.Device.Refresh}, nil
	}
	return Spec{}, s.invalid("device authorization is not available for this connector", "connectorId")
}

// checkTarget validates the alias or the reconnect target and returns the alias.
func (s *Service) checkTarget(in StartInput) (string, error) {
	if in.ReconnectID == "" {
		if err := store.ValidateAlias(in.Alias, in.ConnectorID, "", s.cfg.Store.Snapshot().Connections); err != nil {
			return "", aliasError(in.Alias, s.cfg.Redactor)
		}
		return in.Alias, nil
	}
	c, ok := s.cfg.Store.Connection(in.ReconnectID)
	if !ok || c.Removed || c.ConnectorID != in.ConnectorID {
		return "", s.invalid("connection not found", "reconnectId")
	}
	if st := lifecycle.Status(c.Status); st != lifecycle.StatusExpired && st != lifecycle.StatusError {
		return "", lifecycle.NewError(lifecycle.CodeTransitionRejected, "connection is not expired or in error", s.cfg.Redactor)
	}
	return c.Alias, nil
}

func aliasError(alias string, r lifecycle.Redactor) error {
	if n := len([]rune(alias)); n < store.MinAliasLen || n > store.MaxAliasLen {
		return lifecycle.NewError(lifecycle.CodeAliasInvalid, "alias must be 1 to 40 characters", r)
	}
	return lifecycle.NewError(lifecycle.CodeAliasTaken, "alias is already used by another connection of this connector", r)
}

// reserve registers e as pending so a duplicate start is rejected atomically.
func (s *Service) reserve(e *entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrNotFound
	}
	s.sweepLocked()
	pending := 0
	for _, o := range s.entries {
		o.mu.Lock()
		active := o.state == statePending || o.state == stateConnecting
		same := o.connectorID == e.connectorID && o.alias == e.alias
		o.mu.Unlock()
		if !active {
			continue
		}
		if same {
			return lifecycle.NewError(lifecycle.CodeAlreadyPending, "an authorization is already pending for this connector and alias", s.cfg.Redactor)
		}
		pending++
	}
	if pending >= MaxPending {
		return lifecycle.NewError(lifecycle.CodeAlreadyPending, "too many pending authorizations", s.cfg.Redactor)
	}
	s.entries[e.id] = e
	return nil
}

func (s *Service) client(e *entry) (*http.Client, error) {
	ref, err := s.cfg.PreRef(e.connectorID, e.id)
	if err != nil {
		return nil, s.invalid("device authorization is not available for this connector", "connectorId")
	}
	return s.cfg.Clients.HTTPClient(ref, policy.CallerLifecycle), nil
}

type deviceCode struct {
	deviceCode            []byte
	release               func()
	userCode, verifyURI   string
	expiresIn             time.Duration
	hostChecked, interval bool
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
}

func (s *Service) requestCode(ctx context.Context, client *http.Client, spec Spec) (deviceCode, time.Duration, error) {
	// A GitHub App declares no scopes: its permissions are fixed at registration.
	form := url.Values{"client_id": {spec.ClientID}}
	if len(spec.Scopes) > 0 {
		form.Set("scope", strings.Join(spec.Scopes, " "))
	}
	body, status, err := s.post(ctx, client, spec.DeviceCodeURL, form)
	if err != nil {
		return deviceCode{}, 0, s.transportError(err)
	}
	defer clear(body)
	var r deviceCodeResponse
	if json.Unmarshal(body, &r) != nil || (status >= 500) {
		return deviceCode{}, 0, lifecycle.NewError(lifecycle.CodeNetwork, "GitHub returned an unexpected response", s.cfg.Redactor)
	}
	if r.Error != "" {
		return deviceCode{}, 0, s.mapGrantError(r.Error)
	}
	if r.DeviceCode == "" || r.UserCode == "" || r.VerificationURI == "" {
		return deviceCode{}, 0, lifecycle.NewError(lifecycle.CodeNetwork, "GitHub returned an incomplete response", s.cfg.Redactor)
	}
	dc := deviceCode{deviceCode: []byte(r.DeviceCode), userCode: r.UserCode, verifyURI: r.VerificationURI, expiresIn: defaultCodeExpiry}
	// Registered before any request uses the code.
	dc.release = s.cfg.Redactor.Register(dc.deviceCode)
	if r.ExpiresIn > 0 {
		dc.expiresIn = time.Duration(r.ExpiresIn) * time.Second
	}
	interval := DefaultInterval
	if r.Interval >= 1 {
		interval = time.Duration(r.Interval) * time.Second
	}
	return dc, interval, nil
}

// checkVerifyURI requires an https URL whose host is in the manifest egress.
func (s *Service) checkVerifyURI(e *entry, dc deviceCode) error {
	u, err := url.Parse(dc.verifyURI)
	bad := err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil
	if !bad {
		reg, ok := s.cfg.Registry.Get(e.connectorID)
		bad = !ok || !slices.ContainsFunc(reg.Manifest.Egress, func(h string) bool { return strings.EqualFold(h, u.Hostname()) })
	}
	if bad {
		dc.release()
		return s.invalid("verification address is not allowed", "verification_uri")
	}
	return nil
}

// failStart ends an entry that never began polling.
func (s *Service) failStart(e *entry) {
	e.mu.Lock()
	e.state = stateFailed
	s.zeroLocked(e)
	e.mu.Unlock()
	s.drop(e)
	_ = s.record(s.root, e, PhaseFailed, audit.OutcomeFailure)
}

// ---- polling ----

type pollResult struct {
	outcome  Outcome
	token    []byte
	refresh  []byte
	expires  time.Time
	code     lifecycle.Code // for terminal failures
	retryAfs int
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Interval    int    `json:"interval"`
	Error       string `json:"error"`
}

// refreshResponse is decoded only when the manifest keeps refresh tokens, so a
// connector that does not (GitHub) never has one in memory.
type refreshResponse struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) run(ctx context.Context, e *entry, spec Spec, client *http.Client) {
	defer s.wg.Done()
	defer func() {
		if recover() != nil {
			s.finish(e, stateFailed, "", 0, PhaseFailed)
		}
	}()
	e.mu.Lock()
	p := Poller{Interval: e.interval}
	e.mu.Unlock()
	delay := p.Interval
	for {
		if s.cfg.Sleep(ctx, delay) != nil {
			return
		}
		remaining := e.expiresAt.Sub(s.cfg.Now())
		if remaining <= 0 {
			s.finish(e, stateExpired, lifecycle.CodeDeviceCodeExpired, 0, PhaseExpired)
			return
		}
		res := s.pollOnce(ctx, e, spec, client)
		if ctx.Err() != nil {
			clear(res.token)
			clear(res.refresh)
			return
		}
		if res.outcome.Kind == Token {
			s.connect(e, res)
			return
		}
		step := p.Next(res.outcome, e.expiresAt.Sub(s.cfg.Now()))
		p = step.Poller
		e.mu.Lock()
		e.interval = p.Interval
		e.mu.Unlock()
		if step.Terminal {
			s.finishReason(e, step.Reason, res)
			return
		}
		delay = step.Delay
	}
}

func (s *Service) finishReason(e *entry, reason OutcomeKind, res pollResult) {
	switch reason {
	case Expired:
		s.finish(e, stateExpired, lifecycle.CodeDeviceCodeExpired, 0, PhaseExpired)
	case Denied:
		s.finish(e, stateDenied, lifecycle.CodeAuthorizationDenied, 0, PhaseDenied)
	case Disabled:
		s.finish(e, stateFailed, lifecycle.CodeDeviceFlowDisabled, 0, PhaseFailed)
	case NetworkFailure:
		s.finish(e, stateFailed, lifecycle.CodeNetwork, 0, PhaseFailed)
	case RateLimited:
		s.finish(e, stateFailed, lifecycle.CodeRateLimited, res.retryAfs, PhaseFailed)
	default:
		code := res.code
		if code == "" {
			code = lifecycle.CodeValidationFailed
		}
		s.finish(e, stateFailed, code, 0, PhaseFailed)
	}
}

func (s *Service) pollOnce(ctx context.Context, e *entry, spec Spec, client *http.Client) pollResult {
	e.mu.Lock()
	dev := string(e.deviceCode)
	e.mu.Unlock()
	if dev == "" {
		return pollResult{outcome: Outcome{Kind: Misconfigured}}
	}
	form := url.Values{"client_id": {spec.ClientID}, "device_code": {dev}, "grant_type": {spec.TokenGrant}}
	body, status, err := s.post(ctx, client, spec.TokenURL, form)
	if err != nil {
		var rl *broker.RateLimitedError
		var be *broker.BlockedError
		switch {
		case errors.As(err, &rl):
			return pollResult{outcome: Outcome{Kind: RateLimited, RetryAfter: rl.RetryAfter}, retryAfs: clampSec(rl.RetryAfter)}
		case errors.As(err, &be):
			return pollResult{outcome: Outcome{Kind: Misconfigured}, code: lifecycle.CodeBlockedByPolicy}
		}
		return pollResult{outcome: Outcome{Kind: NetworkFailure}}
	}
	defer clear(body)
	var r tokenResponse
	if json.Unmarshal(body, &r) != nil || status >= 500 {
		return pollResult{outcome: Outcome{Kind: NetworkFailure}}
	}
	if r.AccessToken != "" {
		tok := []byte(r.AccessToken)
		// Registered before the token is used anywhere.
		release := s.cfg.Redactor.Register(tok)
		defer release()
		if !strings.EqualFold(r.TokenType, "bearer") {
			clear(tok)
			return pollResult{outcome: Outcome{Kind: Misconfigured}}
		}
		var exp time.Time
		if r.ExpiresIn > 0 {
			exp = s.cfg.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
		}
		res := pollResult{outcome: Outcome{Kind: Token}, token: tok, expires: exp}
		if spec.KeepRefresh {
			var rr refreshResponse
			if json.Unmarshal(body, &rr) == nil && rr.RefreshToken != "" {
				res.refresh = []byte(rr.RefreshToken)
				// Registered before the token is used anywhere.
				releaseRefresh := s.cfg.Redactor.Register(res.refresh)
				defer releaseRefresh()
			}
		}
		return res
	}
	switch r.Error {
	case "authorization_pending":
		return pollResult{outcome: Outcome{Kind: Pending}}
	case "slow_down":
		return pollResult{outcome: Outcome{Kind: SlowDown, NewInterval: time.Duration(max(r.Interval, 0)) * time.Second}}
	case "expired_token":
		return pollResult{outcome: Outcome{Kind: Expired}}
	case "access_denied":
		return pollResult{outcome: Outcome{Kind: Denied}}
	case "device_flow_disabled":
		return pollResult{outcome: Outcome{Kind: Disabled}}
	}
	return pollResult{outcome: Outcome{Kind: Misconfigured}}
}

// connect claims pending -> connecting before the token is used, then turns it
// into a Connection.
func (s *Service) connect(e *entry, res pollResult) {
	e.mu.Lock()
	if e.state != statePending {
		e.mu.Unlock()
		clear(res.token)
		clear(res.refresh)
		return
	}
	e.state = stateConnecting
	s.zeroLocked(e)
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(s.root, connectTimeout)
	defer cancel()
	conn, err := s.cfg.Connect(ctx, ConnectRequest{
		ConnectorID: e.connectorID, Alias: e.alias, ReconnectID: e.reconnectID, Token: res.token, RefreshToken: res.refresh, ExpiresAt: res.expires,
	})
	clear(res.token)
	clear(res.refresh)

	e.mu.Lock()
	cancelled := e.state == stateCancelled
	e.mu.Unlock()
	if cancelled {
		// Cancel won: nothing is reported, the new Connection is removed.
		if err == nil && e.reconnectID == "" {
			_ = s.cfg.Abandon(s.root, conn.ID)
		}
		return
	}
	if err != nil {
		var le *lifecycle.Error
		code := lifecycle.CodeNetwork
		if errors.As(err, &le) {
			code = le.Code
		}
		s.finish(e, stateFailed, code, 0, PhaseFailed)
		return
	}
	if aerr := s.record(s.root, e, PhaseConnected, audit.OutcomeSuccess); aerr != nil {
		if e.reconnectID == "" {
			_ = s.cfg.Abandon(s.root, conn.ID)
		}
		s.finish(e, stateFailed, lifecycle.CodeAuditFailed, 0, "")
		return
	}
	e.mu.Lock()
	if e.state == stateConnecting {
		e.state = stateConnected
		e.conn = &conn
		e.removeAt = s.cfg.Now().Add(Retention)
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	// Cancelled while the audit entry was written.
	if e.reconnectID == "" {
		_ = s.cfg.Abandon(s.root, conn.ID)
	}
}

// finish moves a pending or connecting entry to a terminal state and writes
// the matching audit phase (best effort; phase "" writes nothing).
func (s *Service) finish(e *entry, to entryState, code lifecycle.Code, retryAfter int, phase string) {
	e.mu.Lock()
	if e.state != statePending && e.state != stateConnecting {
		e.mu.Unlock()
		return
	}
	e.state, e.errCode, e.retryAfterSec = to, code, retryAfter
	e.removeAt = s.cfg.Now().Add(Retention)
	s.zeroLocked(e)
	e.mu.Unlock()
	e.cancelPoll()
	if phase != "" {
		outcome := audit.OutcomeFailure
		if to == stateCancelled {
			outcome = audit.OutcomeSuccess
		}
		_ = s.record(s.root, e, phase, outcome)
	}
}

// zeroLocked drops the device code. e.mu must be held.
func (s *Service) zeroLocked(e *entry) {
	clear(e.deviceCode)
	e.deviceCode = nil
	if e.releaseDevice != nil {
		e.releaseDevice()
		e.releaseDevice = nil
	}
}

// ---- plumbing ----

func (s *Service) post(ctx context.Context, client *http.Client, u *url.URL, form url.Values) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func (s *Service) transportError(err error) error {
	var rl *broker.RateLimitedError
	var be *broker.BlockedError
	switch {
	case errors.As(err, &rl):
		e := lifecycle.NewError(lifecycle.CodeRateLimited, "GitHub rate limit reached", s.cfg.Redactor)
		e.RetryAfterSec = clampSec(rl.RetryAfter)
		return e
	case errors.As(err, &be):
		return lifecycle.NewError(lifecycle.CodeBlockedByPolicy, "operation blocked by policy", s.cfg.Redactor)
	}
	return lifecycle.NewError(lifecycle.CodeNetwork, "GitHub could not be reached", s.cfg.Redactor)
}

func (s *Service) mapGrantError(code string) error {
	switch code {
	case "device_flow_disabled":
		return lifecycle.NewError(lifecycle.CodeDeviceFlowDisabled, "device flow is not enabled for the GitHub App", s.cfg.Redactor)
	case "incorrect_client_credentials", "incorrect_device_code", "unsupported_grant_type":
		return s.invalid("GitHub rejected the client id", "client_id")
	}
	return lifecycle.NewError(lifecycle.CodeNetwork, "GitHub returned an unexpected response", s.cfg.Redactor)
}

func clampSec(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	return min(max(n, 0), maxRetryAfterSec)
}

func (s *Service) invalid(msg string, fields ...string) error {
	return lifecycle.NewError(lifecycle.CodeValidationFailed, msg, s.cfg.Redactor).WithOffenders(fields, s.cfg.Redactor)
}

// record appends a device_authorization entry. It never carries a code or token.
func (s *Service) record(ctx context.Context, e *entry, phase, outcome string) error {
	return s.cfg.Audit.Append(ctx, audit.Entry{
		TS: s.cfg.Now().UTC(), ConnectionID: "device:" + e.id, ConnectorID: e.connectorID,
		Event: audit.EventDeviceAuthorization, Outcome: outcome, Actor: audit.ActorUser,
		Detail: map[string]string{"phase": phase, "alias": e.alias},
	})
}

func (s *Service) selectionEmpty(connectionID string) bool {
	c, ok := s.cfg.Store.Connection(connectionID)
	return ok && !c.Removed && len(c.Selection.Repos) == 0 && len(c.Selection.Regions) == 0
}

func (s *Service) lookup(id string) (*entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	e, ok := s.entries[id]
	return e, ok
}

func (s *Service) drop(e *entry) {
	s.mu.Lock()
	delete(s.entries, e.id)
	s.mu.Unlock()
}

// sweepLocked removes terminal entries past their retention.
func (s *Service) sweepLocked() {
	now := s.cfg.Now()
	for id, e := range s.entries {
		e.mu.Lock()
		gone := !e.removeAt.IsZero() && !now.Before(e.removeAt)
		e.mu.Unlock()
		if gone {
			delete(s.entries, id)
		}
	}
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "da_" + hex.EncodeToString(b)
}
