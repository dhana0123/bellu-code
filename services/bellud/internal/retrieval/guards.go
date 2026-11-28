package retrieval

// Orchestrator guards. The Python retrieval service is never trusted to
// enforce these: budgets, workspace identity, the planning-round bound, agent
// result validation, tool withholding, the connector allowlist and Total_Top_K
// are all decided here, in Go, before and after every service call.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server caps and defaults for the Query_Budget (Requirement 20.4, 20.5).
const (
	CapNodes        = 2000
	CapEdges        = 4000
	CapDuration     = 20 * time.Second
	DefaultNodes    = 500
	DefaultEdges    = 1000
	MaxPlanRounds   = 2
	DefaultTopK     = 4
	MinTopK         = 1
	MaxTopK         = 50
	budgetNodesKey  = "max_nodes"
	budgetEdgesKey  = "max_edges"
	budgetSecondKey = "max_duration_seconds"
)

// ValidationError names the invalid field or value.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return "validation error: " + e.Field + ": " + e.Message
}

// QueryBudget bounds one query.
type QueryBudget struct {
	MaxNodes    int
	MaxEdges    int
	MaxDuration time.Duration
}

// ServerCap is the maximum budget any request may use.
var ServerCap = QueryBudget{MaxNodes: CapNodes, MaxEdges: CapEdges, MaxDuration: CapDuration}

// ClampTo returns the component-wise minimum of b and server.
func (b QueryBudget) ClampTo(server QueryBudget) QueryBudget {
	return QueryBudget{
		MaxNodes:    min(b.MaxNodes, server.MaxNodes),
		MaxEdges:    min(b.MaxEdges, server.MaxEdges),
		MaxDuration: min(b.MaxDuration, server.MaxDuration),
	}
}

// ResolveBudget parses the request's budget object (empty or null means no
// budget), applies defaults to absent components, rejects components that are
// null, non-numeric, non-integer or below 1, and clamps to the server cap.
// The duration defaults to the server cap.
func ResolveBudget(raw json.RawMessage) (QueryBudget, error) {
	fields := map[string]json.RawMessage{}
	if t := bytes.TrimSpace(raw); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
		if err := json.Unmarshal(t, &fields); err != nil {
			return QueryBudget{}, &ValidationError{Field: "budget", Message: "must be an object"}
		}
	}
	nodes, err := budgetInt(fields, budgetNodesKey, DefaultNodes)
	if err != nil {
		return QueryBudget{}, err
	}
	edges, err := budgetInt(fields, budgetEdgesKey, DefaultEdges)
	if err != nil {
		return QueryBudget{}, err
	}
	secs, err := budgetInt(fields, budgetSecondKey, int64(CapDuration/time.Second))
	if err != nil {
		return QueryBudget{}, err
	}
	req := QueryBudget{
		MaxNodes:    int(min(nodes, math.MaxInt32)),
		MaxEdges:    int(min(edges, math.MaxInt32)),
		MaxDuration: time.Duration(min(secs, int64(CapDuration/time.Second))) * time.Second,
	}
	return req.ClampTo(ServerCap), nil
}

func budgetInt(fields map[string]json.RawMessage, key string, def int64) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		return def, nil
	}
	s := string(bytes.TrimSpace(raw))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		var ne *strconv.NumError
		// An integer literal too large for int64 is a valid, huge value.
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) && !strings.HasPrefix(s, "-") {
			return math.MaxInt64, nil
		}
		return 0, &ValidationError{Field: key, Message: "must be an integer of at least 1"}
	}
	if n < 1 {
		return 0, &ValidationError{Field: key, Message: "must be an integer of at least 1"}
	}
	return n, nil
}

// StripIdentityFields removes the top-level `workspace` and `tenant` fields of
// a JSON body. The request Workspace is always the active one (Requirement
// 20.2), so the result of a request is identical with or without them.
func StripIdentityFields(body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, &ValidationError{Field: "body", Message: "must be a JSON object"}
	}
	delete(m, "workspace")
	delete(m, "tenant")
	return json.Marshal(m) // map keys are sorted: deterministic
}

// ClampScope returns the elements of requested that are also permitted, in
// requested order without duplicates, plus the removed elements. It never adds
// an element that was not requested (Requirement 9.3, 9.4).
func ClampScope(requested, permitted []string) (kept, removed []string) {
	allow := make(map[string]bool, len(permitted))
	for _, p := range permitted {
		allow[p] = true
	}
	seen := map[string]bool{}
	kept, removed = []string{}, []string{}
	for _, r := range requested {
		if seen[r] {
			continue
		}
		seen[r] = true
		if allow[r] {
			kept = append(kept, r)
		} else {
			removed = append(removed, r)
		}
	}
	return kept, removed
}

// EntityVisible reports whether an entity may be shown: it exists and belongs
// to the active workspace. A foreign entity is indistinguishable from a
// missing one, so callers answer both with WriteNotFound.
func EntityVisible(activeWorkspace, entityWorkspace string, exists bool) bool {
	return exists && entityWorkspace == activeWorkspace
}

// NotFoundBody is the one not-found body, with no workspace-revealing detail.
var NotFoundBody = []byte(`{"error":"not_found"}` + "\n")

// WriteNotFound writes the not-found response for a missing or foreign entity.
func WriteNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(NotFoundBody)
}

// ErrReplanLimit means the 2-planning-round limit is reached.
var ErrReplanLimit = errors.New("replanning limit of 1 round is reached")

// Rounds counts planning rounds in Go. The retrieval service can request more
// rounds, but Begin refuses the third.
type Rounds struct {
	mu sync.Mutex
	n  int
}

// Begin starts the next planning round and returns its number (0 for the
// first plan, 1 for the replanning round).
func (r *Rounds) Begin() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n >= MaxPlanRounds {
		return 0, ErrReplanLimit
	}
	r.n++
	return r.n - 1, nil
}

// Run returns the number of rounds started.
func (r *Rounds) Run() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// ValidationFailure records a discarded agent result.
type ValidationFailure struct {
	Agent  string
	Schema string
	Reason string
}

// Schema validates a raw agent result.
type Schema struct {
	Name     string
	Validate func(raw []byte) error
}

// ResultValidator validates agent results and records failures.
type ResultValidator struct {
	mu       sync.Mutex
	failures []ValidationFailure
}

// Accept returns raw when it satisfies the schema. Otherwise it records a
// failure naming the agent and schema and returns nil with the error, so no
// downstream component receives the result.
func (v *ResultValidator) Accept(agent string, s Schema, raw []byte) ([]byte, error) {
	var err error
	if s.Validate == nil {
		err = errors.New("no validator")
	} else {
		err = s.Validate(raw)
	}
	if err == nil {
		return raw, nil
	}
	v.mu.Lock()
	v.failures = append(v.failures, ValidationFailure{Agent: agent, Schema: s.Name, Reason: err.Error()})
	v.mu.Unlock()
	return nil, fmt.Errorf("agent %s result failed schema %s: %w", agent, s.Name, err)
}

// Failures returns a copy of the recorded failures.
func (v *ResultValidator) Failures() []ValidationFailure {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]ValidationFailure(nil), v.failures...)
}

// Tool is an agent tool. SideEffect marks any tool that writes, deletes,
// sends, executes, or modifies state outside the agent's own result.
type Tool struct {
	Name       string
	SideEffect bool
}

// AgentSession tracks whether an agent has read untrusted data.
type AgentSession struct {
	mu      sync.Mutex
	tainted bool
}

// MarkUntrustedRead records that the agent has read untrusted data. The mark
// lasts for the session.
func (s *AgentSession) MarkUntrustedRead() {
	s.mu.Lock()
	s.tainted = true
	s.mu.Unlock()
}

// Tools returns the tools the agent may use now: all of them before it reads
// untrusted data, and only side-effect-free ones afterwards.
func (s *AgentSession) Tools(all []Tool) []Tool {
	s.mu.Lock()
	tainted := s.tainted
	s.mu.Unlock()
	out := make([]Tool, 0, len(all))
	for _, t := range all {
		if tainted && t.SideEffect {
			continue
		}
		out = append(out, t)
	}
	return out
}

// RefusedError names a refused connector operation.
type RefusedError struct{ Operation string }

func (e *RefusedError) Error() string {
	return "connector operation refused (not on the read-only allowlist): " + e.Operation
}

// CheckConnectorOp refuses an operation that is not on the read-only
// allowlist. The caller must send no request to the customer system on error.
func CheckConnectorOp(allowed func(connector, operation string) bool, connector, operation string) error {
	if allowed == nil || !allowed(connector, operation) {
		return &RefusedError{Operation: operation}
	}
	return nil
}

// Limit names the budget component that stopped a query.
type Limit string

const (
	LimitNone     Limit = ""
	LimitNodes    Limit = "nodes"
	LimitEdges    Limit = "edges"
	LimitDuration Limit = "duration"
)

// Truncation is returned with partial results.
type Truncation struct {
	Truncated bool  `json:"truncated"`
	Limit     Limit `json:"limit,omitempty"`
}

// Meter enforces a QueryBudget while a query runs. The first limit reached
// sticks; later calls keep returning false.
type Meter struct {
	budget   QueryBudget
	deadline time.Time
	now      func() time.Time
	nodes    int
	edges    int
	hit      Limit
}

// NewMeter starts a meter now.
func NewMeter(b QueryBudget) *Meter { return newMeter(b, time.Now) }

func newMeter(b QueryBudget, now func() time.Time) *Meter {
	return &Meter{budget: b, deadline: now().Add(b.MaxDuration), now: now}
}

// AddNode reports whether one more node fits. It returns false and records the
// limit when it does not; the node must then not be added.
func (m *Meter) AddNode() bool {
	if !m.alive() {
		return false
	}
	if m.nodes >= m.budget.MaxNodes {
		m.hit = LimitNodes
		return false
	}
	m.nodes++
	return true
}

// AddEdge is AddNode for edges.
func (m *Meter) AddEdge() bool {
	if !m.alive() {
		return false
	}
	if m.edges >= m.budget.MaxEdges {
		m.hit = LimitEdges
		return false
	}
	m.edges++
	return true
}

func (m *Meter) alive() bool {
	if m.hit != LimitNone {
		return false
	}
	if !m.now().Before(m.deadline) {
		m.hit = LimitDuration
		return false
	}
	return true
}

// Result reports whether a limit stopped the query and which one.
func (m *Meter) Result() Truncation {
	return Truncation{Truncated: m.hit != LimitNone, Limit: m.hit}
}

// TopK holds the configured Total_Top_K.
type TopK struct {
	mu    sync.Mutex
	value int
}

// NewTopK returns a TopK holding the default of 4.
func NewTopK() *TopK { return &TopK{value: DefaultTopK} }

// Get returns the current Total_Top_K.
func (t *TopK) Get() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.value
}

// Set accepts an integer from 1 to 50. Any other value is rejected with an
// error naming it, and the current value is kept.
func (t *TopK) Set(v any) error {
	n, ok := asInt(v)
	if !ok || n < MinTopK || n > MaxTopK {
		return &ValidationError{Field: "total_top_k", Message: fmt.Sprintf("invalid value %v: must be an integer from %d to %d", v, MinTopK, MaxTopK)}
	}
	t.mu.Lock()
	t.value = n
	t.mu.Unlock()
	return nil
}

func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		if x < math.MinInt32 || x > math.MaxInt32 {
			return 0, false
		}
		return int(x), true
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > math.MaxInt32 {
			return 0, false
		}
		return int(x), true
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 32)
		return int(n), err == nil
	}
	return 0, false
}

// DistributeTopK splits total into `units` non-negative integer shares whose
// sum equals total. Shares differ by at most 1, larger shares first. With no
// units it returns nil (nothing to distribute to).
func DistributeTopK(total, units int) []int {
	if units <= 0 || total < 0 {
		return nil
	}
	out := make([]int, units)
	base, extra := total/units, total%units
	for i := range out {
		out[i] = base
		if i < extra {
			out[i]++
		}
	}
	return out
}
