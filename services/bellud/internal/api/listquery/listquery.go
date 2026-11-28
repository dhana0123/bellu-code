// Package listquery is the shared query contract of every experimental list
// endpoint (Requirements 20.3, 20.4, 20.10): filters, one sort field, a limit
// and an opaque signed cursor. Each endpoint declares a Spec; Parse turns
// url.Values into a typed Query or an *Error naming the bad parameter.
package listquery

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

const (
	DefaultLimit = 50
	MaxLimit     = 500
	// DefaultBudget is the server budget of a list query (20.10).
	DefaultBudget = 10 * time.Second
	// CursorTTL is how long an issued cursor stays valid.
	CursorTTL = 15 * time.Minute
	// MaxValueLen bounds free-text filter values (asset, source).
	MaxValueLen = 512
	// MaxValues bounds repeated values of one filter.
	MaxValues = 100
)

// Filter parameter names.
const (
	Category = "category"
	Severity = "severity"
	Status   = "status"
	Type     = "type"
	Asset    = "asset"
	Source   = "source"
	From     = "from"
	To       = "to"
)

// AllFilters lists every filter the contract knows.
var AllFilters = []string{Category, Severity, Status, Type, Asset, Source, From, To}

// Enum domains. They mirror the constants of internal/findings and the nine
// Overview categories of internal/graph/schema.
var (
	severities = []string{string(findings.SevCritical), string(findings.SevHigh), string(findings.SevMedium), string(findings.SevLow), string(findings.SevInfo)}
	statuses   = []string{string(findings.StatusOpen), string(findings.StatusInProgress), string(findings.StatusResolved), string(findings.StatusIgnored), string(findings.StatusAcceptedRisk)}
	types      = []string{
		string(findings.TypeVulnerability), string(findings.TypeMisconfiguration), string(findings.TypeSecret),
		string(findings.TypeLicense), string(findings.TypeMalware), string(findings.TypeRuntimeThreat),
		string(findings.TypeAIRisk), string(findings.TypeDataExposure), string(findings.TypeIdentityRisk),
	}
)

func categories() []string {
	out := make([]string, len(schema.OverviewOrder))
	for i, c := range schema.OverviewOrder {
		out[i] = string(c)
	}
	return out
}

// Spec is what one endpoint allows. A filter not in Filters is rejected as an
// unknown parameter for that endpoint. Domains overrides the default enum
// domain of category, severity, status or type.
type Spec struct {
	Filters     []string
	Sorts       []string
	DefaultSort string // "field" or "-field"; empty means unsorted
	Domains     map[string][]string
}

func (s Spec) domain(name string) []string {
	if d, ok := s.Domains[name]; ok {
		return d
	}
	switch name {
	case Category:
		return categories()
	case Severity:
		return severities
	case Status:
		return statuses
	case Type:
		return types
	}
	return nil
}

// Error is a rejected request parameter.
type Error struct {
	Param string
	Msg   string
}

func (e *Error) Error() string { return "invalid " + e.Param + ": " + e.Msg }

func bad(param, format string, a ...any) *Error {
	return &Error{Param: param, Msg: fmt.Sprintf(format, a...)}
}

// Query is a validated list request.
type Query struct {
	Categories []string
	Severities []string
	Statuses   []string
	Types      []string
	Assets     []string
	Sources    []string
	From, To   *time.Time
	// SortField is the field without prefix; Desc is true for "-field".
	SortField string
	Desc      bool
	Limit     int
	// Position is the endpoint-defined keyset position decoded from a valid
	// cursor; empty on the first page.
	Position string
}

// Parse validates v against the spec using the per-process cursor key.
func (s Spec) Parse(v url.Values) (Query, error) { return s.ParseWith(processCodec(), v) }

// ParseWith is Parse with an explicit cursor codec.
func (s Spec) ParseWith(c *Codec, v url.Values) (Query, error) {
	known := append([]string{"sort", "limit", "cursor"}, s.Filters...)
	for _, k := range sortedKeys(v) {
		if !slices.Contains(known, k) {
			return Query{}, bad(k, "unknown parameter")
		}
	}
	q := Query{Limit: DefaultLimit}
	enum := func(name string, dst *[]string) error {
		if !slices.Contains(s.Filters, name) {
			return nil
		}
		vals, err := values(v, name)
		if err != nil {
			return err
		}
		dom := s.domain(name)
		for _, x := range vals {
			if !slices.Contains(dom, x) {
				return bad(name, "%q is not one of %s", x, strings.Join(dom, ", "))
			}
		}
		*dst = vals
		return nil
	}
	free := func(name string, dst *[]string) error {
		if !slices.Contains(s.Filters, name) {
			return nil
		}
		vals, err := values(v, name)
		if err != nil {
			return err
		}
		for _, x := range vals {
			if len(x) > MaxValueLen {
				return bad(name, "value longer than %d bytes", MaxValueLen)
			}
		}
		*dst = vals
		return nil
	}
	for _, step := range []func() error{
		func() error { return enum(Category, &q.Categories) },
		func() error { return enum(Severity, &q.Severities) },
		func() error { return enum(Status, &q.Statuses) },
		func() error { return enum(Type, &q.Types) },
		func() error { return free(Asset, &q.Assets) },
		func() error { return free(Source, &q.Sources) },
		func() (err error) { q.From, err = timeParam(s, v, From); return },
		func() (err error) { q.To, err = timeParam(s, v, To); return },
	} {
		if err := step(); err != nil {
			return Query{}, err
		}
	}
	if q.From != nil && q.To != nil && q.From.After(*q.To) {
		return Query{}, bad(From, "from is after to")
	}
	if err := s.parseSort(v, &q); err != nil {
		return Query{}, err
	}
	if vals, ok := v["limit"]; ok {
		if len(vals) != 1 {
			return Query{}, bad("limit", "given more than once")
		}
		n, err := strconv.Atoi(vals[0])
		if err != nil || strings.TrimSpace(vals[0]) != vals[0] || strings.HasPrefix(vals[0], "+") {
			return Query{}, bad("limit", "must be an integer")
		}
		if n < 1 || n > MaxLimit {
			return Query{}, bad("limit", "must be between 1 and %d", MaxLimit)
		}
		q.Limit = n
	}
	if vals, ok := v["cursor"]; ok {
		if len(vals) != 1 || vals[0] == "" {
			return Query{}, bad("cursor", "must be given once and not empty")
		}
		pos, err := c.decode(vals[0], q.fingerprint())
		if err != nil {
			return Query{}, bad("cursor", "%s", err.Error())
		}
		q.Position = pos
	}
	return q, nil
}

func (s Spec) parseSort(v url.Values, q *Query) error {
	raw := s.DefaultSort
	if vals, ok := v["sort"]; ok {
		if len(vals) != 1 {
			return bad("sort", "exactly one sort field is allowed")
		}
		raw = vals[0]
		if raw == "" {
			return bad("sort", "empty value")
		}
	}
	if raw == "" {
		return nil
	}
	q.SortField, q.Desc = strings.CutPrefix(raw, "-")
	if !slices.Contains(s.Sorts, q.SortField) {
		return bad("sort", "%q is not sortable; allowed: %s", q.SortField, strings.Join(s.Sorts, ", "))
	}
	return nil
}

func timeParam(s Spec, v url.Values, name string) (*time.Time, error) {
	if !slices.Contains(s.Filters, name) {
		return nil, nil
	}
	vals, err := values(v, name)
	if err != nil || len(vals) == 0 {
		return nil, err
	}
	if len(vals) > 1 {
		return nil, bad(name, "given more than once")
	}
	t, err := time.Parse(time.RFC3339, vals[0])
	if err != nil {
		return nil, bad(name, "must be an RFC 3339 timestamp")
	}
	t = t.UTC()
	return &t, nil
}

// values returns the distinct values of a repeated parameter, in order.
func values(v url.Values, name string) ([]string, error) {
	raw, ok := v[name]
	if !ok {
		return nil, nil
	}
	if len(raw) > MaxValues {
		return nil, bad(name, "more than %d values", MaxValues)
	}
	var out []string
	for _, x := range raw {
		if x == "" {
			return nil, bad(name, "empty value")
		}
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out, nil
}

func sortedKeys(v url.Values) []string {
	ks := make([]string, 0, len(v))
	for k := range v {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// fingerprint binds a cursor to the filters and sort it was issued for, so a
// cursor cannot be replayed against a different result set.
func (q Query) fingerprint() string {
	enc := func(xs []string) []string { s := slices.Clone(xs); slices.Sort(s); return s }
	fmtT := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal([]any{enc(q.Categories), enc(q.Severities), enc(q.Statuses), enc(q.Types), enc(q.Assets), enc(q.Sources),
		fmtT(q.From), fmtT(q.To), q.SortField, q.Desc})
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// NextCursor issues the cursor for the page after q, carrying an
// endpoint-defined keyset position.
func (q Query) NextCursor(position string) string {
	return processCodec().Encode(position, q.fingerprint())
}

// NextCursorWith is NextCursor with an explicit codec.
func (q Query) NextCursorWith(c *Codec, position string) string {
	return c.Encode(position, q.fingerprint())
}

// Codec signs and verifies cursors with an HMAC key.
type Codec struct {
	key []byte
	now func() time.Time
}

// NewCodec returns a codec with a fresh random key.
func NewCodec() *Codec {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("listquery: no randomness: " + err.Error())
	}
	return &Codec{key: k, now: time.Now}
}

// WithClock returns a copy of c that reads time from now.
func (c *Codec) WithClock(now func() time.Time) *Codec { return &Codec{key: c.key, now: now} }

type cursorBody struct {
	P   string `json:"p"`
	F   string `json:"f"`
	Exp int64  `json:"e"`
}

// Encode returns base64url(body) "." base64url(HMAC-SHA256(body)).
func (c *Codec) Encode(position, fingerprint string) string {
	body, _ := json.Marshal(cursorBody{P: position, F: fingerprint, Exp: c.now().Add(CursorTTL).Unix()})
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(c.mac(body))
}

func (c *Codec) mac(b []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write(b)
	return m.Sum(nil)
}

func (c *Codec) decode(tok, fingerprint string) (string, error) {
	bs, ms, ok := strings.Cut(tok, ".")
	if !ok {
		return "", errors.New("malformed cursor")
	}
	body, err1 := base64.RawURLEncoding.DecodeString(bs)
	sig, err2 := base64.RawURLEncoding.DecodeString(ms)
	if err1 != nil || err2 != nil || !hmac.Equal(sig, c.mac(body)) {
		return "", errors.New("malformed cursor")
	}
	var cb cursorBody
	if json.Unmarshal(body, &cb) != nil {
		return "", errors.New("malformed cursor")
	}
	if !c.now().Before(time.Unix(cb.Exp, 0)) {
		return "", errors.New("cursor expired")
	}
	if cb.F != fingerprint {
		return "", errors.New("cursor does not match the filters or sort of this request")
	}
	return cb.P, nil
}

var defaultCodec = NewCodec()

func processCodec() *Codec { return defaultCodec }

// ---- responses ----

// WriteError writes err as 400 invalid_request in the shape of the existing
// experimental error bodies (_tag InvalidRequestError, kind validation, field
// naming the parameter) plus the stable code invalid_request.
func WriteError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"_tag": "InvalidRequestError", "message": err.Error(), "kind": "validation",
		"code": "invalid_request", "field": err.Param,
	})
}

// WriteIfInvalid writes the 400 and reports true when err is an *Error.
func WriteIfInvalid(w http.ResponseWriter, err error) bool {
	var qe *Error
	if errors.As(err, &qe) {
		WriteError(w, qe)
		return true
	}
	return false
}

// Page is the response envelope of a list endpoint.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
	Truncated  bool   `json:"truncated"`
}

// Budget returns ctx bounded by DefaultBudget (20.10).
func Budget(ctx context.Context) (context.Context, context.CancelFunc) {
	return BudgetFor(ctx, DefaultBudget)
}

// BudgetFor is Budget with an explicit duration.
func BudgetFor(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

// Truncated reports whether err is the budget deadline stopping the query.
func Truncated(ctx context.Context, err error) bool {
	return errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded)
}

// ---- findings adapter ----

// ToFindings converts q for findings.Store.List. OR within every filter, the
// last_seen range, the sort and the keyset cursor position pass through.
func ToFindings(q Query) (findings.ListQuery, error) {
	out := findings.ListQuery{Limit: q.Limit, Cursor: q.Position, AssetIDs: q.Assets, Sources: q.Sources,
		From: q.From, To: q.To, Sort: q.SortField, Desc: q.Desc}
	for _, x := range q.Statuses {
		out.Statuses = append(out.Statuses, findings.Status(x))
	}
	for _, x := range q.Severities {
		out.Severities = append(out.Severities, findings.Severity(x))
	}
	for _, x := range q.Types {
		out.Types = append(out.Types, findings.Type(x))
	}
	for _, x := range q.Categories {
		out.Categories = append(out.Categories, schema.OverviewCategory(x))
	}
	return out, nil
}
