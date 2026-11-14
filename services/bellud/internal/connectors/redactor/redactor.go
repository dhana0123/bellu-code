// Package redactor removes registered credential values and known token
// patterns from strings, JSON documents and graph batches.
package redactor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// Marker replaces every redacted credential.
const Marker = "[REDACTED:credential]"

// MinSecretLen is the shortest value that is registered; shorter values are
// ignored because they would redact ordinary text.
const MinSecretLen = 8

// Redactor holds the set of registered secrets and their derived encodings.
// The zero value is not usable; call New.
type Redactor struct {
	mu      sync.RWMutex
	counts  map[string]int // secret -> registrations
	needles []string       // all derived forms, longest first
}

// New returns an empty Redactor.
func New() *Redactor { return &Redactor{counts: map[string]int{}} }

// Register adds secret (ignored when shorter than MinSecretLen bytes) and
// returns an idempotent release func that removes this registration.
func (r *Redactor) Register(secret []byte) (release func()) {
	if len(secret) < MinSecretLen {
		return func() {}
	}
	s := string(secret)
	r.mu.Lock()
	r.counts[s]++
	r.rebuildLocked()
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			if r.counts[s] <= 1 {
				delete(r.counts, s)
			} else {
				r.counts[s]--
			}
			r.rebuildLocked()
			r.mu.Unlock()
		})
	}
}

func (r *Redactor) rebuildLocked() {
	set := map[string]struct{}{}
	for s := range r.counts {
		for _, f := range forms(s) {
			set[f] = struct{}{}
		}
	}
	n := make([]string, 0, len(set))
	for f := range set {
		n = append(n, f)
	}
	sort.Slice(n, func(i, j int) bool {
		if len(n[i]) != len(n[j]) {
			return len(n[i]) > len(n[j])
		}
		return n[i] < n[j]
	})
	r.needles = n
}

// forms returns the plain, JSON-escaped, base64 and URL-escaped renderings.
func forms(s string) []string {
	out := []string{s}
	for _, esc := range []bool{true, false} {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(esc)
		if enc.Encode(s) == nil {
			j := strings.TrimSuffix(buf.String(), "\n")
			j = j[1 : len(j)-1]
			out = append(out, j, asciiJSON(j))
		}
	}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		out = append(out, e.EncodeToString([]byte(s)))
	}
	out = append(out, url.QueryEscape(s), url.PathEscape(s))
	keep := out[:0]
	for _, f := range out {
		if len(f) >= MinSecretLen {
			keep = append(keep, f)
		}
	}
	return keep
}

// asciiJSON rewrites non-ASCII runes in an escaped JSON string body as \uXXXX.
func asciiJSON(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c < 0x80:
			b.WriteRune(c)
		case c >= 0x10000:
			c -= 0x10000
			b.WriteString(u16(0xd800 + (c >> 10)))
			b.WriteString(u16(0xdc00 + (c & 0x3ff)))
		default:
			b.WriteString(u16(c))
		}
	}
	return b.String()
}

func u16(c rune) string {
	const hex = "0123456789abcdef"
	return string([]byte{'\\', 'u', hex[c>>12&15], hex[c>>8&15], hex[c>>4&15], hex[c&15]})
}

func (r *Redactor) snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.needles
}

// String replaces registered values (all encodings) and known token patterns
// with Marker.
func (r *Redactor) String(s string) string {
	for _, n := range r.snapshot() {
		if strings.Contains(s, n) {
			s = strings.ReplaceAll(s, n, Marker)
		}
	}
	for _, v := range redact.ValueRules {
		s = v.Re.ReplaceAllString(s, Marker)
	}
	return s
}

// JSON redacts a JSON (or any text) document, keeping it valid JSON because
// replacements only occur inside string bodies.
func (r *Redactor) JSON(b []byte) []byte {
	return []byte(r.String(string(b)))
}

// Registered replaces only registered values (all encodings) and skips the
// token-pattern rules. It is for responses that legitimately carry a fresh
// credential for the lifecycle caller (manifest issues_credential).
func (r *Redactor) Registered(b []byte) []byte {
	s := string(b)
	for _, n := range r.snapshot() {
		if strings.Contains(s, n) {
			s = strings.ReplaceAll(s, n, Marker)
		}
	}
	return []byte(s)
}

// Contains reports whether s holds any registered value in any encoding.
func (r *Redactor) Contains(s string) bool {
	for _, n := range r.snapshot() {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// Guard wraps base: Scrub delegates to base unchanged (registered values are
// never scrubbed from batches), and Leaks is true when base leaks or any
// registered value appears anywhere in the batch.
func (r *Redactor) Guard(base redact.Guard) redact.Guard { return &guard{r: r, base: base} }

type guard struct {
	r    *Redactor
	base redact.Guard
}

// RuleCredential is the rule id reported by FirstLeak for registered values.
const RuleCredential = "credential"

func (g *guard) Scrub(b batch.Batch) batch.Batch { return g.base.Scrub(b) }

func (g *guard) Leaks(b batch.Batch) bool {
	_, l := g.FirstLeak(b)
	return l
}

func (g *guard) FirstLeak(b batch.Batch) (string, bool) {
	if id, ok := g.base.FirstLeak(b); ok {
		return id, true
	}
	if len(g.r.snapshot()) == 0 {
		return "", false
	}
	if g.batchContains(b) {
		return RuleCredential, true
	}
	return "", false
}

func (g *guard) batchContains(b batch.Batch) bool {
	c := g.r.Contains
	if c(b.Collector) {
		return true
	}
	for _, e := range b.Entities {
		if c(e.Type) || anyMapString(c, e.Identity) || anyAny(c, e.Attributes) {
			return true
		}
	}
	for _, rel := range b.Relations {
		if c(rel.Type) || c(rel.From) || c(rel.To) || anyAny(c, rel.Attributes) {
			return true
		}
	}
	return false
}

func anyMapString(c func(string) bool, m map[string]string) bool {
	for k, v := range m {
		if c(k) || c(v) {
			return true
		}
	}
	return false
}

func anyAny(c func(string) bool, v any) bool {
	switch x := v.(type) {
	case string:
		return c(x)
	case []byte:
		return c(string(x))
	case []string:
		for _, s := range x {
			if c(s) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if anyAny(c, e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if c(k) || anyAny(c, e) {
				return true
			}
		}
	case map[string]string:
		return anyMapString(c, x)
	}
	return false
}
