package redact

import (
	"errors"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
)

// ErrSecretLeak means a batch still matched a rule after scrubbing.
var ErrSecretLeak = errors.New("redact: secret leak detected")

// Guard is the final filter applied to every batch before the engine.
type Guard interface {
	Scrub(b batch.Batch) batch.Batch
	// Leaks reports whether any rule still matches b.
	Leaks(b batch.Batch) bool
	// FirstLeak returns the rule id of the first leak, for audit events.
	FirstLeak(b batch.Batch) (ruleID string, leaked bool)
}

// New returns the default guard using the generated and value rules.
func New() Guard { return guard{} }

type guard struct{}

func marker(id string) string { return "[REDACTED:" + id + "]" }

func isMarker(s string) bool {
	return strings.HasPrefix(s, "[REDACTED:") && strings.HasSuffix(s, "]") && !strings.ContainsAny(s[1:len(s)-1], "[]")
}

func keyRule(key string) (string, bool) {
	for _, r := range KeyRules {
		if r.Re.MatchString(key) {
			return r.ID, true
		}
	}
	return "", false
}

func pathRule(path []string) (string, bool) {
	for _, r := range PathRules {
		if len(r.Segments) != len(path) {
			continue
		}
		ok := true
		for i, s := range r.Segments {
			if s != "*" && s != path[i] {
				ok = false
				break
			}
		}
		if ok {
			return r.ID, true
		}
	}
	return "", false
}

// sensitive reports whether v is a value that a key/path rule must replace.
// Numbers and bools carry no secret text and are kept.
func sensitive(v any) bool {
	switch x := v.(type) {
	case string:
		return x != "" && !isMarker(x)
	case []string, []any, map[string]any, map[string]string:
		return true
	}
	return false
}

func scrubString(s string) string {
	for _, r := range ValueRules {
		s = r.Re.ReplaceAllString(s, marker(r.ID))
	}
	return s
}

func firstValueRule(s string) (string, bool) {
	for _, r := range ValueRules {
		if r.Re.MatchString(s) {
			return r.ID, true
		}
	}
	return "", false
}

// ValueLeak reports the id of the first value rule that matches s.
func ValueLeak(s string) (string, bool) { return firstValueRule(s) }

func (guard) Scrub(b batch.Batch) batch.Batch {
	out := batch.Batch{Collector: b.Collector, ObservedAt: b.ObservedAt}
	if b.Entities != nil {
		out.Entities = make([]batch.Entity, len(b.Entities))
		for i, e := range b.Entities {
			out.Entities[i] = batch.Entity{Type: e.Type, Identity: cloneIdentity(e.Identity), Attributes: scrubMap(e.Attributes, nil)}
		}
	}
	if b.Relations != nil {
		out.Relations = make([]batch.Relation, len(b.Relations))
		for i, r := range b.Relations {
			out.Relations[i] = batch.Relation{Type: r.Type, From: r.From, To: r.To, Attributes: scrubMap(r.Attributes, nil)}
		}
	}
	if b.Retain != nil {
		out.Retain = make([]batch.Retain, len(b.Retain))
		for i, r := range b.Retain {
			out.Retain[i] = batch.Retain{Kind: r.Kind, Attrs: cloneIdentity(r.Attrs)}
		}
	}
	return out
}

func cloneIdentity(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

func scrubMap(m map[string]any, path []string) map[string]any {
	if m == nil {
		return nil
	}
	o := make(map[string]any, len(m))
	for k, v := range m {
		p := append(append([]string(nil), path...), k)
		if id, ok := keyRule(k); ok && sensitive(v) {
			o[k] = marker(id)
		} else if id, ok := pathRule(p); ok && sensitive(v) {
			o[k] = marker(id)
		} else {
			o[k] = scrubValue(v, p)
		}
	}
	return o
}

func scrubValue(v any, path []string) any {
	switch x := v.(type) {
	case string:
		return scrubString(x)
	case []string:
		o := make([]string, len(x))
		for i, s := range x {
			o[i] = scrubString(s)
		}
		return o
	case []any:
		o := make([]any, len(x))
		for i, e := range x {
			o[i] = scrubValue(e, path)
		}
		return o
	case map[string]any:
		return scrubMap(x, path)
	case map[string]string:
		o := make(map[string]string, len(x))
		for k, s := range x {
			o[k] = scrubString(s)
		}
		return o
	}
	return v
}

func (g guard) Leaks(b batch.Batch) bool {
	_, l := g.FirstLeak(b)
	return l
}

func (guard) FirstLeak(b batch.Batch) (string, bool) {
	strs := []string{b.Collector}
	for _, e := range b.Entities {
		strs = append(strs, e.Type)
		for _, v := range e.Identity {
			strs = append(strs, v)
		}
		if id, ok := leakMap(e.Attributes, nil); ok {
			return id, true
		}
	}
	for _, r := range b.Relations {
		strs = append(strs, r.Type, r.From, r.To)
		if id, ok := leakMap(r.Attributes, nil); ok {
			return id, true
		}
	}
	for _, s := range strs {
		if id, ok := firstValueRule(s); ok {
			return id, true
		}
	}
	return "", false
}

func leakMap(m map[string]any, path []string) (string, bool) {
	for k, v := range m {
		p := append(append([]string(nil), path...), k)
		if id, ok := keyRule(k); ok && sensitive(v) {
			return id, true
		}
		if id, ok := pathRule(p); ok && sensitive(v) {
			return id, true
		}
		if id, ok := leakValue(v, p); ok {
			return id, true
		}
	}
	return "", false
}

func leakValue(v any, path []string) (string, bool) {
	switch x := v.(type) {
	case string:
		return firstValueRule(x)
	case []string:
		for _, s := range x {
			if id, ok := firstValueRule(s); ok {
				return id, true
			}
		}
	case []any:
		for _, e := range x {
			if id, ok := leakValue(e, path); ok {
				return id, true
			}
		}
	case map[string]any:
		return leakMap(x, path)
	case map[string]string:
		for _, s := range x {
			if id, ok := firstValueRule(s); ok {
				return id, true
			}
		}
	}
	return "", false
}
