package seek

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

var cweIDPattern = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)

// ParsePlan validates raw against the Plan schema before any BSKG call.
// Structural errors, unknown or missing fields, wrong types and length limits
// (counted in Unicode code points) return issues and no plan. Per-unit cwe_id
// format failures and duplicate cwe_ids (first wins) are returned in rejected
// and the remaining units keep their order. Only the returned typed values may
// be used downstream; model text is never interpolated into anything.
func ParsePlan(raw []byte) (plan Plan, rejected []Dropped, issues []Issue) {
	top, ok := asObject(raw)
	if !ok {
		return Plan{}, nil, []Issue{{Path: "plan", Reason: "must be a JSON object"}}
	}
	issues = unknownFields(issues, "", top, "language", "reasoning", "weaknesses")

	var p Plan
	p.Language, issues = stringField(issues, top, "", "language", 1, MaxLanguage)
	p.Reasoning, issues = stringField(issues, top, "", "reasoning", 0, MaxReasoning)

	var items []json.RawMessage
	switch wraw, present := top["weaknesses"]; {
	case !present:
		issues = append(issues, Issue{"weaknesses", "required field is missing"})
	case firstByte(wraw) != '[' || json.Unmarshal(wraw, &items) != nil:
		issues = append(issues, Issue{"weaknesses", "must be an array"})
	}

	if len(items) > MaxWeaknesses {
		issues = append(issues, Issue{"weaknesses", fmt.Sprintf("has %d items, at most %d allowed", len(items), MaxWeaknesses)})
	}
	p.Weaknesses = []Unit{}
	seen := map[string]bool{}
	for i, item := range items {
		prefix := "weaknesses[" + strconv.Itoa(i) + "]"
		obj, ok := asObject(item)
		if !ok {
			issues = append(issues, Issue{prefix, "must be an object"})
			continue
		}
		issues = unknownFields(issues, prefix+".", obj, "cwe_id", "root_cause", "code_snippet")
		var u Unit
		u.CWEID, issues = stringField(issues, obj, prefix+".", "cwe_id", 0, -1)
		u.RootCause, issues = stringField(issues, obj, prefix+".", "root_cause", 1, MaxRootCause)
		u.Snippet, issues = stringField(issues, obj, prefix+".", "code_snippet", 1, MaxSnippet)

		switch {
		case !cweIDPattern.MatchString(u.CWEID):
			// A missing or mistyped cwe_id already has an issue; do not double report.
			if !hasIssue(issues, prefix+".cwe_id") {
				rejected = append(rejected, Dropped{Index: i, Reason: "cwe_id must match ^CWE-[0-9]{1,5}$"})
			}
		case seen[u.CWEID]:
			rejected = append(rejected, Dropped{Index: i, Reason: "duplicate cwe_id " + u.CWEID + "; first occurrence kept"})
		default:
			seen[u.CWEID] = true
			p.Weaknesses = append(p.Weaknesses, u)
		}
	}

	if len(issues) > 0 {
		return Plan{}, nil, issues
	}
	return p, rejected, nil
}

// ParseTopK accepts nil (default 4) or a plain integer JSON number in [1,10].
func ParseTopK(raw json.RawMessage) (int, []Issue) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return DefaultTopK, nil
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, []Issue{{"top_k", "must be an integer"}}
	}
	if n < MinTopK || n > MaxTopK {
		return 0, []Issue{{"top_k", fmt.Sprintf("must be between %d and %d", MinTopK, MaxTopK)}}
	}
	return int(n), nil
}

// Marshal is the canonical encoding used by the round-trip property.
func (p Plan) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

func firstByte(raw []byte) byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0
	}
	return raw[0]
}

// asObject decodes raw as a JSON object; null and non-objects are rejected.
func asObject(raw []byte) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if firstByte(raw) != '{' || json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	return m, true
}

func unknownFields(issues []Issue, prefix string, obj map[string]json.RawMessage, known ...string) []Issue {
	var extra []string
outer:
	for k := range obj {
		for _, n := range known {
			if k == n {
				continue outer
			}
		}
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		issues = append(issues, Issue{prefix + k, "unknown field"})
	}
	return issues
}

// stringField reads a required string. max < 0 means no upper bound.
func stringField(issues []Issue, obj map[string]json.RawMessage, prefix, name string, min, max int) (string, []Issue) {
	path := prefix + name
	raw, present := obj[name]
	if !present {
		return "", append(issues, Issue{path, "required field is missing"})
	}
	var s string
	if firstByte(raw) != '"' || json.Unmarshal(raw, &s) != nil {
		return "", append(issues, Issue{path, "must be a string"})
	}
	n := utf8.RuneCountInString(s)
	if n < min {
		return "", append(issues, Issue{path, "must not be empty"})
	}
	if max >= 0 && n > max {
		return "", append(issues, Issue{path, fmt.Sprintf("has %d characters, at most %d allowed", n, max)})
	}
	return s, issues
}

func hasIssue(issues []Issue, path string) bool {
	for _, is := range issues {
		if is.Path == path {
			return true
		}
	}
	return false
}
