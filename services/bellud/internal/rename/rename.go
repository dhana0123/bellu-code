// Package rename implements the ordered Toise -> Bellu Graph Engine rename
// rules used by the sync tool. All functions are pure: they read no files
// (other than LoadFile) and never touch the vendored tree.
package rename

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule kinds. KindPath rewrites file paths; every other kind rewrites content.
const (
	KindModule     = "module"
	KindProto      = "proto"
	KindEnv        = "env"
	KindMetric     = "metric"
	KindURI        = "uri"
	KindIdentifier = "identifier"
	KindText       = "text"
	KindBinary     = "binary"
	KindPath       = "path"
)

var kinds = map[string]bool{
	KindModule: true, KindProto: true, KindEnv: true, KindMetric: true, KindURI: true,
	KindIdentifier: true, KindText: true, KindBinary: true, KindPath: true,
}

// Rule is one literal replacement. Scope is a list of globs (empty = all files).
// Exact restricts matches to whole tokens (no adjacent word characters or '-').
type Rule struct {
	Kind  string   `yaml:"kind"`
	From  string   `yaml:"from"`
	To    string   `yaml:"to"`
	Scope []string `yaml:"scope,omitempty"`
	Exact bool     `yaml:"exact,omitempty"`
}

type file struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type compiled struct {
	rule  Rule
	match *regexp.Regexp
	scope []*regexp.Regexp
}

// Map is a validated, compiled rule set.
type Map struct {
	rules []compiled
}

// Rules returns the rules in application order.
func (m *Map) Rules() []Rule {
	out := make([]Rule, len(m.rules))
	for i, c := range m.rules {
		out[i] = c.rule
	}
	return out
}

// Load parses and validates a rename map. It performs no file access, so a
// validation failure happens before any vendored file is read or written.
func Load(data []byte) (*Map, error) {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("rename map: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("rename map: unsupported version %d", f.Version)
	}
	if err := Validate(f.Rules); err != nil {
		return nil, err
	}
	m, err := compile(f.Rules)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// LoadFile reads the map file at path and calls Load.
func LoadFile(path string) (*Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rename map: %w", err)
	}
	return Load(data)
}

// Validate checks rule well-formedness and that no rule's output matches any
// rule's input (of the same domain: path rules vs content rules). Scopes are
// ignored on purpose, which is the conservative reading.
func Validate(rules []Rule) error {
	m, err := compile(rules)
	if err != nil {
		return err
	}
	for i, r := range m.rules {
		for j, other := range m.rules {
			if isPath(r.rule) != isPath(other.rule) {
				continue
			}
			if other.match.MatchString(r.rule.To) {
				return fmt.Errorf("rename rule %d (%s %q -> %q): output matches input of rule %d (%s %q)",
					i+1, r.rule.Kind, r.rule.From, r.rule.To, j+1, other.rule.Kind, other.rule.From)
			}
		}
	}
	return nil
}

func isPath(r Rule) bool { return r.Kind == KindPath }

func compile(rules []Rule) (*Map, error) {
	m := &Map{}
	for i, r := range rules {
		n := i + 1
		switch {
		case !kinds[r.Kind]:
			return nil, fmt.Errorf("rename rule %d: unknown kind %q", n, r.Kind)
		case r.From == "":
			return nil, fmt.Errorf("rename rule %d (%s): empty from", n, r.Kind)
		case r.From == r.To:
			return nil, fmt.Errorf("rename rule %d (%s %q): from equals to", n, r.Kind, r.From)
		}
		expr := regexp.QuoteMeta(r.From)
		if r.Exact {
			expr = `(?:^|[^A-Za-z0-9_-])` + expr + `(?:$|[^A-Za-z0-9_-])`
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("rename rule %d (%s %q): %w", n, r.Kind, r.From, err)
		}
		c := compiled{rule: r, match: re}
		for _, g := range r.Scope {
			sr, err := globRegexp(g)
			if err != nil {
				return nil, fmt.Errorf("rename rule %d (%s %q): scope %q: %w", n, r.Kind, r.From, g, err)
			}
			c.scope = append(c.scope, sr)
		}
		m.rules = append(m.rules, c)
	}
	return m, nil
}

// ApplyText applies all in-scope content rules, in order, to content of the
// file at path. Binary content (containing a NUL byte) is returned unchanged.
func (m *Map) ApplyText(path string, content []byte) []byte {
	if bytes.IndexByte(content, 0) >= 0 {
		return content
	}
	s := string(content)
	for _, c := range m.rules {
		if isPath(c.rule) || !c.inScope(path) {
			continue
		}
		s = c.replace(s)
	}
	return []byte(s)
}

// ApplyPath applies all path rules, in order, to a slash-separated path.
func (m *Map) ApplyPath(path string) string {
	for _, c := range m.rules {
		if isPath(c.rule) {
			path = c.replace(path)
		}
	}
	return path
}

func (c compiled) inScope(path string) bool {
	if len(c.scope) == 0 {
		return true
	}
	base := path[strings.LastIndex(path, "/")+1:]
	for i, re := range c.scope {
		if re.MatchString(path) || (!strings.Contains(c.rule.Scope[i], "/") && re.MatchString(base)) {
			return true
		}
	}
	return false
}

func (c compiled) replace(s string) string {
	if !c.rule.Exact {
		return strings.ReplaceAll(s, c.rule.From, c.rule.To)
	}
	// Whole-token replacement: scan manually so adjacent matches work.
	var b strings.Builder
	from := c.rule.From
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], from) && !wordAt(s, i-1) && !wordAt(s, i+len(from)) {
			b.WriteString(c.rule.To)
			i += len(from)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func wordAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	ch := s[i]
	return ch == '_' || ch == '-' || (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// globRegexp converts a glob (supporting **, *, ?) to an anchored regexp.
func globRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch ch := g[i]; {
		case ch == '*' && strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case ch == '*' && strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i++
		case ch == '*':
			b.WriteString("[^/]*")
		case ch == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
