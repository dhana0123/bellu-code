// Package dataclass is the Data_Classifier: it labels data store entities with
// sensitivity classes from their names, tags and schema metadata (Requirements
// 13.3, 13.9, 13.10). Content is read only by opt-in sampling (sample.go).
//
// Results are stored in the data_classification table, not as graph
// attributes. The graph facade applies every Batch in full mode, so a batch
// from collector "dataclass" that names an aws_resource entity adds a second
// assertion to it. The cloud collector retiring the entity then keeps it live
// (the planner retires only entities no other collector asserts), and the
// classifier would find it live again on the next run.
package dataclass

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Classes are the sensitivity classes.
const (
	ClassPII         = "pii"
	ClassFinancial   = "financial"
	ClassHealth      = "health"
	ClassCredentials = "credentials"
	ClassNone        = "none"
)

// Pattern load limits (Requirement 13.9).
const (
	TestInputSize = 10 * 1024
	MaxEvalTime   = 50 * time.Millisecond
)

//go:embed patterns.yaml
var builtin []byte

// Fields a pattern can target.
const (
	fieldName   = "name"
	fieldTag    = "tag"
	fieldSchema = "schema"
	fieldAny    = "any"
	// fieldContent patterns apply only to sampled content (13.4).
	fieldContent = "content"
)

// Store is the metadata of one data store entity that classification reads.
type Store struct {
	ID     string // Entity_ID
	Type   string // for example s3:bucket
	Name   string
	Region string
	Tags   map[string]string
	Schema []string // column, attribute or field names
}

// PatternError describes a pattern that was excluded at load.
type PatternError struct {
	Source string // file the pattern came from
	ID     string
	Cause  string
}

func (e PatternError) Error() string {
	return fmt.Sprintf("pattern %q in %s excluded: %s", e.ID, e.Source, e.Cause)
}

type pattern struct {
	id    string
	class string
	field string
	re    *regexp.Regexp
}

// Patterns is a validated pattern set.
type Patterns struct{ list []pattern }

type spec struct {
	ID    string `yaml:"id"`
	Class string `yaml:"class"`
	Field string `yaml:"field"`
	Regex string `yaml:"regex"`
}

// Load returns the built-in patterns plus every *.yaml and *.yml file of
// userDir (empty or missing means none). Each pattern is compiled and timed
// against a 10 KB input; a pattern that fails either, or that has an unknown
// class or field, is excluded and returned in the error list while the rest
// stay usable.
func Load(userDir string) (Patterns, []PatternError) {
	var p Patterns
	var errs []PatternError
	add := func(source string, data []byte) {
		var f struct {
			Patterns []spec `yaml:"patterns"`
		}
		if err := yaml.Unmarshal(data, &f); err != nil {
			errs = append(errs, PatternError{Source: source, Cause: "file not readable as patterns: " + err.Error()})
			return
		}
		for _, s := range f.Patterns {
			pt, err := build(s, MaxEvalTime)
			if err != nil {
				errs = append(errs, PatternError{Source: source, ID: s.ID, Cause: err.Error()})
				continue
			}
			p.list = append(p.list, pt)
		}
	}
	add("builtin", builtin)
	if userDir == "" {
		return p, errs
	}
	files, _ := filepath.Glob(filepath.Join(userDir, "*.y*ml"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, PatternError{Source: f, Cause: err.Error()})
			continue
		}
		add(f, b)
	}
	return p, errs
}

func build(s spec, limit time.Duration) (pattern, error) {
	switch s.Class {
	case ClassPII, ClassFinancial, ClassHealth, ClassCredentials:
	default:
		return pattern{}, fmt.Errorf("class %q must be one of pii, financial, health, credentials", s.Class)
	}
	field := s.Field
	if field == "" {
		field = fieldAny
	}
	switch field {
	case fieldName, fieldTag, fieldSchema, fieldAny, fieldContent:
	default:
		return pattern{}, fmt.Errorf("field %q must be one of name, tag, schema, any, content", field)
	}
	if s.ID == "" {
		return pattern{}, fmt.Errorf("id is empty")
	}
	re, err := regexp.Compile(s.Regex)
	if err != nil {
		return pattern{}, fmt.Errorf("does not compile: %w", err)
	}
	in := testInput()
	start := time.Now()
	re.MatchString(in)
	if d := time.Since(start); d > limit {
		return pattern{}, fmt.Errorf("took %s on a %d byte input, limit is %s", d.Round(time.Millisecond), TestInputSize, limit)
	}
	return pattern{id: s.ID, class: s.Class, field: field, re: re}, nil
}

// testInput is 10 KB of name-, tag- and column-like text.
func testInput() string {
	const unit = "customer_email=user@example.com patient-id ssn 123-45-6789 payment_card 4111 aaaa bbbb "
	return strings.Repeat(unit, TestInputSize/len(unit)+1)[:TestInputSize]
}

// Classify returns the sorted classes of s. It returns ["none"] only when no
// pattern matches.
func (p Patterns) Classify(s Store) []string {
	hit := map[string]struct{}{}
	for _, pt := range p.list {
		if _, done := hit[pt.class]; done {
			continue
		}
		if pt.matches(s) {
			hit[pt.class] = struct{}{}
		}
	}
	if len(hit) == 0 {
		return []string{ClassNone}
	}
	out := make([]string, 0, len(hit))
	for c := range hit {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// CountMatches counts the content patterns that match in content, per class.
// The content is only read; nothing of it is returned or kept.
func (p Patterns) CountMatches(content []byte, counts map[string]int) {
	for _, pt := range p.list {
		if pt.field == fieldContent {
			counts[pt.class] += len(pt.re.FindAllIndex(content, -1))
		}
	}
}

func (pt pattern) matches(s Store) bool {
	if pt.field == fieldName || pt.field == fieldAny {
		if pt.re.MatchString(s.Name) {
			return true
		}
	}
	if pt.field == fieldTag || pt.field == fieldAny {
		for k, v := range s.Tags {
			if pt.re.MatchString(k + "=" + v) {
				return true
			}
		}
	}
	if pt.field == fieldSchema || pt.field == fieldAny {
		for _, c := range s.Schema {
			if pt.re.MatchString(c) {
				return true
			}
		}
	}
	return false
}
