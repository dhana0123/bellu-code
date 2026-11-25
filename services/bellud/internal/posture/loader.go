package posture

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
)

// Pack format: <root>/<dir>/pack.json plus .rego files next to it.
//
//	{"id","version","rules":[{"id","title","description","severity","category",
//	  "applies_to","remediation","benchmarks","kind"?,"rego"}]}
//
// severity is critical, high, medium, low or informational. rego is the .rego
// file name relative to the pack directory.

//go:embed packs
var bundled embed.FS

// Bundled returns the root of the embedded Rule_Packs.
func Bundled() fs.FS {
	sub, err := fs.Sub(bundled, "packs")
	if err != nil {
		panic(err) // the embed directive guarantees "packs" exists
	}
	return sub
}

// RuleError names a rejected rule. Check is "schema" or "compile"; RuleID is
// empty for a pack-level problem.
type RuleError struct{ Pack, RuleID, Check, Detail string }

func (e RuleError) Error() string {
	id := e.RuleID
	if id == "" {
		id = "<pack>"
	}
	return fmt.Sprintf("%s/%s: %s: %s", e.Pack, id, e.Check, e.Detail)
}

type packFile struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Rules   []struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Category    string   `json:"category"`
		AppliesTo   []string `json:"applies_to"`
		Remediation string   `json:"remediation"`
		Benchmarks  []string `json:"benchmarks"`
		Kind        string   `json:"kind"`
		Rego        string   `json:"rego"`
	} `json:"rules"`
}

var packageClause = regexp.MustCompile(`(?m)^package\s+\S+`)

// LoadAll loads every pack directory under root (directories holding a
// pack.json). A bad rule is rejected and the others are kept; each rejection is
// returned as a RuleError naming the rule. Each rule's Rego is compiled under the
// restricted capabilities (see CompileRego).
func LoadAll(root fs.FS) ([]Pack, []RuleError, error) {
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, nil, err
	}
	var packs []Pack
	var errs []RuleError
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		dir, err := fs.Sub(root, ent.Name())
		if err != nil {
			return nil, nil, err
		}
		raw, err := fs.ReadFile(dir, "pack.json")
		if err != nil {
			continue // not a pack directory
		}
		p, e := loadPack(ent.Name(), raw, dir)
		errs = append(errs, e...)
		if p != nil {
			packs = append(packs, *p)
		}
	}
	return packs, errs, nil
}

func loadPack(name string, raw []byte, dir fs.FS) (*Pack, []RuleError) {
	var pf packFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return nil, []RuleError{{Pack: name, Check: "schema", Detail: "pack.json: " + err.Error()}}
	}
	if strings.TrimSpace(pf.ID) == "" {
		return nil, []RuleError{{Pack: name, Check: "schema", Detail: "id is required"}}
	}
	p := &Pack{ID: pf.ID, Version: pf.Version, Source: dir}
	var errs []RuleError
	seen := map[string]bool{}
	for _, r := range pf.Rules {
		rule := Rule{
			ID: r.ID, Title: r.Title, Description: r.Description, Remediation: r.Remediation,
			Severity: normalizeSeverity(r.Severity), Category: schema.OverviewCategory(r.Category),
			AppliesTo: r.AppliesTo, Benchmarks: r.Benchmarks, Kind: RuleKind(r.Kind), Rego: r.Rego,
		}
		if rule.Kind == "" {
			rule.Kind = KindPosture
		}
		bad := false
		for _, m := range Validate(rule) {
			errs = append(errs, RuleError{Pack: name, RuleID: r.ID, Check: "schema", Detail: m})
			bad = true
		}
		if seen[r.ID] {
			errs = append(errs, RuleError{Pack: name, RuleID: r.ID, Check: "schema", Detail: "id: duplicate rule id in pack"})
			bad = true
		}
		seen[r.ID] = true
		if m := regoProblem(dir, rule.Rego); m != "" {
			errs = append(errs, RuleError{Pack: name, RuleID: r.ID, Check: "compile", Detail: m})
			bad = true
		}
		if !bad {
			p.Rules = append(p.Rules, rule)
		}
	}
	sort.SliceStable(p.Rules, func(i, j int) bool { return p.Rules[i].ID < p.Rules[j].ID })
	return p, errs
}

func regoProblem(dir fs.FS, file string) string {
	if file == "" {
		return "rego file is not declared"
	}
	if !fs.ValidPath(file) {
		return file + ": invalid path"
	}
	src, err := fs.ReadFile(dir, file)
	if err != nil {
		return err.Error()
	}
	if !packageClause.Match(src) {
		return file + ": no package clause"
	}
	if err := CompileRego(context.Background(), string(src)); err != nil {
		return file + ": " + err.Error()
	}
	return ""
}

// The requirement spells the lowest severity "informational"; findings use "info".
func normalizeSeverity(s string) findings.Severity {
	if s == "informational" {
		return findings.SevInfo
	}
	return findings.Severity(s)
}

// Validate checks r against the Requirement 10.2 schema. Each message starts
// with the name of the offending field.
func Validate(r Rule) []string {
	var e []string
	if !within(r.ID, 1, 128) {
		e = append(e, "id: must be 1 to 128 characters")
	}
	if !within(r.Title, 1, 200) {
		e = append(e, "title: must be 1 to 200 characters")
	}
	if !within(r.Description, 1, 2000) {
		e = append(e, "description: must be 1 to 2000 characters")
	}
	switch r.Severity {
	case findings.SevCritical, findings.SevHigh, findings.SevMedium, findings.SevLow, findings.SevInfo:
	default:
		e = append(e, "severity: must be one of critical, high, medium, low, informational")
	}
	if !r.Category.Valid() {
		e = append(e, "category: must be one of the nine Overview categories")
	}
	if n := len(r.AppliesTo); n < 1 || n > 50 {
		e = append(e, "applies_to: must list 1 to 50 entity kinds")
	}
	if !within(r.Remediation, 1, 4000) {
		e = append(e, "remediation: must be 1 to 4000 characters")
	}
	if len(r.Benchmarks) > 20 {
		e = append(e, "benchmarks: must have 0 to 20 entries")
	}
	if !r.Kind.Valid() {
		e = append(e, "kind: must be posture, toxic_combination, runtime or identity")
	}
	return e
}

func within(s string, lo, hi int) bool {
	n := utf8.RuneCountInString(strings.TrimSpace(s))
	return n >= lo && n <= hi
}
