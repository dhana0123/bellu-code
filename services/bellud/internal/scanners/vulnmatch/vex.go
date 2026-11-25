package vulnmatch

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// vexDoc is the part of an OpenVEX document the matcher reads. Only
// `not_affected` statements act; other statuses leave the match alone.
type vexDoc struct {
	ID         string `json:"@id"`
	Statements []struct {
		Vulnerability struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"vulnerability"`
		Products []struct {
			ID          string            `json:"@id"`
			Identifiers map[string]string `json:"identifiers"`
		} `json:"products"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"statements"`
}

// vexStatement is one `not_affected` statement ready for matching.
type vexStatement struct {
	vulns         []string // lower case vulnerability name and aliases
	products      []string // normalized purls; empty means every product
	justification string
}

// vexSet holds the not_affected statements of one OpenVEX file.
type vexSet struct {
	source string // path of the file, recorded in finding evidence
	docID  string
	stmts  []vexStatement
}

// loadVEX reads an OpenVEX JSON file.
func loadVEX(path string) (*vexSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vulnmatch: read VEX file %s: %w", path, err)
	}
	var d vexDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("vulnmatch: parse VEX file %s: %w", path, err)
	}
	set := &vexSet{source: path, docID: d.ID}
	for _, s := range d.Statements {
		if s.Status != "not_affected" {
			continue
		}
		st := vexStatement{justification: s.Justification}
		for _, n := range append([]string{s.Vulnerability.Name}, s.Vulnerability.Aliases...) {
			if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
				st.vulns = append(st.vulns, n)
			}
		}
		for _, p := range s.Products {
			if id := normalizePurl(p.ID); strings.HasPrefix(id, "pkg:") {
				st.products = append(st.products, id)
			}
			if id := normalizePurl(p.Identifiers["purl"]); id != "" {
				st.products = append(st.products, id)
			}
		}
		if len(st.vulns) > 0 {
			set.stmts = append(set.stmts, st)
		}
	}
	return set, nil
}

// notAffected returns the justification of the first statement that declares
// the package not affected by the vulnerability or one of its aliases. A
// product without a version covers every version of the package.
func (s *vexSet) notAffected(purl, vulnID string, aliases []string) (justification string, ok bool) {
	if s == nil {
		return "", false
	}
	names := map[string]bool{strings.ToLower(vulnID): true}
	for _, a := range aliases {
		names[strings.ToLower(a)] = true
	}
	full := normalizePurl(purl)
	name, _ := splitVersion(full)
	for _, st := range s.stmts {
		if !anyIn(st.vulns, names) {
			continue
		}
		if len(st.products) == 0 {
			return st.justification, true
		}
		for _, p := range st.products {
			if pn, pv := splitVersion(p); p == full || (pv == "" && pn == name) {
				return st.justification, true
			}
		}
	}
	return "", false
}

func anyIn(list []string, set map[string]bool) bool {
	for _, v := range list {
		if set[v] {
			return true
		}
	}
	return false
}

// normalizePurl drops qualifiers and subpath, which VEX products often omit.
func normalizePurl(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}

// splitVersion splits a purl without qualifiers at its version.
func splitVersion(p string) (name, version string) {
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}
