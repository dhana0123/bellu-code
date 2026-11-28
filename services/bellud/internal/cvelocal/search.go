package cvelocal

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bellu/bellucode/services/bellud/internal/canonical"
)

const maxTokens = 16

// Search runs a lexical match of q against vulnerability ids and summaries and
// returns at most min(limit, 100) results by descending relevance, ties by id.
func (s *Source) Search(ctx context.Context, q string, limit int) ([]Vulnerability, error) {
	q = strings.TrimSpace(q)
	switch {
	case q == "":
		return nil, invalid("query", "must not be empty")
	case utf8.RuneCountInString(q) > MaxQueryLen:
		return nil, invalid("query", "longer than 500 characters")
	case limit < 1:
		return nil, invalid("limit", "must be at least 1")
	}
	limit = min(limit, MaxSearchHits)
	if s.empty {
		return []Vulnerability{}, nil
	}
	tokens := tokenize(q)
	if len(tokens) == 0 {
		return []Vulnerability{}, nil
	}
	ranked, err := s.base().rank(ctx, q, tokens)
	if err != nil {
		return nil, err
	}
	out := []Vulnerability{}
	for _, c := range ranked {
		if len(out) == limit {
			break
		}
		v, err := s.load(ctx, c.id)
		if err != nil {
			return nil, err
		}
		if v == nil {
			continue // not visible at the as-of time
		}
		v.Relevance = c.score
		out = append(out, *v)
	}
	return out, nil
}

type candidate struct {
	id    string
	score float64
}

// rank scores every vulnerability that contains at least one token. An exact id
// match outranks everything; an id token match outranks a summary match.
func (s *Source) rank(ctx context.Context, q string, tokens []string) ([]candidate, error) {
	conds := make([]string, 0, len(tokens))
	args := make([]any, 0, 2*len(tokens))
	for _, t := range tokens {
		like := "%" + escapeLike(t) + "%"
		conds = append(conds, `(lower(id) LIKE ? ESCAPE '\' OR lower(json_extract(props,'$.summary')) LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, props FROM nodes WHERE type='Vulnerability' AND (`+
		strings.Join(conds, " OR ")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	exact := strings.ToLower(q)
	var out []candidate
	for rows.Next() {
		var id, props string
		if err := rows.Scan(&id, &props); err != nil {
			return nil, err
		}
		m, err := decodeProps(props)
		if err != nil {
			return nil, err
		}
		id = strings.TrimPrefix(id, "vuln:")
		lid, sum := strings.ToLower(id), strings.ToLower(str(m, "summary"))
		var score float64
		if lid == exact {
			score += 100
		}
		for _, t := range tokens {
			if strings.Contains(lid, t) {
				score += 5
			}
			score += float64(strings.Count(sum, t))
		}
		if score > 0 {
			out = append(out, candidate{id, score})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].id < out[j].id
	})
	return out, nil
}

func tokenize(q string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.'
	}) {
		if f != "" && !seen[f] && len(out) < maxTokens {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func decodeProps(s string) (map[string]any, error) {
	var m map[string]any
	return m, json.Unmarshal([]byte(s), &m)
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// ---------------------------------------------------------------------------
// purl

type purl struct {
	ecosystem string // graph ecosystem name, e.g. "PyPI"
	name      string // package name as the graph spells it
	version   string // version carried by the purl, may be empty
	key       string // normalised purl without version
}

func (p purl) stableID() string { return PkgPrefix + p.key }

// parsePurl reads pkg:<type>/[<namespace>/]<name>[@<version>] and ignores
// qualifiers and subpath.
func parsePurl(raw string) (purl, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return purl{}, invalid("purl", "must not be empty")
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return purl{}, invalid("purl", "must start with pkg:")
	}
	s = strings.TrimLeft(s[4:], "/")
	var version string
	if at := strings.LastIndexByte(s, '@'); at > strings.LastIndexByte(s, '/') {
		v, err := url.PathUnescape(s[at+1:])
		if err != nil {
			return purl{}, invalid("purl", "malformed version")
		}
		s, version = s[:at], v
	}
	segs := strings.Split(s, "/")
	if len(segs) < 2 {
		return purl{}, invalid("purl", "needs a type and a name")
	}
	for i := range segs {
		d, err := url.PathUnescape(segs[i])
		if err != nil || d == "" || strings.ContainsAny(d, " \t\r\n") {
			return purl{}, invalid("purl", "malformed path segment")
		}
		segs[i] = d
	}
	typ, rest := strings.ToLower(segs[0]), segs[1:]
	p := purl{version: version}
	switch typ {
	case "npm":
		p.ecosystem, p.name = "npm", strings.Join(rest, "/")
	case "pypi":
		p.ecosystem, p.name = "PyPI", strings.Join(rest, "/")
	case "maven":
		if len(rest) < 2 {
			return purl{}, invalid("purl", "maven needs a group and an artifact")
		}
		p.ecosystem, p.name = "Maven", strings.Join(rest[:len(rest)-1], ".")+":"+rest[len(rest)-1]
	case "golang":
		p.ecosystem, p.name = "Go", strings.Join(rest, "/")
	case "cargo":
		p.ecosystem, p.name = "crates.io", strings.Join(rest, "/")
	case "nuget":
		p.ecosystem, p.name = "NuGet", strings.Join(rest, "/")
	default:
		p.ecosystem, p.name = typ, strings.Join(rest, "/")
	}
	key, ok := canonical.Key(canonical.KindPurl, "pkg:"+typ+"/"+strings.Join(rest, "/"))
	if !ok {
		return purl{}, invalid("purl", "cannot be normalised")
	}
	p.key = key
	return p, nil
}
