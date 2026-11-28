// Package aiinv finds AI assets (agents, tools, MCP servers, vector stores and
// model files) in a repository with a signature table, and writes them to the
// graph as aischema entities (Requirements 6.2, 6.13, 16.2, 16.4, 16.12).
//
// The built-in table is bom/data/ai-signatures.yaml. Files in the user
// directory (~/.config/bellucode/ai-signatures.d/*.yaml) add entries and
// replace built-in entries with the same id. A bad entry is skipped with a
// scanner error row that names it.
package aiinv

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bellu/bellucode/services/bellud/internal/bom/data"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema/aischema"
	"github.com/bellu/bellucode/services/bellud/internal/scanners"
)

// Name is the adapter name.
const Name = "aiinv"

const (
	adapterVersion = "1"
	connection     = "repository"
	maxFileSize    = 1 << 20
	// LinkUnresolved is the attribute that names a link that found no target.
	LinkUnresolved = "link_unresolved"
)

var kinds = map[string]bool{
	aischema.KindModel: true, aischema.KindAgent: true, aischema.KindTool: true,
	aischema.KindMCPServer: true, aischema.KindVectorStore: true,
}

// Signature is one table entry.
type Signature struct {
	ID        string   `yaml:"id"`
	Kind      string   `yaml:"kind"`
	Files     []string `yaml:"files"`
	Pattern   string   `yaml:"pattern"`
	LinkTools bool     `yaml:"link_tools"`
	re        *regexp.Regexp
}

type table struct {
	Signatures []yaml.Node `yaml:"signatures"`
}

// LoadError is a skipped entry.
type LoadError struct{ Source, ID, Cause string }

// Load returns the built-in signatures overlaid with the user files in dir.
// Entries with an invalid kind, files list or pattern are skipped and reported.
func Load(dir string) ([]Signature, []LoadError) {
	byID := map[string]Signature{}
	var order []string
	var errs []LoadError
	add := func(src string, raw []byte) {
		var t table
		if err := yaml.Unmarshal(raw, &t); err != nil {
			errs = append(errs, LoadError{Source: src, ID: "-", Cause: "invalid yaml: " + err.Error()})
			return
		}
		for _, n := range t.Signatures {
			var s Signature
			if err := n.Decode(&s); err != nil {
				errs = append(errs, LoadError{Source: src, ID: "line " + strconv.Itoa(n.Line), Cause: err.Error()})
				continue
			}
			if err := s.compile(); err != nil {
				errs = append(errs, LoadError{Source: src, ID: s.ID, Cause: err.Error()})
				continue
			}
			if _, ok := byID[s.ID]; !ok {
				order = append(order, s.ID)
			}
			byID[s.ID] = s
		}
	}
	add("builtin", data.AISignatures)
	matches, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	sort.Strings(matches)
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			errs = append(errs, LoadError{Source: m, ID: "-", Cause: err.Error()})
			continue
		}
		add(m, raw)
	}
	out := make([]Signature, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, errs
}

func (s *Signature) compile() error {
	switch {
	case s.ID == "":
		return fmt.Errorf("missing id")
	case !kinds[s.Kind]:
		return fmt.Errorf("unknown kind %q", s.Kind)
	case len(s.Files) == 0:
		return fmt.Errorf("files is empty")
	}
	for _, g := range s.Files {
		if _, err := filepath.Match(g, "x"); err != nil {
			return fmt.Errorf("bad file glob %q", g)
		}
	}
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("bad pattern: %w", err)
		}
		s.re = re
	}
	return nil
}

func (s Signature) matchesFile(base string) bool {
	for _, g := range s.Files {
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
	}
	return false
}

// Adapter implements scanners.Adapter.
type Adapter struct{ userDir string }

var _ scanners.Adapter = Adapter{}

// New returns the adapter. userDir is ~/.config/bellucode/ai-signatures.d.
func New(userDir string) Adapter { return Adapter{userDir: userDir} }

func (Adapter) Kind() scanners.Kind { return scanners.KindAIInventory }
func (Adapter) Info() scanners.Info {
	return scanners.Info{Name: Name, Version: adapterVersion, License: "Apache-2.0"}
}
func (Adapter) Applies(t scanners.TargetType) bool { return t == scanners.TargetRepository }

// Digest hashes the sorted (path, size, mtime) of the scannable files.
func (a Adapter) Digest(ctx context.Context, t scanners.Target) (string, error) {
	sigs, _ := Load(a.userDir)
	h := sha256.New()
	err := walk(ctx, t.Path, sigs, func(rel string, fi fs.FileInfo) error {
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", rel, fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Hit is one match.
type Hit struct {
	Sig  Signature
	Path string
	Name string
	Line int
	// File-level facts that feed the bellu pack AI rules. They are heuristics
	// over the file's lines, set only on hits of files that were read.
	WriteTool, ExternalInput, Validated bool
}

var (
	writeToolRe     = regexp.MustCompile(`\bdef\s+\w*(?:write|delete|remove|update|create|send|exec|drop|insert|post|put|save|email)\w*\s*\(`)
	externalInputRe = regexp.MustCompile(`\b(?:input|request\.(?:json|form|args|body)|sys\.argv)\b|@(?:app|router)\.(?:get|post|put|route)\(|requests\.get\(|WebBaseLoader\(`)
	validatedRe     = regexp.MustCompile(`(?i)\b(?:validate\w*|sanitiz\w*|BaseModel|guardrails?)\b`)
)

// ID is the derived entity id of a repository item.
func ID(repo, path, name string) string {
	sum := sha256.Sum256([]byte(repo + "\x00" + path + "\x00" + name))
	return hex.EncodeToString(sum[:16])
}

// Run scans the repository and applies one batch.
func (a Adapter) Run(ctx context.Context, t scanners.Target, out scanners.Sink) error {
	sigs, lerrs := Load(a.userDir)
	for _, le := range lerrs {
		if err := out.ScannerError(le.Source+"#"+le.ID, le.Cause); err != nil {
			return err
		}
	}
	var hits []Hit
	err := walk(ctx, t.Path, sigs, func(rel string, _ fs.FileInfo) error {
		hs, err := scanFile(filepath.Join(t.Path, rel), rel, sigs)
		if err != nil {
			return out.ScannerError(rel, err.Error())
		}
		hits = append(hits, hs...)
		return nil
	})
	if err != nil {
		return err
	}
	b, err := Batch(t, hits)
	if err != nil {
		return err
	}
	return out.Batch(b)
}

func walk(ctx context.Context, root string, sigs []Signature, f func(rel string, fi fs.FileInfo) error) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (n == ".git" || n == "node_modules" || n == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		wanted := false
		for _, s := range sigs {
			if s.matchesFile(d.Name()) {
				wanted = true
				break
			}
		}
		if !wanted {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		return f(filepath.ToSlash(rel), fi)
	})
}

func scanFile(abs, rel string, sigs []Signature) ([]Hit, error) {
	var hits []Hit
	var textSigs []Signature
	for _, s := range sigs {
		if !s.matchesFile(filepath.Base(rel)) {
			continue
		}
		if s.re == nil {
			hits = append(hits, Hit{Sig: s, Path: rel, Name: filepath.Base(rel), Line: 1})
			continue
		}
		textSigs = append(textSigs, s)
	}
	if len(textSigs) == 0 {
		return hits, nil
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxFileSize {
		return hits, nil
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxFileSize)
	first := len(hits)
	var write, external, validated bool
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		write = write || writeToolRe.MatchString(line)
		external = external || externalInputRe.MatchString(line)
		validated = validated || validatedRe.MatchString(line)
		for _, s := range textSigs {
			m := s.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := s.ID
			if len(m) > 1 && m[1] != "" {
				name = m[1]
			}
			hits = append(hits, Hit{Sig: s, Path: rel, Name: name, Line: n})
		}
	}
	for i := first; i < len(hits); i++ {
		hits[i].WriteTool, hits[i].ExternalInput, hits[i].Validated = write, external, validated
	}
	return hits, sc.Err()
}

// Batch builds the graph batch for the hits of one repository. Entities have
// the derived id of (repo, path, name), so a repeated scan updates in place.
// An agent entry with link_tools gets ai_has_tool to each tool of its file; an
// agent with none is stored with link_unresolved and raises no finding.
func Batch(t scanners.Target, hits []Hit) (batch.Batch, error) {
	repoID := t.ID
	if repoID == "" {
		repoID = t.Path
	}
	repoHash, err := identity.Hash("repository", map[string]string{"path": t.Path})
	if err != nil {
		return batch.Batch{}, fmt.Errorf("repository identity: %w", err)
	}
	out := batch.Batch{Collector: Name + ":" + repoID}
	out.Entities = append(out.Entities, batch.Entity{Type: "repository", Identity: map[string]string{"path": t.Path}, Attributes: map[string]any{"source": Name}})
	type ent struct {
		kind, id, path string
		hash           identity.ID
		unresolved     bool
	}
	seen := map[string]*ent{}
	var all []*ent
	for _, h := range hits {
		id := ID(repoID, h.Path, h.Name)
		key := h.Sig.Kind + "\x00" + id
		if seen[key] != nil {
			continue
		}
		idm := map[string]string{"connection": connection, "id": id}
		hash, err := identity.Hash(h.Sig.Kind, idm)
		if err != nil {
			return batch.Batch{}, fmt.Errorf("%s %q identity: %w", h.Sig.Kind, h.Name, err)
		}
		e := &ent{kind: h.Sig.Kind, id: id, path: h.Path, hash: hash}
		seen[key] = e
		all = append(all, e)
		attrs := map[string]any{
			"source": Name, "repo": repoID, "path": h.Path, "name": h.Name,
			"signature": h.Sig.ID, "file": h.Path, "line": h.Line,
		}
		switch h.Sig.Kind {
		case aischema.KindAgent:
			attrs["has_write_tool"] = strconv.FormatBool(h.WriteTool)
			attrs["external_input"] = strconv.FormatBool(h.ExternalInput)
			attrs["input_validated"] = strconv.FormatBool(h.Validated)
		case aischema.KindModel:
			attrs["serialization_format"] = strings.ToLower(strings.TrimPrefix(filepath.Ext(h.Path), "."))
		}
		out.Entities = append(out.Entities, batch.Entity{Type: h.Sig.Kind, Identity: idm, Attributes: attrs})
		out.Relations = append(out.Relations, batch.Relation{Type: aischema.RelRunsIn, From: string(hash), To: string(repoHash)})
		if h.Sig.LinkTools {
			linked := false
			for _, o := range hits {
				if o.Sig.Kind == aischema.KindTool && o.Path == h.Path {
					th, err := identity.Hash(aischema.KindTool, map[string]string{"connection": connection, "id": ID(repoID, o.Path, o.Name)})
					if err != nil {
						return batch.Batch{}, err
					}
					out.Relations = append(out.Relations, batch.Relation{Type: aischema.RelHasTool, From: string(hash), To: string(th)})
					linked = true
				}
			}
			if !linked {
				attrs[LinkUnresolved] = aischema.RelHasTool
			}
		}
	}
	return out, nil
}
