package codesec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func parsePackageJSON(b *builder, f file, data []byte) {
	var pj struct {
		Deps     map[string]string `json:"dependencies"`
		Dev      map[string]string `json:"devDependencies"`
		Peer     map[string]string `json:"peerDependencies"`
		Optional map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(data, &pj) != nil {
		return
	}
	for scope, m := range map[string]map[string]string{
		"runtime": pj.Deps, "dev": pj.Dev, "peer": pj.Peer, "optional": pj.Optional,
	} {
		for n, r := range m {
			b.dep(f, n, r, "npm", scope)
		}
	}
}

// stripJSONC removes comments and trailing commas outside of strings.
func stripJSONC(in []byte) []byte {
	var out bytes.Buffer
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out.WriteByte(c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

func parseBunLock(b *builder, f file, data []byte) {
	var lock struct {
		Workspaces map[string]struct {
			Deps     map[string]string `json:"dependencies"`
			Dev      map[string]string `json:"devDependencies"`
			Peer     map[string]string `json:"peerDependencies"`
			Optional map[string]string `json:"optionalDependencies"`
		} `json:"workspaces"`
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(stripJSONC(data), &lock) != nil {
		return
	}
	for _, w := range lock.Workspaces {
		for scope, m := range map[string]map[string]string{
			"runtime": w.Deps, "dev": w.Dev, "peer": w.Peer, "optional": w.Optional,
		} {
			for n, r := range m {
				b.dep(f, n, r, "npm", scope)
			}
		}
	}
	// Resolved packages: entry[0] is "name@version".
	for key, ent := range lock.Packages {
		if len(ent) == 0 {
			continue
		}
		var spec string
		if json.Unmarshal(ent[0], &spec) != nil {
			continue
		}
		i := strings.LastIndex(spec, "@")
		if i <= 0 {
			_ = key
			continue
		}
		b.dep(f, spec[:i], spec[i+1:], "npm", "resolved")
	}
}

func parseGoMod(b *builder, f file, data []byte) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		scope := "direct"
		if indirect {
			scope = "indirect"
		}
		switch {
		case inBlock && line == ")":
			inBlock = false
		case line == "require (":
			inBlock = true
		case inBlock:
			if p := strings.Fields(line); len(p) >= 2 {
				b.dep(f, p[0], p[1], "go", scope)
			}
		case strings.HasPrefix(line, "require "):
			if p := strings.Fields(strings.TrimPrefix(line, "require ")); len(p) >= 2 {
				b.dep(f, p[0], p[1], "go", scope)
			}
		}
	}
}

var reqSplit = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$`)

func parseRequirements(b *builder, f file, data []byte) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, ";"); i >= 0 { // environment marker
			line = strings.TrimSpace(line[:i])
		}
		m := reqSplit.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		b.dep(f, strings.ToLower(m[1]), strings.ReplaceAll(m[3], " ", ""), "pypi", "runtime")
	}
}

var (
	exprRe   = regexp.MustCompile(`\$\{\{(.*?)\}\}`)
	secretRe = regexp.MustCompile(`\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)`)
)

func permString(v any) string {
	switch p := v.(type) {
	case string:
		return p
	case map[string]any:
		ks := make([]string, 0, len(p))
		for k := range p {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts := make([]string, 0, len(ks))
		for _, k := range ks {
			parts = append(parts, fmt.Sprintf("%s:%v", k, p[k]))
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func parseWorkflow(b *builder, f file, data []byte) {
	var wf map[string]any
	if yaml.Unmarshal(data, &wf) != nil || wf == nil {
		return
	}
	triggers := []string{}
	switch on := wf["on"].(type) {
	case string:
		triggers = append(triggers, on)
	case []any:
		for _, t := range on {
			triggers = append(triggers, fmt.Sprint(t))
		}
	case map[string]any:
		for t := range on {
			triggers = append(triggers, t)
		}
	}
	sort.Strings(triggers)
	hasPRT := false
	for _, t := range triggers {
		if t == "pull_request_target" {
			hasPRT = true
		}
	}

	uses := map[string]bool{}
	var jobPerms []string
	if jobs, ok := wf["jobs"].(map[string]any); ok {
		ids := make([]string, 0, len(jobs))
		for id := range jobs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			job, _ := jobs[id].(map[string]any)
			if u, ok := job["uses"].(string); ok {
				uses[u] = true
			}
			if p := permString(job["permissions"]); p != "" {
				jobPerms = append(jobPerms, id+"="+p)
			}
			if steps, ok := job["steps"].([]any); ok {
				for _, s := range steps {
					if sm, ok := s.(map[string]any); ok {
						if u, ok := sm["uses"].(string); ok {
							uses[u] = true
						}
					}
				}
			}
		}
	}
	usesList := make([]string, 0, len(uses))
	for u := range uses {
		usesList = append(usesList, u)
	}
	sort.Strings(usesList)

	name, _ := wf["name"].(string)
	if name == "" {
		name = f.rel
	}
	attrs := map[string]any{
		"name":                name,
		"triggers":            strings.Join(triggers, ","),
		"permissions":         permString(wf["permissions"]),
		"job_permissions":     strings.Join(jobPerms, ";"),
		"uses":                strings.Join(usesList, ","),
		"pull_request_target": hasPRT,
	}
	repo := b.repo(f.root)
	wk, _ := b.add("workflow", map[string]string{"repo": f.root, "path": f.rel}, attrs)
	b.rel("defined_in", wk, repo)

	for _, e := range exprRe.FindAllSubmatch(data, -1) {
		for _, s := range secretRe.FindAllSubmatch(e[1], -1) {
			sk, _ := b.add("secret_ref", map[string]string{"repo": f.root, "path": f.rel, "name": string(s[1])}, nil)
			b.rel("used_by", sk, wk)
		}
	}
}
