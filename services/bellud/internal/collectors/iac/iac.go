// Package iac is the infrastructure-as-code collector: it reads Terraform
// *.tf files and Kubernetes manifests under configured roots and produces
// iac_resource and k8s_object entities.
package iac

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/batch"
	"github.com/bellu/bellucode/services/bellud/internal/graph/identity"
)

// Name is the collector name.
const Name = "iac"

// MaxFileSize caps the size of any file that is read.
const MaxFileSize = 1 << 20

// Collector scans Roots for Terraform and Kubernetes files.
type Collector struct {
	Roots    []string
	Every    time.Duration
	Now      func() time.Time
	skipDirs map[string]bool
}

// New builds a collector over roots.
func New(roots ...string) *Collector {
	return &Collector{Roots: roots, Every: time.Minute, Now: time.Now,
		skipDirs: map[string]bool{"node_modules": true, ".git": true, "dist": true,
			"bellugraph": true, ".terraform": true, "vendor": true}}
}

func (c *Collector) Name() string            { return Name }
func (c *Collector) Interval() time.Duration { return c.Every }

// Collect returns the full current observation.
func (c *Collector) Collect(ctx context.Context) (graph.Batch, error) {
	b := graph.Batch{Collector: Name, ObservedAt: c.Now()}
	seen := map[string]bool{}
	k8s := map[string]k8sObj{}
	var order []string
	for _, root := range c.Roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err != nil {
				return nil // unreadable entries are skipped
			}
			if d.IsDir() {
				if p != root && c.skipDirs[d.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".tf" && ext != ".yaml" && ext != ".yml" {
				return nil
			}
			if info, err := d.Info(); err != nil || info.Size() > MaxFileSize || !info.Mode().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			if ext == ".tf" {
				for _, r := range scanTerraform(data) {
					key := "tf\x00" + p + "\x00" + r.address
					if seen[key] {
						continue
					}
					seen[key] = true
					b.Entities = append(b.Entities, batch.Entity{
						Type:       "iac_resource",
						Identity:   map[string]string{"path": p, "address": r.address},
						Attributes: r.attrs,
					})
				}
				return nil
			}
			for _, o := range parseK8s(p, data) {
				id := o.key()
				if _, dup := k8s[id]; dup {
					continue
				}
				k8s[id] = o
				order = append(order, id)
			}
			return nil
		})
		if err != nil {
			return graph.Batch{}, err
		}
	}
	for _, id := range order {
		o := k8s[id]
		b.Entities = append(b.Entities, batch.Entity{Type: "k8s_object", Identity: o.identity(), Attributes: o.attrs})
	}
	b.Relations = k8sRelations(k8s, order)
	return b, nil
}

// ---- Terraform ----

type tfResource struct {
	address string
	attrs   map[string]any
}

var (
	tfHeader = regexp.MustCompile(`^(resource|data|module)((?:\s+"[^"]*")+)\s*\{?\s*$`)
	tfQuoted = regexp.MustCompile(`"([^"]*)"`)
	tfAttr   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)
	tfLits   = map[string]bool{"acl": true, "publicly_accessible": true, "encrypted": true,
		"storage_encrypted": true, "source": true, "version": true, "cidr_blocks": false}
)

// scanTerraform is a minimal top-level HCL block scanner.
func scanTerraform(data []byte) []tfResource {
	var out []tfResource
	var cur *tfResource
	depth := 0
	inBlockComment := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), MaxFileSize)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if inBlockComment {
			if i := strings.Index(line, "*/"); i >= 0 {
				inBlockComment = false
				line = strings.TrimSpace(line[i+2:])
			} else {
				continue
			}
		}
		if strings.HasPrefix(line, "/*") && !strings.Contains(line, "*/") {
			inBlockComment = true
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if cur != nil && cur.attrs["_pending"] != nil {
			if line == "{" {
				depth = 1
				delete(cur.attrs, "_pending")
			} else {
				cur = nil // header without a body
			}
			continue
		}
		if depth == 0 {
			m := tfHeader.FindStringSubmatch(line)
			if m == nil {
				depth += braceDelta(line)
				continue
			}
			names := tfQuoted.FindAllStringSubmatch(m[2], -1)
			var parts []string
			for _, n := range names {
				parts = append(parts, n[1])
			}
			addr, ok := tfAddress(m[1], parts)
			if !ok {
				depth += braceDelta(line)
				continue
			}
			cur = &tfResource{address: addr, attrs: map[string]any{"block": m[1]}}
			if m[1] == "resource" || m[1] == "data" {
				cur.attrs["type"] = parts[0]
				cur.attrs["provider"] = strings.SplitN(parts[0], "_", 2)[0]
			}
			if strings.HasSuffix(line, "{") {
				depth = 1
			} else {
				depth = 0 // brace on a following line
				cur.attrs["_pending"] = true
			}
			if strings.HasSuffix(line, "{}") {
				depth = 0
				delete(cur.attrs, "_pending")
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if depth == 1 && cur != nil {
			if m := tfAttr.FindStringSubmatch(line); m != nil && tfLits[m[1]] {
				if v, ok := tfLiteral(m[2]); ok {
					cur.attrs[m[1]] = v
				}
			}
		}
		depth += braceDelta(line)
		if depth <= 0 {
			depth = 0
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
		}
	}
	// Pending header with no body is dropped; an unterminated block is kept.
	if cur != nil && cur.attrs["_pending"] == nil {
		out = append(out, *cur)
	}
	return out
}

func tfAddress(kind string, parts []string) (string, bool) {
	switch kind {
	case "resource":
		if len(parts) == 2 {
			return parts[0] + "." + parts[1], true
		}
	case "data":
		if len(parts) == 2 {
			return "data." + parts[0] + "." + parts[1], true
		}
	case "module":
		if len(parts) == 1 {
			return "module." + parts[0], true
		}
	}
	return "", false
}

// braceDelta counts braces outside string literals and trailing comments.
func braceDelta(line string) int {
	d, inStr := 0, false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inStr:
			if ch == '\\' {
				i++
			} else if ch == '"' {
				inStr = false
			}
		case ch == '"':
			inStr = true
		case ch == '#' || (ch == '/' && i+1 < len(line) && line[i+1] == '/'):
			return d
		case ch == '{':
			d++
		case ch == '}':
			d--
		}
	}
	return d
}

// tfLiteral extracts a trivially literal value (bool or plain string).
func tfLiteral(s string) (any, bool) {
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	switch s {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		v := s[1 : len(s)-1]
		if !strings.ContainsAny(v, `"\$`) {
			return v, true
		}
	}
	return nil, false
}

// ---- Kubernetes ----

type k8sObj struct {
	source, kind, namespace, name string
	attrs                         map[string]any
	saName                        string
	podBearing                    bool
	roleRef                       *struct{ kind, name string }
}

func (o k8sObj) key() string {
	return o.source + "\x00" + o.kind + "\x00" + o.namespace + "\x00" + o.name
}

func (o k8sObj) identity() map[string]string {
	return map[string]string{"source": o.source, "kind": o.kind, "namespace": o.namespace, "name": o.name}
}

var clusterScoped = map[string]bool{
	"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true, "Node": true,
	"PersistentVolume": true, "StorageClass": true, "CustomResourceDefinition": true,
}

func parseK8s(path string, data []byte) []k8sObj {
	var out []k8sObj
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			// io.EOF or malformed stream: stop at the first error.
			return out
		}
		if o, ok := k8sFromDoc(path, doc); ok {
			out = append(out, o)
		}
	}
}

func k8sFromDoc(path string, doc map[string]any) (k8sObj, bool) {
	apiVersion, _ := doc["apiVersion"].(string)
	kind, _ := doc["kind"].(string)
	meta, _ := doc["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if apiVersion == "" || kind == "" || name == "" {
		return k8sObj{}, false
	}
	ns, _ := meta["namespace"].(string)
	if clusterScoped[kind] || ns == "" && clusterScoped[kind] {
		ns = "-"
	} else if ns == "" {
		ns = "default"
	}
	o := k8sObj{source: path, kind: kind, namespace: ns, name: name,
		attrs: map[string]any{"api_version": apiVersion}}
	if labels, ok := meta["labels"].(map[string]any); ok && len(labels) > 0 {
		ls := make([]string, 0, len(labels))
		for k, v := range labels {
			if s, ok := v.(string); ok {
				ls = append(ls, k+"="+s)
			}
		}
		sort.Strings(ls)
		o.attrs["labels"] = ls
	}
	if spec := podSpec(kind, doc); spec != nil {
		o.podBearing = true
		o.podAttrs(spec)
	}
	switch kind {
	case "Role", "ClusterRole":
		o.attrs["rules"] = ruleSummary(doc["rules"])
	case "RoleBinding", "ClusterRoleBinding":
		if rr, ok := doc["roleRef"].(map[string]any); ok {
			k, _ := rr["kind"].(string)
			n, _ := rr["name"].(string)
			if k != "" && n != "" {
				o.roleRef = &struct{ kind, name string }{k, n}
				o.attrs["role_ref"] = k + "/" + n
			}
		}
	}
	return o, true
}

// podSpec returns the pod spec of a pod-bearing kind, or nil.
func podSpec(kind string, doc map[string]any) map[string]any {
	spec, _ := doc["spec"].(map[string]any)
	switch kind {
	case "Pod":
		return spec
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		return nested(spec, "template", "spec")
	case "CronJob":
		return nested(spec, "jobTemplate", "spec", "template", "spec")
	}
	return nil
}

func nested(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		m, _ = m[k].(map[string]any)
		if m == nil {
			return nil
		}
	}
	return m
}

func (o *k8sObj) podAttrs(spec map[string]any) {
	if sa, _ := spec["serviceAccountName"].(string); sa != "" {
		o.saName = sa
		o.attrs["service_account_name"] = sa
	}
	for _, f := range [][2]string{{"hostNetwork", "host_network"}, {"hostPID", "host_pid"}} {
		if v, ok := spec[f[0]].(bool); ok && v {
			o.attrs[f[1]] = true
		}
	}
	var images []string
	privileged := false
	for _, key := range []string{"containers", "initContainers"} {
		list, _ := spec[key].([]any)
		for _, e := range list {
			c, _ := e.(map[string]any)
			if img, _ := c["image"].(string); img != "" {
				images = append(images, img)
			}
			if sc, _ := c["securityContext"].(map[string]any); sc != nil {
				if p, _ := sc["privileged"].(bool); p {
					privileged = true
				}
			}
		}
	}
	if len(images) > 0 {
		o.attrs["images"] = images
	}
	if privileged {
		o.attrs["privileged"] = true
	}
}

func ruleSummary(v any) []string {
	rules, _ := v.([]any)
	var out []string
	for _, r := range rules {
		m, _ := r.(map[string]any)
		out = append(out, "apiGroups="+join(m["apiGroups"])+" resources="+join(m["resources"])+" verbs="+join(m["verbs"]))
	}
	return out
}

func join(v any) string {
	l, _ := v.([]any)
	s := make([]string, 0, len(l))
	for _, e := range l {
		if str, ok := e.(string); ok {
			s = append(s, str)
		}
	}
	return strings.Join(s, ",")
}

// k8sRelations links pods to service accounts and bindings to roles when both
// ends are present. Relations carry no attributes.
func k8sRelations(objs map[string]k8sObj, order []string) []batch.Relation {
	byKind := map[string]k8sObj{} // kind\0ns\0name -> object
	for _, id := range order {
		o := objs[id]
		byKind[o.kind+"\x00"+o.namespace+"\x00"+o.name] = o
	}
	var rels []batch.Relation
	add := func(typ string, from, to k8sObj) {
		f, err1 := identity.Hash("k8s_object", from.identity())
		t, err2 := identity.Hash("k8s_object", to.identity())
		if err1 == nil && err2 == nil {
			rels = append(rels, batch.Relation{Type: typ, From: string(f), To: string(t)})
		}
	}
	for _, id := range order {
		o := objs[id]
		if o.podBearing && o.saName != "" {
			if sa, ok := byKind["ServiceAccount\x00"+o.namespace+"\x00"+o.saName]; ok {
				add("uses_service_account", o, sa)
			}
		}
		if o.roleRef != nil {
			ns := "-"
			if o.roleRef.kind == "Role" {
				ns = o.namespace
			}
			if role, ok := byKind[o.roleRef.kind+"\x00"+ns+"\x00"+o.roleRef.name]; ok {
				add("binds", o, role)
			}
		}
	}
	return rels
}
