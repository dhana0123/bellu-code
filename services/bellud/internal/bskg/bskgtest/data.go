package bskgtest

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Fixed fake data. IDs are real CVEs, but the field values are test data.
var vulns = map[string]map[string]any{
	"CVE-2021-44228": {
		"cveID": "CVE-2021-44228", "description": "Fake: Log4j JNDI lookup remote code execution.",
		"cvssV3": 10.0, "severity": "CRITICAL", "published": "2021-12-10T10:15:00Z",
		"exploitability": "high", "kev": true, "sources": []string{"nvd", "cwe", "exploitdb"},
	},
	"CVE-2021-23337": {
		"cveID": "CVE-2021-23337", "description": "Fake: lodash template command injection.",
		"cvssV3": 7.2, "severity": "HIGH", "published": "2021-02-15T13:15:00Z",
		"exploitability": "low", "sources": []string{"nvd", "cwe", "exploitdb"},
	},
}

var weaknessOf = map[string][]map[string]any{
	"CVE-2021-44228": {{"cweID": "CWE-502", "name": "Deserialization of Untrusted Data"}, {"cweID": "CWE-917", "name": "Expression Language Injection"}},
	"CVE-2021-23337": {{"cweID": "CWE-94", "name": "Improper Control of Generation of Code"}},
}

var exploitsOf = map[string][]map[string]any{
	"CVE-2021-44228": {{"eid": "EDB-50592", "title": "Fake Log4Shell RCE", "type": "remote", "platform": "java"}},
	"CVE-2021-23337": {{"eid": "EDB-49999", "title": "Fake lodash template injection", "type": "local", "platform": "nodejs"}},
}

var affectedOf = map[string][]map[string]any{
	"CVE-2021-44228": {{"vendor": "apache", "product": "log4j", "versions": "2.0-beta9 to 2.15.0"}},
	"CVE-2021-23337": {{"vendor": "lodash", "product": "lodash", "versions": "< 4.17.21"}},
}

var weaknessNames = map[string]string{
	"CWE-502": "Deserialization of Untrusted Data",
	"CWE-917": "Expression Language Injection",
	"CWE-94":  "Improper Control of Generation of Code",
}

func notFound(kind, id string) (int, map[string]any) {
	return 404, map[string]any{"error": map[string]any{"code": "not_found", "message": kind + " " + id + " not found"}}
}

// route returns the success (or 404) body for a request path.
func route(r *http.Request) (int, map[string]any) {
	p := strings.Trim(r.URL.Path, "/")
	seg := strings.Split(p, "/")
	if r.Method != http.MethodGet || len(seg) < 2 || seg[0] != "v1" {
		return notFound("Route", r.URL.Path)
	}
	q := r.URL.Query()
	switch {
	case p == "v1/vulnerabilities":
		return search(q.Get("q"), q.Get("cwe"), q.Get("limit"))
	case len(seg) == 3 && seg[1] == "vulnerabilities":
		v, ok := vulns[strings.ToUpper(seg[2])]
		if !ok {
			return notFound("Vulnerability", seg[2])
		}
		id := v["cveID"].(string)
		out := map[string]any{"weaknesses": weaknessOf[id], "exploits": exploitsOf[id], "products": affectedOf[id]}
		for k, val := range v {
			out[k] = val
		}
		return 200, out
	case len(seg) == 3 && seg[1] == "weaknesses":
		id := strings.ToUpper(seg[2])
		name, ok := weaknessNames[id]
		if !ok {
			return notFound("Weakness", seg[2])
		}
		return 200, map[string]any{"cweID": id, "name": name, "vulnerabilities": cvesWithCWE(id)}
	case p == "v1/graph/neighborhood":
		return neighborhood(q.Get("id"), q.Get("type"), q.Get("relTypes"), q.Get("nodeTypes"))
	}
	return notFound("Route", r.URL.Path)
}

func cvesWithCWE(cwe string) []string {
	var out []string
	for id, ws := range weaknessOf {
		for _, w := range ws {
			if w["cweID"] == cwe {
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

func search(text, cwe, limit string) (int, map[string]any) {
	var ids []string
	for id, v := range vulns {
		if text != "" && !strings.Contains(strings.ToLower(id+" "+v["description"].(string)), strings.ToLower(text)) {
			continue
		}
		if cwe != "" && !contains(cvesWithCWE(strings.ToUpper(cwe)), id) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if n, err := strconv.Atoi(limit); err == nil && n >= 0 && n < len(ids) {
		ids = ids[:n]
	}
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		items = append(items, vulns[id])
	}
	return 200, map[string]any{"items": items, "nextCursor": ""}
}

// neighborhood follows the BSKG design for GET /v1/graph/neighborhood: node
// ids are Label:key, edges carry source and target, nodeTypes restricts every
// non-start node and relTypes every relationship. Depth is always one hop.
func neighborhood(id, typ, relTypes, nodeTypes string) (int, map[string]any) {
	id = strings.ToUpper(id)
	if _, ok := vulns[id]; !ok || (typ != "" && typ != "Vulnerability") {
		return notFound("Vulnerability", id)
	}
	wantNode := func(t string) bool { return nodeTypes == "" || contains(strings.Split(nodeTypes, ","), t) }
	wantRel := func(t string) bool { return relTypes == "" || contains(strings.Split(relTypes, ","), t) }
	start := "Vulnerability:" + id
	nodes := []map[string]any{node(start, "Vulnerability", id, id)}
	edges := []map[string]any{}
	seen := map[string]bool{start: true}
	add := func(nid, t, key, label, rel, from, to string) {
		if !wantNode(t) || !wantRel(rel) {
			return
		}
		if !seen[nid] {
			seen[nid] = true
			nodes = append(nodes, node(nid, t, key, label))
		}
		edges = append(edges, map[string]any{"id": from + "|" + rel + "|" + to, "source": from, "target": to, "type": rel})
	}
	for _, w := range weaknessOf[id] {
		k := w["cweID"].(string)
		add("Weakness:"+k, "Weakness", k, w["name"].(string), "HAS_WEAKNESS", start, "Weakness:"+k)
	}
	for _, e := range exploitsOf[id] {
		k := e["eid"].(string)
		add("Exploit:"+k, "Exploit", k, e["title"].(string), "EXPLOITS", "Exploit:"+k, start)
	}
	for _, p := range affectedOf[id] {
		vk, pk := p["vendor"].(string), p["product"].(string)
		add("Product:"+pk, "Product", pk, pk, "AFFECTS", start, "Product:"+pk)
		if wantNode("Product") { // the vendor is one hop beyond the product
			add("Vendor:"+vk, "Vendor", vk, vk, "BELONGS_TO", "Product:"+pk, "Vendor:"+vk)
		}
	}
	sort.Slice(nodes[1:], func(i, j int) bool { return nodes[1+i]["id"].(string) < nodes[1+j]["id"].(string) })
	sort.Slice(edges, func(i, j int) bool { return edges[i]["id"].(string) < edges[j]["id"].(string) })
	return 200, map[string]any{"nodes": nodes, "edges": edges, "truncated": false}
}
func node(id, typ, key, label string) map[string]any {
	return map[string]any{"id": id, "type": typ, "key": key, "label": label, "properties": map[string]any{}}
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
