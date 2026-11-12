package routes

import (
	"strings"
	"testing"
)

func TestLookupMostSpecific(t *testing.T) {
	tbl, err := NewTable([]Route{
		{Method: "GET", Pattern: "/api/session/*", Group: "a", Owner: OwnerTS},
		{Method: "GET", Pattern: "/api/session/{id}", Group: "b", Owner: OwnerGo},
		{Method: "GET", Pattern: "/api/session/list", Group: "c", Owner: OwnerTS},
		{Method: "*", Pattern: "/api/session/list", Group: "d", Owner: OwnerGo},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ method, path, group string }{
		{"GET", "/api/session/list", "c"},
		{"GET", "/api/session/abc", "b"},
		{"GET", "/api/session/abc/child", "a"},
		{"POST", "/api/session/list", "d"},
		{"GET", "/api//session/./abc/", "b"},
	}
	for _, c := range cases {
		r, ok := tbl.Lookup(c.method, c.path)
		if !ok || r.Group != c.group {
			t.Errorf("%s %s: got %q ok=%v, want %q", c.method, c.path, r.Group, ok, c.group)
		}
	}
}

func TestLookupNoMatchFallsToDefaultOwnerTS(t *testing.T) {
	tbl, err := NewTable([]Route{{Method: "GET", Pattern: "/a", Group: "g", Owner: OwnerGo}})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tbl.Lookup("GET", "/unknown")
	if ok {
		t.Fatalf("expected no match, got %+v", r)
	}
	// The dispatcher treats a miss as OwnerTS; verify a wrong method also misses.
	if _, ok := tbl.Lookup("POST", "/a"); ok {
		t.Fatal("method mismatch should not match")
	}
	owner := OwnerTS
	if r, ok := tbl.Lookup("GET", "/a"); ok {
		owner = r.Owner
	}
	if owner != OwnerGo {
		t.Fatalf("owner = %s", owner)
	}
}

func TestOverlapErrorNamesBothPatterns(t *testing.T) {
	_, err := NewTable([]Route{
		{Method: "GET", Pattern: "/x/{id}", Group: "g", Owner: OwnerGo},
		{Method: "GET", Pattern: "/x/{name}", Group: "g", Owner: OwnerTS},
	})
	if err == nil {
		t.Fatal("expected overlap error")
	}
	for _, want := range []string{"/x/{id}", "/x/{name}", "overlap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestValidateMissingOperationNamesMethodAndPath(t *testing.T) {
	routes := []Route{{Method: "GET", Pattern: "/a", Group: "g", Owner: OwnerGo}}
	err := Validate(routes, []Operation{{Method: "DELETE", Path: "/things/{id}"}})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"DELETE", "/things/{id}"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if err := Validate(routes, []Operation{{Method: "GET", Path: "/a"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"":         "/",
		"/":        "/",
		"a/b":      "/a/b",
		"//a///b/": "/a/b",
		"/a/./b":   "/a/b",
		"/a/../b":  "/b",
		"/../../a": "/a",
		"/a/b/../": "/a",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMissingFieldErrors(t *testing.T) {
	full := "method: GET\n    pattern: /a\n    group: g\n    owner: go\n    public: false\n    stream: false\n"
	if _, err := Parse([]byte("version: 1\nroutes:\n  - " + full)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"method", "pattern", "group", "owner", "public", "stream"} {
		var kept []string
		for _, l := range strings.Split(strings.TrimSpace(full), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), field+":") {
				kept = append(kept, strings.TrimSpace(l))
			}
		}
		doc := "version: 1\nroutes:\n  - " + strings.Join(kept, "\n    ") + "\n"
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "missing "+field) || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("field %s: err = %v", field, err)
		}
	}
}

func TestNewTableRejectsBadEntries(t *testing.T) {
	bad := []Route{
		{Method: "GET", Pattern: "/a", Group: "g", Owner: "x"},
		{Method: "FETCH", Pattern: "/a", Group: "g", Owner: OwnerGo},
		{Method: "GET", Pattern: "a", Group: "g", Owner: OwnerGo},
		{Method: "GET", Pattern: "/a/*/b", Group: "g", Owner: OwnerGo},
	}
	for _, r := range bad {
		if _, err := NewTable([]Route{r}); err == nil {
			t.Errorf("expected error for %+v", r)
		}
	}
}
