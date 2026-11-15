package facade

import (
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: go-server-bellu-graph, Property 9: Identity hash determinism
// **Validates: Requirements 13.1, 13.2, 13.3, 13.4**

func ihKind() *rapid.Generator[string] {
	return rapid.SampledFrom(Kinds())
}

func ihValue() *rapid.Generator[string] {
	return rapid.StringN(1, 12, -1)
}

// ihIdentity draws a non-empty value for every identity attribute of kind.
func ihIdentity(t *rapid.T, kind string) map[string]string {
	keys, _ := IdentityAttributes(kind)
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[k] = ihValue().Draw(t, "val_"+k)
	}
	return m
}

// ihShuffledCopy rebuilds m inserting entries in a random order, merging extra.
func ihShuffledCopy(t *rapid.T, m, extra map[string]string) map[string]string {
	type kv struct{ k, v string }
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	for k, v := range extra {
		all = append(all, kv{k, v})
	}
	out := make(map[string]string, len(all))
	for len(all) > 0 {
		i := rapid.IntRange(0, len(all)-1).Draw(t, "pick")
		out[all[i].k] = all[i].v
		all = append(all[:i], all[i+1:]...)
	}
	return out
}

func TestIdentityHashOrderAndExtraAttrsInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		id := ihIdentity(t, kind)
		extra := map[string]string{}
		for _, k := range rapid.SliceOfN(rapid.StringN(1, 8, -1), 0, 5).Draw(t, "extraKeys") {
			if _, isID := id[k]; !isID {
				extra["x_"+k] = ihValue().Draw(t, "extraVal")
			}
		}
		want, err := Hash(kind, id)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		got, err := Hash(kind, ihShuffledCopy(t, id, extra))
		if err != nil {
			t.Fatalf("Hash with extras: %v", err)
		}
		if got != want {
			t.Fatalf("hash changed: %q vs %q", got, want)
		}
	})
}

func TestIdentityHashDistinguishes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		a := ihIdentity(t, kind)
		keys, _ := IdentityAttributes(kind)

		// Differing identity value => different ID.
		k := rapid.SampledFrom(keys).Draw(t, "key")
		b := ihShuffledCopy(t, a, nil)
		b[k] = ihValue().Draw(t, "other")
		ha, _ := Hash(kind, a)
		hb, _ := Hash(kind, b)
		if (a[k] == b[k]) != (ha == hb) {
			t.Fatalf("a[%s]=%q b[%s]=%q but hashes %q / %q", k, a[k], k, b[k], ha, hb)
		}

		// Different kind with the same attribute values => different ID.
		other := ihKind().Draw(t, "otherKind")
		if other == kind {
			return
		}
		oa := ihIdentity(t, other)
		for kk, v := range a {
			if _, ok := oa[kk]; ok {
				oa[kk] = v
			}
		}
		ho, err := Hash(other, oa)
		if err != nil {
			t.Fatalf("Hash(other): %v", err)
		}
		if ho == ha {
			t.Fatalf("kinds %q and %q collide: %q", kind, other, ho)
		}
	})
}

func TestIdentityHashMissingOrEmptyIsValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		attrs := ihIdentity(t, kind)
		keys, _ := IdentityAttributes(kind)
		k := rapid.SampledFrom(keys).Draw(t, "key")
		if rapid.Bool().Draw(t, "empty") {
			attrs[k] = ""
		} else {
			delete(attrs, k)
		}
		if _, err := Hash(kind, attrs); !errors.Is(err, ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
}

func TestIdentityHashUnknownKind(t *testing.T) {
	if _, err := Hash("no_such_kind", map[string]string{"id": "x"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// TestIdentityHashGolden pins IDs so they stay stable across platforms and releases.
func TestIdentityHashGolden(t *testing.T) {
	cases := []struct {
		kind  string
		attrs map[string]string
		want  EntityID
	}{
		{"host", map[string]string{"hostname": "web-1"}, "host:fe1c72acbf340314776943d30489cf82"},
		{"container", map[string]string{"id": "abc123"}, "container:519e9b3282adbda5e91413d99f2c5f3c"},
		{"listening_port", map[string]string{"host": "web-1", "protocol": "tcp", "address": "0.0.0.0", "port": "443"}, "listening_port:96ec1501c61e5d9662f329fe8fccc242"},
	}
	for _, c := range cases {
		got, err := Hash(c.kind, c.attrs)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.kind, got, c.want)
		}
	}
}

// Feature: unified-security-graph, Property 1: Entity_ID depends only on kind and identity attributes
// **Validates: Requirements 2.1, 2.2**
func TestEntityIDDependsOnlyOnKindAndIdentityAttributes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := ihKind().Draw(t, "kind")
		id := ihIdentity(t, kind)
		want, err := Hash(kind, id)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		// Add arbitrary non-identity attributes, including canonical_key.
		extra := map[string]string{"canonical_key": ihValue().Draw(t, "ck")}
		for _, k := range rapid.SliceOfN(rapid.StringN(1, 8, -1), 0, 5).Draw(t, "extraKeys") {
			if _, isID := id[k]; !isID {
				extra[k] = ihValue().Draw(t, "extraVal")
			}
		}
		for k := range id {
			delete(extra, k)
		}
		got, err := Hash(kind, ihShuffledCopy(t, id, extra))
		if err != nil {
			t.Fatalf("Hash with extras: %v", err)
		}
		if got != want {
			t.Fatalf("non-identity attributes changed the ID: %q vs %q", got, want)
		}
		if !strings.HasPrefix(string(got), kind+":") {
			t.Fatalf("ID %q lacks kind prefix %q", got, kind)
		}
	})
}

// TestEntityIDGoldenPreExistingKinds pins one ID per kind registered before
// the unified security graph. Each attribute value is "v-<attribute>".
func TestEntityIDGoldenPreExistingKinds(t *testing.T) {
	golden := map[string]EntityID{
		"aws_account":         "aws_account:de3c2606cd65f90dbf258fb64e2ec7fb",
		"aws_resource":        "aws_resource:15f349dcc31b8b2687803025bb271b85",
		"collector_status":    "collector_status:278a591d79d55ca2f705a3a852d8f611",
		"container":           "container:ad9e69ebd344713e81c87dcc831a53ad",
		"dependency":          "dependency:6bb2a4534f76e10c5e424ff887b296eb",
		"endpoint":            "endpoint:2ef5c2509b34f88968da7d12fe2e6238",
		"github_alert":        "github_alert:4b0923f2318cc49059d39a5c8d2d831f",
		"github_org":          "github_org:5e3c72e8b798b4ba99b9aede03b77296",
		"github_pull_request": "github_pull_request:1216be5fe2bd33d228663b14ee0216ce",
		"github_repo":         "github_repo:e3b5340b237bf56a8819f8c11cf2acd3",
		"github_workflow":     "github_workflow:42d9a6a1f37554f27976de0c501a1212",
		"host":                "host:ace9d4c2039090d09ee97a7e0e87c4fb",
		"iac_resource":        "iac_resource:b277e1cdd87e3f8455339647d88a51eb",
		"image":               "image:d0ea7c9494e38d1704d09125b450d05d",
		"k8s_object":          "k8s_object:beb1fa1f0af8d023063e9841e6b7947e",
		"listening_port":      "listening_port:351a916a68935d250bfaa8e0ce4bcb84",
		"network":             "network:05d5cf072fef438aa5219f871a56e16d",
		"process":             "process:e42fa491f1c6aff0882fd1db376dc705",
		"repository":          "repository:e3da088c4ea3ab729fe82a46d944a655",
		"secret_finding":      "secret_finding:98785eaf54189039e2faeef159af8ca8",
		"secret_ref":          "secret_ref:030ca2424f1384a8d1fdb94b80ca8e6c",
		"volume":              "volume:2eaf78bfc5b0bd75efc05be34b0fb5f1",
		"workflow":            "workflow:c5192837545bc06e387324175d5bafbd",
	}
	for kind, want := range golden {
		keys, ok := IdentityAttributes(kind)
		if !ok {
			t.Errorf("%s: kind no longer registered", kind)
			continue
		}
		attrs := make(map[string]string, len(keys))
		for _, k := range keys {
			attrs[k] = "v-" + k
		}
		got, err := Hash(kind, attrs)
		if err != nil {
			t.Errorf("%s: %v", kind, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %q want %q", kind, got, want)
		}
	}
}
