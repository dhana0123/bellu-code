package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// rapid runs 100 checks per property by default; do not lower it with
// -rapid.checks.

var (
	hostGen   = rapid.StringMatching(`[a-z0-9]{1,12}\.example\.com`)
	kindGen   = rapid.StringMatching(`[a-z][a-z0-9_]{0,30}`)
	nameGen   = rapid.StringMatching(`[A-Za-zé0-9]{1,64}`)
	idGen     = rapid.StringMatching(`[a-z0-9-]{1,64}`)
	semverGen = rapid.Custom(func(t *rapid.T) string {
		s := fmt.Sprintf("%d.%d.%d", rapid.IntRange(0, 99).Draw(t, "major"), rapid.IntRange(0, 99).Draw(t, "minor"), rapid.IntRange(0, 99).Draw(t, "patch"))
		if rapid.Bool().Draw(t, "pre") {
			s += "-" + rapid.StringMatching(`[a-z]{1,5}(\.(0|[1-9][0-9]{0,2}))?`).Draw(t, "prerelease")
		}
		return s
	})
)

// readOpGen draws an operation that is classified as a read.
func readOpGen() *rapid.Generator[Operation] {
	return rapid.Custom(func(t *rapid.T) Operation {
		op := Operation{Class: ClassRead, Host: hostGen.Draw(t, "host")}
		switch rapid.IntRange(0, 2).Draw(t, "shape") {
		case 0:
			op.Method = rapid.SampledFrom([]string{"GET", "HEAD", "OPTIONS"}).Draw(t, "method")
			op.Path = "/" + rapid.StringMatching(`[a-z{}/]{0,20}`).Draw(t, "path")
			op.Name = op.Method + " " + op.Path
		case 1:
			op.Method = "POST"
			op.Query = true
			op.Path = "/graphql"
			op.Name = "POST /graphql"
		default:
			verb := rapid.SampledFrom(awsReadVerbs).Draw(t, "verb")
			op.Name = rapid.StringMatching(`[a-z0-9]{1,8}`).Draw(t, "svc") + ":" + verb + rapid.StringMatching(`([A-Z][a-z]{1,8}){0,3}`).Draw(t, "rest")
		}
		if rapid.Bool().Draw(t, "strip") {
			op.StripKeys = rapid.SliceOfN(rapid.StringMatching(`[a-z]{1,10}`), 1, 5).Draw(t, "strip_keys")
		}
		op.MaxBytes = rapid.IntRange(0, 1<<20).Draw(t, "max_bytes")
		return op
	})
}

// writeOpGen draws an operation that IsWrite classifies as a write, with
// class read so Validate must reject it.
func writeOpGen() *rapid.Generator[Operation] {
	return rapid.Custom(func(t *rapid.T) Operation {
		op := Operation{Class: ClassRead, Host: hostGen.Draw(t, "host")}
		if rapid.Bool().Draw(t, "aws") {
			verb := rapid.SampledFrom([]string{"Run", "Put", "Delete", "Create", "Terminate", "Assume", "Update"}).Draw(t, "verb")
			op.Name = "ec2:" + verb + rapid.StringMatching(`[A-Z][a-z]{1,8}`).Draw(t, "rest")
			return op
		}
		op.Method = rapid.SampledFrom([]string{"POST", "PUT", "PATCH", "DELETE"}).Draw(t, "method")
		op.Name = op.Method + " /x"
		return op
	})
}

func authOpGen() *rapid.Generator[Operation] {
	return rapid.Custom(func(t *rapid.T) Operation {
		return Operation{Name: "sts:AssumeRole", Class: ClassAuth, Host: hostGen.Draw(t, "host")}
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// manifestGen draws a valid manifest. Empty lists are non-nil so they compare
// equal after a JSON round trip.
func manifestGen() *rapid.Generator[Manifest] {
	return rapid.Custom(func(t *rapid.T) Manifest {
		auth := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) AuthMethod {
			a := AuthMethod{ID: idGen.Draw(t, "aid"), Name: nameGen.Draw(t, "aname"), Enabled: rapid.Bool().Draw(t, "enabled")}
			if !a.Enabled {
				a.DisabledReason = nameGen.Draw(t, "reason")
			}
			return a
		}), MinAuthMethods, MaxAuthMethods).Draw(t, "auth")
		perms := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Permission {
			return Permission{Name: nameGen.Draw(t, "pname"), Description: rapid.StringMatching(`[a-z ]{0,40}`).Draw(t, "pdesc"), ReadOnly: true}
		}), 0, MaxPermissions).Draw(t, "perms")
		ops := rapid.SliceOfN(rapid.OneOf(readOpGen(), authOpGen()), 0, MaxOperations).Draw(t, "ops")
		return Manifest{
			ID:          idGen.Draw(t, "id"),
			Version:     semverGen.Draw(t, "version"),
			Name:        nameGen.Draw(t, "name"),
			Icon:        rapid.StringMatching(`[a-z]{0,16}`).Draw(t, "icon"),
			AuthMethods: auth,
			Permissions: nonNil(perms),
			Operations:  nonNil(ops),
			Egress:      nonNil(rapid.SliceOfN(hostGen, 0, MaxEgress).Draw(t, "egress")),
			Entities:    rapid.SliceOfN(kindGen, MinEntities, MaxEntities).Draw(t, "entities"),
		}
	})
}

func hasField(errs []FieldError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}

// Feature: cloud-connectors, Property 8: Manifest validation
// Validates: Requirements 5.8, 8.2, 8.3, 8.14
//
// Every in-bounds manifest is accepted by Validate and by the published JSON
// Schema. Duplicate-id rejection is a registry concern (task 2.5).
func TestPropertyManifestValidationAccepts(t *testing.T) {
	rs := resolved(t)
	rapid.Check(t, func(t *rapid.T) {
		m := manifestGen().Draw(t, "manifest")
		if errs := Validate(m); len(errs) != 0 {
			t.Fatalf("in-bounds manifest rejected: %v", errs)
		}
		data, err := Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var inst any
		if err := json.Unmarshal(data, &inst); err != nil {
			t.Fatal(err)
		}
		if err := rs.Validate(inst); err != nil {
			t.Fatalf("schema rejected in-bounds manifest: %v", err)
		}
	})
}

// Feature: cloud-connectors, Property 8: Manifest validation
// Validates: Requirements 5.8, 8.2, 8.3, 8.14
//
// Any single out-of-bounds field is rejected, the error names that field and
// never echoes the offending value.
func TestPropertyManifestValidationRejectsOutOfBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := manifestGen().Draw(t, "manifest")
		const marker = "SECRETMARK"
		var field string
		switch rapid.IntRange(0, 11).Draw(t, "mutation") {
		case 0:
			m.ID = marker + rapid.StringMatching(`[a-z0-9]{0,5}`).Draw(t, "bad id") // uppercase
			field = "id"
		case 1:
			m.ID = rapid.StringMatching(`[a-z0-9]{65,80}`).Draw(t, "long id")
			field = "id"
		case 2:
			m.Version = marker + rapid.SampledFrom([]string{"", "1", "1.0", "v1.0.0", "01.0.0"}).Draw(t, "bad version")
			field = "version"
		case 3:
			m.Name = rapid.SampledFrom([]string{"", "   "}).Draw(t, "blank name")
			field = "name"
		case 4:
			m.AuthMethods = nonNil(m.AuthMethods[:0])
			field = "auth_methods"
		case 5:
			m.AuthMethods = make([]AuthMethod, rapid.IntRange(MaxAuthMethods+1, 12).Draw(t, "auth count"))
			field = "auth_methods"
		case 6:
			m.Permissions = make([]Permission, rapid.IntRange(MaxPermissions+1, 80).Draw(t, "perm count"))
			field = "permissions"
		case 7:
			m.Operations = make([]Operation, rapid.IntRange(MaxOperations+1, 260).Draw(t, "op count"))
			field = "operations"
		case 8:
			m.Egress = make([]string, rapid.IntRange(MaxEgress+1, 80).Draw(t, "egress count"))
			field = "egress"
		case 9:
			m.Entities = make([]string, rapid.SampledFrom([]int{0, MaxEntities + 1, MaxEntities + 20}).Draw(t, "entity count"))
			field = "entities"
		case 10:
			w := writeOpGen().Draw(t, "write op")
			i := rapid.IntRange(0, len(m.Operations)).Draw(t, "index")
			m.Operations = append(append(append([]Operation{}, m.Operations[:i]...), w), m.Operations[i:]...)
			if len(m.Operations) > MaxOperations {
				t.Skip("operation bound reached")
			}
			field = fmt.Sprintf("operations[%d].class", i)
		default:
			m.Entities[0] = marker
			field = "entities[0]"
		}
		errs := Validate(m)
		if !hasField(errs, field) {
			t.Fatalf("want field %q in %v", field, fields(errs))
		}
		for _, e := range errs {
			if strings.Contains(e.Error(), marker) {
				t.Fatalf("offending value echoed: %v", e)
			}
		}
	})
}

// Feature: cloud-connectors, Property 9: Manifest and state serialization round trip
// Validates: Requirements 9.2 (manifest part), 8.2
func TestPropertyManifestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := manifestGen().Draw(t, "manifest")
		data, err := Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("round trip changed the manifest:\n%+v\n%+v", got, m)
		}
		again, err := Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, data) {
			t.Fatal("serialization is not stable")
		}
		if errs := Validate(got); len(errs) != 0 {
			t.Fatalf("parsed manifest no longer valid: %v", errs)
		}
	})
}
