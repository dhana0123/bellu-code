package schema

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// expected is one failure a defect must produce: the rule, the name, and the
// sources involved (one for a single-source defect, two for a conflict).
type expected struct {
	rule, name string
	srcs       []Source
}

// defect injects one defect class into ds and returns the failure it must
// cause. It only adds new names, so defects never disturb each other.
type defect struct {
	label  string
	inject func(t *rapid.T, ds []SourceDeclaration, required map[Source]Requirement) expected
}

func pickSource(t *rapid.T, ds []SourceDeclaration) int {
	return rapid.IntRange(0, len(ds)-1).Draw(t, "target")
}

// nonCore returns the index of a source that has a prefix. Every generated
// set has at least two distinct sources, so one exists.
func nonCore(ds []SourceDeclaration) int {
	return slices.IndexFunc(ds, func(d SourceDeclaration) bool { return d.Source != SourceCore })
}

func addKind(ds []SourceDeclaration, i int, k KindDeclaration) {
	ds[i].Kinds = append(ds[i].Kinds, k)
}

func goodKind(name string) KindDeclaration {
	return KindDeclaration{Name: name, Identity: []string{"arn"}, Description: "A kind."}
}

func kindDefect(label, rule string, mutate func(k *KindDeclaration, p string)) defect {
	return defect{label, func(t *rapid.T, ds []SourceDeclaration, _ map[Source]Requirement) expected {
		i := pickSource(t, ds)
		p := ds[i].Prefix
		k := goodKind(p + "d_" + label)
		mutate(&k, p)
		addKind(ds, i, k)
		return expected{rule, k.Name, []Source{ds[i].Source}}
	}}
}

// pairDefect declares the same name in two sources, mutated by f.
func pairDefect(label, rule, name string, f func(a, b *SourceDeclaration)) defect {
	return defect{label, func(t *rapid.T, ds []SourceDeclaration, _ map[Source]Requirement) expected {
		f(&ds[0], &ds[1])
		return expected{rule, name, []Source{ds[0].Source, ds[1].Source}}
	}}
}

func relation(name string, dir Direction, conf Confidence) RelationDeclaration {
	return RelationDeclaration{Name: name, Direction: dir, Confidence: conf, Description: "A relation."}
}

var defects = []defect{
	kindDefect("bad name", "name-pattern", func(k *KindDeclaration, p string) { k.Name = p + "Bad-Name" }),
	kindDefect("long name", "name-pattern", func(k *KindDeclaration, p string) { k.Name = p + strings.Repeat("a", 65) }),
	kindDefect("empty identity", "identity-empty", func(k *KindDeclaration, _ string) { k.Identity = []string{"arn", ""} }),
	kindDefect("duplicate identity", "identity-duplicate", func(k *KindDeclaration, _ string) { k.Identity = []string{"arn", "arn"} }),
	kindDefect("secret identity", "attribute-secret", func(k *KindDeclaration, _ string) { k.Identity = []string{"api_token"} }),
	kindDefect("blank description", "description-blank", func(k *KindDeclaration, _ string) { k.Description = " \t " }),
	kindDefect("long description", "description-length", func(k *KindDeclaration, _ string) { k.Description = strings.Repeat("d", 501) }),
	{"invalid confidence", func(t *rapid.T, ds []SourceDeclaration, _ map[Source]Requirement) expected {
		i := pickSource(t, ds)
		r := relation(ds[i].Prefix+"d_conf", Forward, "maybe")
		ds[i].Relations = append(ds[i].Relations, r)
		return expected{"confidence", r.Name, []Source{ds[i].Source}}
	}},
	{"duplicate name in one source", func(t *rapid.T, ds []SourceDeclaration, _ map[Source]Requirement) expected {
		i := pickSource(t, ds)
		k := goodKind(ds[i].Prefix + "d_dup")
		addKind(ds, i, k)
		addKind(ds, i, k)
		return expected{"duplicate-name", k.Name, []Source{ds[i].Source}}
	}},
	pairDefect("direction conflict", "direction-conflict", "depends_on", func(a, b *SourceDeclaration) {
		a.Relations = append(a.Relations, relation("depends_on", Forward, Extracted))
		b.Relations = append(b.Relations, relation("depends_on", Reverse, Extracted))
	}),
	pairDefect("identity list conflict", "identity-conflict", "package", func(a, b *SourceDeclaration) {
		a.Kinds = append(a.Kinds, KindDeclaration{Name: "package", Identity: []string{"name", "version"}, Description: "A package."})
		// Same attributes in another order is still a conflict.
		b.Kinds = append(b.Kinds, KindDeclaration{Name: "package", Identity: []string{"version", "name"}, Description: "A package."})
	}),
	pairDefect("generic confidence conflict", "confidence-conflict", "found_in", func(a, b *SourceDeclaration) {
		a.Relations = append(a.Relations, relation("found_in", Forward, Extracted))
		b.Relations = append(b.Relations, relation("found_in", Forward, Inferred))
	}),
	{"missing prefix", func(t *rapid.T, ds []SourceDeclaration, _ map[Source]Requirement) expected {
		i := nonCore(ds)
		k := goodKind("noprefix_kind")
		addKind(ds, i, k)
		return expected{"prefix", k.Name, []Source{ds[i].Source}}
	}},
	{"missing required", func(t *rapid.T, ds []SourceDeclaration, required map[Source]Requirement) expected {
		i := pickSource(t, ds)
		name := ds[i].Prefix + "d_required"
		required[ds[i].Source] = Requirement{Kinds: []string{name}}
		return expected{"missing-required", name, []Source{ds[i].Source}}
	}},
}

func (e expected) matches(f Failure) bool {
	if f.Name != e.name || f.Rule != e.rule {
		return false
	}
	if len(e.srcs) == 1 {
		return f.Source == e.srcs[0] && f.Other == ""
	}
	return slices.Contains(e.srcs, f.Source) && slices.Contains(e.srcs, f.Other) && f.Source != f.Other
}

// checkRejected injects the chosen defects and asserts rejection, a failure
// for every defect, and the same error text for every ordering.
func checkRejected(t *rapid.T, chosen []int) {
	ds := genValidDecls().Draw(t, "decls")
	required := map[Source]Requirement{}
	var want []expected
	var labels []string
	for _, i := range chosen {
		want = append(want, defects[i].inject(t, ds, required))
		labels = append(labels, defects[i].label)
	}

	_, err := MergeRequired(required, ds...)
	if err == nil {
		t.Fatalf("defects %v accepted", labels)
	}
	var ce *CheckError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CheckError, got %v", err)
	}
	fs := ce.Failures
	text := err.Error()
	for i, e := range want {
		if !slices.ContainsFunc(fs, e.matches) {
			t.Fatalf("no failure for defect %q (want %+v):\n%s", labels[i], e, text)
		}
		if !strings.Contains(text, strconv.Quote(e.name)) || !strings.Contains(text, e.rule) {
			t.Fatalf("error text lacks name or rule of defect %q:\n%s", labels[i], text)
		}
		for _, s := range e.srcs {
			if !strings.Contains(text, string(s)) {
				t.Fatalf("error text lacks source %q of defect %q:\n%s", s, labels[i], text)
			}
		}
	}

	for _, order := range [][]SourceDeclaration{reversed(ds), rapid.Permutation(ds).Draw(t, "order")} {
		_, err2 := MergeRequired(required, order...)
		if err2 == nil || err2.Error() != text {
			t.Fatalf("error text differs for ordering %v:\n%v\n---\n%s", sourcesOf(order), err2, text)
		}
	}
}

// Feature: aws-relationship-registry, Property 2: Invalid declarations are rejected with every failure reported
//
// **Validates: Requirements 1.8, 2.1, 2.2, 2.3, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 16.1**
func TestInvalidDeclarationsRejectedWithEveryFailureProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		chosen := rapid.SliceOfNDistinct(rapid.IntRange(0, len(defects)-1), 1, len(defects), func(i int) int { return i }).Draw(t, "defects")
		checkRejected(t, chosen)
	})
}

// Every defect class is also exercised alone, so none depends on the random
// subset happening to include it.
func TestEachDefectClassRejectedProperty(t *testing.T) {
	for i, d := range defects {
		t.Run(d.label, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) { checkRejected(t, []int{i}) })
		})
	}
}
