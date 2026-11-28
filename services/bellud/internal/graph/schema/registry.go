package schema

import (
	"errors"
	"slices"
	"sort"
)

// ErrImmutable is returned by Registry.Register.
var ErrImmutable = errors.New("schema: registry is immutable")

// Registry is the merged, read-only result of the source declarations. Every
// accessor returns copies, so a caller cannot change the registry.
type Registry struct {
	kinds      []KindDeclaration
	relations  []RelationDeclaration
	categories []CategoryDeclaration

	kindIdx    map[string]int
	relIdx     map[string]int
	catIdx     map[string]int
	typeCat    map[string]string
	typeOv     map[string]OverviewCategory
	kindSource map[string]Source
	relSource  map[string]Source
}

// newRegistry builds a Registry from declarations that already passed the
// check and are sorted by source.
func newRegistry(ds []SourceDeclaration) *Registry {
	r := &Registry{
		kindIdx:    map[string]int{},
		relIdx:     map[string]int{},
		catIdx:     map[string]int{},
		typeCat:    map[string]string{},
		typeOv:     map[string]OverviewCategory{},
		kindSource: map[string]Source{},
		relSource:  map[string]Source{},
	}
	for _, d := range ds {
		for _, k := range d.Kinds {
			r.kinds = append(r.kinds, cloneKind(k))
			r.kindSource[k.Name] = d.Source
			for _, t := range k.Types {
				r.typeCat[t.Name] = t.Category
				if t.Overview != "" {
					r.typeOv[k.Name+"\x00"+t.Name] = t.Overview
				}
			}
		}
		for _, rel := range d.Relations {
			if _, dup := r.relSource[rel.Name]; dup {
				continue // identical Generic_Relation from a later source
			}
			r.relations = append(r.relations, cloneRelation(rel))
			r.relSource[rel.Name] = d.Source
		}
		for _, c := range d.Categories {
			r.categories = append(r.categories, cloneCategory(c))
		}
	}
	sort.Slice(r.kinds, func(i, j int) bool { return r.kinds[i].Name < r.kinds[j].Name })
	sort.Slice(r.relations, func(i, j int) bool { return r.relations[i].Name < r.relations[j].Name })
	sort.Slice(r.categories, func(i, j int) bool { return r.categories[i].ID < r.categories[j].ID })
	for i, k := range r.kinds {
		r.kindIdx[k.Name] = i
	}
	for i, rel := range r.relations {
		r.relIdx[rel.Name] = i
	}
	for i, c := range r.categories {
		r.catIdx[c.ID] = i
	}
	return r
}

// Register always fails: the registry cannot change after Build.
func (r *Registry) Register(SourceDeclaration) error { return ErrImmutable }

// Kinds returns every kind sorted by name.
func (r *Registry) Kinds() []KindDeclaration {
	out := make([]KindDeclaration, len(r.kinds))
	for i, k := range r.kinds {
		out[i] = cloneKind(k)
	}
	return out
}

// Kind returns one kind by name.
func (r *Registry) Kind(name string) (KindDeclaration, bool) {
	i, ok := r.kindIdx[name]
	if !ok {
		return KindDeclaration{}, false
	}
	return cloneKind(r.kinds[i]), true
}

// Relations returns every relation type sorted by name.
func (r *Registry) Relations() []RelationDeclaration {
	out := make([]RelationDeclaration, len(r.relations))
	for i, rel := range r.relations {
		out[i] = cloneRelation(rel)
	}
	return out
}

// Relation returns one relation type by name.
func (r *Registry) Relation(name string) (RelationDeclaration, bool) {
	i, ok := r.relIdx[name]
	if !ok {
		return RelationDeclaration{}, false
	}
	return cloneRelation(r.relations[i]), true
}

// Categories returns every category sorted by ID.
func (r *Registry) Categories() []CategoryDeclaration {
	out := make([]CategoryDeclaration, len(r.categories))
	for i, c := range r.categories {
		out[i] = cloneCategory(c)
	}
	return out
}

// Category returns one category by ID.
func (r *Registry) Category(id string) (CategoryDeclaration, bool) {
	i, ok := r.catIdx[id]
	if !ok {
		return CategoryDeclaration{}, false
	}
	return cloneCategory(r.categories[i]), true
}

// CategoryOfType returns the category ID of a declared type name.
func (r *Registry) CategoryOfType(typeName string) (string, bool) {
	c, ok := r.typeCat[typeName]
	return c, ok
}

// OverviewOf returns the Overview category of an entity: the type override
// when typeValue names a declared type of the kind with one, else the kind's
// default. It returns "" only for an unregistered kind.
func (r *Registry) OverviewOf(kind, typeValue string) OverviewCategory {
	i, ok := r.kindIdx[kind]
	if !ok {
		return ""
	}
	if ov, ok := r.typeOv[kind+"\x00"+typeValue]; ok {
		return ov
	}
	return r.kinds[i].Overview
}

// SourceOfKind returns the source that owns a kind.
func (r *Registry) SourceOfKind(name string) (Source, bool) {
	s, ok := r.kindSource[name]
	return s, ok
}

// SourceOfRelation returns the source that owns a relation type. A
// Generic_Relation declared identically by several sources reports the first
// in source-name order.
func (r *Registry) SourceOfRelation(name string) (Source, bool) {
	s, ok := r.relSource[name]
	return s, ok
}

// RegisteredOnly returns the ids, sorted and without duplicates, whose
// category is registered-only or not declared.
func (r *Registry) RegisteredOnly(ids []string) []string {
	out := []string{}
	for _, id := range ids {
		if c, ok := r.Category(id); ok && c.Status == Implemented {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func cloneKind(k KindDeclaration) KindDeclaration {
	k.Identity = slices.Clone(k.Identity)
	k.Types = slices.Clone(k.Types)
	return k
}

func cloneRelation(r RelationDeclaration) RelationDeclaration {
	r.From = slices.Clone(r.From)
	r.To = slices.Clone(r.To)
	return r
}

func cloneCategory(c CategoryDeclaration) CategoryDeclaration {
	c.ReadOps = slices.Clone(c.ReadOps)
	return c
}
