package schema

import (
	"slices"
	"strings"
)

// RoadmapMarkdown renders one table row per category with its status and the
// read operations a future collector needs. The output is deterministic.
func RoadmapMarkdown(r *Registry) string {
	var b strings.Builder
	b.WriteString("| Category | Status | Read operations a collector needs |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, c := range r.Categories() {
		ops := slices.Clone(c.ReadOps)
		slices.Sort(ops)
		cell := "none"
		if len(ops) > 0 {
			cell = "`" + strings.Join(ops, "`, `") + "`"
		}
		b.WriteString("| `" + c.ID + "` | " + string(c.Status) + " | " + cell + " |\n")
	}
	return b.String()
}
