package posture

import (
	"fmt"
	"os"
)

// LoadCustom loads the user's Rule_Packs from dir (posture.custom_dir), which
// uses the same format as the bundled packs. Rules are schema-validated and
// compiled as in LoadAll; only passing rules are activated. Each rejection
// names its source file (<dir>/<pack>/pack.json or the .rego file in Detail).
// A pack whose id equals a bundled pack id, or an earlier custom pack id, is
// rejected whole. A missing or unreadable dir returns an error for the caller
// to log; the bundled packs are unaffected because they load separately.
func LoadCustom(dir string) ([]Pack, []RuleError, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("posture.custom_dir: %w", err)
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("posture.custom_dir %q is not a directory", dir)
	}
	packs, errs, err := LoadAll(os.DirFS(dir))
	if err != nil {
		return nil, nil, fmt.Errorf("posture.custom_dir: %w", err)
	}
	for i := range errs {
		if errs[i].Check == "schema" || errs[i].Check == "compile" {
			errs[i].Detail = fmt.Sprintf("%s/%s/pack.json: %s", dir, errs[i].Pack, errs[i].Detail)
		}
	}
	taken := map[string]bool{}
	if bundled, _, err := LoadAll(Bundled()); err == nil {
		for _, p := range bundled {
			taken[p.ID] = true
		}
	}
	var out []Pack
	for _, p := range packs {
		if taken[p.ID] {
			errs = append(errs, RuleError{Pack: p.ID, Check: "schema",
				Detail: fmt.Sprintf("%s: id: pack id %q is already in use", dir, p.ID)})
			continue
		}
		taken[p.ID] = true
		out = append(out, p)
	}
	return out, errs, nil
}
