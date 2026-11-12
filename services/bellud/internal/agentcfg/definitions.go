package agentcfg

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvConfigDir is the compatibility name of the child config directory variable.
	EnvConfigDir = "OPENCODE_CONFIG_DIR"
	// SkillName is the embedded skill name.
	SkillName = "security-context"
	// AgentName is the embedded agent name.
	AgentName = "security"
	// GeneratedDirName is the generated directory under ~/.config/bellucode.
	GeneratedDirName = "generated"

	skillPath = "defs/skills/security-context/SKILL.md"
	agentPath = "defs/agents/security.md"
)

//go:embed defs
var defsFS embed.FS

// SkillContent returns the embedded skill file.
func SkillContent() string { return mustRead(skillPath) }

// AgentContent returns the embedded agent file.
func AgentContent() string { return mustRead(agentPath) }

func mustRead(p string) string {
	b, err := fs.ReadFile(defsFS, p)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// WriteDefinitions writes the embedded skill and agent under dir
// (skills/security-context/SKILL.md and agents/security.md).
func WriteDefinitions(dir string) error {
	files := map[string]string{
		filepath.Join(dir, "skills", SkillName, "SKILL.md"): SkillContent(),
		filepath.Join(dir, "agents", AgentName+".md"):       AgentContent(),
	}
	for p, content := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// InjectDefinitions merges the security agent into a config object (content/present
// describe it). The skill text is appended to the agent's system prompt because
// the config schema cannot carry skill bodies. An existing agents.security is kept.
func InjectDefinitions(content string, present bool) (string, error) {
	root := map[string]json.RawMessage{}
	if present {
		if err := decodeObject([]byte(content), &root); err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidInbound, err)
		}
	}
	agents := map[string]json.RawMessage{}
	if raw, ok := root["agents"]; ok {
		if err := decodeObject(raw, &agents); err != nil {
			return "", fmt.Errorf("%w: \"agents\" must be an object", ErrInvalidInbound)
		}
	}
	if _, ok := agents[AgentName]; !ok {
		meta, body := splitFrontmatter(AgentContent())
		_, skill := splitFrontmatter(SkillContent())
		entry, err := json.Marshal(map[string]any{
			"description": meta["description"],
			"mode":        meta["mode"],
			"system":      strings.TrimSpace(body) + "\n\n" + strings.TrimSpace(skill) + "\n",
		})
		if err != nil {
			return "", err
		}
		agents[AgentName] = entry
	}
	var err error
	if root["agents"], err = json.Marshal(agents); err != nil {
		return "", err
	}
	out, err := json.Marshal(root)
	return string(out), err
}

// splitFrontmatter parses simple "key: value" frontmatter and returns the body.
func splitFrontmatter(s string) (map[string]string, string) {
	meta := map[string]string{}
	rest, ok := strings.CutPrefix(s, "---\n")
	if !ok {
		return meta, s
	}
	head, body, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return meta, s
	}
	for _, line := range strings.Split(head, "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok {
			meta[k] = strings.TrimSpace(v)
		}
	}
	return meta, body
}

// Plan is how the definitions reach the child.
type Plan struct {
	// ConfigDir is set as OPENCODE_CONFIG_DIR when non-empty.
	ConfigDir string
	// Inject means the definitions must go through OPENCODE_CONFIG_CONTENT.
	Inject bool
	// Warn is a non-fatal write failure to log.
	Warn error
}

// PlanDefinitions decides delivery. With a user config dir the dir is left untouched and
// definitions are injected. Otherwise they are written to genDir; a write failure
// falls back to injection with a warning.
func PlanDefinitions(userDirSet bool, genDir string) Plan {
	if userDirSet {
		return Plan{Inject: true}
	}
	if err := WriteDefinitions(genDir); err != nil {
		return Plan{Inject: true, Warn: errors.Join(errors.New("write generated config dir"), err)}
	}
	return Plan{ConfigDir: genDir}
}
