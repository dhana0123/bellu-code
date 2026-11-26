package bom

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/bom/data"
)

// EOLRule is the rule id of the end-of-life version finding.
const EOLRule = "bellu-eol-version"

// eolRecentDays is the window in which an EOL component is only medium.
const eolRecentDays = 180

type eolCycle struct {
	Cycle string `json:"cycle"`
	EOL   string `json:"eol"`
}

type eolFile struct {
	Products        map[string][]eolCycle `json:"products"`
	AIUnsafeFormats []string              `json:"ai_unsafe_formats"`
}

func loadEOL(raw []byte) (eolFile, error) {
	var f eolFile
	err := json.Unmarshal(raw, &f)
	return f, err
}

// LicenseDenied builds the AIOptions.LicenseDenied func from the
// bom.license_deny config list. Matching is case-insensitive.
func LicenseDenied(deny []string) func(string) bool {
	set := map[string]bool{}
	for _, d := range deny {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			set[d] = true
		}
	}
	return func(l string) bool { return set[strings.ToLower(strings.TrimSpace(l))] }
}

// EOLCheck returns the CloudCheck for the built-in EOL table.
func EOLCheck() (CloudCheck, error) { return NewEOLCheck(data.EOL) }

// NewEOLCheck returns a CloudCheck for the given EOL table JSON. A component
// whose EOL date has passed yields one finding: medium when EOL was at most
// 180 days ago, otherwise high. The id derives from component and version.
func NewEOLCheck(raw []byte) (CloudCheck, error) {
	f, err := loadEOL(raw)
	if err != nil {
		return nil, fmt.Errorf("eol table: %w", err)
	}
	return func(p Package, now time.Time) []Finding {
		if p.Version == nil {
			return nil
		}
		name, version := strings.ToLower(p.Name), *p.Version
		best := -1
		var eol time.Time
		for _, c := range f.Products[name] {
			if version != c.Cycle && !strings.HasPrefix(version, c.Cycle+".") {
				continue
			}
			t, err := time.Parse("2006-01-02", c.EOL)
			if err != nil || len(c.Cycle) <= best {
				continue
			}
			best, eol = len(c.Cycle), t
		}
		if best < 0 || !now.After(eol) {
			return nil
		}
		sev := "high"
		if now.Sub(eol) <= eolRecentDays*24*time.Hour {
			sev = "medium"
		}
		sum := sha256.Sum256([]byte(EOLRule + "\x00" + name + "\x00" + version))
		return []Finding{{
			ID: EOLRule + "-" + hex.EncodeToString(sum[:8]), Rule: EOLRule, Severity: sev,
			Component: p.Name, Version: version,
			Message: fmt.Sprintf("%s %s reached end of life on %s", p.Name, version, eol.Format("2006-01-02")),
		}}
	}, nil
}

// PostureData returns the values for the posture engine Data function
// (input.data.ai_unsafe_formats).
func PostureData() map[string]any {
	f, _ := loadEOL(data.EOL)
	formats := make([]any, len(f.AIUnsafeFormats))
	for i, s := range f.AIUnsafeFormats {
		formats[i] = s
	}
	return map[string]any{"ai_unsafe_formats": formats}
}
