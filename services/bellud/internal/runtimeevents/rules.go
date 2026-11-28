package runtimeevents

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schema"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

// RulePackVersion tags runtime_threat findings with the bundled rule set.
const RulePackVersion = "bellu-runtime-1"

// Rule is one runtime detection rule of the bellu pack.
type Rule struct {
	ID       string
	Title    string
	Severity findings.Severity
	Match    func(wire.Event) bool
}

var (
	reverseShellRe = regexp.MustCompile(`(?i)(/dev/(tcp|udp)/|\bnc(at)?\b.*\s-[a-z]*e\b|\bbash\s+-i\b|\bsocat\b.*exec:|\bmkfifo\b.*\bnc\b)`)
	minerPoolRe    = regexp.MustCompile(`(?i)(stratum\+(tcp|ssl)://|\bpool\.[a-z0-9.-]*(minexmr|supportxmr|nanopool|2miners)|--donate-level|\bxmrig\b)`)
	dockerSockRe   = regexp.MustCompile(`/var/run/docker\.sock|/run/docker\.sock`)
	minerNames     = map[string]bool{"xmrig": true, "minerd": true, "cpuminer": true, "ethminer": true, "cgminer": true, "bfgminer": true}
	cloudCLIs      = map[string]bool{"kubectl": true, "aws": true, "gcloud": true, "az": true}
	sensitiveFiles = map[string]bool{"/etc/shadow": true, "/etc/passwd": true}
)

func base(e wire.Event) string { return path.Base(e.ProcessPath) }

func isExec(e wire.Event) bool {
	return e.Type == wire.TypeProcessExec || e.Type == wire.TypeShellSpawn
}

// inContainer reports whether the event came from a container.
func inContainer(e wire.Event) bool { return e.ContainerID != "" || e.Pod != "" }

// Rules is the bellu runtime pack.
var Rules = []Rule{
	{"runtime.reverse_shell", "Reverse shell detected", findings.SevCritical, func(e wire.Event) bool {
		return isExec(e) && reverseShellRe.MatchString(e.ProcessPath+" "+e.Args)
	}},
	{"runtime.crypto_miner", "Crypto miner process or pool connection", findings.SevHigh, func(e wire.Event) bool {
		switch e.Type {
		case wire.TypeProcessExec:
			return minerNames[base(e)] || minerPoolRe.MatchString(e.Args)
		case wire.TypeNetworkConnect:
			return minerPoolRe.MatchString(e.Args)
		}
		return false
	}},
	{"runtime.sensitive_file_write", "Write to /etc/shadow or /etc/passwd", findings.SevHigh, func(e wire.Event) bool {
		if e.Type != wire.TypeFileWrite {
			return false
		}
		for _, f := range strings.Fields(e.Args + " " + e.ProcessPath) {
			if sensitiveFiles[path.Clean(f)] {
				return true
			}
		}
		return false
	}},
	{"runtime.docker_socket_mount", "Host Docker socket accessed from container", findings.SevHigh, func(e wire.Event) bool {
		return inContainer(e) && dockerSockRe.MatchString(e.ProcessPath+" "+e.Args)
	}},
	{"runtime.cli_in_container", "kubectl or cloud CLI executed in container", findings.SevMedium, func(e wire.Event) bool {
		return e.Type == wire.TypeProcessExec && inContainer(e) && cloudCLIs[base(e)]
	}},
}

// WorkloadAsset names the workload an event belongs to. Pod events use
// namespace/pod; container-only events use the container id; otherwise the node.
func WorkloadAsset(e wire.Event) string {
	switch {
	case e.Pod != "":
		return "runtime:" + e.Node + "/" + e.Namespace + "/" + e.Pod
	case e.ContainerID != "":
		return "runtime:" + e.Node + "/container/" + e.ContainerID
	}
	return "runtime:" + e.Node
}

// EvaluateEvent returns one runtime_threat finding per matching rule. The
// finding id is (rule, workload), so repeats raise Occurrences in the store.
func EvaluateEvent(ws string, e wire.Event) []findings.Finding {
	var out []findings.Finding
	asset := WorkloadAsset(e)
	for _, r := range Rules {
		if !r.Match(e) {
			continue
		}
		detail, _ := json.Marshal(map[string]string{"event_type": e.Type, "process": e.ProcessPath, "user": e.User})
		out = append(out, findings.Finding{
			ID:              findings.ID(r.ID, asset, ""),
			WorkspaceID:     ws,
			RuleID:          r.ID,
			Title:           r.Title,
			Description:     "Runtime sensor observed " + e.Type + " on " + asset + ".",
			Category:        schema.OvRuntime,
			Type:            findings.TypeRuntimeThreat,
			Severity:        r.Severity,
			AssetID:         asset,
			Evidence:        []findings.EvidenceRef{{Kind: "runtime_event", Ref: asset, Excerpt: truncate(e.ProcessPath+" "+e.Args, 512)}},
			Source:          "runtime",
			RulePackVersion: RulePackVersion,
			Occurrences:     1,
			Details:         detail,
		})
	}
	return out
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// FindingReporter is the part of findings.Store the rules use.
type FindingReporter interface {
	Report(ctx context.Context, scan findings.ScanRef, fs []findings.Finding) (findings.ReportResult, error)
}

// RuleHook returns an OnEvent callback that reports findings for matching events.
func RuleHook(ws string, rep FindingReporter, onErr func(error)) func(wire.Event) {
	return func(e wire.Event) {
		fs := EvaluateEvent(ws, e)
		if len(fs) == 0 {
			return
		}
		if _, err := rep.Report(context.Background(), findings.ScanRef{JobID: "runtime"}, fs); err != nil && onErr != nil {
			onErr(err)
		}
	}
}
