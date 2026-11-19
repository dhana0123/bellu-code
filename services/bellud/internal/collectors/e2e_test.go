package collectors_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/codesec"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/docker"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/host"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/iac"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/secrets"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
)

func fakeDockerSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			w.Write([]byte(`[{"Id":"c1"}]`))
		case "/containers/c1/json":
			w.Write([]byte(`{"Id":"c1","Name":"/web","Image":"sha256:img1","State":{"Status":"running"},
"Config":{"Image":"nginx:1","Env":["A=b"]},"HostConfig":{"NetworkMode":"bridge"},
"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"n1"}}},"Mounts":[{"Type":"volume","Name":"v1"}]}`))
		case "/images/json":
			w.Write([]byte(`[{"Id":"sha256:img1","RepoTags":["nginx:1"],"Size":5}]`))
		case "/networks":
			w.Write([]byte(`[{"Id":"n1","Name":"bridge","Driver":"bridge","Scope":"local"}]`))
		case "/volumes":
			w.Write([]byte(`{"Volumes":[{"Name":"v1","Driver":"local"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

// Every collector's real output, run against its own fixture, must be accepted
// by the engine's Apply (valid relation types, endpoints resolvable, only
// the fixed relation attributes) and be recorded with collector_status "ok".
func TestEveryCollectorOutputIsApplied(t *testing.T) {
	iacRoot := t.TempDir()
	os.WriteFile(filepath.Join(iacRoot, "main.tf"), []byte("resource \"aws_s3_bucket\" \"logs\" {\n  acl = \"public-read\"\n}\n"), 0o644)
	os.WriteFile(filepath.Join(iacRoot, "k8s.yaml"), []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: app, namespace: prod}\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: prod}\nspec:\n  template:\n    spec:\n      serviceAccountName: app\n      containers:\n        - name: c\n          image: nginx:1\n"), 0o644)
	secRoot := t.TempDir()
	os.WriteFile(filepath.Join(secRoot, "a.env"), []byte("AWS="+"AKIA"+"ABCDEFGHIJKLMNOP\n"), 0o644)

	cols := []collectors.Collector{
		docker.New(docker.WithSocket(fakeDockerSock(t))),
		codesec.New("codesec/testdata/repo"),
		iac.New(iacRoot),
		secrets.New(secRoot),
	}
	if runtime.GOOS == "linux" {
		cols = append(cols, host.New(time.Second, host.WithProcRoot("host/testdata/proc"), host.WithHostname("h1")))
	}

	eng, err := graph.Open(context.Background(), graph.Config{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "g"),
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close(context.Background()) })

	ctx := context.Background()
	for _, c := range cols {
		b, err := c.Collect(ctx)
		if err != nil {
			t.Fatalf("%s: collect: %v", c.Name(), err)
		}
		if len(b.Entities) == 0 {
			t.Fatalf("%s: fixture produced no entities", c.Name())
		}
		for _, r := range b.Relations {
			for name := range r.Attributes {
				if name != "evidence" && name != "confidence" && name != "observed_at" {
					t.Fatalf("%s: relation %s has attribute %q outside the fixed set", c.Name(), r.Type, name)
				}
			}
		}
		if _, err := eng.Ingest().Apply(ctx, b); err != nil {
			t.Fatalf("%s: apply: %v", c.Name(), err)
		}
	}

	// The same through the runner: every collector reports ok.
	r := collectors.New(eng, cols)
	for _, c := range cols {
		if err := r.RunOnce(ctx, c); err != nil {
			t.Fatalf("%s: RunOnce: %v", c.Name(), err)
		}
	}
}
