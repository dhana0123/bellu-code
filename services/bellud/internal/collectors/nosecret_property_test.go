package collectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bellucode/services/bellud/internal/collectors/codesec"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/iac"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/secrets"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

const (
	nsUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nsAlnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nsURL   = nsAlnum + "_-"
)

// nsSecret is a generated secret. full is what appears in files; body is the
// random part whose 9+ char windows must never reach disk. Fixed prefixes
// (e.g. "Bearer ", "AKIA") are excluded from windows to avoid benign matches.
type nsSecret struct{ rule, full, body string }

func nsStr(t *rapid.T, alphabet string, lo, hi int, label string) string {
	return rapid.StringOfN(rapid.SampledFrom([]rune(alphabet)), lo, hi, -1).Draw(t, label)
}

func nsDraw(t *rapid.T) []nsSecret {
	aws := nsStr(t, nsUpper, 16, 16, "aws")
	gh := nsStr(t, nsAlnum, 36, 40, "gh")
	slack := nsStr(t, nsAlnum+"-", 20, 30, "slack")
	goog := nsStr(t, nsURL, 35, 35, "goog")
	bearer := nsStr(t, nsAlnum, 24, 40, "bearer")
	pw := nsStr(t, nsAlnum, 20, 32, "pw")
	pkWord := rapid.SampledFrom([]string{"RSA", "EC", "OPENSSH", "DSA", ""}).Draw(t, "pk")
	pk := "-----BEGIN " + pkWord + " PRIVATE KEY-----"
	pk = strings.Replace(pk, "  ", " ", 1)
	return []nsSecret{
		{"aws", "AKIA" + aws, aws},
		{"github", "ghp_" + gh, gh},
		{"slack", "xoxb-" + slack, slack},
		{"google", "AIza" + goog, goog},
		{"bearer", "Bearer " + bearer, bearer},
		{"password", pw, pw},
		{"pkheader", pk, ""}, // fixed text: only the whole header is checked
	}
}

// nsSpy records which collectors reached the engine.
type nsSpy struct {
	graph.Engine
	applied []string
	batches []graph.Batch
}

func (s *nsSpy) Ingest() graph.Ingest { return nsIngest{s} }

type nsIngest struct{ s *nsSpy }

func (i nsIngest) Apply(ctx context.Context, b graph.Batch) (graph.Receipt, error) {
	i.s.applied = append(i.s.applied, b.Collector)
	i.s.batches = append(i.s.batches, b)
	return i.s.Engine.Ingest().Apply(ctx, b)
}

func nsWrite(t *rapid.T, p, content string) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func nsFixture(t *rapid.T, root string, s []nsSecret) {
	var lines []string
	for _, x := range s {
		lines = append(lines, "token_line: "+x.full)
	}
	lines = append(lines, "password = "+s[5].full, `password: "`+s[5].full+`"`)
	nsWrite(t, filepath.Join(root, "notes", "creds.txt"), strings.Join(lines, "\n")+"\n")
	nsWrite(t, filepath.Join(root, "src", "config.env"), "API_KEY="+s[0].full+"\nSECRET="+s[1].full+"\n")

	// codesec: package.json fields and workflow env values.
	nsWrite(t, filepath.Join(root, "package.json"), fmt.Sprintf(
		`{"name":"x","version":"%s","dependencies":{"%s":"%s","left-%s":"^1.0.0"},"devDependencies":{"dev":"%s","%s":"%s"}}`,
		s[6].full, s[1].full, s[4].full, s[0].full, s[4].full, s[2].full, s[3].full))
	nsWrite(t, filepath.Join(root, ".github", "workflows", "ci.yml"), fmt.Sprintf(`name: ci
on: push
env:
  GLOBAL: %s
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: %s
      AUTH: %s
      SL: %s
      GK: %s
    steps:
      - uses: actions/checkout@v4
      - run: echo %s
        env:
          KEY: %s
`, s[1].full, s[0].full, s[2].full, s[3].full, s[4].full, s[1].full, s[0].full))

	// iac: k8s env values and terraform literals.
	nsWrite(t, filepath.Join(root, "k8s", "deploy.yaml"), fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
  annotations:
    note: %s
spec:
  template:
    spec:
      containers:
        - name: app
          image: img:1
          env:
            - name: DB_PASSWORD
              value: %s
            - name: OTHER
              value: %s
            - name: PK
              value: "%s"
            - name: SL
              value: %s
            - name: GK
              value: %s
---
apiVersion: v1
kind: Secret
metadata:
  name: sec
  namespace: default
stringData:
  key: %s
data:
  k: %s
`, s[4].full, s[5].full, s[0].full, s[6].full, s[2].full, s[3].full, s[1].full, s[0].full))
	nsWrite(t, filepath.Join(root, "infra", "main.tf"), fmt.Sprintf(`resource "aws_db_instance" "db" {
  password = "%s"
  acl = "%s"
  source = "%s"
  version = "%s"
  access_key = "%s"
  slack = "%s"
  gkey = "%s"
}
`, s[5].full, s[1].full, s[4].full, s[6].full, s[0].full, s[2].full, s[3].full))
}

func nsReadAll(t *rapid.T, dir string) map[string][]byte {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[p] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Feature: go-server-bellu-graph, Property 4: No secret bytes in stored events
// **Validates: Requirements 14.13, 15.6, 15.7, 15.8**
func TestNoSecretBytesInStoredEvents(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		secs := nsDraw(rt)
		base, err := os.MkdirTemp("", "nosecret")
		if err != nil {
			rt.Fatal(err)
		}
		defer os.RemoveAll(base)
		repo := filepath.Join(base, "repo")
		nsFixture(rt, repo, secs)

		dir := filepath.Join(base, "g")
		eng, err := graph.Open(context.Background(), graph.Config{
			Enabled: true, Dir: dir,
			Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		})
		if err != nil {
			rt.Fatal(err)
		}
		spy := &nsSpy{Engine: eng}
		r := New(spy, nil, WithGuard(redact.New()))
		cols := []Collector{secrets.New(repo), codesec.New(repo), iac.New(repo)}
		leaked := map[string]bool{}
		for _, c := range cols {
			err := r.RunOnce(context.Background(), c)
			if errors.Is(err, redact.ErrSecretLeak) {
				leaked[c.Name()] = true
			} else if err != nil {
				rt.Fatalf("collector %s: %v", c.Name(), err)
			}
		}
		if err := eng.Close(context.Background()); err != nil {
			rt.Fatal(err)
		}

		// Batches dropped as leaks must never have reached Apply.
		for i, name := range spy.applied {
			if leaked[name] {
				rt.Fatalf("collector %s was dropped as a leak but Apply received batch %d", name, i)
			}
		}

		files := nsReadAll(rt, dir)
		if len(files) == 0 {
			rt.Fatal("engine wrote no files")
		}
		for p, data := range files {
			for _, s := range secs {
				if bytes.Contains(data, []byte(s.full)) {
					rt.Fatalf("%s secret %q found in %s", s.rule, s.full, p)
				}
				for i := 0; i+9 <= len(s.body); i++ {
					if bytes.Contains(data, []byte(s.body[i:i+9])) {
						rt.Fatalf("%s secret substring %q (of %q) found in %s", s.rule, s.body[i:i+9], s.full, p)
					}
				}
			}
		}
	})
}
