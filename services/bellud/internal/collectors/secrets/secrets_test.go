package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/redact"
)

// Fake secrets assembled at runtime so this file holds no scannable literals.
var (
	awsKey = "AKIA" + "ABCDEFGHIJKLMNOP"
	ghTok  = "ghp_" + strings.Repeat("aB3dE5gH7k", 4)
	slack  = "xoxb-" + "1234567890-abcdefghij"
	pw     = "Zx9qLm2Vb7Rt5Yw1"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollect(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.env", "x=1\nAWS="+awsKey+"\npassword = \""+pw+"\"\n")
	write(t, root, "src/b.txt", "token "+ghTok+" and "+slack+"\n")
	write(t, root, "node_modules/x.txt", awsKey)
	write(t, root, ".git/c", awsKey)
	write(t, root, "dist/d", awsKey)
	write(t, root, "testdata/e", awsKey)
	write(t, root, "bin.dat", "\x00\x01"+awsKey)
	write(t, root, "big.txt", strings.Repeat("a", MaxFileSize)+awsKey)
	write(t, root, "low.txt", "password=aaaaaaaaaaaaaaaa\n")

	b, err := New(root).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range b.Entities {
		if e.Type != "secret_finding" {
			continue
		}
		got[filepath.Base(e.Identity["path"])+":"+e.Identity["line"]+":"+e.Identity["rule"]] = e.Attributes["hash_prefix"].(string)
		if len(e.Attributes) != 5 || e.Attributes["rule_id"] != e.Identity["rule"] {
			t.Fatalf("unexpected attrs %v", e.Attributes)
		}
	}
	// Gitleaks rule ids replace the old regex ids. The fake slack token is not
	// in Gitleaks' slack-bot-token format, so it is no longer reported.
	want := []string{"a.env:2:aws-access-token", "a.env:3:generic-api-key",
		"b.txt:1:github-pat"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Fatalf("missing %s in %v", w, got)
		}
	}
	// SHA-256("AKIAABCDEFGHIJKLMNOP")[:8] must be 8 lowercase hex chars.
	h := got["a.env:2:aws-access-token"]
	if len(h) != 8 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("bad hash prefix %q", h)
	}
	if len(b.Relations) != 3 {
		t.Fatalf("relations: %d", len(b.Relations))
	}
}

func TestBatchHasNoSecretBytes(t *testing.T) {
	root := t.TempDir()
	write(t, root, "f.txt", awsKey+"\n"+ghTok+"\n"+slack+"\npassword="+pw+"\n")
	b, err := New(root).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%#v", b)
	for _, s := range []string{awsKey, ghTok, slack, pw} {
		for i := 0; i+9 <= len(s); i++ {
			if strings.Contains(dump, s[i:i+9]) {
				t.Fatalf("batch leaks substring %q", s[i:i+9])
			}
		}
	}
	if g := redact.New(); g.Leaks(b) {
		t.Fatal("guard reports leak")
	}
}
