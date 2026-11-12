package auth

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectors.json is generated from packages/server/src/auth.ts by
// script/gen-auth-vectors.ts. Its "excluded" list documents intentional TS/Go differences.
type vectorFile struct {
	Excluded []string `json:"excluded"`
	Issued   []struct {
		Password string `json:"password"`
		Now      int64  `json:"now"`
		Token    string `json:"token"`
	} `json:"issued"`
	Cases []struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Now      int64  `json:"now"`
		Token    string `json:"token"`
		Expected bool   `json:"expected"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 || len(v.Issued) == 0 || len(v.Excluded) == 0 {
		t.Fatal("vectors.json is missing cases, issued tokens or the excluded list")
	}
	return v
}

func TestVerifySessionMatchesTSVectors(t *testing.T) {
	for _, c := range loadVectors(t).Cases {
		got := New(c.Password).VerifySession(c.Token, time.UnixMilli(c.Now))
		if got != c.Expected {
			t.Errorf("%s: VerifySession(%q) = %v, TS says %v", c.Name, c.Token, got, c.Expected)
		}
	}
}

// Go-issued tokens must equal the TS-issued ones for the same password and time, so every
// token Go issues is in the set TS verifies, and every TS token verifies in Go.
func TestIssueSessionMatchesTSTokens(t *testing.T) {
	for _, i := range loadVectors(t).Issued {
		a := New(i.Password)
		now := time.UnixMilli(i.Now)
		got, ok := a.IssueSession(now)
		if !ok || got != i.Token {
			t.Errorf("IssueSession(%q, %d) = %q, %v; TS issued %q", i.Password, i.Now, got, ok, i.Token)
		}
		if !a.VerifySession(i.Token, now) {
			t.Errorf("TS token %q not verified by Go at issue time", i.Token)
		}
	}
}
