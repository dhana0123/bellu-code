package canonical

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: unified-security-graph, Property 2: Canonical_Key normalization is
// idempotent and spelling-invariant.
//
// **Validates: Requirements 2.2**

func randomCase(t *rapid.T, s string) string {
	var b strings.Builder
	for _, r := range s {
		if rapid.Bool().Draw(t, "upper") {
			b.WriteString(strings.ToUpper(string(r)))
			continue
		}
		b.WriteString(strings.ToLower(string(r)))
	}
	return b.String()
}

func pad(t *rapid.T, s string) string {
	ws := rapid.StringOfN(rapid.SampledFrom([]rune(" \t\n")), 0, 3, -1)
	return ws.Draw(t, "lead") + s + ws.Draw(t, "trail")
}

func TestKeyIdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.SampledFrom([]string{KindARN, KindPurl, KindVuln, KindImage, KindGit}).Draw(t, "kind")
		raw := rapid.OneOf(
			rapid.String(),
			arnGen(),
			purlGen(),
			vulnGen(),
			digestGen(),
			gitGen(),
		).Draw(t, "raw")
		key, ok := Key(kind, raw)
		if !ok {
			return
		}
		again, ok2 := Key(kind, key)
		if !ok2 || again != key {
			t.Fatalf("Key(%q, Key(%q)) = %q, %v; want %q", kind, raw, again, ok2, key)
		}
	})
}

func TestKeyARNSpellingInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		arn := arnGen().Draw(t, "arn")
		want, ok := Key(KindARN, arn)
		if !ok {
			t.Fatalf("valid arn %q has no key", arn)
		}
		// Case of the first five segments and surrounding whitespace do not matter.
		parts := strings.SplitN(arn, ":", 6)
		for i := range 5 {
			parts[i] = randomCase(t, parts[i])
		}
		got, ok := Key(KindARN, pad(t, strings.Join(parts, ":")))
		if !ok || got != want {
			t.Fatalf("respelled arn gave %q, %v; want %q", got, ok, want)
		}
		// The resource part is case-sensitive.
		if strings.ToLower(parts[5]) != parts[5] {
			other, _ := Key(KindARN, strings.Join(append(parts[:5:5], strings.ToLower(parts[5])), ":"))
			if other == want {
				t.Fatalf("resource case was folded: %q", want)
			}
		}
	})
}

func TestKeyPurlSpellingInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z][a-z0-9-]{0,8}`).Draw(t, "name")
		ns := rapid.StringMatching(`[a-z][a-z0-9-]{0,8}`).Draw(t, "ns")
		typ := rapid.SampledFrom([]string{"npm", "maven", "golang", "pypi"}).Draw(t, "type")
		version := rapid.StringMatching(`[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+)?`).Draw(t, "version")
		base := "pkg:" + typ + "/" + ns + "/" + name + "@" + version
		want, ok := Key(KindPurl, base)
		if !ok {
			t.Fatalf("valid purl %q has no key", base)
		}
		if want != base {
			t.Fatalf("lowercase purl changed: %q -> %q", base, want)
		}
		head := randomCase(t, "pkg:"+typ+"/"+ns+"/"+name)
		spelled := head + "@" + version
		if rapid.Bool().Draw(t, "qualifiers") {
			spelled += "?arch=" + rapid.StringMatching(`[a-z0-9]{1,6}`).Draw(t, "q")
		}
		if rapid.Bool().Draw(t, "subpath") {
			spelled += "#" + rapid.StringMatching(`[a-z0-9/]{1,8}`).Draw(t, "sub")
		}
		got, ok := Key(KindPurl, pad(t, spelled))
		if !ok || got != want {
			t.Fatalf("respelled purl %q gave %q, %v; want %q", spelled, got, ok, want)
		}
	})
}

func TestKeyVulnSpellingInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := vulnGen().Draw(t, "id")
		want, ok := Key(KindVuln, id)
		if !ok || want != "vuln:"+strings.ToUpper(id) {
			t.Fatalf("Key(vuln, %q) = %q, %v", id, want, ok)
		}
		got, ok := Key(KindVuln, pad(t, randomCase(t, id)))
		if !ok || got != want {
			t.Fatalf("respelled id gave %q, %v; want %q", got, ok, want)
		}
	})
}

func TestKeyImageSpellingInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		digest := digestGen().Draw(t, "digest")
		want, ok := Key(KindImage, digest)
		if !ok || want != strings.ToLower(digest) {
			t.Fatalf("Key(image, %q) = %q, %v", digest, want, ok)
		}
		got, ok := Key(KindImage, pad(t, randomCase(t, digest)))
		if !ok || got != want {
			t.Fatalf("respelled digest gave %q, %v; want %q", got, ok, want)
		}
	})
}

func TestKeyGitSpellingInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		host := rapid.StringMatching(`[a-z][a-z0-9]{0,6}\.(com|org|io)`).Draw(t, "host")
		owner := rapid.StringMatching(`[a-z][a-z0-9-]{0,8}`).Draw(t, "owner")
		repo := rapid.StringMatching(`[a-z][a-z0-9-]{0,8}`).Draw(t, "repo")
		want := "git:" + host + "/" + owner + "/" + repo
		path := owner + "/" + repo
		suffix := rapid.SampledFrom([]string{"", ".git", "/", ".git/"}).Draw(t, "suffix")
		forms := []string{
			"https://" + host + "/" + path + suffix,
			"http://" + host + "/" + path + suffix,
			"git://" + host + "/" + path + suffix,
			"ssh://git@" + host + "/" + path + suffix,
			"ssh://git@" + host + ":22/" + path + suffix,
			"https://user:pw@" + host + "/" + path + suffix + "?x=1#frag",
			"git@" + host + ":" + path + strings.TrimSuffix(suffix, "/"),
		}
		raw := rapid.SampledFrom(forms).Draw(t, "form")
		got, ok := Key(KindGit, pad(t, randomCase(t, raw)))
		if !ok || got != want {
			t.Fatalf("Key(git, %q) = %q, %v; want %q", raw, got, ok, want)
		}
	})
}

func arnGen() *rapid.Generator[string] {
	seg := rapid.StringMatching(`[a-z0-9-]{1,8}`)
	return rapid.Custom(func(t *rapid.T) string {
		res := rapid.StringMatching(`[A-Za-z0-9][A-Za-z0-9/_.:-]{0,15}`).Draw(t, "resource")
		return "arn:" + seg.Draw(t, "partition") + ":" + seg.Draw(t, "service") + ":" +
			seg.Draw(t, "region") + ":" + rapid.StringMatching(`[0-9]{12}`).Draw(t, "account") + ":" + res
	})
}

func purlGen() *rapid.Generator[string] {
	return rapid.StringMatching(`pkg:[A-Za-z]{2,6}/[A-Za-z0-9-]{1,8}/[A-Za-z0-9-]{1,8}@[0-9]\.[0-9]\.[0-9]`)
}

func vulnGen() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.StringMatching(`CVE-[0-9]{4}-[0-9]{4,7}`),
		rapid.StringMatching(`GHSA(-[a-z0-9]{4}){3}`),
	)
}

func digestGen() *rapid.Generator[string] {
	return rapid.StringMatching(`sha256:[0-9a-f]{64}`)
}

func gitGen() *rapid.Generator[string] {
	return rapid.StringMatching(`(https|http|git)://[a-z]{3,8}\.com/[a-z]{2,8}/[a-z]{2,8}(\.git)?`)
}
