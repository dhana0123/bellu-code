package aws

import (
	"context"
	"regexp"
	"testing"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"pgregory.net/rapid"
)

var rootARNOracle = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:root$`)

// callerARNGen mixes real root ARNs, near misses and arbitrary strings.
func callerARNGen() *rapid.Generator[string] {
	partition := rapid.SampledFrom([]string{"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b"})
	return rapid.OneOf(
		// Account root in any partition.
		rapid.Custom(func(t *rapid.T) string {
			return "arn:" + partition.Draw(t, "partition") + ":iam::" + rapid.StringMatching(`[0-9]{12}`).Draw(t, "acct") + ":root"
		}),
		// Near misses: bad account, service, resource or region field.
		rapid.Custom(func(t *rapid.T) string {
			return "arn:" + partition.Draw(t, "partition") + ":" +
				rapid.SampledFrom([]string{"iam", "sts", "s3"}).Draw(t, "svc") + ":" +
				rapid.SampledFrom([]string{"", "us-east-1"}).Draw(t, "region") + ":" +
				rapid.OneOf(rapid.StringMatching(`[0-9]{12}`), rapid.StringMatching(`[0-9]{0,14}`), rapid.StringMatching(`[0-9a-z]{12}`)).Draw(t, "acct") + ":" +
				rapid.SampledFrom([]string{"root", "Root", "root/x", "user/root", "role/root", "user/alice", "assumed-role/R/s", "", "root\n"}).Draw(t, "res")
		}),
		// Non-root principals as returned by GetCallerIdentity.
		rapid.Custom(func(t *rapid.T) string {
			acct := rapid.StringMatching(`[0-9]{12}`).Draw(t, "acct")
			return rapid.SampledFrom([]string{
				"arn:aws:iam::" + acct + ":user/",
				"arn:aws:sts::" + acct + ":assumed-role/",
				"arn:aws:iam::" + acct + ":role/",
			}).Draw(t, "kind") + rapid.StringMatching(`[A-Za-z0-9+=,.@_/-]{1,30}`).Draw(t, "name")
		}),
		rapid.String(),
	)
}

// Feature: cloud-connectors, Property 21: AWS root identity rejected
//
// **Validates: Requirements 3.10**
func TestPropertyAWSRootIdentityRejected(t *testing.T) {
	cl := &stubClient{}
	p := stubProvider(t, cl, Params{})
	call := callFor(t, staticConn())
	rapid.Check(t, func(t *rapid.T) {
		arn := callerARNGen().Draw(t, "arn")
		want := rootARNOracle.MatchString(arn)
		if got := IsRootARN(arn); got != want {
			t.Fatalf("IsRootARN(%q)=%v want %v", arn, got, want)
		}

		cl.id = Identity{Account: "123456789012", ARN: arn, PrincipalARN: PrincipalFromARN(arn)}
		id, err := p.Verify(context.Background(), call)
		if !want {
			if err != nil || id.AccountLabel != "123456789012" {
				t.Fatalf("non-root %q must verify: %+v %v", arn, id, err)
			}
			return
		}
		le, ok := asLifecycleError(err)
		if !ok || le.Code != lifecycle.CodeInvalidCredential {
			t.Fatalf("root %q must be rejected as invalid_credential, got %v", arn, err)
		}
		if id != (lifecycle.Identity{}) {
			t.Fatalf("rejected root must return no identity, got %+v", id)
		}
		if !regexp.MustCompile(`root credentials are not allowed`).MatchString(err.Error()) {
			t.Fatalf("message must state root credentials are not allowed: %v", err)
		}
		p.mu.Lock()
		n := len(p.sessions)
		p.mu.Unlock()
		if n != 0 {
			t.Fatalf("credential session retained after root rejection: %d", n)
		}
	})
}

func asLifecycleError(err error) (*lifecycle.Error, bool) {
	le, ok := err.(*lifecycle.Error)
	return le, ok
}
