package broker

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
)

var errBadAWSSecret = errors.New("broker: invalid aws credential document")

// awsSecret is the JSON document stored in the vault for AWS static keys.
type awsSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// AWSCredentials returns a vault-backed aws.CredentialsProvider for ref. The
// key is released per Retrieve; a vault failure returns a credential-free
// *CredentialError, so the SDK never signs or sends a request.
func (b *Broker) AWSCredentials(ref ConnectionRef, caller string) aws.CredentialsProvider {
	return &awsProvider{b: b, ref: ref, caller: caller}
}

type awsProvider struct {
	b      *Broker
	ref    ConnectionRef
	caller string

	mu      sync.Mutex
	release []func()
}

func (p *awsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var creds aws.Credentials
	err := p.b.cfg.Opener.Use(ctx, p.ref.Credential, func(secret []byte) error {
		var s awsSecret
		if err := json.Unmarshal(secret, &s); err != nil || s.AccessKeyID == "" || s.SecretAccessKey == "" {
			return errBadAWSSecret
		}
		// Registered until the next Retrieve so SDK error text and responses
		// that echo the key are redacted.
		rels := []func(){
			p.b.cfg.Redactor.Register([]byte(s.AccessKeyID)),
			p.b.cfg.Redactor.Register([]byte(s.SecretAccessKey)),
		}
		if s.SessionToken != "" {
			rels = append(rels, p.b.cfg.Redactor.Register([]byte(s.SessionToken)))
		}
		p.mu.Lock()
		old := p.release
		p.release = rels
		p.mu.Unlock()
		for _, r := range old {
			r()
		}
		creds = aws.Credentials{
			AccessKeyID: s.AccessKeyID, SecretAccessKey: s.SecretAccessKey,
			SessionToken: s.SessionToken, Source: "bellud-vault",
		}
		return nil
	})
	if err != nil {
		code := "unavailable"
		_ = p.b.appendAudit(ctx, audit.Entry{
			ConnectionID: p.ref.ID, ConnectorID: p.ref.ConnectorID,
			Event: audit.EventCredentialRelease, Outcome: audit.OutcomeFailure, Actor: orSystem(p.caller),
			Detail: map[string]string{"caller": p.caller, "code": code},
		})
		return aws.Credentials{}, &CredentialError{Code: code}
	}
	// Static keys are re-read from the vault on every signing so rotation applies at once.
	creds.CanExpire = true
	creds.Expires = p.b.now().Add(time.Minute)
	return creds, nil
}
