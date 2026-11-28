package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Auth constants.
const (
	// SourceAmbient and SourceVault name where the base credentials of an
	// AssumeRole connection come from. They are used only for
	// sts:AssumeRole and sts:GetCallerIdentity (class auth).
	SourceAmbient = "ambient"
	SourceVault   = "vault"

	// MaxSessionDuration is the longest STS session requested (Req 3.4).
	MaxSessionDuration = time.Hour
	minSessionDuration = 15 * time.Minute
	// RefreshWindow is how long before expiry a session is refreshed.
	RefreshWindow = 300 * time.Second
	// RefreshRetries is the number of retries after the first failed refresh.
	RefreshRetries = 3
)

var roleARNRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var sessionNameRe = regexp.MustCompile(`[^A-Za-z0-9+=,.@_-]`)

// AssumeRoleConfig configures NewAssumeRoleProvider.
type AssumeRoleConfig struct {
	RoleARN    string
	ExternalID string // sent in every AssumeRole call
	// SessionName defaults to "bellu"; it is sanitized and cut to 64 chars.
	SessionName string
	Region      string
	// Duration is clamped to 15 min..1 h; zero means 1 h.
	Duration time.Duration
	// Base signs the AssumeRole call: the vault provider (broker.AWSCredentials)
	// or AmbientCredentials.
	Base awssdk.CredentialsProvider
	// HTTPClient must be a broker client for a lifecycle caller.
	HTTPClient *http.Client

	// Backoff is the first retry delay, doubled per retry (default 1 s).
	Backoff time.Duration
	// Sleep waits d or until ctx is done (default: a real timer).
	Sleep func(ctx context.Context, d time.Duration) error
	// Register adds a secret to the redactor and returns its release.
	Register func(secret []byte) func()
	// OnExpired is called once when the refresh retries are exhausted.
	OnExpired func(err error)
}

// RoleProvider is an aws.CredentialsProvider for assumed-role sessions. The
// session credentials live only in memory.
type RoleProvider struct {
	cfg     AssumeRoleConfig
	sts     *sts.Client
	cache   *awssdk.CredentialsCache
	expired atomic.Bool

	mu      sync.Mutex
	release []func()
}

// NewAssumeRoleProvider validates cfg and returns a provider that refreshes
// the session 300 s before it expires.
func NewAssumeRoleProvider(cfg AssumeRoleConfig) (*RoleProvider, error) {
	switch {
	case !roleARNRe.MatchString(cfg.RoleARN):
		return nil, errors.New("aws: invalid role arn")
	case !externalIDRe.MatchString(cfg.ExternalID):
		return nil, errors.New("aws: invalid external id")
	case cfg.Base == nil || cfg.HTTPClient == nil || cfg.Region == "":
		return nil, errors.New("aws: assume role requires base credentials, an http client and a region")
	}
	if cfg.Duration <= 0 || cfg.Duration > MaxSessionDuration {
		cfg.Duration = MaxSessionDuration
	}
	if cfg.Duration < minSessionDuration {
		cfg.Duration = minSessionDuration
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	cfg.SessionName = sessionNameRe.ReplaceAllString(cfg.SessionName, "-")
	if cfg.SessionName == "" {
		cfg.SessionName = "bellu"
	}
	if len(cfg.SessionName) > 64 {
		cfg.SessionName = cfg.SessionName[:64]
	}
	p := &RoleProvider{cfg: cfg}
	p.sts = sts.NewFromConfig(awssdk.Config{
		Region: cfg.Region, HTTPClient: cfg.HTTPClient, Credentials: cfg.Base, RetryMaxAttempts: 1,
	})
	p.cache = awssdk.NewCredentialsCache(awssdk.CredentialsProviderFunc(p.refresh), func(o *awssdk.CredentialsCacheOptions) {
		o.ExpiryWindow = RefreshWindow
		o.ExpiryWindowJitterFrac = 0
	})
	return p, nil
}

// Expired reports that all refresh retries failed. The cached credentials are
// dropped and Retrieve returns ErrExpired without sending anything until a new
// provider is built (Reconnect).
func (p *RoleProvider) Expired() bool { return p.expired.Load() }

// Retrieve implements aws.CredentialsProvider.
func (p *RoleProvider) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	if p.expired.Load() {
		return awssdk.Credentials{}, ErrExpired
	}
	c, err := p.cache.Retrieve(ctx)
	if err != nil {
		return awssdk.Credentials{}, err
	}
	return c, nil
}

// refresh calls AssumeRole with up to RefreshRetries retries and increasing
// delay, then reports expiry.
func (p *RoleProvider) refresh(ctx context.Context) (awssdk.Credentials, error) {
	delay := p.cfg.Backoff
	var last error
	for attempt := 0; attempt <= RefreshRetries; attempt++ {
		if attempt > 0 {
			if err := p.cfg.Sleep(ctx, delay); err != nil {
				return awssdk.Credentials{}, err
			}
			delay *= 2
		}
		creds, err := p.assume(ctx)
		if err == nil {
			return creds, nil
		}
		if ctx.Err() != nil {
			return awssdk.Credentials{}, ctx.Err()
		}
		last = err
	}
	p.expire(last)
	// Both are wrapped so callers can still match the typed cause.
	return awssdk.Credentials{}, fmt.Errorf("%w: %w", ErrExpired, last)
}

func (p *RoleProvider) assume(ctx context.Context) (awssdk.Credentials, error) {
	out, err := p.sts.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn: awssdk.String(p.cfg.RoleARN), RoleSessionName: awssdk.String(p.cfg.SessionName),
		ExternalId:      awssdk.String(p.cfg.ExternalID),
		DurationSeconds: awssdk.Int32(int32(p.cfg.Duration / time.Second)),
	})
	if err != nil {
		return awssdk.Credentials{}, mapErr(err)
	}
	c := out.Credentials
	if c == nil || awssdk.ToString(c.AccessKeyId) == "" || awssdk.ToString(c.SecretAccessKey) == "" {
		return awssdk.Credentials{}, errors.New("aws: empty assume role response")
	}
	p.track(c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	creds := awssdk.Credentials{
		AccessKeyID: *c.AccessKeyId, SecretAccessKey: *c.SecretAccessKey,
		SessionToken: awssdk.ToString(c.SessionToken), Source: "bellud-assume-role", CanExpire: true,
	}
	if c.Expiration != nil {
		creds.Expires = *c.Expiration
	} else {
		creds.Expires = time.Now().Add(p.cfg.Duration)
	}
	return creds, nil
}

// track registers session secrets with the redactor until the next refresh.
func (p *RoleProvider) track(secrets ...*string) {
	if p.cfg.Register == nil {
		return
	}
	var rels []func()
	for _, s := range secrets {
		if v := awssdk.ToString(s); v != "" {
			rels = append(rels, p.cfg.Register([]byte(v)))
		}
	}
	p.mu.Lock()
	old := p.release
	p.release = rels
	p.mu.Unlock()
	for _, r := range old {
		r()
	}
}

// expire drops the cached session and its redaction registrations.
func (p *RoleProvider) expire(err error) {
	if !p.expired.CompareAndSwap(false, true) {
		return
	}
	p.cache.Invalidate()
	p.mu.Lock()
	old := p.release
	p.release = nil
	p.mu.Unlock()
	for _, r := range old {
		r()
	}
	if p.cfg.OnExpired != nil {
		p.cfg.OnExpired(err)
	}
}

// DetectPrincipal runs sts:GetCallerIdentity and returns the identity with a
// session ARN converted to its role ARN ("Detect principal").
func DetectPrincipal(ctx context.Context, c Client) (Identity, error) {
	return c.Identity(ctx)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
