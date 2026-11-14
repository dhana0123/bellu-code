package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/audit"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/vault"
)

// GCP token exchange.
const (
	// GCPTokenOperation is the manifest operation name (ClassAuth, POST, Query,
	// IssuesCredential) the Google Cloud manifest must list for the exchange.
	GCPTokenOperation = "POST /token"
	// GCPTokenURL is the fixed exchange endpoint. The key's own token_uri is
	// ignored so a pasted key cannot redirect the signed assertion.
	GCPTokenURL = "https://oauth2.googleapis.com/token"
	// GCPScope is the read-capable scope; the roles on the account limit it.
	GCPScope = "https://www.googleapis.com/auth/cloud-platform"

	gcpTokenSkew = 60 * time.Second
	gcpJWTTTL    = time.Hour
)

var errBadGCPKey = errors.New("broker: invalid gcp service account key")

// injects reports whether the transport sets an Authorization header.
func (t *policyTransport) injects() bool {
	switch t.ref.Auth {
	case AuthBearer, AuthBasic, AuthGCPServiceAccount, AuthK8sBearer:
		return true
	}
	return false
}

// inject sets the Authorization header from the vault. Every secret involved
// is registered with the redactor until the response has been processed.
func (t *policyTransport) inject(ctx context.Context, out *http.Request) (func(), error) {
	var release func()
	var err error
	switch t.ref.Auth {
	case AuthGCPServiceAccount:
		var token string
		token, release, err = t.gcpToken(ctx)
		if err == nil {
			out.Header.Set("Authorization", "Bearer "+token)
		}
	default:
		err = t.b.cfg.Opener.Use(ctx, t.ref.Credential, func(secret []byte) error {
			switch t.ref.Auth {
			case AuthBasic:
				user, pass, ok := strings.Cut(string(secret), "\n")
				if !ok || user == "" || pass == "" {
					return errBadBasicSecret
				}
				enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
				release = joinRelease(
					t.b.cfg.Redactor.Register([]byte(pass)),
					t.b.cfg.Redactor.Register([]byte(enc)),
				)
				out.Header.Set("Authorization", "Basic "+enc)
			default:
				release = t.b.cfg.Redactor.Register(secret)
				out.Header.Set("Authorization", "Bearer "+string(secret))
			}
			return nil
		})
	}
	if err != nil {
		var ce *CredentialError
		if !errors.As(err, &ce) {
			ce = &CredentialError{Code: credentialCode(err)}
		}
		_ = t.b.appendAudit(ctx, audit.Entry{
			ConnectionID: t.ref.ID, ConnectorID: t.ref.ConnectorID,
			Event: audit.EventCredentialRelease, Outcome: audit.OutcomeFailure, Actor: orSystem(t.caller),
			Detail: map[string]string{"caller": t.caller, "code": ce.Code},
		})
		return nil, ce
	}
	return release, nil
}

var errBadBasicSecret = errors.New("broker: invalid basic credential")

func credentialCode(err error) string {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return "not_found"
	case errors.Is(err, vault.ErrDecrypt):
		return "decrypt"
	case errors.Is(err, errBadBasicSecret), errors.Is(err, errBadGCPKey):
		return "invalid"
	}
	return "unavailable"
}

func joinRelease(fns ...func()) func() {
	return func() {
		for _, f := range fns {
			f()
		}
	}
}

// gcpToken returns a cached access token, or signs a JWT and exchanges it.
// The exchange is sent through a policy transport as the ClassAuth operation
// GCPTokenOperation, so it is allowlisted, rate limited and audited like any
// other call. The returned func unregisters the token from the redactor.
func (t *policyTransport) gcpToken(ctx context.Context) (string, func(), error) {
	st := t.b.state(t.ref.ID)
	st.tokMu.Lock()
	defer st.tokMu.Unlock()
	if st.token != "" && t.b.now().Add(gcpTokenSkew).Before(st.tokExp) {
		return st.token, t.b.cfg.Redactor.Register([]byte(st.token)), nil
	}
	st.token, st.tokExp = "", time.Time{}

	var assertion string
	err := t.b.cfg.Opener.Use(ctx, t.ref.Credential, func(secret []byte) error {
		var err error
		assertion, err = signGCPJWT(secret, t.b.now())
		return err
	})
	if err != nil {
		return "", nil, err
	}
	releaseAssertion := t.b.cfg.Redactor.Register([]byte(assertion))
	defer releaseAssertion()

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(context.WithValue(ctx, keyOperation, GCPTokenOperation),
		http.MethodPost, GCPTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, &CredentialError{Code: "unavailable"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	exRef := t.ref
	exRef.Auth = AuthNone
	resp, err := newPolicyTransport(t.b, exRef, t.caller).RoundTrip(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || json.Unmarshal(body, &tok) != nil ||
		tok.AccessToken == "" || tok.ExpiresIn <= 0 {
		return "", nil, &CredentialError{Code: "exchange_failed"}
	}
	st.token = tok.AccessToken
	st.tokExp = t.b.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return st.token, t.b.cfg.Redactor.Register([]byte(st.token)), nil
}

// signGCPJWT builds the RS256 assertion for a service-account key document.
func signGCPJWT(keyDoc []byte, now time.Time) (string, error) {
	var k struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(keyDoc, &k); err != nil || k.ClientEmail == "" || k.PrivateKey == "" {
		return "", errBadGCPKey
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return "", errBadGCPKey
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errBadGCPKey
		}
		key = rk
	} else if rk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = rk
	} else {
		return "", errBadGCPKey
	}
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": k.ClientEmail, "scope": GCPScope, "aud": GCPTokenURL,
		"iat": now.Unix(), "exp": now.Add(gcpJWTTTL).Unix(),
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errBadGCPKey
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// ForgetToken drops the cached GCP access token of a connection (rotation, delete).
func (b *Broker) ForgetToken(connectionID string) {
	st := b.state(connectionID)
	st.tokMu.Lock()
	st.token, st.tokExp = "", time.Time{}
	st.tokMu.Unlock()
}

// k8sEntry is a cached per-connection transport with the inputs it was built from.
type k8sEntry struct {
	fingerprint [sha256.Size]byte
	rt          *http.Transport
}

// k8sTransport returns the guarded transport of a Kubernetes connection. It
// trusts only the CA bundle in the vault and denies private ranges unless the
// connection allows them. The transport is rebuilt when the CA or the
// private-range setting changes.
func (b *Broker) k8sTransport(ctx context.Context, ref ConnectionRef) (http.RoundTripper, error) {
	var pemBytes []byte
	err := b.cfg.Opener.Use(ctx, ref.CACredential, func(secret []byte) error {
		pemBytes = append([]byte(nil), secret...)
		return nil
	})
	if err != nil {
		return nil, &CredentialError{Code: credentialCode(err)}
	}
	fp := sha256.Sum256(append(pemBytes, boolByte(ref.AllowPrivate)))

	b.k8sMu.Lock()
	defer b.k8sMu.Unlock()
	if e, ok := b.k8s[ref.ID]; ok && e.fingerprint == fp {
		return e.rt, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, &CredentialError{Code: "invalid"}
	}
	rt := newGuardedTransport(controlForK8s(ref.AllowPrivate), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if old, ok := b.k8s[ref.ID]; ok {
		old.rt.CloseIdleConnections()
	}
	b.k8s[ref.ID] = k8sEntry{fingerprint: fp, rt: rt}
	return rt, nil
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
