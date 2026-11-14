package kubernetes

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

const (
	maxBody       = 1 << 20
	maxTokenLen   = 16 << 10
	maxCredential = 256 << 10
	// rulesNamespace is the namespace whose rules CheckPermissions reviews.
	rulesNamespace = "default"
)

// Credential is the canonical pasted credential: the JSON {server, token, ca}.
type Credential struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	CA     string `json:"ca"`
}

// ProviderConfig wires a Provider.
type ProviderConfig struct {
	// ServerFor returns the API server URL of a connection (from its stored
	// selection or settings). Describe needs it because the credential lives
	// in the vault.
	ServerFor func(store.Connection) string
	// AllowPrivateFor reports whether the connection may reach private ranges.
	AllowPrivateFor func(store.Connection) bool
}

// Provider is the Kubernetes lifecycle.Provider.
type Provider struct{ cfg ProviderConfig }

var (
	_ lifecycle.Provider                  = (*Provider)(nil)
	_ lifecycle.MethodCredentialValidator = (*Provider)(nil)
	_ lifecycle.NonRefreshable            = (*Provider)(nil)
)

// NewProvider returns the Kubernetes provider.
func NewProvider(cfg ProviderConfig) *Provider { return &Provider{cfg: cfg} }

func invalid(msg string) error {
	return lifecycle.NewError(lifecycle.CodeValidationFailed, msg, nil)
}

// ValidateCredentialFor checks the stored credential: the bare ServiceAccount
// token the service keeps in the credential slot after splitting the pasted
// input with Normalize. Errors name fields only.
func (p *Provider) ValidateCredentialFor(method string, secret []byte) error {
	if method != MethodToken && method != MethodKubeconfig {
		return invalid("unsupported authentication method")
	}
	if len(secret) == 0 || len(secret) > maxTokenLen || bytes.ContainsFunc(secret, unicode.IsSpace) {
		return invalid("field token must be non-empty, at most 16384 characters and contain no whitespace")
	}
	return nil
}

// Normalize validates the pasted input of a method and returns the canonical
// credential. The service stores Token in the credential slot and CA in the
// CASlot slot, and keeps Server for Describe.
func Normalize(method string, secret []byte) (Credential, error) {
	if len(secret) == 0 || len(secret) > maxCredential {
		return Credential{}, invalid("credential must be non-empty and at most 256 KiB")
	}
	switch method {
	case MethodToken:
		var c Credential
		if json.Unmarshal(secret, &c) != nil {
			return Credential{}, invalid("credential must be a JSON object with fields server, token and ca")
		}
		return c, c.validate()
	case MethodKubeconfig:
		c, err := fromKubeconfig(secret)
		if err != nil {
			return Credential{}, err
		}
		return c, c.validate()
	}
	return Credential{}, invalid("unsupported authentication method")
}

func (c Credential) validate() error {
	if _, err := ParseServer(c.Server); err != nil {
		return err
	}
	if c.Token == "" || len(c.Token) > maxTokenLen || strings.ContainsFunc(c.Token, unicode.IsSpace) {
		return invalid("field token must be non-empty, at most 16384 characters and contain no whitespace")
	}
	if !validPEM(c.CA) {
		return invalid("field ca must be a PEM encoded CA certificate")
	}
	return nil
}

func validPEM(s string) bool {
	rest, n := []byte(s), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
	return n > 0 && len(bytes.TrimSpace(rest)) == 0
}

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseServer validates the API server URL (https only, DNS name host, optional
// port, no credentials, path or query) and returns host[:port]. IP literals
// are rejected because the egress policy never matches them.
func ParseServer(raw string) (apiHost string, err error) {
	bad := invalid("field server must be an https URL with a DNS host name, such as https://k8s.example.com:6443")
	u, perr := url.Parse(raw)
	if perr != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", bad
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return "", bad
	}
	if slices.ContainsFunc(strings.Split(h, "."), func(l string) bool { return !hostLabelRe.MatchString(l) }) {
		return "", bad
	}
	if port := u.Port(); port != "" {
		if len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return "", bad
		}
		return h + ":" + port, nil
	}
	return h, nil
}

// kubeconfig is the subset of the kubeconfig schema that is read.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
			CAData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// fromKubeconfig extracts the current (or only) context's server, token and CA.
func fromKubeconfig(secret []byte) (Credential, error) {
	var k kubeconfig
	if yaml.Unmarshal(secret, &k) != nil {
		return Credential{}, invalid("kubeconfig must be valid YAML")
	}
	ctxName := k.CurrentContext
	if ctxName == "" && len(k.Contexts) == 1 {
		ctxName = k.Contexts[0].Name
	}
	var cluster, user string
	for _, c := range k.Contexts {
		if c.Name == ctxName {
			cluster, user = c.Context.Cluster, c.Context.User
		}
	}
	if cluster == "" || user == "" {
		return Credential{}, invalid("kubeconfig: field current-context must name a context with a cluster and a user")
	}
	var c Credential
	found := false
	for _, cl := range k.Clusters {
		if cl.Name != cluster {
			continue
		}
		found = true
		if cl.Cluster.CAData == "" {
			return Credential{}, invalid("kubeconfig: cluster field certificate-authority-data is required (file paths are not supported)")
		}
		ca, err := base64.StdEncoding.DecodeString(cl.Cluster.CAData)
		if err != nil {
			return Credential{}, invalid("kubeconfig: cluster field certificate-authority-data must be base64")
		}
		c.Server, c.CA = cl.Cluster.Server, string(ca)
	}
	if !found {
		return Credential{}, invalid("kubeconfig: the context's cluster is not listed in clusters")
	}
	for _, u := range k.Users {
		if u.Name == user {
			c.Token = u.User.Token
		}
	}
	if c.Token == "" {
		return Credential{}, invalid("kubeconfig: user field token is required (exec, auth-provider, tokenFile and client certificates are not supported)")
	}
	return c, nil
}

type version struct {
	GitVersion string `json:"gitVersion"`
}

// Verify calls GET /version. The label is the API server host and git version.
func (p *Provider) Verify(ctx context.Context, c lifecycle.Call) (lifecycle.Identity, error) {
	var v version
	if err := p.do(ctx, c, http.MethodGet, "/version", nil, &v); err != nil {
		return lifecycle.Identity{}, err
	}
	label := c.Ref.APIHost
	if label == "" {
		label = p.apiHost(c.Connection)
	}
	if v.GitVersion != "" {
		label += " " + v.GitVersion
	}
	return lifecycle.Identity{AccountLabel: label}, nil
}

type rulesReview struct {
	Status struct {
		ResourceRules []struct {
			Verbs     []string `json:"verbs"`
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
		} `json:"resourceRules"`
	} `json:"status"`
}

var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true, "*": true}

// CheckPermissions reviews the rules of the default namespace and reports the
// ones that grant create, update, patch, delete or "*".
func (p *Provider) CheckPermissions(ctx context.Context, c lifecycle.Call) (lifecycle.PermissionReport, error) {
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
		"spec": map[string]string{"namespace": rulesNamespace},
	})
	var r rulesReview
	if err := p.do(ctx, c, http.MethodPost, rulesReviewPath, body, &r); err != nil {
		var le *lifecycle.Error
		if errors.As(err, &le) && le.Code == lifecycle.CodeInsufficientPermission {
			return lifecycle.PermissionReport{Unverifiable: true, WriteOffenders: []string{}}, nil
		}
		return lifecycle.PermissionReport{}, err
	}
	seen := map[string]bool{}
	for _, rule := range r.Status.ResourceRules {
		for _, v := range rule.Verbs {
			if !writeVerbs[v] {
				continue
			}
			groups := strings.Join(rule.APIGroups, ",")
			seen[fmt.Sprintf("%s %s/%s", v, groups, strings.Join(rule.Resources, ","))] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return lifecycle.PermissionReport{WriteOffenders: out}, nil
}

// Refreshable is false: a ServiceAccount token cannot be renewed here.
func (p *Provider) Refreshable(store.Connection) bool { return false }

// Refresh is a no-op and returns the known expiry.
func (p *Provider) Refresh(_ context.Context, c lifecycle.Call) (time.Time, error) {
	if e := c.Connection.CredentialExpiresAt; e != nil {
		return *e, nil
	}
	return time.Time{}, nil
}

// Collector is nil: version 1 verifies and connects only.
func (p *Provider) Collector(store.Connection, broker.ConnectionRef) collectors.Collector {
	return nil
}

// Describe routes the connection to its API server. Host is the host name for
// the policy placeholder; APIHost (with port) is what the broker pins requests to.
func (p *Provider) Describe(conn store.Connection) lifecycle.Descriptor {
	api := p.apiHost(conn)
	host, _, err := net.SplitHostPort(api)
	if err != nil {
		host = api
	}
	d := lifecycle.Descriptor{Auth: broker.AuthK8sBearer, APIHost: api, Host: host, CASlot: CASlot}
	if p.cfg.AllowPrivateFor != nil {
		d.AllowPrivate = p.cfg.AllowPrivateFor(conn)
	}
	return d
}

func (p *Provider) apiHost(conn store.Connection) string {
	if p.cfg.ServerFor == nil {
		return ""
	}
	h, err := ParseServer(p.cfg.ServerFor(conn))
	if err != nil {
		return ""
	}
	return h
}

// do sends one request through the broker client and decodes a JSON 2xx body.
func (p *Provider) do(ctx context.Context, c lifecycle.Call, method, path string, body []byte, out any) error {
	host := c.Ref.APIHost
	if host == "" {
		host = p.apiHost(c.Connection)
	}
	if host == "" {
		return invalid("connection has no API server")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err // typed broker errors stay reachable through errors.As
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return mapStatus(resp.StatusCode)
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("kubernetes: malformed response")
	}
	return nil
}

func mapStatus(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return lifecycle.NewError(lifecycle.CodeInvalidCredential, "token is invalid, revoked or expired", nil)
	case http.StatusForbidden:
		return lifecycle.NewError(lifecycle.CodeInsufficientPermission, "token lacks the required read permissions", nil)
	case http.StatusTooManyRequests:
		return lifecycle.NewError(lifecycle.CodeRateLimited, "provider rate limit reached", nil)
	}
	return fmt.Errorf("kubernetes: unexpected status %d", status)
}
