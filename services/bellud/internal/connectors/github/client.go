package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	perPage  = 100
	maxPages = 20
	// maxBody bounds one decoded response (the broker caps at 16 MiB already).
	maxBody = 16 << 20
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// ErrBadName means an owner, repository or organization name is not a valid
// GitHub name. Nothing is sent.
var ErrBadName = errors.New("github: invalid name")

// StatusError is a non-2xx response. It carries no response body, which could
// echo request data.
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return "github: unexpected status " + strconv.Itoa(e.Status) }

// Unauthorized reports a 401: the token is invalid, revoked or expired.
func (e *StatusError) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// Client is the typed GitHub REST wrapper. Its HTTP client must be built by
// broker.HTTPClient; the Client never creates a transport of its own.
type Client struct {
	hc       *http.Client
	host     string
	basePath string
}

// NewClient returns a Client. host is "api.github.com" or a validated GHES
// host; basePath is "" or "/api/v3". Requests always use https.
func NewClient(hc *http.Client, host, basePath string) *Client {
	if host == "" {
		host = "api.github.com"
	}
	return &Client{hc: hc, host: host, basePath: strings.TrimRight(basePath, "/")}
}

// User is the authenticated account.
type User struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

// Owner is the account that owns a repository.
type Owner struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// Org is an organization.
type Org struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

// Repo is a repository projection. Descriptions and contents are not kept.
type Repo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Owner         Owner  `json:"owner"`
}

// PullRequest is an open pull request without its body.
type PullRequest struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	State     string    `json:"state"`
	Draft     bool      `json:"draft"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

// Workflow is a GitHub Actions workflow definition.
type Workflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

// CodeScanningAlert is alert metadata.
type CodeScanningAlert struct {
	Number    int       `json:"number"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	Rule      struct {
		ID                    string `json:"id"`
		Severity              string `json:"severity"`
		SecuritySeverityLevel string `json:"security_severity_level"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
}

// DependabotAlert is alert metadata.
type DependabotAlert struct {
	Number    int       `json:"number"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	Advisory  struct {
		GHSAID   string `json:"ghsa_id"`
		Severity string `json:"severity"`
	} `json:"security_advisory"`
	Dependency struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"dependency"`
}

// SecretScanningAlert is alert metadata. The alert's secret value is not part
// of the type, so it cannot be decoded even if a response carries it (the
// broker also strips the "secret" key). Detector holds the detector id that
// GitHub reports as secret_type; consumers must expose it as "detector".
type SecretScanningAlert struct {
	Number    int       `json:"number"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	Detector  string    `json:"secret_type"`
}

// Verify calls GET /user. The expiry is the token expiry from the response
// header; ok is false when GitHub did not send one.
func (c *Client) Verify(ctx context.Context) (u User, expiry time.Time, ok bool, err error) {
	h, err := c.get(ctx, "/user", nil, &u)
	if err != nil {
		return User{}, time.Time{}, false, err
	}
	expiry, ok = ParseTokenExpiry(h.Get(TokenExpiryHeader))
	return u, expiry, ok, nil
}

// User returns the authenticated user.
func (c *Client) User(ctx context.Context) (User, error) {
	var u User
	_, err := c.get(ctx, "/user", nil, &u)
	return u, err
}

// Repositories lists the repositories the token can access (GET /user/repos).
func (c *Client) Repositories(ctx context.Context) ([]Repo, error) {
	return list[Repo](ctx, c, "/user/repos", url.Values{"affiliation": {"owner,collaborator,organization_member"}})
}

// InstallationRepositories lists repositories of an installation token
// (GET /installation/repositories). The response wraps the list.
func (c *Client) InstallationRepositories(ctx context.Context) ([]Repo, error) {
	var out []Repo
	for page := 1; page <= maxPages; page++ {
		var w struct {
			Repositories []Repo `json:"repositories"`
		}
		if _, err := c.get(ctx, "/installation/repositories", pageQuery(nil, page), &w); err != nil {
			return nil, err
		}
		out = append(out, w.Repositories...)
		if len(w.Repositories) < perPage {
			break
		}
	}
	return out, nil
}

// Installation is one installation of the GitHub App reachable by a user token.
type Installation struct {
	ID int64 `json:"id"`
}

// MaxListedRepos caps one repository listing.
const MaxListedRepos = maxPages * perPage

// InstallationsProbe calls GET /user/installations?per_page=1. It proves the
// endpoint class works for the token and returns the total installation count.
func (c *Client) InstallationsProbe(ctx context.Context) (int, error) {
	var w struct {
		TotalCount    int            `json:"total_count"`
		Installations []Installation `json:"installations"`
	}
	if _, err := c.get(ctx, "/user/installations", url.Values{"per_page": {"1"}}, &w); err != nil {
		return 0, err
	}
	return max(w.TotalCount, len(w.Installations)), nil
}

// UserInstallations lists the installations the user token can reach
// (GET /user/installations).
func (c *Client) UserInstallations(ctx context.Context) ([]Installation, error) {
	var out []Installation
	for page := 1; page <= maxPages; page++ {
		var w struct {
			Installations []Installation `json:"installations"`
		}
		if _, err := c.get(ctx, "/user/installations", pageQuery(nil, page), &w); err != nil {
			return nil, err
		}
		out = append(out, w.Installations...)
		if len(w.Installations) < perPage {
			break
		}
	}
	return out, nil
}

// UserInstallationRepositories lists the repositories of one installation that
// the user token can reach (GET /user/installations/{id}/repositories).
func (c *Client) UserInstallationRepositories(ctx context.Context, installationID int64) ([]Repo, error) {
	if installationID <= 0 {
		return nil, ErrBadName
	}
	path := "/user/installations/" + strconv.FormatInt(installationID, 10) + "/repositories"
	var out []Repo
	for page := 1; page <= maxPages; page++ {
		var w struct {
			Repositories []Repo `json:"repositories"`
		}
		if _, err := c.get(ctx, path, pageQuery(nil, page), &w); err != nil {
			return nil, err
		}
		out = append(out, w.Repositories...)
		if len(w.Repositories) < perPage {
			break
		}
	}
	return out, nil
}

// Org returns one organization.
func (c *Client) Org(ctx context.Context, org string) (Org, error) {
	var o Org
	if !namePattern.MatchString(org) {
		return o, ErrBadName
	}
	_, err := c.get(ctx, "/orgs/"+url.PathEscape(org), nil, &o)
	return o, err
}

// Repo returns one repository.
func (c *Client) Repo(ctx context.Context, owner, repo string) (Repo, error) {
	var r Repo
	p, err := repoPath(owner, repo, "")
	if err != nil {
		return r, err
	}
	_, err = c.get(ctx, p, nil, &r)
	return r, err
}

// OpenPullRequests lists open pull requests.
func (c *Client) OpenPullRequests(ctx context.Context, owner, repo string) ([]PullRequest, error) {
	return repoList[PullRequest](ctx, c, owner, repo, "/pulls", url.Values{"state": {"open"}})
}

// Workflows lists workflow definitions.
func (c *Client) Workflows(ctx context.Context, owner, repo string) ([]Workflow, error) {
	p, err := repoPath(owner, repo, "/actions/workflows")
	if err != nil {
		return nil, err
	}
	var out []Workflow
	for page := 1; page <= maxPages; page++ {
		var w struct {
			Workflows []Workflow `json:"workflows"`
		}
		if _, err := c.get(ctx, p, pageQuery(nil, page), &w); err != nil {
			return nil, err
		}
		out = append(out, w.Workflows...)
		if len(w.Workflows) < perPage {
			break
		}
	}
	return out, nil
}

// CodeScanningAlerts lists open code-scanning alerts.
func (c *Client) CodeScanningAlerts(ctx context.Context, owner, repo string) ([]CodeScanningAlert, error) {
	return repoList[CodeScanningAlert](ctx, c, owner, repo, "/code-scanning/alerts", url.Values{"state": {"open"}})
}

// DependabotAlerts lists open Dependabot alerts.
func (c *Client) DependabotAlerts(ctx context.Context, owner, repo string) ([]DependabotAlert, error) {
	return repoList[DependabotAlert](ctx, c, owner, repo, "/dependabot/alerts", url.Values{"state": {"open"}})
}

// Package is one SBOM package that carries a purl.
type Package struct {
	Name      string
	Version   string
	Purl      string
	Ecosystem string
}

// SBOM reads the repository's dependency graph SBOM and returns its packages
// that have a purl. Packages without a purl (including the repository itself)
// are omitted.
func (c *Client) SBOM(ctx context.Context, owner, repo string) ([]Package, error) {
	p, err := repoPath(owner, repo, "/dependency-graph/sbom")
	if err != nil {
		return nil, err
	}
	var body struct {
		SBOM struct {
			Packages []struct {
				Name         string `json:"name"`
				VersionInfo  string `json:"versionInfo"`
				ExternalRefs []struct {
					Type    string `json:"referenceType"`
					Locator string `json:"referenceLocator"`
				} `json:"externalRefs"`
			} `json:"packages"`
		} `json:"sbom"`
	}
	if _, err := c.get(ctx, p, nil, &body); err != nil {
		return nil, err
	}
	var out []Package
	for _, sp := range body.SBOM.Packages {
		for _, r := range sp.ExternalRefs {
			if strings.EqualFold(r.Type, "purl") && r.Locator != "" {
				pk := Package{Name: sp.Name, Version: sp.VersionInfo, Purl: r.Locator}
				if rest, ok := strings.CutPrefix(strings.ToLower(r.Locator), "pkg:"); ok {
					pk.Ecosystem, _, _ = strings.Cut(rest, "/")
				}
				out = append(out, pk)
				break
			}
		}
	}
	return out, nil
}

// SecretScanningAlerts lists open secret-scanning alert metadata.
func (c *Client) SecretScanningAlerts(ctx context.Context, owner, repo string) ([]SecretScanningAlert, error) {
	return repoList[SecretScanningAlert](ctx, c, owner, repo, "/secret-scanning/alerts", url.Values{"state": {"open"}})
}

// OpenIssueCount returns the number of open issues without reading any issue
// content: it asks for one item per page and reads the last page number from
// the Link header. GitHub counts pull requests as issues here.
func (c *Client) OpenIssueCount(ctx context.Context, owner, repo string) (int, error) {
	p, err := repoPath(owner, repo, "/issues")
	if err != nil {
		return 0, err
	}
	var items []struct {
		Number int `json:"number"`
	}
	h, err := c.get(ctx, p, url.Values{"state": {"open"}, "per_page": {"1"}}, &items)
	if err != nil {
		return 0, err
	}
	if n, ok := lastPage(h.Get("Link")); ok {
		return n, nil
	}
	return len(items), nil
}

var lastRel = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="last"`)

func lastPage(link string) (int, bool) {
	m := lastRel.FindStringSubmatch(link)
	if m == nil {
		return 0, false
	}
	u, err := url.Parse(m[1])
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(u.Query().Get("page"))
	return n, err == nil && n >= 0
}

func repoPath(owner, repo, suffix string) (string, error) {
	if !namePattern.MatchString(owner) || !namePattern.MatchString(repo) ||
		owner == "." || owner == ".." || repo == "." || repo == ".." {
		return "", ErrBadName
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + suffix, nil
}

func repoList[T any](ctx context.Context, c *Client, owner, repo, suffix string, q url.Values) ([]T, error) {
	p, err := repoPath(owner, repo, suffix)
	if err != nil {
		return nil, err
	}
	return list[T](ctx, c, p, q)
}

// list pages through a top-level array response.
func list[T any](ctx context.Context, c *Client, path string, q url.Values) ([]T, error) {
	var out []T
	for page := 1; page <= maxPages; page++ {
		var items []T
		if _, err := c.get(ctx, path, pageQuery(q, page), &items); err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(items) < perPage {
			break
		}
	}
	return out, nil
}

func pageQuery(q url.Values, page int) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = v
	}
	out.Set("per_page", strconv.Itoa(perPage))
	out.Set("page", strconv.Itoa(page))
	return out
}

// get performs one GET and decodes a 2xx JSON body into out.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) (http.Header, error) {
	u := url.URL{Scheme: "https", Host: c.host}
	// path is already escaped per segment; Parse keeps Path and RawPath consistent.
	parsed, err := url.Parse(c.basePath + path)
	if err != nil {
		return nil, ErrBadName
	}
	u.Path, u.RawPath = parsed.Path, parsed.RawPath
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("github: build request: %w", ErrBadName)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err // typed broker errors stay reachable through errors.As
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, &StatusError{Status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, errors.New("github: malformed response")
	}
	return resp.Header, nil
}
