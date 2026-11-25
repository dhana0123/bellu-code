package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/config"
)

// securityPoll is the interval between job polls of `scan --wait`.
var securityPoll = 2 * time.Second

var (
	scanKinds       = []string{"sbom", "vulnerability", "misconfiguration", "secret", "posture", "data_classification", "ai_inventory"}
	scanTargetTypes = []string{"repository", "image", "host", "cloud_account", "cluster"}
)

// securityEnv carries the process inputs of the security command group.
type securityEnv struct {
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
}

// runSecurity runs `bellud security scan|findings|sbom` and returns the exit
// code. Output is buffered: on any error nothing reaches stdout, and the cause
// is written to stderr. The commands need a running server; there is no
// in-process mode.
func runSecurity(args []string, env securityEnv) int {
	var out bytes.Buffer
	if err := securityCommand(args, env, &out); err != nil {
		fmt.Fprintln(env.stderr, "error:", err)
		if errors.Is(err, errSecurityUsage) {
			return 2
		}
		return 1
	}
	if _, err := env.stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintln(env.stderr, "error:", err)
		return 1
	}
	return 0
}

var errSecurityUsage = errors.New("usage")

func usageErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errSecurityUsage, fmt.Sprintf(format, a...))
}

func securityCommand(args []string, env securityEnv, out *bytes.Buffer) error {
	if len(args) == 0 {
		return usageErr("bellud security scan|findings|sbom [flags]")
	}
	fs := flag.NewFlagSet("security "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "server URL (default from BELLUCODE_HOSTNAME and BELLUCODE_PORT)")
	if args[0] == "cve" {
		return cveCommand(args[1:], env, out)
	}
	switch args[0] {
	case "scan":
		kind := fs.String("kind", "", "scan kind: "+strings.Join(scanKinds, ", "))
		ttype := fs.String("target-type", "", "target type: "+strings.Join(scanTargetTypes, ", "))
		target := fs.String("target", "", "target id")
		wait := fs.Bool("wait", false, "wait for the job to finish")
		if err := parseSecurity(fs, args[1:]); err != nil {
			return err
		}
		if err := oneOf("kind", *kind, scanKinds); err != nil {
			return err
		}
		if err := oneOf("target-type", *ttype, scanTargetTypes); err != nil {
			return err
		}
		if strings.TrimSpace(*target) == "" {
			return usageErr("--target is required")
		}
		c, err := newSecurityClient(env, *server)
		if err != nil {
			return err
		}
		return c.scan(*kind, *ttype, *target, *wait, out)
	case "findings":
		sev := fs.String("severity", "", "severity filter")
		status := fs.String("status", "", "status filter")
		cat := fs.String("category", "", "category filter")
		limit := fs.Int("limit", 50, "maximum findings (1 to 500)")
		format := fs.String("output", "table", "output format: table or json")
		if err := parseSecurity(fs, args[1:]); err != nil {
			return err
		}
		if *limit < 1 || *limit > 500 {
			return usageErr("--limit must be between 1 and 500")
		}
		if err := oneOf("output", *format, []string{"table", "json"}); err != nil {
			return err
		}
		c, err := newSecurityClient(env, *server)
		if err != nil {
			return err
		}
		q := url.Values{"limit": {fmt.Sprint(*limit)}}
		for k, v := range map[string]string{"severity": *sev, "status": *status, "category": *cat} {
			if v != "" {
				q.Set(k, v)
			}
		}
		return c.findings(q, *format == "json", out)
	case "sbom":
		asset := fs.String("asset", "", "asset id; omit to list SBOMs")
		format := fs.String("format", "cyclonedx", "document format: cyclonedx or spdx")
		outFile := fs.String("out", "", "write the document to this file instead of stdout")
		if err := parseSecurity(fs, args[1:]); err != nil {
			return err
		}
		if err := oneOf("format", *format, []string{"cyclonedx", "spdx"}); err != nil {
			return err
		}
		if *outFile != "" && *asset == "" {
			return usageErr("--out requires --asset")
		}
		c, err := newSecurityClient(env, *server)
		if err != nil {
			return err
		}
		return c.sbom(*asset, *format, *outFile, out)
	}
	return usageErr("unknown security command %q (want scan, findings, sbom or cve)", args[0])
}

func parseSecurity(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func oneOf(name, v string, allowed []string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	if v == "" {
		return usageErr("--%s is required (one of %s)", name, strings.Join(allowed, ", "))
	}
	return usageErr("--%s %q must be one of %s", name, v, strings.Join(allowed, ", "))
}

// securityClient calls the experimental HTTP API with the local credential.
type securityClient struct {
	base     string
	password string
	http     *http.Client
}

func newSecurityClient(env securityEnv, server string) (*securityClient, error) {
	cfg, err := config.Load(env.getenv)
	if err != nil {
		return nil, err
	}
	base := server
	if base == "" {
		base = "http://" + cfg.Addr()
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, usageErr("invalid --server %q", base)
	}
	return &securityClient{base: strings.TrimRight(base, "/"), password: cfg.Password, http: &http.Client{Timeout: 5 * time.Minute}}, nil
}

// do performs a request and returns the body of a 2xx answer. A refused
// connection reports that the server is not running.
func (c *securityClient) do(method, path string, q url.Values, body any) ([]byte, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.password != "" {
		req.SetBasicAuth(auth.Username, c.password)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the bellud server at %s (security commands need a running server; start it with `bellud serve`): %w", c.base, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("server answered %d: %s", res.StatusCode, apiMessage(data))
	}
	return data, nil
}

func apiMessage(data []byte) string {
	var e struct {
		Message string `json:"message"`
		Param   string `json:"param"`
	}
	if json.Unmarshal(data, &e) == nil && e.Message != "" {
		if e.Param != "" {
			return e.Param + ": " + e.Message
		}
		return e.Message
	}
	if s := strings.TrimSpace(string(data)); s != "" {
		return s
	}
	return "no detail"
}

type scanJob struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	TargetType string `json:"targetType"`
	TargetID   string `json:"targetId"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Resolved   int    `json:"resolved"`
}

func (j scanJob) line() string {
	s := fmt.Sprintf("job %s %s (created %d, updated %d, resolved %d)", j.ID, j.Status, j.Created, j.Updated, j.Resolved)
	if j.Reason != "" {
		s += ": " + j.Reason
	}
	return s
}

func (c *securityClient) scan(kind, ttype, target string, wait bool, out *bytes.Buffer) error {
	data, err := c.do(http.MethodPost, "/api/experimental/scans", nil, map[string]string{"kind": kind, "targetType": ttype, "targetId": target})
	if err != nil {
		return err
	}
	var job scanJob
	if err := json.Unmarshal(data, &job); err != nil {
		return fmt.Errorf("decode scan job: %w", err)
	}
	for wait {
		switch job.Status {
		case "failed", "cancelled":
			return fmt.Errorf("%s", job.line())
		case "succeeded", "skipped_unchanged":
			wait = false
			continue
		}
		time.Sleep(securityPoll)
		data, err = c.do(http.MethodGet, "/api/experimental/scans/"+url.PathEscape(job.ID), nil, nil)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &job); err != nil {
			return fmt.Errorf("decode scan job: %w", err)
		}
	}
	fmt.Fprintln(out, job.line())
	return nil
}

func (c *securityClient) findings(q url.Values, asJSON bool, out *bytes.Buffer) error {
	data, err := c.do(http.MethodGet, "/api/experimental/findings", q, nil)
	if err != nil {
		return err
	}
	if asJSON {
		out.Write(bytes.TrimSpace(data))
		out.WriteByte('\n')
		return nil
	}
	var page struct {
		Items []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Category string `json:"category"`
			AssetID  string `json:"assetId"`
			Title    string `json:"title"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return fmt.Errorf("decode findings: %w", err)
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tCATEGORY\tASSET\tTITLE")
	for _, f := range page.Items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.Severity, f.Status, f.Category, f.AssetID, f.Title)
	}
	return tw.Flush()
}

func (c *securityClient) sbom(asset, format, outFile string, out *bytes.Buffer) error {
	if asset == "" {
		data, err := c.do(http.MethodGet, "/api/experimental/sbom", nil, nil)
		if err != nil {
			return err
		}
		var list struct {
			Items []struct {
				AssetID      string `json:"assetId"`
				PackageCount int    `json:"packageCount"`
				CreatedAt    string `json:"createdAt"`
			} `json:"items"`
		}
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("decode sbom list: %w", err)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ASSET\tPACKAGES\tCREATED")
		for _, s := range list.Items {
			fmt.Fprintf(tw, "%s\t%d\t%s\n", s.AssetID, s.PackageCount, s.CreatedAt)
		}
		return tw.Flush()
	}
	data, err := c.do(http.MethodGet, "/api/experimental/sbom/"+url.PathEscape(asset)+"/export", url.Values{"format": {format}}, nil)
	if err != nil {
		return err
	}
	if outFile == "" {
		out.Write(data)
		return nil
	}
	if err := os.WriteFile(outFile, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (%d bytes)\n", outFile, len(data))
	return nil
}

// cveCommand runs `security cve status|lookup`.
func cveCommand(args []string, env securityEnv, out *bytes.Buffer) error {
	if len(args) == 0 {
		return usageErr("bellud security cve status|lookup [flags]")
	}
	fs := flag.NewFlagSet("security cve "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "server URL (default from BELLUCODE_HOSTNAME and BELLUCODE_PORT)")
	format := fs.String("output", "table", "output format: table or json")
	switch args[0] {
	case "status":
		if err := parseSecurity(fs, args[1:]); err != nil {
			return err
		}
		if err := oneOf("output", *format, []string{"table", "json"}); err != nil {
			return err
		}
		c, err := newSecurityClient(env, *server)
		if err != nil {
			return err
		}
		data, err := c.do(http.MethodGet, "/api/experimental/cve/status", nil, nil)
		if err != nil {
			return err
		}
		return printCVE(data, *format == "json", []string{"mode", "dbInstalled", "dataAge", "stale", "bskgReachable", "lastGap"}, out)
	case "lookup":
		id := fs.String("id", "", "CVE or advisory id")
		purl := fs.String("purl", "", "package URL")
		version := fs.String("version", "", "package version (with --purl)")
		if err := parseSecurity(fs, args[1:]); err != nil {
			return err
		}
		if err := oneOf("output", *format, []string{"table", "json"}); err != nil {
			return err
		}
		if (*id == "") == (*purl == "") {
			return usageErr("exactly one of --id or --purl is required")
		}
		if *purl != "" && *version == "" {
			return usageErr("--version is required with --purl")
		}
		if *id != "" && *version != "" {
			return usageErr("--version only applies to --purl")
		}
		c, err := newSecurityClient(env, *server)
		if err != nil {
			return err
		}
		q := url.Values{}
		for k, v := range map[string]string{"id": *id, "purl": *purl, "version": *version} {
			if v != "" {
				q.Set(k, v)
			}
		}
		data, err := c.do(http.MethodGet, "/api/experimental/cve/lookup", q, nil)
		if err != nil {
			return err
		}
		return printCVE(data, *format == "json", nil, out)
	}
	return usageErr("unknown cve command %q (want status or lookup)", args[0])
}

// printCVE writes a JSON object as indented JSON or as a key/value table.
// Listed keys come first; any further keys follow alphabetically.
func printCVE(data []byte, asJSON bool, first []string, out *bytes.Buffer) error {
	if asJSON {
		out.Write(bytes.TrimSpace(data))
		out.WriteByte('\n')
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("decode cve response: %w", err)
	}
	keys := []string{}
	seen := map[string]bool{}
	for _, k := range first {
		if _, ok := m[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	rest := []string{}
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, k := range append(keys, rest...) {
		v := m[k]
		switch x := v.(type) {
		case nil:
			v = "-"
		case map[string]any, []any:
			b, _ := json.Marshal(x)
			v = string(b)
		}
		fmt.Fprintf(tw, "%s\t%v\n", strings.ToUpper(k[:1])+k[1:], v)
	}
	return tw.Flush()
}
