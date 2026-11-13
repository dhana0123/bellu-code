// Command bellud is the bellucode Go server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bellu/bellucode/services/bellud/internal/agentcfg"
	apigraph "github.com/bellu/bellucode/services/bellud/internal/api/graph"
	"github.com/bellu/bellucode/services/bellud/internal/auth"
	"github.com/bellu/bellucode/services/bellud/internal/collectors"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/codesec"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/docker"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/host"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/iac"
	"github.com/bellu/bellucode/services/bellud/internal/collectors/secrets"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/logx"
	"github.com/bellu/bellucode/services/bellud/internal/mcptoken"
	"github.com/bellu/bellucode/services/bellud/internal/proxy"
	"github.com/bellu/bellucode/services/bellud/internal/sdnotify"
	"github.com/bellu/bellucode/services/bellud/internal/server"
	"github.com/bellu/bellucode/services/bellud/internal/server/routes"
	"github.com/bellu/bellucode/services/bellud/internal/tschild"
	"github.com/bellu/bellucode/services/bellud/internal/webui"
)

const (
	drainTimeout     = 30 * time.Second
	childStopTimeout = 10 * time.Second
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: bellud serve [--hostname HOST] [--port PORT] [--repo DIR]")
		os.Exit(2)
	}
	if err := serve(os.Args[2:]); err != nil {
		logx.New(os.Stderr).Println("error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	logger := logx.New(os.Stderr)
	cfg, err := config.LoadEnv()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	hostname := fs.String("hostname", cfg.Hostname, "listen hostname")
	port := fs.Int("port", cfg.Port, "listen port")
	repo := fs.String("repo", os.Getenv("BELLUCODE_REPO"), "repository root containing packages/cli")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port %d", *port)
	}
	if strings.TrimSpace(*hostname) == "" {
		return errors.New("invalid empty hostname")
	}
	cfg.Hostname, cfg.Port = *hostname, *port
	for _, w := range cfg.Warnings() {
		logger.Println("warning:", w)
	}

	cliDir, err := findCLIDir(*repo)
	if err != nil {
		return err
	}
	bun, err := findBun()
	if err != nil {
		return err
	}

	table := routes.MustLoadEmbedded()
	// Fails the start when BELLUCODE_WEB_DIST is set but unreadable (no fallback).
	web, err := webui.New(webui.Options{Dir: cfg.WebDist})
	if err != nil {
		return err
	}
	// The MCP token lives in memory only; it is handed to the TS child via agentcfg.
	tok, err := mcptoken.New()
	if err != nil {
		return fmt.Errorf("mcp token: %w", err)
	}
	set, err := mcptoken.NewSet(tok)
	if err != nil {
		return fmt.Errorf("graph tokens: %w", err)
	}
	engine, runner := openGraph(logger, set, scanRoots(filepath.Dir(filepath.Dir(cliDir))))

	if engine != nil {
		if dd, derr := config.DataDir(); derr != nil {
			logger.Println("warning: graph tokens file:", derr)
		} else if werr := writeGraphTokens(dd, set); werr != nil {
			logger.Println("warning: graph tokens file:", werr)
		}
	}

	// Connectors need the open graph engine; nil while the flag is off.
	conn := openConnectors(logger, engine, set, allowedHostsOf(cfg.Hostname))
	closeAll := func() {
		conn.close(logger) // before the graph: its collectors write to the engine
		stopGraph(engine, runner, logger)
	}

	// Bind first so a bind failure never starts the child.
	ln, err := net.Listen("tcp", cfg.Addr())
	if err != nil {
		return fmt.Errorf("bind %s (hostname %q, port %d): %w", cfg.Addr(), cfg.Hostname, cfg.Port, err)
	}

	// Merge mcp.bellu-graph into the child config; an invalid inbound value stops the start.
	inbound, present := os.LookupEnv(agentcfg.EnvConfigContent)
	enabled := false
	if engine != nil {
		k := graph.StateOf(engine).Kind
		enabled = k == graph.StateReady || k == graph.StateStarting
	}
	content, setContent, err := agentcfg.Build(inbound, present, enabled,
		agentcfg.MCPURL(cfg.Hostname, ln.Addr().(*net.TCPAddr).Port), tok.String())
	if err != nil {
		_ = ln.Close()
		closeAll()
		return err
	}
	// The bellu-connectors entry carries only its own MCP token; no credential,
	// master key or passphrase ever reaches the child.
	if conn != nil {
		if content, err = agentcfg.AddConnectors(content, setContent,
			agentcfg.ConnectorsMCPURL(cfg.Hostname, ln.Addr().(*net.TCPAddr).Port), conn.token.Header()); err != nil {
			_ = ln.Close()
			closeAll()
			return err
		}
		setContent = true
	}
	childEnv := map[string]string{}
	if enabled {
		_, userDirSet := os.LookupEnv(agentcfg.EnvConfigDir)
		genDir := ""
		if cd, cerr := config.ConfigDir(); cerr == nil {
			genDir = filepath.Join(cd, agentcfg.GeneratedDirName)
		}
		plan := agentcfg.PlanDefinitions(userDirSet || genDir == "", genDir)
		if plan.Warn != nil {
			logger.Println("warning:", plan.Warn)
		}
		if plan.ConfigDir != "" {
			childEnv[agentcfg.EnvConfigDir] = plan.ConfigDir
		}
		if plan.Inject {
			if content, err = agentcfg.InjectDefinitions(content, setContent); err != nil {
				_ = ln.Close()
				closeAll()
				return err
			}
			setContent = true
		}
	}
	if setContent {
		childEnv[agentcfg.EnvConfigContent] = content
	}

	sup := tschild.New(tschild.Config{
		Env:     childEnv,
		Command: []string{bun, "run", "src/index.ts", "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"},
		Dir:     cliDir,
		Logger:  logger,
	})
	var origins []string
	for _, o := range strings.Split(cfg.CORS, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	authn := auth.New(cfg.Password)
	handler := &server.Server{
		Table:  table,
		Auth:   authn,
		Go:     conn.wrap(goHandler(engine, set, func() apigraph.ChildState { return apigraph.ChildStateOf(sup.State()) })),
		GoAuth: conn.auth(graphGoAuth(table, set, authn.Authorize)),
		Proxy:  proxy.New(sup.Current),
		CORS:   origins,
		Web:    web,
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(context.Background()); err != nil {
		_ = ln.Close()
		closeAll()
		return err
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Println("listening on", ln.Addr())
	if _, err := sdnotify.Ready(); err != nil {
		logger.Println("warning: sd_notify:", err)
	}

	select {
	case err := <-serveErr:
		closeAll()
		stopChild(sup, logger)
		return err
	case <-ctx.Done():
	}

	logger.Println("shutting down")
	closeAll()
	var forced bool
	drain, cancel := context.WithTimeout(context.Background(), drainTimeout)
	if err := srv.Shutdown(drain); err != nil {
		forced = true
		logger.Println("drain incomplete, forcing close:", err)
		_ = srv.Close()
	}
	cancel()
	if err := stopChild(sup, logger); err != nil {
		forced = true
	}
	if forced {
		return errors.New("forced shutdown")
	}
	return nil
}

// openGraph opens the graph engine and, when it is enabled and ready, starts the
// collector runner. A failed open leaves the engine disabled; serving continues.
func openGraph(logger *log.Logger, set mcptoken.Set, roots []string) (graph.Engine, *collectors.Runner) {
	gcfg, err := graph.LoadConfig()
	if err != nil {
		logger.Println("warning: graph config:", err)
		return nil, nil
	}
	gcfg.MCPToken = set.Write.String()
	gcfg.Grants = grantsOf(set)
	eng, err := graph.Open(context.Background(), gcfg)
	if err != nil {
		logger.Println("warning: graph unavailable:", err)
		return nil, nil
	}
	if graph.StateOf(eng).Kind != graph.StateReady {
		return eng, nil
	}
	cols := []collectors.Collector{
		host.New(15 * time.Second),
		docker.New(docker.WithInterval(30 * time.Second)),
	}
	if len(roots) > 0 {
		cols = append(cols, codesec.New(roots...), iac.New(roots...), secrets.New(roots...))
	}
	r := collectors.New(eng, cols, collectors.WithLogger(logger))
	r.Start(context.Background())
	return eng, r
}

// stopGraph stops the runner, then closes the engine.
func stopGraph(eng graph.Engine, r *collectors.Runner, logger *log.Logger) {
	if r != nil {
		r.Stop()
	}
	if eng == nil {
		return
	}
	c, cancel := context.WithTimeout(context.Background(), childStopTimeout)
	defer cancel()
	if err := eng.Close(c); err != nil {
		logger.Println("graph close:", err)
	}
}

func stopChild(sup *tschild.Supervisor, logger interface{ Println(...any) }) error {
	c, cancel := context.WithTimeout(context.Background(), childStopTimeout)
	defer cancel()
	if err := sup.Stop(c); err != nil {
		logger.Println("child stop forced:", err)
		return err
	}
	return nil
}

// goHandler serves the Go-owned routes: the MCP endpoint and the graph read API.
func goHandler(eng graph.Engine, set mcptoken.Set, child func() apigraph.ChildState) http.Handler {
	var mcp http.Handler
	if eng == nil {
		mcp = graph.UnavailableHandler("graph disabled")
	} else {
		mcp = eng.MCPHandler()
	}
	api := apigraph.New(eng, child)
	mux := http.NewServeMux()
	hs := graph.HandlersOf(eng)
	mux.Handle(apigraph.Prefix+"/mcp", mcp)
	mux.Handle(apigraph.Prefix+"/graphql", hs.GraphQL)
	mux.Handle(apigraph.Prefix+"/subscribe", hs.Subscribe)
	mux.Handle(apigraph.Prefix+"/debug", hs.Debug)
	mux.Handle(apigraph.Prefix+"/debug/", hs.Debug)
	mux.Handle(apigraph.Prefix+"/metrics", hs.Metrics)
	mux.Handle("/", api) // reads and POST /batches
	return roleMiddleware(set, mux)
}

// scanRoots returns the code scan roots from BELLUCODE_SCAN_ROOTS (colon
// separated), defaulting to the repository root.
func scanRoots(repo string) []string {
	var out []string
	for _, r := range strings.Split(os.Getenv("BELLUCODE_SCAN_ROOTS"), ":") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	if len(out) == 0 && repo != "" {
		out = []string{repo}
	}
	return out
}

// findCLIDir resolves <repo>/packages/cli from the flag/env or by walking up from the executable and cwd.
func findCLIDir(repo string) (string, error) {
	if repo != "" {
		d := filepath.Join(repo, "packages", "cli")
		if isDir(d) {
			return d, nil
		}
		return "", fmt.Errorf("repo %q has no packages/cli", repo)
	}
	var starts []string
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, s := range starts {
		for d := s; ; d = filepath.Dir(d) {
			if c := filepath.Join(d, "packages", "cli"); isDir(c) {
				return c, nil
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	}
	return "", errors.New("cannot find packages/cli; set --repo or BELLUCODE_REPO")
}

func findBun() (string, error) {
	if p, err := exec.LookPath("bun"); err == nil {
		return p, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".bun", "bin", "bun")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("bun not found in PATH or ~/.bun/bin")
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }
