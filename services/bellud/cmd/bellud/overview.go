package main

import (
	"context"
	apidata "github.com/bellu/bellucode/services/bellud/internal/api/data"
	apirules "github.com/bellu/bellucode/services/bellud/internal/api/rules"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/dataclass"
	"net/http"

	apibom "github.com/bellu/bellucode/services/bellud/internal/api/bom"
	apicve "github.com/bellu/bellucode/services/bellud/internal/api/cve"
	apifindings "github.com/bellu/bellucode/services/bellud/internal/api/findings"
	apiissues "github.com/bellu/bellucode/services/bellud/internal/api/issues"
	apiov "github.com/bellu/bellucode/services/bellud/internal/api/overview"
	apisbom "github.com/bellu/bellucode/services/bellud/internal/api/sbom"
	apiscans "github.com/bellu/bellucode/services/bellud/internal/api/scans"
	"github.com/bellu/bellucode/services/bellud/internal/config"
	"github.com/bellu/bellucode/services/bellud/internal/cveupdate"
	"github.com/bellu/bellucode/services/bellud/internal/findings"
	"github.com/bellu/bellucode/services/bellud/internal/graph"
	"github.com/bellu/bellucode/services/bellud/internal/graph/schemaall"
	"github.com/bellu/bellucode/services/bellud/internal/overview"
	"github.com/bellu/bellucode/services/bellud/internal/scanners/sbomstore"
)

// overviewFlag is the feature flag guarding the overview API.
const overviewFlag = "security_overview"

// scannersFlag is the feature flag guarding the SBOM and BOM routes.
const scannersFlag = "security_scanners"

// overviewWiring is the running overview service. It is nil while the flag is
// off, the graph engine is not ready, or the service fails to start.
type overviewWiring struct {
	svc    *overview.Service
	cancel context.CancelFunc
}

// openOverview starts the overview service. Findings may be nil (the severity
// counts are then zero). Any failure yields nil and serving continues.
func openOverview(logger interface{ Println(...any) }, getenv func(string) string, eng graph.Engine, fnd *findingsWiring) *overviewWiring {
	if !config.FeatureEnabled(getenv, overviewFlag, graph.IsRelease()) {
		return nil
	}
	if eng == nil || graph.StateOf(eng).Kind != graph.StateReady {
		logger.Println("warning: overview unavailable: graph engine is not ready")
		return nil
	}
	reg, err := schemaall.Default()
	if err != nil {
		logger.Println("warning: overview unavailable:", err)
		return nil
	}
	svc := overview.New(eng, reg, nil, nil, cveupdate.CLIWorkspace)
	if fnd != nil { // the contract test keeps database/sql out of cmd, so no typed local
		svc = overview.New(eng, reg, fnd.store, fnd.db.DB(), cveupdate.CLIWorkspace)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.Start(ctx); err != nil {
		cancel()
		logger.Println("warning: overview unavailable:", err)
		return nil
	}
	return &overviewWiring{svc: svc, cancel: cancel}
}

// securityHandler mounts the findings and overview routes in front of next.
// The routes always exist because the route table owns them; a flag that is off
// (or a missing service) makes them answer 404.
func securityHandler(getenv func(string) string, fnd *findingsWiring, ov *overviewWiring, pw *postureWiring, eng graph.Engine, next http.Handler) http.Handler {
	release := graph.IsRelease()
	var store *findings.Store
	if fnd != nil {
		store = fnd.store
	}
	var src apiov.Source
	if ov != nil {
		src = ov.svc
	}
	var scanDeps apiscans.Deps
	if fnd != nil {
		scanDeps = apiscans.Deps{Orch: fnd.mgr, Adapters: fnd.scannerList}
	}
	mux := http.NewServeMux()
	apiscans.Mount(mux, scanDeps, config.FeatureEnabled(getenv, scannersFlag, release))
	apifindings.Mount(mux, store, config.FeatureEnabled(getenv, findingsFlag, release))
	apiov.Mount(mux, src, config.FeatureEnabled(getenv, overviewFlag, release))
	var sboms *sbomstore.Store // shares the findings workspace database
	if fnd != nil {
		sboms = sbomstore.New(fnd.db)
	}
	scanners := config.FeatureEnabled(getenv, scannersFlag, release)
	var cveDeps apicve.Deps
	if fnd != nil && fnd.cve != nil {
		cveDeps = apicve.Deps{Source: fnd.cve, Modes: fnd.cve}
	}
	apicve.Mount(mux, cveDeps, apicve.Flags{Scanners: scanners, Graph: config.FeatureEnabled(getenv, cveGraphFlag, release)})
	apisbom.Mount(mux, sboms, scanners)
	apibom.Mount(mux, sboms, scanners)
	apiissues.Mount(mux, pw.issueStore(), fndStore(store), config.FeatureEnabled(getenv, postureFlag, release))
	posture := config.FeatureEnabled(getenv, postureFlag, release)
	var auditor apirules.Auditor
	if re := pw.rulesEngine(); re != nil {
		auditor = pw.engine
	}
	apirules.Mount(mux, pw.rulesEngine(), auditor, posture)
	deps := apidata.Deps{}
	if eng != nil {
		deps.Graph = eng.Query()
	}
	if fnd != nil {
		deps.Classes = dataclass.NewResults(fnd.db)
		deps.Findings = fnd.store
	}
	apidata.Mount(mux, deps, posture)
	mux.Handle("/", next)
	return mux
}

// stop ends the background loop. Safe on nil.
func (o *overviewWiring) stop() {
	if o != nil {
		o.cancel()
	}
}

// fndStore avoids a typed nil in the interface the issues handler takes.
func fndStore(s *findings.Store) apiissues.Findings {
	if s == nil {
		return nil
	}
	return s
}
