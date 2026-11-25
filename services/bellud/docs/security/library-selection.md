# Scanner library selection and binary size (task 1.5)

Measured 2026-11-25 inside `services/bellud` with the real `go.mod`, Go 1.27.4, linux/amd64.
Requirements: 19.6, 19.7, 19.8, 19.10, 19.12.

## Pinned versions

Re-verified against each repository's `releases/latest` and license metadata on 2026-11-25. All matched the design's library table.

| Module | Version in `go.mod` | SPDX | Note |
|---|---|---|---|
| `github.com/anchore/syft` | v1.57.2 | Apache-2.0 | |
| `github.com/anchore/grype` | v0.122.1 | Apache-2.0 | |
| `github.com/google/osv-scanner/v2` | v2.7.2-0.20261123234433-66586f4a200a | Apache-2.0 | Pseudo-version after v2.7.1, see Conflicts |
| `github.com/aquasecurity/trivy` | v0.76.2 | Apache-2.0 | Only `pkg/iac/...` is imported |
| `github.com/aquasecurity/trivy-checks` | v1.12.2-0.20261012053351-ac85645895ed (indirect) | MIT | Selected by Trivy v0.76.2, see Conflicts |
| `github.com/zricethezav/gitleaks/v8` | v8.30.1 | MIT | |
| `github.com/open-policy-agent/opa` | v1.22.4 | Apache-2.0 | Imported as `opa/v1/rego` |
| `github.com/CycloneDX/cyclonedx-go` | v0.12.0 | Apache-2.0 | Pinned by task 13.1 (`internal/bom`); latest release on 2026-11-25 |
| `github.com/spdx/tools-golang` | v0.6.0-rc4 | Apache-2.0 | Pinned by task 13.2 (`internal/bom`); Apache-2.0 elected, see below |
| `github.com/google/osv-scalibr` | v0.5.4-0.20261125003509-1fc6960339c3 (indirect) | Apache-2.0 | Raised from the version osv-scanner selects |

CycloneDX Go was already in the module graph as an indirect dependency at the same version, so pinning it did not change any other module version.

`spdx/tools-golang` is pinned at v0.6.0-rc4, not at the latest release (v0.5.7, 2026-01-12). Syft v1.57.2 and Grype v0.122.1 already require v0.6.0-rc4, so Go selects it for every build whatever version `go.mod` names; pinning v0.5.7 would only record a version that is never compiled. `internal/bom` uses only the `spdx/v2/v2_3` and `spdx/v2/common` types, which are the same in both. Move to v0.6.0 when it is released.

License election: the tools-golang source (`LICENSE.code`) is offered under Apache-2.0 OR GPL-2.0-or-later (not CDLA-Permissive-1.0). We elect Apache-2.0 from the dual license and record plain `Apache-2.0` in `THIRD_PARTY_LICENSES`. The documentation license (CC-BY-4.0) does not apply to the code we link.
`THIRD_PARTY_LICENSES` lists the eight direct modules above; the checker accepts direct requirements only.
`go-licenses` over the probe's dependency graph found no AGPL, GPL, LGPL or SSPL package. It reported "Unknown" for `github.com/xi2/xz` (public domain), `modernc.org/mathutil` (BSD-3-Clause) and the probe package itself. Those need a manual entry in the reviewed exceptions flow if the CI check is widened to the scanner build tags.

## Size measurement

`script/check-binary-size.sh` builds `cmd/sizeprobe` with `-trimpath -ldflags "-s -w"` twice and fails when the difference exceeds 157,286,400 bytes (150 MiB).

- Baseline (`-tags sizeprobe,sizebase`, no scanner imports): 1,507,488 bytes.
- Probe with `-tags sizeprobe,osvmatch` (Syft, Grype, OSV-Scanner, Trivy IaC scanners with embedded trivy-checks, Gitleaks, OPA): 138,911,904 bytes. Delta 137,404,416 bytes (131 MiB), 19.9 MiB under budget.
- Probe with `-tags sizeprobe` (no OSV-Scanner): 121,032,864 bytes. Delta 119,525,376 bytes (113 MiB). OSV-Scanner adds about 18 MiB.

The probe references real entry points (`syft.CreateSBOM`, `grype.LoadVulnerabilityDB`, the Trivy scanner constructors and `rego.LoadAndRegister`, `detect.NewDetector`, `opa/v1/rego.New`, `osvscanner.DoScan`) so the linker keeps the cataloging and matching code, not only package init.

**Mitigation: none applied.** The budget holds with OSV-Scanner included, so the design's mitigation list was not needed. The release build keeps `osvmatch` behind its tag, so a slim build is available (about 18 MiB smaller). Later tasks that wire real adapters can link more of each library than the probe does, so rerun `script/check-binary-size.sh` when they land. The headroom is about 19.9 MiB.

The script is not part of `go build ./...`: the probe sits behind the `sizeprobe` tag, so the default `bellud` binary does not link the scanners.

## Conflicts

1. **`gobwas/glob` v0.2.3 vs v1.x (the earlier spike's blocker, confirmed and resolved).** v1.0.0 replaced the `glob.Glob` interface with `*glob.Pattern`. OPA v1.22.4 requires `gobwas/glob` v1.1.0, and Trivy v0.76.2 requires v1.0.0. `osv-scanner` v2.7.1 and the `osv-scalibr` it selects (v0.5.4-0.20261105012210-c80efcc25cd9) still used `glob.Glob`, so the build failed with `undefined: glob.Glob`. Upstream fixed both after the releases. The minimal fix is two pins: `osv-scanner/v2` at commit 66586f4 (2026-11-24, `go.mod` requires glob v1.0.0) and `osv-scalibr` at commit 1fc6960 (2026-11-24, glob v1.0.0). OSV-Scanner therefore uses a pseudo-version until a release after v2.7.1 ships. Move to that release when it exists and update the table and `THIRD_PARTY_LICENSES`.
2. **trivy-checks v2.3.0 cannot be used.** The design lists v2.3.0, but the repository's v2 tags keep the module path `github.com/aquasecurity/trivy-checks` without a `/v2` suffix, so Go rejects them. Trivy v0.76.2 itself requires `v1.12.2-0.20261012053351-ac85645895ed`, which Go selects. The design table should record that version, not v2.3.0.
3. **Existing dependency upgrades.** The scanners' requirements raised 25 existing `go.mod` entries through minimum version selection, including these direct ones: `prometheus/common` v0.42.0 to v0.72.0, `prometheus/client_golang` v1.15.0 to a newer minor, `klauspost/compress`, `hashicorp/hcl/v2`, `vektah/gqlparser/v2`, `gorilla/websocket` (now a pseudo-version), `modelcontextprotocol/go-sdk` (v1.6.1 to v1.8.0), `oklog/ulid/v2`, plus `zclconf/go-cty`, `google.golang.org/grpc`, `google.golang.org/protobuf` and `golang.org/x/oauth2` as indirect. Nothing was downgraded. See `git diff go.mod` for the exact list.
4. **One existing test needed a one-line fix.** `internal/bellugraph/internal/bge/metrics/metrics_test.go` used a zero-value `expfmt.TextParser`. `prometheus/common` v0.72 panics on an unset name-validation scheme, so the test now uses `expfmt.NewTextParser(model.UTF8Validation)`. No production code changed.
5. **Pre-existing failure, unrelated.** `internal/contract` `TestNoSQLiteAccess` fails on the original `go.mod` as well (it flags `database/sql` in `internal/cce` and `internal/scanners/manager.go`).
