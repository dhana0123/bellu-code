# Scan fixtures (Requirement 23.1)

Offline, deterministic inputs for scanner tests. No secrets. Lock files are minimal
(no integrity hashes) and are not meant to be installable.

| Dir | Files | Packages | Known-vulnerable |
|---|---|---|---|
| `repos/go` | go.mod | golang.org/x/text v0.3.5, gopkg.in/yaml.v2 v2.2.2 | golang.org/x/text 0.3.5 (CVE-2021-38561); yaml.v2 2.2.2 (CVE-2019-11254) |
| `repos/npm` | package.json, package-lock.json | lodash 4.17.20, minimist 1.2.5 | lodash 4.17.20 (CVE-2021-23337); minimist 1.2.5 (CVE-2021-44906) |
| `repos/python` | requirements.txt | requests 2.19.0, PyYAML 5.3, urllib3 1.24.1 | requests 2.19.0 (CVE-2018-18074) |
| `repos/java` | pom.xml | log4j-core 2.14.1, commons-collections 3.2.1 | log4j-core 2.14.1 (CVE-2021-44228) |
| `repos/rust` | Cargo.toml, Cargo.lock | smallvec 0.6.9, time 0.1.43 | time 0.1.43 (CVE-2020-26235); smallvec 0.6.9 (RUSTSEC-2019-0009) |
| `repos/ruby` | Gemfile, Gemfile.lock | rack 2.0.5, nokogiri 1.10.3, mini_portile2 2.4.0 | rack 2.0.5 (CVE-2018-16471) |
| `repos/php` | composer.json, composer.lock | guzzlehttp/guzzle 6.3.0, monolog/monolog 1.25.1 | guzzle 6.3.0 (CVE-2022-29248) |
| `repos/dotnet` | fixture.csproj, packages.lock.json | Newtonsoft.Json 12.0.1, log4net 2.0.8 | Newtonsoft.Json 12.0.1 (CVE-2024-21907) |
| `repos/apk` | lib/apk/db/installed, etc/os-release | libcrypto1.1 1.1.1k-r0, busybox 1.32.1-r5 | libcrypto1.1 1.1.1k-r0 (CVE-2021-3711) |
| `repos/deb` | var/lib/dpkg/status, etc/os-release | zlib1g 1:1.2.11.dfsg-2, tzdata 2021a-1+deb11u1 | zlib1g 1.2.11.dfsg-2 (CVE-2018-25032) |
| `repos/rpm` | README.md only | none | none (gap, see below) |
| `images/sample.tar` | OCI layout, 2 layers | layer 1: apk libcrypto1.1 1.1.1k-r0; layer 2: npm lodash 4.17.20 | both |

CVE ids are the expected matches in public advisory data; confirm against the
vulnerability DB in use before asserting on them.

## Gaps

- `repos/rpm`: the rpm database is binary and cannot be produced offline without rpm tooling.
- `repos/go`: no go.sum. Hashes cannot be computed offline, and Syft's go.mod cataloger does not need it.

## Regenerating sample.tar

`cd images && go run gen.go` (fixed timestamps, byte-identical output).
