# bellugraph-conformance

Validate a producer's OTLP entity-event output against the Bellu Graph Engine wire contract,
without a running Bellu Graph Engine. Works for producers in **any language** — feed it the
bytes your producer would export.

## Install

```bash
go install github.com/bellu/bellucode/services/bellud/internal/bellugraph/pkg/emit/cmd/bellugraph-conformance@latest
```

## Use

```bash
# a captured OTLP ExportLogsServiceRequest (protobuf or JSON, auto-detected)
bellugraph-conformance producer-output.bin

# or straight from stdin
my-producer --dump-otlp | bellugraph-conformance

# force a format, and treat advisories as failures (CI)
bellugraph-conformance -format json -strict batch.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Conformant — Bellu Graph Engine accepts the records without per-record rejection. |
| 1 | Rejections found (or advisories under `-strict`); fix the producer. |
| 2 | Usage or decode error. |

*Advisory* problems (e.g. a missing `service.instance.id`, which collapses
per-producer liveness reference counting) are reported but do not fail the run
unless `-strict` is set.

Go producers can also import [`pkg/emit/conformance`](../../conformance) and
check the `plog.Logs` they build directly in their tests, against the same
byte-pinned contract fixture.
