# Changes from upstream

Upstream base commit: 340268a70a83588d6b3c6de1fffb05326350ef1d

Every path in this directory that differs from the Base Manifest in
`PROVENANCE.md` is listed here with its change type (added, removed, changed).
Every modified Python file must carry an Apache-2.0 section 4(b) change notice
within its first 30 lines. No Python file has been modified so far.

## 1. Rename to bellu-graphify (2026-11-19)

The directory and the Python distribution are named `bellu-graphify`. The
import package stays `graphify` so later upstream merges stay small.

| Path | Change type | Note |
| --- | --- | --- |
| `pyproject.toml` | changed | `[project] name` changed from `graphifyy` to `bellu-graphify` |
| `uv.lock` | changed | package entry name changed from `graphifyy` to `bellu-graphify` to match |
| `README.md` | changed | Replaced by the Bellu README. The upstream text moved to `UPSTREAM_README.md` |
| `UPSTREAM_README.md` | added | Upstream `README.md`, byte-identical |
| `NOTICE` | changed | Upstream lines kept unchanged and in order; Bellu attribution lines appended |
| `PROVENANCE.md` | added | Upstream origin and Base Manifest |
| `CHANGES.md` | added | This file |

`LICENSE` is byte-identical to upstream.
