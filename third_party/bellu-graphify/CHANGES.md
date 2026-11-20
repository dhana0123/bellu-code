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


| `requirements.lock` | added | Hash-pinned dependency lock for offline install (task 1.4) |
| `wheelhouse/` | added | Vendored wheels for CPython 3.13 and 3.14, `MISSING.txt` lists gaps (task 1.4) |
| `scripts/bellu_install_offline.py` | added | Offline installer into the private virtual environment |
| `scripts/bellu_refresh_wheelhouse.py` | added | Maintainer tool that regenerates the lock and wheelhouse from `uv.lock` |
| `scripts/bellu_graphify_check.py` | added | `bellu-graphify-check`: offline hard-copy integrity check (task 1.5) |
| `bellu_graphify/` | added | Bellu wrapper package: `build_code_graph`, guard, provenance, `DirtyTree` (task 1.7) |
| `bellu_graphify/confidence.py` | added | Graphify confidence tag to Bellu state and confidence mapping, edge rejection (task 1.11) |
| `bellu_graphify/xrefs.py` | added | `propose_xrefs`: cross-graph proposals only (task 1.11) |
| `tests/test_bellu_graphify_confidence.py` | added | Tests for confidence mapping and xref proposals (task 1.11) |
| `tests/test_bellu_graphify_wrapper.py` | added | Wrapper guard, dirty-tree, Pass 3 and provenance tests (task 1.7) |
| `tests/test_bellu_graphify_check_property.py` | added | Property 3 test for `bellu-graphify-check` (task 1.6) |
| `bellu_graphify/bundle.py` | added | Code_Graph_Bundle writer, retention, `dirty` label, as-of reads (task 1.13) |
| `tests/test_bellu_bundle.py` | added | Bundle layout, retention, dirty, as-of and cache-reuse tests (task 1.13) |
| `bellu_graphify/symbol_ids.py` | added | `assign_symbol_ids`: stable `bid` assignment with collision tie-break (task 1.8) |
| `tests/test_bellu_symbol_ids.py` | added | Golden `bid` vectors, permutation and collision tests (task 1.8) |

`LICENSE` is byte-identical to upstream.
