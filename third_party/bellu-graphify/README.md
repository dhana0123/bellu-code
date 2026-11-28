# bellu-graphify

## What it is

A hard copy of [Graphify](https://github.com/Graphify-Labs/graphify), a tool that turns code, documents and other files into a queryable knowledge graph. Bellu uses it as the Graph 1 (code intelligence) extractor. The files are ordinary committed files in this repository: no symlink, no git submodule, no download stub. The distribution is named `bellu-graphify`; the Python import package is still `graphify`.

## Upstream origin

| Field | Value |
| --- | --- |
| Repository URL | https://github.com/Graphify-Labs/graphify |
| Release tag | v0.9.112 |
| Commit SHA | 340268a70a83588d6b3c6de1fffb05326350ef1d |
| Archive SHA256 | db2d81b66a2e521d2243bcaeb1d6d09abf0b60d4f87211b617c859ca7efc1759 |

Copy date and the per-file Base Manifest are in `PROVENANCE.md`. The upstream README is kept as `UPSTREAM_README.md`.

## Licence

Apache-2.0. `LICENSE` is byte-identical to upstream. `NOTICE` keeps every upstream line unchanged and in order, then adds Bellu attribution lines. Some early contributions were made under MIT; that text is kept in `LICENSE-MIT`. Under Apache-2.0 section 4(b), every Python file Bellu modifies carries a change notice within its first 30 lines.

## What Bellu changed

See `CHANGES.md`, which lists every file that differs from the Base Manifest by path and change type, with the upstream base commit. At the time of the first commit the changes are the rename (`pyproject.toml`, `uv.lock`), this README, and the provenance files.

## How to update from upstream

1. Fetch the new upstream archive once (tag or PyPI sdist) and record its URL, tag, full commit SHA and SHA256.
2. Three-way merge: base is the Base Manifest in `PROVENANCE.md`, ours is this directory, theirs is the new archive.
3. Replace the base commit and Base Manifest in `PROVENANCE.md`, and re-log every difference in `CHANGES.md`, in one reviewed commit.
4. Add the section 4(b) change notice to any newly modified Python file.
5. Run the `bellu-graphify-check` and the golden tests.

## How Bellu uses it

Bellu runs the code-only pass (tree-sitter structure extraction, no LLM) through the `bellu_graphify` wrapper and writes a code graph bundle. Pass 3 (LLM analysis of documents and images) stays disabled for security analysis. Bellu extends behaviour in the wrapper where possible so this copy stays close to upstream.

## Offline install

Nothing is fetched from the network at build, test, install or run time. Dependencies are installed once from a repository `wheelhouse/` with hash-pinned `requirements.lock`, inside a private virtual environment:

```
pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock
```

`requirements.lock` pins every direct and transitive dependency (core dependencies plus the `leiden` extra) with an exact version and the SHA256 of each vendored wheel. `wheelhouse/` holds the wheels for CPython 3.13 and 3.14 on Linux (x86_64, aarch64, glibc), macOS (x86_64, arm64) and Windows (x86_64, arm64). `wheelhouse/MISSING.txt` lists any package and target pair without a wheel (currently none).

Install (offline, standard library only):

```
python scripts/bellu_install_offline.py --data-dir <workspace data dir>
```

This creates the private environment `<workspace data dir>/venv`, runs the `pip install` command above against the lockfile with `PIP_NO_INDEX=1`, and adds a `.pth` file so `graphify` and `bellu_graphify` import from this tree. A pip dry run in a throwaway environment runs first. If the wheelhouse has no complete set of wheels for the current interpreter and platform, the installer exits 1, prints the one-time step below, creates no environment, and makes no network request. Use `--force` to replace an existing environment.

### One-time online step (never run implicitly)

Needed only when the installer reports a missing wheel (for example another platform, musllinux, or Python 3.11/3.12). On a machine with network access, from this directory:

```
uv run --with packaging python scripts/bellu_refresh_wheelhouse.py
```

Add the platform to `PLATFORMS` in that script first if it is absent. The script reads the pins from `uv.lock`, downloads each wheel from the URL in `uv.lock`, verifies it against the `uv.lock` hash, then rewrites `requirements.lock` and `wheelhouse/`. Commit the result, then rerun the installer. Python 3.11 and 3.12 resolve the much larger `graspologic` set and are not vendored.
