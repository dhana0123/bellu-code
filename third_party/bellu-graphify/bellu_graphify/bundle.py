# Bellu addition (not upstream): Code_Graph_Bundle writer, retention and as-of reads
# (Requirements 2.11, 2.13, 2.14, 2.15).
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from .confidence import map_edges
from .guard import TREE_ROOT
from .symbol_ids import assign_symbol_ids

log = logging.getLogger("bellu_graphify")

DEFAULT_RETENTION = 10
BUNDLE_FILES = ("nodes.jsonl", "edges.jsonl", "communities.json")
_SHA = re.compile(r"[0-9a-f]{40}")
_BASE_SHA = re.compile(r"\|\s*Upstream commit SHA\s*\|\s*([0-9a-f]{40})\s*\|")


class BundleConflict(Exception):
    """A dirty build would replace the existing clean bundle for the same revision."""


class BundleIntegrityError(Exception):
    """A bundle file does not match the SHA256 recorded in its manifest."""


def upstream_base_sha(root: Path = TREE_ROOT) -> str:
    match = _BASE_SHA.search((root / "PROVENANCE.md").read_text(encoding="utf-8"))
    if not match:
        raise ValueError("PROVENANCE.md has no 'Upstream commit SHA' field")
    return match.group(1)


def graphify_version(root: Path = TREE_ROOT) -> str:
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(encoding="utf-8"))
    if not match:
        raise ValueError("pyproject.toml has no version")
    return match.group(1)


def bundle_dir(out: Path, repo_id: str, revision: str) -> Path:
    return Path(out) / "code-graph" / repo_id / revision


def write_bundle(nx_graph, communities: dict[int, list[str]], *, out: Path, repo_id: str, revision: str,
                 dirty: bool = False, retention: int = DEFAULT_RETENTION, cluster_params: dict | None = None) -> dict:
    """Write ``<out>/code-graph/<repo_id>/<revision>/`` and return its manifest.

    The bundle is built in a temporary sibling directory and moved into place only when complete,
    so a failure leaves earlier bundles untouched. Retention runs after the move.
    Nodes must already carry ``bid`` (see ``assign_symbol_ids``) and ``bellu_source_location``.
    """
    if not _SHA.fullmatch(revision):
        raise ValueError("revision must be a 40-character lowercase hex commit SHA")
    if retention < 1:
        raise ValueError("retention must be at least 1")
    repo_dir = Path(out) / "code-graph" / repo_id
    final = repo_dir / revision
    if dirty and final.is_dir() and not read_manifest(final).get("dirty"):
        raise BundleConflict(f"a clean bundle for {repo_id}@{revision} exists; a dirty build will not replace it")

    ids = assign_symbol_ids(nx_graph, repo_id)
    nodes = [_node_record(ids[str(nid)], data) for nid, data in nx_graph.nodes(data=True)]
    nodes.sort(key=lambda n: n["bid"])
    edges, errors = _edge_records(nx_graph, ids)
    for error in errors:
        log.warning("edge_rejected %s", error)
    communities_doc = {
        "parameters": {"algorithm": "leiden", "resolution": 1.0, **(cluster_params or {}),
                       "graphify_version": graphify_version()},
        "communities": {str(cid): sorted(ids[str(n)] for n in members if str(n) in ids)
                        for cid, members in sorted(communities.items())},
    }

    repo_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f".tmp-{revision}-", dir=repo_dir))
    try:
        _write_lines(tmp / "nodes.jsonl", nodes)
        _write_lines(tmp / "edges.jsonl", edges)
        (tmp / "communities.json").write_text(_dumps(communities_doc) + "\n", encoding="utf-8")
        manifest = {
            "repo_id": repo_id,
            "revision": revision,
            "graphify_version": graphify_version(),
            "bellu_graphify_base_sha": upstream_base_sha(),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "sha256": {name: _sha256(tmp / name) for name in BUNDLE_FILES},
            "dirty": dirty,
        }
        if dirty:
            manifest["label"] = "dirty"
        (tmp / "manifest.json").write_text(_dumps(manifest) + "\n", encoding="utf-8")
        _install(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    prune_bundles(repo_dir, keep=retention, protect=revision)
    return manifest


def prune_bundles(repo_dir: Path, *, keep: int = DEFAULT_RETENTION, protect: str | None = None) -> list[str]:
    """Delete all but the ``keep`` most recently written bundles. Returns deleted revisions."""
    bundles = sorted((d for d in Path(repo_dir).iterdir() if d.is_dir() and _SHA.fullmatch(d.name)
                      and (d / "manifest.json").is_file()),
                     key=lambda d: ((d / "manifest.json").stat().st_mtime_ns, d.name), reverse=True)
    stale = [d for d in bundles[keep:] if d.name != protect]
    for d in stale:
        shutil.rmtree(d)
    return [d.name for d in stale]


def read_manifest(bundle: Path) -> dict:
    return json.loads((Path(bundle) / "manifest.json").read_text(encoding="utf-8"))


def load_bundle(out: Path, repo_id: str, revision: str) -> dict:
    """Answer as of ``revision``: read only that revision's bundle and verify its file hashes."""
    bundle = bundle_dir(out, repo_id, revision)
    manifest = read_manifest(bundle)
    for name in BUNDLE_FILES:
        if _sha256(bundle / name) != manifest["sha256"][name]:
            raise BundleIntegrityError(f"{bundle / name} does not match manifest.json")
    return {
        "manifest": manifest,
        "nodes": _read_lines(bundle / "nodes.jsonl"),
        "edges": _read_lines(bundle / "edges.jsonl"),
        "communities": json.loads((bundle / "communities.json").read_text(encoding="utf-8")),
    }


def _install(tmp: Path, final: Path) -> None:
    """Move a finished bundle into place. A replaced bundle is set aside first and removed after."""
    if not final.exists():
        os.replace(tmp, final)
        return
    aside = final.with_name(f".old-{final.name}-{os.getpid()}")
    os.replace(final, aside)
    try:
        os.replace(tmp, final)
    except BaseException:
        os.replace(aside, final)
        raise
    shutil.rmtree(aside, ignore_errors=True)


def _node_record(bid: str, data: dict) -> dict:
    record = {k: v for k, v in data.items() if k != "bid"}
    record["bid"] = bid
    return record


def _edge_records(nx_graph, ids: dict[str, str]):
    raw = [dict(data, source=str(data.get("_src", u)), target=str(data.get("_tgt", v)))
           for u, v, data in nx_graph.edges(data=True)]
    mapped, errors = map_edges(raw)
    records = []
    for m in mapped:
        src, dst = ids.get(m.edge["source"]), ids.get(m.edge["target"])
        if src is None or dst is None:
            errors.append(f"edge {m.edge['source']}->{m.edge['target']}: endpoint is not a node")
            continue
        extra = {k: v for k, v in m.edge.items() if k not in ("source", "target", "_src", "_tgt", "confidence")}
        records.append({**extra, "source": src, "target": dst, "state": m.state, "confidence": m.confidence,
                        "graphify_tag": m.edge["confidence"]})
    records.sort(key=lambda e: (e["source"], e["target"], str(e.get("relation", "")), _dumps(e)))
    return records, errors


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _write_lines(path: Path, records: list[dict]) -> None:
    path.write_text("".join(_dumps(r) + "\n" for r in records), encoding="utf-8")


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
