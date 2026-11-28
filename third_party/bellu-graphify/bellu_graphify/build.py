# Bellu addition (not upstream): build_code_graph entry point (skeleton; later tasks add the pipeline).
from __future__ import annotations

from pathlib import Path
from typing import Literal

from .bundle import write_bundle
from .guard import run_check
from .provenance import attach_provenance, head_revision, require_clean

CACHE_DIR = "_cache"  # shared upstream per-file cache; not a bundle, never pruned


def build_code_graph(checkout: Path, repo_id: str, *, out: Path, passes: Literal["code"] = "code",
                     allow_dirty: bool = False):
    """Build a Code_Graph_Bundle under ``out``.

    Order matters: the hard-copy check runs first so a failing tree starts no Graphify work.
    Only the code pass is allowed. Pass 3 (LLM analysis of documents and images) stays disabled.
    """
    run_check()
    if passes != "code":
        raise ValueError("only passes='code' is supported; Graphify Pass 3 (LLM) is disabled")
    checkout = Path(checkout)
    dirty = require_clean(checkout, allow_dirty)
    revision = head_revision(checkout)
    return _run_graphify(checkout, repo_id, revision, Path(out), dirty)


def _run_graphify(checkout: Path, repo_id: str, revision: str, out: Path, dirty: bool) -> dict:
    """Code pass only: AST extraction (no LLM), graph build, Leiden clustering, then the bundle writer.

    The upstream per-file SHA256 cache lives beside the bundles and is shared by every revision of
    the repository, so ``extract`` skips each file whose hash matches its cached entry (Req 21.5).
    """
    from graphify.build import build_from_json
    from graphify.cluster import cluster
    from graphify.extract import collect_files, extract

    checkout = checkout.resolve()
    cache_root = out / "code-graph" / repo_id / CACHE_DIR
    cache_root.mkdir(parents=True, exist_ok=True)
    extraction = extract(collect_files(checkout), cache_root=cache_root, root=checkout)
    graph = build_from_json(extraction, root=checkout)
    attach_provenance(graph, checkout, revision, repo_id)
    return write_bundle(graph, cluster(graph), out=out, repo_id=repo_id, revision=revision, dirty=dirty)
