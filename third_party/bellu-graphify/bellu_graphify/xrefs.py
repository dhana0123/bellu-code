# Bellu addition (not upstream): cross-graph proposals for the Correlation Engine.
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "go.mod", "go.sum", "requirements.txt", "pyproject.toml",
    "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "Gemfile", "Gemfile.lock", "composer.json",
})


@dataclass(frozen=True)
class XrefProposal:
    """A proposal only. The wrapper never writes it to the Unified_Graph."""
    source_bid: str
    graph: str          # target graph, e.g. "graph3"
    key: str            # purl or workflow path in the target graph
    relation_hint: str


def propose_xrefs(nodes: Iterable[Mapping]) -> list[XrefProposal]:
    """Return proposals for nodes that map to Graph 3 entities. Pure: no writes, no I/O.

    A node is a mapping with ``bid``, ``source_file`` and optional ``purls`` (package URLs
    found in a manifest file node). Dockerfiles and GitHub workflow files map to a
    ``github_workflow`` entity keyed by their repo-relative path.
    """
    out: list[XrefProposal] = []
    for node in nodes:
        bid, path = node.get("bid"), node.get("source_file")
        if not bid or not path:
            continue
        name = path.rsplit("/", 1)[-1]
        if name in MANIFEST_NAMES:
            out.extend(XrefProposal(bid, "graph3", purl, "declares_package") for purl in sorted(set(node.get("purls") or ())))
        elif name == "Dockerfile" or name.startswith("Dockerfile.") or _is_workflow(path):
            out.append(XrefProposal(bid, "graph3", path, "defines_workflow"))
    return out


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
