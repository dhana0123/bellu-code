# Bellu addition (not upstream): stable symbol identities, `bid` (Requirements 2.2, 2.3, 2.4).
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import unicodedata
from collections import defaultdict
from pathlib import PurePosixPath

log = logging.getLogger("bellu_graphify")

_SEP = "\x1f"  # unit separator: fields cannot run together the way they could with "|"
_LINE = re.compile(r"L?(\d+)")
_LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".rb": "ruby",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".cs": "csharp", ".php": "php",
    ".swift": "swift", ".scala": "scala", ".sh": "bash", ".lua": "lua", ".ex": "elixir", ".exs": "elixir",
}


def assign_symbol_ids(nx_graph, repo_id: str) -> dict[str, str]:
    """Upstream node id -> ``bid``. Pure, deterministic, total over nodes, pairwise distinct.

    Identity inputs are repo_id, language, module path, qualified name, kind and disambiguator.
    Line numbers and commit SHAs never enter the hash. Symbols whose inputs are identical are
    ordered by source file path, then zero-based definition ordinal in the file, and receive
    distinct ids in that order (the first keeps the base id); one ``bid_collision`` event is
    logged per group.
    """
    nodes = {str(nid): data for nid, data in nx_graph.nodes(data=True)}
    ordinals = _definition_ordinals(nodes)
    groups: dict[tuple, list[str]] = defaultdict(list)
    for nid in sorted(nodes):
        groups[_identity(nodes[nid], repo_id)].append(nid)

    ids: dict[str, str] = {}
    taken: set[str] = set()
    for key in sorted(groups, key=lambda k: _make_bid(k)):
        members = sorted(groups[key], key=lambda n: (_path(nodes[n]), ordinals[n], n))
        if len(members) > 1:
            log.warning("bid_collision %s", json.dumps({
                "event": "bid_collision", "repo_id": repo_id, "bid": _make_bid(key),
                "symbols": [{"id": n, "source_file": _path(nodes[n]), "ordinal": ordinals[n]} for n in members],
            }, sort_keys=True))
        for rank, nid in enumerate(members):
            bid = _make_bid(key if rank == 0 else key + (f"collision:{rank}",))
            extra = 0
            while bid in taken:  # vanishingly unlikely: a derived id equals another symbol's id
                extra += 1
                bid = _make_bid(key + (f"collision:{rank}", f"retry:{extra}"))
            taken.add(bid)
            ids[nid] = bid
    return ids


def _identity(data: dict, repo_id: str) -> tuple:
    path = _path(data)
    return (repo_id, _language(path), _module(path), _qualified_name(data), _kind(data, path),
            str(data.get("disambiguator") or data.get("signature") or ""))


def _make_bid(key: tuple) -> str:
    raw = _SEP.join(unicodedata.normalize("NFC", part) for part in key).encode()
    digest = base64.b32encode(hashlib.sha256(raw).digest()).decode().rstrip("=").lower()
    return "bid:code:" + digest[:26]


def _path(data: dict) -> str:
    return unicodedata.normalize("NFC", str(data.get("source_file") or "").replace("\\", "/"))


def _language(path: str) -> str:
    return _LANGUAGES.get(PurePosixPath(path).suffix.lower(), "unknown")


def _module(path: str) -> str:
    return str(PurePosixPath(path).with_suffix("")) if path else ""


def _qualified_name(data: dict) -> str:
    name = data.get("qualified_name") or data.get("label") or ""
    return str(name).strip().removesuffix("()").lstrip(".")


def _kind(data: dict, path: str) -> str:
    if data.get("kind"):
        return str(data["kind"])
    label = str(data.get("label") or "")
    if label.endswith("()"):
        return "method" if label.startswith(".") else "function"
    if path and label == PurePosixPath(path).name:
        return "file"
    return str(data.get("file_type") or "symbol")


def _definition_ordinals(nodes: dict[str, dict]) -> dict[str, int]:
    """Zero-based position of each definition among the nodes of its source file."""
    by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for nid, data in nodes.items():
        line = _LINE.fullmatch(str(data.get("source_location", "")))
        by_file[_path(data)].append((int(line.group(1)) if line else 0, nid))
    return {nid: i for entries in by_file.values() for i, (_, nid) in enumerate(sorted(entries))}
