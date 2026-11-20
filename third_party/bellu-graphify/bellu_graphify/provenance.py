# Bellu addition (not upstream): commit provenance for code graph nodes (Requirements 2.1, 2.5, 2.14).
from __future__ import annotations

import hashlib
import re
import subprocess
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import DirtyTree

_SHA = re.compile(r"[0-9a-f]{40}")
_LINE = re.compile(r"L?(\d+)")
MAX_PATH = 4096


@dataclass(frozen=True)
class SourceLocation:
    repo_id: str
    revision: str  # full 40-hex commit SHA
    path: str  # repo-relative, POSIX separators, NFC normalised
    start_line: int
    end_line: int
    content_sha256: str  # SHA256 of the file bytes at `revision`

    def __post_init__(self) -> None:
        if not self.repo_id:
            raise ValueError("repo_id must be non-empty")
        if not _SHA.fullmatch(self.revision):
            raise ValueError("revision must be a 40-character lowercase hex commit SHA")
        if not self.path or len(self.path) > MAX_PATH or self.path.startswith("/") or "\\" in self.path:
            raise ValueError("path must be a repo-relative POSIX path of 1 to 4096 characters")
        if self.path != unicodedata.normalize("NFC", self.path):
            raise ValueError("path must be NFC normalised")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("lines must satisfy 1 <= start_line <= end_line")
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_sha256):
            raise ValueError("content_sha256 must be 64 lowercase hex characters")


def _git(checkout: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(checkout), *args], check=True, capture_output=True).stdout


def head_revision(checkout: Path) -> str:
    """Full commit SHA from ``git rev-parse HEAD``."""
    revision = _git(checkout, "rev-parse", "HEAD").decode().strip()
    if not _SHA.fullmatch(revision):
        raise ValueError(f"git rev-parse HEAD did not return a 40-character SHA: {revision!r}")
    return revision


def is_dirty(checkout: Path) -> bool:
    """Any modified or staged tracked file, or untracked file not excluded by ignore rules."""
    return bool(_git(checkout, "status", "--porcelain", "--untracked-files=all").strip())


def require_clean(checkout: Path, allow_dirty: bool) -> bool:
    """Raise DirtyTree for a dirty worktree unless allowed. Return True when the tree is dirty."""
    dirty = is_dirty(checkout)
    if dirty and not allow_dirty:
        raise DirtyTree(f"{checkout} has uncommitted changes; commit or stash, or pass --allow-dirty")
    return dirty


def attach_provenance(nx_graph, checkout: Path, revision: str, repo_id: str = "") -> None:
    """Set ``bellu_source_location`` (a SourceLocation as a dict) on every node that has a file and line.

    Nodes without a ``source_file`` (external or synthetic) are left untouched.
    """
    checkout = Path(checkout)
    hashes: dict[str, str] = {}
    for _, data in nx_graph.nodes(data=True):
        source = data.get("source_file")
        line = _LINE.fullmatch(str(data.get("source_location", "")))
        if not source or not line:
            continue
        absolute = Path(source) if Path(source).is_absolute() else checkout / source
        try:
            rel = unicodedata.normalize("NFC", absolute.resolve().relative_to(checkout.resolve()).as_posix())
        except ValueError:
            continue  # outside the checkout
        if rel not in hashes:
            hashes[rel] = _file_sha256(checkout, revision, rel)
        start = max(int(line.group(1)), 1)
        end = max(int(data.get("end_line", start) or start), start)
        data["bellu_source_location"] = asdict(SourceLocation(repo_id, revision, rel, start, end, hashes[rel]))


def _file_sha256(checkout: Path, revision: str, rel: str) -> str:
    try:
        content = _git(checkout, "show", f"{revision}:{rel}")
    except subprocess.CalledProcessError:
        content = (checkout / rel).read_bytes()  # untracked file in an --allow-dirty build
    return hashlib.sha256(content).hexdigest()
