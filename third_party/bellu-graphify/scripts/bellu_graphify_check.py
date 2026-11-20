# Bellu addition (not upstream): bellu-graphify-check, the hard-copy integrity check.
"""Verify that the bellu-graphify hard copy is complete, attributed and logged.

    python scripts/bellu_graphify_check.py [--root <bellu-graphify directory>]

Checks (Requirement 1.7):
  * the directory exists;
  * ``LICENSE`` and ``NOTICE`` are present and non-empty;
  * every ``PROVENANCE.md`` field is present and well formed (URL, tag, 40-hex commit SHA,
    ISO date, 64-hex archive SHA256, Base Manifest lines);
  * ``CHANGES.md`` records the 40-hex upstream base commit, equal to the provenance SHA;
  * every path that differs from the Base Manifest (added, removed, changed) appears in
    ``CHANGES.md`` with the matching change type;
  * every changed Python file carries an Apache-2.0 section 4(b) change notice within its
    first 30 lines;
  * no symlink exists in the tree.

Exit status 0 when clean. Otherwise exit status 1 with one line per violation, in the form
``VIOLATION <item>: <file or field>: <detail>``. The check reads only local files, makes no
network request, and uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import re
import sys
from pathlib import Path

NOTICE_LINES = 30
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
CHANGE_NOTICE = re.compile(r"section\s+4\(b\)", re.IGNORECASE)
CHANGE_TYPES = ("added", "removed", "changed")
SKIP_DIRS = {".git", "__pycache__"}
SKIP_SUFFIXES = (".pyc", ".pyo")
FIELDS = (
    ("Upstream repository URL", "url"),
    ("Release tag", "tag"),
    ("Upstream commit SHA", "sha"),
    ("Copy date", "date"),
    ("Archive SHA256", "archive"),
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(root: Path) -> tuple[list[str], list[str]]:
    """Return (regular file relative paths, symlink relative paths), POSIX style."""
    files: list[str] = []
    links: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for d in sorted(dirnames):
            full = Path(dirpath) / d
            if full.is_symlink():
                links.append(full.relative_to(root).as_posix())
            elif d not in SKIP_DIRS:
                kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            if name.endswith(SKIP_SUFFIXES):
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            (links if full.is_symlink() else files).append(rel)
    return files, links


def _parse_provenance(text: str, violations: list[str]) -> tuple[str | None, dict[str, str]]:
    """Validate the provenance fields. Return (commit sha or None, base manifest)."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and len(cells) >= 2:
            values.setdefault(cells[0], cells[1])
    for label, key in FIELDS:
        raw = values.get(label)
        if raw is None or not raw.strip("` "):
            violations.append(f"VIOLATION provenance-field: PROVENANCE.md: field '{label}' missing or empty")
            continue
        value = raw.strip("` ")
        ok = True
        if key == "url":
            ok = re.fullmatch(r"https://\S+", value) is not None
        elif key == "sha":
            ok = HEX40.fullmatch(value) is not None
        elif key == "archive":
            ok = HEX64.fullmatch(value) is not None
        elif key == "date":
            try:
                ok = re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None
                if ok:
                    datetime.date.fromisoformat(value)
            except ValueError:
                ok = False
        if not ok:
            violations.append(f"VIOLATION provenance-field: PROVENANCE.md: field '{label}' is malformed: {value!r}")
    manifest: dict[str, str] = {}
    m = re.search(r"```base-manifest\.sha256\n(.*?)\n```", text, re.DOTALL)
    if m is None:
        violations.append("VIOLATION provenance-field: PROVENANCE.md: field 'base-manifest.sha256' missing")
    else:
        for n, line in enumerate(m.group(1).splitlines(), 1):
            parts = line.split("  ", 1)
            if len(parts) != 2 or not HEX64.fullmatch(parts[0]) or not parts[1]:
                violations.append(f"VIOLATION provenance-field: PROVENANCE.md: base-manifest.sha256 line {n} is malformed")
            elif parts[1] in manifest:
                violations.append(f"VIOLATION provenance-field: PROVENANCE.md: base-manifest.sha256 line {n} repeats {parts[1]}")
            else:
                manifest[parts[1]] = parts[0]
        if not manifest:
            violations.append("VIOLATION provenance-field: PROVENANCE.md: field 'base-manifest.sha256' has no entries")
    sha = values.get("Upstream commit SHA", "").strip("` ")
    return (sha if HEX40.fullmatch(sha) else None), manifest


def _parse_changes(text: str) -> dict[str, str]:
    """Map each path listed in a CHANGES.md table row to its change type."""
    entries: dict[str, str] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and len(cells) >= 2:
            m = re.fullmatch(r"`([^`]+)`", cells[0])
            if m and cells[1].lower() in CHANGE_TYPES:
                entries[m.group(1)] = cells[1].lower()
    return entries


def _logged_type(path: str, entries: dict[str, str]) -> str | None:
    """Change type logged for a path: an exact entry, or a directory entry ending in '/'."""
    if path in entries:
        return entries[path]
    parts = path.split("/")
    for i in range(1, len(parts)):
        d = "/".join(parts[:i]) + "/"
        if d in entries:
            return entries[d]
    return None


def check(root: Path) -> list[str]:
    """Return one violation line per violated item. An empty list means the check passed."""
    violations: list[str] = []
    if not root.is_dir():
        return [f"VIOLATION directory-missing: {root.as_posix()}: directory does not exist"]
    for name in ("LICENSE", "NOTICE"):
        p = root / name
        if not p.is_file():
            violations.append(f"VIOLATION file-missing: {name}: file is not present")
        elif p.stat().st_size == 0:
            violations.append(f"VIOLATION file-empty: {name}: file is empty")

    sha: str | None = None
    manifest: dict[str, str] = {}
    prov = root / "PROVENANCE.md"
    if prov.is_file():
        sha, manifest = _parse_provenance(prov.read_text(encoding="utf-8", errors="replace"), violations)
    else:
        violations.append("VIOLATION file-missing: PROVENANCE.md: file is not present")

    entries: dict[str, str] = {}
    changes = root / "CHANGES.md"
    if changes.is_file():
        ctext = changes.read_text(encoding="utf-8", errors="replace")
        entries = _parse_changes(ctext)
        m = re.search(r"Upstream base commit:\s*`?([0-9a-fA-F]+)`?", ctext)
        if m is None or not HEX40.fullmatch(m.group(1)):
            violations.append("VIOLATION changes-base-commit: CHANGES.md: 40-character lowercase upstream base commit missing or malformed")
        elif sha is not None and m.group(1) != sha:
            violations.append("VIOLATION changes-base-commit: CHANGES.md: base commit differs from PROVENANCE.md 'Upstream commit SHA'")
    else:
        violations.append("VIOLATION file-missing: CHANGES.md: file is not present")
    if not (root / "README.md").is_file():
        violations.append("VIOLATION file-missing: README.md: file is not present")

    files, links = _walk(root)
    for link in links:
        violations.append(f"VIOLATION symlink: {link}: symlinks are not allowed in the hard copy")

    # Only compare to the manifest when it parsed; a broken manifest is already reported.
    if manifest:
        present = set(files)
        diffs: dict[str, str] = {}
        for rel in files:
            if rel not in manifest:
                diffs[rel] = "added"
            elif _sha256(root / rel) != manifest[rel]:
                diffs[rel] = "changed"
        for rel in manifest:
            if rel not in present:
                diffs[rel] = "removed"
        for rel in sorted(diffs):
            logged = _logged_type(rel, entries)
            if logged is None:
                violations.append(f"VIOLATION changes-missing: {rel}: {diffs[rel]} path is not listed in CHANGES.md")
            elif logged != diffs[rel]:
                violations.append(f"VIOLATION changes-type: {rel}: CHANGES.md says {logged}, tree shows {diffs[rel]}")
            if diffs[rel] == "changed" and rel.endswith(".py"):
                with (root / rel).open("r", encoding="utf-8", errors="replace") as f:
                    head = [line for _, line in zip(range(NOTICE_LINES), f)]
                if not CHANGE_NOTICE.search("".join(head)):
                    violations.append(f"VIOLATION change-notice: {rel}: no Apache-2.0 section 4(b) change notice in the first {NOTICE_LINES} lines")
    return violations


def main(argv: list[str] | None = None) -> int:
    default_root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="bellu-graphify-check")
    ap.add_argument("--root", type=Path, default=default_root, help="bellu-graphify directory")
    args = ap.parse_args(argv)
    violations = check(args.root)
    for line in violations:
        print(line)
    if violations:
        return 1
    print("bellu-graphify-check: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
