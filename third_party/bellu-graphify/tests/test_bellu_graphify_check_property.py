# Bellu addition (not upstream): Property 3, hard-copy presence and CHANGES completeness.
"""Property test for ``scripts/bellu_graphify_check.py`` (Requirements 1.1, 1.2, 1.3, 1.5, 1.7, 1.8).

**Validates: Requirements 1.1, 1.2, 1.3, 1.5, 1.7, 1.8**

Property 3: a clean synthetic hard copy passes the check. A state with one added, removed or
modified file lacking a ``CHANGES.md`` entry, a missing licence file, a missing provenance
field, a modified Python file without the change notice, or a symlink fails, and the violation
names the offending file or field.

Limit: ``hypothesis`` is not installed and the wheelhouse is offline, so states are generated
with a seeded ``random.Random`` over many iterations instead of a shrinking strategy. The test
uses only the standard library and runs under ``unittest`` or ``pytest``.
"""
from __future__ import annotations

import hashlib
import importlib.util
import random
import shutil
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "bellu_graphify_check", Path(__file__).resolve().parent.parent / "scripts" / "bellu_graphify_check.py"
)
check_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_mod)

SHA = "0123456789abcdef0123456789abcdef01234567"
ARCHIVE = "ab" * 32
NOTICE_TEXT = "# Modified by Bellu under Apache-2.0 section 4(b).\n"
PROV_FIELDS = ("Upstream repository URL", "Release tag", "Upstream commit SHA", "Copy date", "Archive SHA256")
ITERATIONS = 60


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _provenance(manifest: dict[str, str], omit: str | None = None) -> str:
    rows = {
        "Upstream repository URL": "https://github.com/example/graphify",
        "Release tag": "v1.2.3",
        "Upstream commit SHA": SHA,
        "Copy date": "2026-11-19",
        "Archive SHA256": ARCHIVE,
    }
    lines = ["# Provenance", "| Field | Value |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in rows.items() if k != omit]
    body = "\n".join(f"{h}  {p}" for p, h in sorted(manifest.items()))
    lines += ["## Base Manifest", "```base-manifest.sha256", body, "```", ""]
    return "\n".join(lines)


def _changes(entries: dict[str, str]) -> str:
    lines = [f"Upstream base commit: {SHA}", "| Path | Change type | Note |", "| --- | --- | --- |"]
    lines += [f"| `{p}` | {t} | note |" for p, t in sorted(entries.items())]
    return "\n".join(lines) + "\n"


class Tree:
    """A synthetic hard copy: base files, provenance, CHANGES and the licence files."""

    def __init__(self, rng: random.Random, root: Path):
        self.rng, self.root = rng, root
        self.base: dict[str, bytes] = {"LICENSE": b"Apache\n", "NOTICE": b"Upstream notice\n"}
        for i in range(rng.randint(3, 8)):
            ext = rng.choice([".py", ".md", ".json"])
            self.base[f"d{rng.randint(0, 2)}/f{i}{ext}"] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 40)))
        # README.md is changed by Bellu, as in the real copy.
        self.base["README.md"] = b"upstream readme\n"
        self.entries = {"PROVENANCE.md": "added", "CHANGES.md": "added", "README.md": "changed"}
        self.files = dict(self.base)
        self.files["README.md"] = b"bellu readme\n"
        self.omit_field: str | None = None

    def write(self) -> Path:
        manifest = {p: _sha(d) for p, d in self.base.items()}
        shutil.rmtree(self.root, ignore_errors=True)
        for p, d in self.files.items():
            f = self.root / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(d)
        (self.root / "PROVENANCE.md").write_text(_provenance(manifest, self.omit_field))
        (self.root / "CHANGES.md").write_text(_changes(self.entries))
        return self.root

    def python_files(self) -> list[str]:
        return sorted(p for p in self.base if p.endswith(".py"))

    def other_files(self) -> list[str]:
        return sorted(p for p in self.base if p not in ("LICENSE", "NOTICE", "README.md"))


class HardCopyCheckProperty(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "bellu-graphify"

    def trees(self):
        for seed in range(ITERATIONS):
            rng = random.Random(seed)
            yield rng, Tree(rng, self.root)

    def violations(self, tree: Tree) -> list[str]:
        return check_mod.check(tree.write())

    def test_clean_state_passes(self):
        for _, t in self.trees():
            self.assertEqual(self.violations(t), [])

    def test_logged_changes_pass(self):
        for rng, t in self.trees():
            added = f"bellu/new{rng.randint(0, 99)}.txt"
            t.files[added] = b"x"
            t.entries[added] = "added"
            victim = rng.choice(t.other_files())
            del t.files[victim]
            t.entries[victim] = "removed"
            rest = [p for p in t.other_files() if p in t.files and not p.endswith(".py")]
            if rest:
                t.files[rest[0]] += b"edit"
                t.entries[rest[0]] = "changed"
            self.assertEqual(self.violations(t), [])

    def test_modified_python_with_notice_passes(self):
        for rng, t in self.trees():
            py = t.python_files()
            if not py:
                continue
            t.files[py[0]] = NOTICE_TEXT.encode() + t.files[py[0]]
            t.entries[py[0]] = "changed"
            self.assertEqual(self.violations(t), [])

    def test_unlogged_added_file_fails(self):
        for rng, t in self.trees():
            added = f"extra{rng.randint(0, 99)}.txt"
            t.files[added] = b"x"
            self.assertTrue(any(f"changes-missing: {added}:" in v for v in self.violations(t)))

    def test_unlogged_removed_file_fails(self):
        for rng, t in self.trees():
            victim = rng.choice(t.other_files())
            del t.files[victim]
            self.assertTrue(any(f"changes-missing: {victim}:" in v for v in self.violations(t)))

    def test_unlogged_modified_file_fails(self):
        for rng, t in self.trees():
            victim = rng.choice(t.other_files())
            t.files[victim] += b"edit"
            self.assertTrue(any(f"changes-missing: {victim}:" in v for v in self.violations(t)))

    def test_wrong_change_type_fails(self):
        for rng, t in self.trees():
            victim = rng.choice(t.other_files())
            t.files[victim] += b"edit"
            t.entries[victim] = "added"
            self.assertTrue(any(f"changes-type: {victim}:" in v for v in self.violations(t)))

    def test_modified_python_without_notice_fails(self):
        for rng, t in self.trees():
            py = t.python_files()
            if not py:
                continue
            t.files[py[0]] += b"# edit\n"
            t.entries[py[0]] = "changed"
            self.assertTrue(any(f"change-notice: {py[0]}:" in v for v in self.violations(t)))

    def test_missing_licence_file_fails(self):
        for rng, t in self.trees():
            name = rng.choice(["LICENSE", "NOTICE"])
            del t.files[name]
            del t.base[name]
            t.write()
            self.assertTrue(any(f"file-missing: {name}:" in v for v in check_mod.check(self.root)))

    def test_missing_provenance_field_fails(self):
        for rng, t in self.trees():
            t.omit_field = rng.choice(PROV_FIELDS)
            self.assertTrue(any(f"field '{t.omit_field}'" in v for v in self.violations(t)))

    def test_missing_provenance_file_and_directory_fail(self):
        for _, t in self.trees():
            t.write()
            (self.root / "PROVENANCE.md").unlink()
            self.assertTrue(any("file-missing: PROVENANCE.md" in v for v in check_mod.check(self.root)))
        self.assertTrue(any("directory-missing" in v for v in check_mod.check(self.root / "nope")))

    def test_symlink_fails(self):
        for rng, t in self.trees():
            t.write()
            (self.root / "link").symlink_to(self.root / "LICENSE")
            self.assertTrue(any("symlink: link:" in v for v in check_mod.check(self.root)))


if __name__ == "__main__":
    unittest.main()
