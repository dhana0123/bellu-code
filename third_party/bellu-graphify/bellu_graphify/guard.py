# Bellu addition (not upstream): run the bellu-graphify-check conditions before any Graphify work.
from __future__ import annotations

import importlib.util
from pathlib import Path

from .errors import GuardFailure

TREE_ROOT = Path(__file__).resolve().parent.parent
_CHECK = TREE_ROOT / "scripts" / "bellu_graphify_check.py"


def run_check(root: Path = TREE_ROOT) -> None:
    """Raise GuardFailure naming the failing file or field. Local files only, no network."""
    if not _CHECK.is_file():
        raise GuardFailure([f"VIOLATION file-missing: scripts/bellu_graphify_check.py: file is not present"])
    spec = importlib.util.spec_from_file_location("_bellu_graphify_check", _CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    violations = module.check(root)
    if violations:
        raise GuardFailure(violations)
