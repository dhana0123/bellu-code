# Bellu addition (not upstream): command line entry for the wrapper.
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .build import build_code_graph
from .errors import DirtyTree, GuardFailure


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bellu_graphify")
    ap.add_argument("checkout", type=Path)
    ap.add_argument("--repo-id", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--allow-dirty", action="store_true")
    args = ap.parse_args(argv)
    try:
        build_code_graph(args.checkout, args.repo_id, out=args.out, allow_dirty=args.allow_dirty)
    except GuardFailure as e:
        print("\n".join(e.violations), file=sys.stderr)
        return 2
    except DirtyTree as e:
        print(f"DirtyTree: {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
