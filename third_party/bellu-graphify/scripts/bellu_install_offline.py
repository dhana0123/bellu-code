# Bellu addition (not upstream): offline installer for the bellu-graphify dependencies.
"""Install the hash-pinned dependencies into a private virtual environment, offline.

    python scripts/bellu_install_offline.py --data-dir <workspace data dir>

Creates ``<data-dir>/venv`` and runs

    pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock

This script makes no network request and never falls back to an index. If the wheelhouse
has no wheel for the current interpreter and platform it exits 1, prints the documented
one-time step, and leaves no virtual environment behind (a pip ``--dry-run`` against a
throwaway environment runs first, so nothing partial is installed into the real one).
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUPPORTED = ((3, 13), (3, 14))

ONE_TIME_STEP = """\
One-time step (needs network access, run by hand, never run implicitly):
  1. On a machine with network access, from third_party/bellu-graphify, run
       uv run --with packaging python scripts/bellu_refresh_wheelhouse.py
     If this platform is not listed in PLATFORMS in that script, add it first.
  2. Commit or copy the updated wheelhouse/ and requirements.lock, then rerun this installer.
See README.md, section "Offline install"."""


def main() -> int:
    args = parse_args()
    wheelhouse, lock = args.wheelhouse.resolve(), args.lock.resolve()
    target = args.data_dir.resolve() / "venv"

    if sys.version_info[:2] not in SUPPORTED:
        return fail(f"Python {sys.version_info.major}.{sys.version_info.minor} is not in the wheelhouse "
                    f"(supported: {', '.join('%d.%d' % v for v in SUPPORTED)}).")
    if not lock.is_file() or not any(wheelhouse.glob("*.whl")):
        return fail(f"missing {lock} or no wheels in {wheelhouse}.")
    if target.exists() and not args.force:
        return fail(f"{target} already exists. Pass --force to replace it.")

    env = offline_env()
    pip_args = ["install", "--no-index", "--find-links", str(wheelhouse), "--require-hashes", "-r", str(lock)]

    # Preflight in a throwaway environment: resolves and hash-checks the whole set without installing.
    with tempfile.TemporaryDirectory(prefix="bellu-preflight-") as tmp:
        probe = tmp + os.sep + "venv"
        venv.EnvBuilder(with_pip=True).create(probe)
        check = subprocess.run([python_of(probe), "-m", "pip", *pip_args, "--dry-run"], env=env,
                               capture_output=True, text=True)
    if check.returncode != 0:
        sys.stderr.write(check.stdout[-2000:] + check.stderr[-2000:])
        return fail("the wheelhouse has no complete set of wheels for this platform and interpreter "
                    f"({sys.platform}, Python {sys.version_info.major}.{sys.version_info.minor}). Nothing was installed.",
                    ONE_TIME_STEP)

    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    venv.EnvBuilder(with_pip=True).create(target)
    done = subprocess.run([python_of(target), "-m", "pip", *pip_args], env=env)
    if done.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)  # never leave a partial set behind
        return fail("pip install failed. The virtual environment was removed.", ONE_TIME_STEP)

    # Make the committed `graphify` and `bellu_graphify` packages importable from this tree.
    site = subprocess.run([python_of(target), "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
                          capture_output=True, text=True, check=True).stdout.strip()
    (Path(site) / "bellu_graphify_tree.pth").write_text(str(ROOT) + "\n", encoding="utf-8")
    print(f"installed into {target}")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--data-dir", type=Path, default=os.environ.get("BELLU_WORKSPACE_DATA_DIR"),
                   help="workspace data directory; the environment is created in <data-dir>/venv "
                        "(default: $BELLU_WORKSPACE_DATA_DIR)")
    p.add_argument("--wheelhouse", type=Path, default=ROOT / "wheelhouse")
    p.add_argument("--lock", type=Path, default=ROOT / "requirements.lock")
    p.add_argument("--force", action="store_true", help="replace an existing environment")
    args = p.parse_args()
    if args.data_dir is None:
        p.error("--data-dir or BELLU_WORKSPACE_DATA_DIR is required")
    args.data_dir = Path(args.data_dir)
    return args


def offline_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PIP_", "UV_"))}
    env.update(PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    return env


def python_of(env_dir: str | Path) -> str:
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    return str(Path(env_dir) / sub)


def fail(*lines: str) -> int:
    print("bellu-graphify offline install failed: " + lines[0], file=sys.stderr)
    for extra in lines[1:]:
        print(extra, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
