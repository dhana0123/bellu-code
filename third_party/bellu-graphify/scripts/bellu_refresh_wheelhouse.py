# Bellu addition (not upstream): maintainer tool that rebuilds requirements.lock and wheelhouse/.
"""Rebuild ``requirements.lock`` and ``wheelhouse/`` from the upstream ``uv.lock``.

MAINTAINER TOOL. This is the only script in the tree that uses the network, and it is
never run implicitly: not at build, test, install or run time. Run it by hand when the
dependency set changes, then commit the result.

    python scripts/bellu_refresh_wheelhouse.py            # needs `uv` and `packaging`

What it does:
  1. ``uv export`` the exact pins (core dependencies plus the ``leiden`` extra) from uv.lock.
  2. For every supported interpreter x platform, evaluate the environment markers and pick
     the best compatible wheel listed in uv.lock.
  3. Download each chosen wheel once from the URL in uv.lock and check its SHA256 against uv.lock.
  4. Write ``requirements.lock`` (``name==version ; marker`` plus ``--hash`` for each vendored wheel).
  5. Write ``wheelhouse/MISSING.txt`` listing (package, target) pairs that have no wheel.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

from packaging import tags
from packaging.markers import Marker
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parent.parent
WHEELHOUSE = ROOT / "wheelhouse"
LOCKFILE = ROOT / "requirements.lock"

PYTHONS = [(3, 13), (3, 14)]
EXTRAS = ["leiden"]


def _linux(arch: str) -> list[str]:
    plats = [f"manylinux_2_{n}_{arch}" for n in range(40, 4, -1)]
    plats += [f"manylinux2014_{arch}", f"manylinux2010_{arch}", f"manylinux1_{arch}", f"linux_{arch}"]
    return plats


# name -> (marker environment, wheel platform tags in priority order)
PLATFORMS: dict[str, tuple[dict[str, str], list[str]]] = {
    "linux-x86_64": ({"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix", "platform_machine": "x86_64"}, _linux("x86_64")),
    "linux-aarch64": ({"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix", "platform_machine": "aarch64"}, _linux("aarch64")),
    "macos-x86_64": ({"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix", "platform_machine": "x86_64"}, list(tags.mac_platforms((15, 0), "x86_64"))),
    "macos-arm64": ({"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix", "platform_machine": "arm64"}, list(tags.mac_platforms((15, 0), "arm64"))),
    "windows-x86_64": ({"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt", "platform_machine": "AMD64"}, ["win_amd64"]),
    "windows-arm64": ({"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt", "platform_machine": "ARM64"}, ["win_arm64"]),
}


def exported_pins() -> list[tuple[str, str, str]]:
    cmd = ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--no-hashes", "--no-annotate",
           "--format", "requirements-txt", "--project", str(ROOT)]
    for e in EXTRAS:
        cmd += ["--extra", e]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    pins = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        req, _, marker = line.partition(";")
        name, _, version = req.strip().partition("==")
        pins.append((canonicalize_name(name), version.strip(), marker.strip()))
    return pins


def lock_wheels() -> dict[tuple[str, str], dict[str, tuple[str, str]]]:
    data = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    table: dict[tuple[str, str], dict[str, tuple[str, str]]] = {}
    for pkg in data["package"]:
        files = {}
        for w in pkg.get("wheels", []):
            files[w["url"].rsplit("/", 1)[1]] = (w["url"], w["hash"].removeprefix("sha256:"))
        table[(canonicalize_name(pkg["name"]), pkg.get("version", ""))] = files
    return table


def target_tags(py: tuple[int, int], plats: list[str]) -> list[tags.Tag]:
    interp = f"cp{py[0]}{py[1]}"
    out = list(tags.cpython_tags(py, [interp, "abi3", "none"], plats))
    out += list(tags.compatible_tags(py, interp, plats))
    return out


def pick(files: dict[str, tuple[str, str]], ordered: list[tags.Tag]) -> str | None:
    rank = {t: i for i, t in enumerate(ordered)}
    best, best_rank = None, None
    for fname in files:
        _, _, _, wtags = parse_wheel_filename(fname)
        r = min((rank[t] for t in wtags if t in rank), default=None)
        if r is not None and (best_rank is None or r < best_rank):
            best, best_rank = fname, r
    return best


def main() -> int:
    pins = exported_pins()
    table = lock_wheels()
    chosen: dict[tuple[str, str, str], set[str]] = {}  # pin -> filenames
    missing: list[str] = []
    for py in PYTHONS:
        for tname, (penv, plats) in PLATFORMS.items():
            env = {
                "python_version": f"{py[0]}.{py[1]}",
                "python_full_version": f"{py[0]}.{py[1]}.0",
                "implementation_name": "cpython",
                "platform_python_implementation": "CPython",
                "extra": "",
                **penv,
            }
            ordered = target_tags(py, plats)
            for name, version, marker in pins:
                if marker and not Marker(marker).evaluate(env):
                    continue
                files = table[(name, version)]
                fname = pick(files, ordered)
                if fname is None:
                    missing.append(f"{name}=={version}  cp{py[0]}{py[1]}  {tname}")
                    chosen.setdefault((name, version, marker), set())
                else:
                    chosen.setdefault((name, version, marker), set()).add(fname)

    WHEELHOUSE.mkdir(exist_ok=True)
    needed = sorted({f for fs in chosen.values() for f in fs})
    for fname in needed:
        name_ver = next(k for k, fs in chosen.items() if fname in fs)
        url, sha = table[(name_ver[0], name_ver[1])][fname]
        dest = WHEELHOUSE / fname
        if not dest.exists():
            print("download", fname, file=sys.stderr)
            with urllib.request.urlopen(url) as r:  # noqa: S310 - maintainer tool, https URL from uv.lock
                dest.write_bytes(r.read())
        if hashlib.sha256(dest.read_bytes()).hexdigest() != sha:
            dest.unlink()
            raise SystemExit(f"hash mismatch against uv.lock: {fname}")
    for stale in WHEELHOUSE.glob("*.whl"):
        if stale.name not in needed:
            stale.unlink()

    lines = [
        "# Bellu addition (not upstream). Generated by scripts/bellu_refresh_wheelhouse.py from uv.lock.",
        "# Every direct and transitive dependency, exact version, SHA256 of each vendored wheel.",
        "# Install only with scripts/bellu_install_offline.py (pip --no-index --require-hashes).",
        "# Interpreters: CPython 3.13 and 3.14. Extras: " + ", ".join(EXTRAS) + ".",
    ]
    for (name, version, marker), fnames in sorted(chosen.items()):
        if not fnames:
            continue
        hashes = sorted(table[(name, version)][f][1] for f in fnames)
        head = f"{name}=={version}" + (f" ; {marker}" if marker else "")
        lines.append(head + "".join(f" \\\n    --hash=sha256:{h}" for h in hashes))
    LOCKFILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    (WHEELHOUSE / "MISSING.txt").write_text(
        "# Package/target pairs with no wheel in uv.lock. Installing on these targets fails by design.\n"
        + "".join(m + "\n" for m in sorted(set(missing))),
        encoding="utf-8",
    )
    print(f"{len(needed)} wheels, {len(chosen)} pins, {len(set(missing))} missing pairs", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
