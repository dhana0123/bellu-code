# Bellu addition (not upstream): tests for the Code_Graph_Bundle writer, retention and cache reuse (task 1.13).
from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from bellu_graphify import DirtyTree, build_code_graph, load_bundle
from bellu_graphify.bundle import BundleConflict, bundle_dir, read_manifest, upstream_base_sha

SRC = "def f():\n    return g()\n\n\ndef g():\n    return 1\n"


def _git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, name, text):
    (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"change {name}")
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _commit(r, "a.py", SRC)
    return r


def test_bundle_layout_and_manifest(repo, tmp_path):
    rev = _git(repo, "rev-parse", "HEAD")
    out = tmp_path / "data"
    manifest = build_code_graph(repo, "r1", out=out)
    d = bundle_dir(out, "r1", rev)
    assert sorted(p.name for p in d.iterdir()) == ["communities.json", "edges.jsonl", "manifest.json", "nodes.jsonl"]
    on_disk = json.loads((d / "manifest.json").read_text())
    assert on_disk == manifest
    assert manifest["repo_id"] == "r1" and manifest["revision"] == rev
    assert manifest["bellu_graphify_base_sha"] == upstream_base_sha() and len(manifest["bellu_graphify_base_sha"]) == 40
    assert manifest["dirty"] is False and "label" not in manifest
    for name in ("nodes.jsonl", "edges.jsonl", "communities.json"):
        assert manifest["sha256"][name] == hashlib.sha256((d / name).read_bytes()).hexdigest()
    nodes = [json.loads(line) for line in (d / "nodes.jsonl").read_text().splitlines()]
    assert manifest["node_count"] == len(nodes) > 0
    assert manifest["edge_count"] == len((d / "edges.jsonl").read_text().splitlines())
    assert len({n["bid"] for n in nodes}) == len(nodes)
    ids = {n["bid"] for n in nodes}
    for line in (d / "edges.jsonl").read_text().splitlines():
        e = json.loads(line)
        assert e["source"] in ids and e["target"] in ids and e["state"] in ("confirmed", "candidate", "hypothesis")
    assert load_bundle(out, "r1", rev)["manifest"] == manifest


def test_rebuild_is_deterministic(repo, tmp_path):
    a = build_code_graph(repo, "r1", out=tmp_path / "a")
    b = build_code_graph(repo, "r1", out=tmp_path / "b")
    assert a["sha256"] == b["sha256"]


def test_retention_keeps_most_recent_ten(repo, tmp_path):
    out = tmp_path / "data"
    revs = []
    for i in range(12):
        revs.append(_commit(repo, "a.py", SRC + f"\nx{i} = {i}\n"))
        build_code_graph(repo, "r1", out=out)
    kept = {p.name for p in (out / "code-graph" / "r1").iterdir() if len(p.name) == 40}
    assert kept == set(revs[2:])


def test_as_of_revision_uses_only_that_bundle(repo, tmp_path):
    out = tmp_path / "data"
    r1 = _git(repo, "rev-parse", "HEAD")
    build_code_graph(repo, "r1", out=out)
    before = load_bundle(out, "r1", r1)
    _commit(repo, "b.py", "def h():\n    return 2\n")
    build_code_graph(repo, "r1", out=out)
    assert load_bundle(out, "r1", r1) == before


def test_dirty_label_and_earlier_bundles_untouched(repo, tmp_path):
    out = tmp_path / "data"
    clean_rev = _git(repo, "rev-parse", "HEAD")
    build_code_graph(repo, "r1", out=out)
    clean_dir = bundle_dir(out, "r1", clean_rev)
    snapshot = {p.name: p.read_bytes() for p in clean_dir.iterdir()}

    (repo / "a.py").write_text("changed\n")
    with pytest.raises(DirtyTree):
        build_code_graph(repo, "r1", out=out)
    assert {p.name: p.read_bytes() for p in clean_dir.iterdir()} == snapshot
    assert sorted(p.name for p in (out / "code-graph" / "r1").iterdir() if not p.name.startswith("_")) == [clean_rev]

    # --allow-dirty must not replace the clean bundle for the same revision
    with pytest.raises(BundleConflict):
        build_code_graph(repo, "r1", out=out, allow_dirty=True)
    assert {p.name: p.read_bytes() for p in clean_dir.iterdir()} == snapshot

    # dirty build on a new revision is labelled
    _git(repo, "checkout", "-q", "--", "a.py")
    new_rev = _commit(repo, "c.py", "z = 1\n")
    (repo / "c.py").write_text("z = 2\n")
    manifest = build_code_graph(repo, "r1", out=out, allow_dirty=True)
    assert manifest["label"] == "dirty" and manifest["dirty"] is True
    assert read_manifest(bundle_dir(out, "r1", new_rev))["label"] == "dirty"
    assert {p.name: p.read_bytes() for p in clean_dir.iterdir()} == snapshot


def test_cache_reused_for_unchanged_files(repo, tmp_path, capsys):
    out = tmp_path / "data"
    build_code_graph(repo, "r1", out=out)
    assert "0/1 files served from cache" in capsys.readouterr().out
    _commit(repo, "b.py", "def h():\n    return 2\n")
    build_code_graph(repo, "r1", out=out)
    assert "1/2 files served from cache" in capsys.readouterr().out
