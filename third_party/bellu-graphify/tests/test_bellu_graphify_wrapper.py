# Bellu addition (not upstream): tests for the bellu_graphify wrapper skeleton.
from __future__ import annotations

import hashlib
import subprocess
import time

import networkx as nx
import pytest

import bellu_graphify
from bellu_graphify import DirtyTree, GuardFailure, SourceLocation, attach_provenance, build_code_graph
from bellu_graphify import build, guard


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "a.py").write_text("def f():\n    pass\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "init")
    return r


@pytest.fixture
def reached(monkeypatch):
    calls = []
    monkeypatch.setattr(build, "_run_graphify", lambda *a: calls.append(a))
    return calls


def test_guard_failure_names_file_and_starts_nothing(repo, tmp_path, reached, monkeypatch):
    bad = tmp_path / "tree"
    bad.mkdir()
    monkeypatch.setattr(guard, "TREE_ROOT", bad)
    monkeypatch.setattr(guard.run_check, "__defaults__", (bad,))
    started = time.monotonic()
    with pytest.raises(GuardFailure) as e:
        build_code_graph(repo, "r1", out=tmp_path / "o")
    assert time.monotonic() - started < 5
    assert "LICENSE" in str(e.value)
    assert reached == []


def test_clean_tree_reaches_graphify(repo, tmp_path, reached):
    build_code_graph(repo, "r1", out=tmp_path / "o")
    assert len(reached) == 1 and reached[0][3:] == (tmp_path / "o", False)


def test_dirty_tree_rejected_and_writes_nothing(repo, tmp_path, reached):
    (repo / "a.py").write_text("changed\n")
    out = tmp_path / "o"
    with pytest.raises(DirtyTree):
        build_code_graph(repo, "r1", out=out)
    assert reached == [] and not out.exists()


def test_allow_dirty_labels_bundle_dirty(repo, tmp_path, reached):
    (repo / "new.py").write_text("x = 1\n")
    build_code_graph(repo, "r1", out=tmp_path / "o", allow_dirty=True)
    assert reached[0][4] is True


def test_pass3_disabled_and_zero_llm_calls(repo, tmp_path, reached, monkeypatch):
    import graphify.llm as llm
    calls = []
    for name in dir(llm):
        fn = getattr(llm, name)
        if callable(fn) and not name.startswith("_") and getattr(fn, "__module__", "") == llm.__name__:
            monkeypatch.setattr(llm, name, lambda *a, _n=name, **k: calls.append(_n))
    with pytest.raises(ValueError):
        build_code_graph(repo, "r1", out=tmp_path / "o", passes="semantic")  # type: ignore[arg-type]
    build_code_graph(repo, "r1", out=tmp_path / "o")
    assert calls == []


def test_attach_provenance(repo):
    from bellu_graphify.provenance import head_revision
    rev = head_revision(repo)
    g = nx.Graph()
    g.add_node("f", source_file=str(repo / "a.py"), source_location="L1")
    g.add_node("ext")
    attach_provenance(g, repo, rev, "r1")
    loc = g.nodes["f"]["bellu_source_location"]
    assert loc["revision"] == rev and loc["path"] == "a.py" and loc["start_line"] == loc["end_line"] == 1
    assert loc["content_sha256"] == hashlib.sha256(b"def f():\n    pass\n").hexdigest()
    assert "bellu_source_location" not in g.nodes["ext"]


@pytest.mark.parametrize("kw", [{"revision": "main"}, {"start_line": 0}, {"end_line": 0}, {"path": "/abs"}, {"path": "a" * 4097}])
def test_source_location_rejects_invalid(kw):
    base = dict(repo_id="r", revision="a" * 40, path="a.py", start_line=1, end_line=1, content_sha256="b" * 64)
    with pytest.raises(ValueError):
        SourceLocation(**{**base, **kw})
