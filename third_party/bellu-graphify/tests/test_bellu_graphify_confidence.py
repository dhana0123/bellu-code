# Bellu addition (not upstream): tests for confidence mapping and cross-graph proposals (task 1.11).
from __future__ import annotations

from bellu_graphify import map_edges, propose_xrefs


def _e(tag, score=None, s="a", t="b"):
    e = {"source": s, "target": t, "confidence": tag}
    if score is not None:
        e["confidence_score"] = score
    return e


def test_mapping():
    mapped, errors = map_edges([_e("EXTRACTED"), _e("INFERRED", 0.7), _e("AMBIGUOUS", 0.9)])
    assert errors == []
    assert [(m.state, m.confidence) for m in mapped] == [("confirmed", 1.0), ("candidate", 0.7), ("hypothesis", 0.40)]


def test_inferred_bounds_inclusive():
    mapped, errors = map_edges([_e("INFERRED", 0.0), _e("INFERRED", 1.0)])
    assert len(mapped) == 2 and not errors


def test_rejects_and_continues():
    edges = [_e("BOGUS", s="x", t="y"), _e("INFERRED", s="m", t="n"), _e("INFERRED", 1.5), _e("INFERRED", True),
             _e("EXTRACTED", s="ok", t="fine")]
    mapped, errors = map_edges(edges)
    assert [m.edge["source"] for m in mapped] == ["ok"]
    assert len(errors) == 4
    assert errors[0].edge == "x->y" and "BOGUS" in errors[0].reason
    assert errors[1].edge == "m->n" and "missing" in errors[1].reason


def test_xrefs_proposals_only():
    nodes = [
        {"bid": "b1", "source_file": "svc/go.mod", "purls": ["pkg:golang/x/y", "pkg:golang/a/b"]},
        {"bid": "b2", "source_file": ".github/workflows/ci.yml"},
        {"bid": "b3", "source_file": "Dockerfile"},
        {"bid": "b4", "source_file": "main.py"},
    ]
    props = propose_xrefs(nodes)
    assert [(p.source_bid, p.key) for p in props] == [
        ("b1", "pkg:golang/a/b"), ("b1", "pkg:golang/x/y"), ("b2", ".github/workflows/ci.yml"), ("b3", "Dockerfile")]
    assert all(p.graph == "graph3" for p in props)
