# Bellu addition (not upstream): tests for assign_symbol_ids (task 1.8; Requirements 2.2, 2.3, 2.4).
from __future__ import annotations
import logging
import random
import networkx as nx
from bellu_graphify import assign_symbol_ids

GOLDEN = {
    "a_f": "bid:code:a5rmkpeqiszy37jwkdjk3vu3vn",
    "a_C_m": "bid:code:y2gvxpeeo2pgorv2nvgkyewx2f",
    "a": "bid:code:pc2mzyakrov67as5zx65led7q6",
    "m_Svc": "bid:code:damvxbn6ydeadvfysmtn4iblhc",
}


def _graph(lines=(3, 9, 1, 5), order=None, extra=()):
    specs = [("a_f", "f()", "pkg/a.py", lines[0]), ("a_C_m", ".m()", "pkg/a.py", lines[1]),
             ("a", "a.py", "pkg/a.py", lines[2]), ("m_Svc", "Svc", "src/main.go", lines[3]), *extra]
    random.Random(order).shuffle(specs) if order is not None else None
    g = nx.Graph()
    for nid, label, path, line in specs:
        g.add_node(nid, label=label, source_file=path, source_location=f"L{line}", file_type="code")
    return g


def test_golden_vectors():
    assert assign_symbol_ids(_graph(), "r1") == GOLDEN


def test_line_numbers_and_repo_change_ids():
    assert assign_symbol_ids(_graph(lines=(30, 90, 10, 50)), "r1") == GOLDEN
    assert set(assign_symbol_ids(_graph(), "r2").values()).isdisjoint(GOLDEN.values())


def test_permutation_invariant():
    assert all(assign_symbol_ids(_graph(order=s), "r1") == GOLDEN for s in range(20))


def test_collision_is_ordered_distinct_and_logged_once(caplog):
    extra = [("x1", "dup()", "z.py", 7), ("x2", "dup()", "z.py", 2), ("x3", "dup()", "z.py", 11)]
    with caplog.at_level(logging.WARNING, logger="bellu_graphify"):
        ids = assign_symbol_ids(_graph(extra=extra), "r1")
        again = assign_symbol_ids(_graph(order=3, extra=extra), "r1")
    assert ids == again
    assert len(set(ids.values())) == len(ids)
    records = [r for r in caplog.records if r.getMessage().startswith("bid_collision")]
    assert len(records) == 2  # one per call, one group each
    assert records[0].getMessage().index('"x2"') < records[0].getMessage().index('"x1"') < records[0].getMessage().index('"x3"')
    assert ids["x2"] != ids["x1"] != ids["x3"]
