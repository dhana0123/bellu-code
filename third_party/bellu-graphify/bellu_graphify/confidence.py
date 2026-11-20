# Bellu addition (not upstream): map Graphify edge confidence tags to the Bellu edge model.
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable

HYPOTHESIS_CONFIDENCE = 0.40


@dataclass(frozen=True)
class MappedEdge:
    edge: dict
    state: str  # confirmed | candidate | hypothesis
    confidence: float


@dataclass(frozen=True)
class EdgeError:
    edge: str  # "source->target" identification
    reason: str

    def __str__(self) -> str:
        return f"edge {self.edge}: {self.reason}"


def edge_label(edge: dict) -> str:
    return f"{edge.get('source', edge.get('_src', '?'))}->{edge.get('target', edge.get('_tgt', '?'))}"


def map_edge(edge: dict) -> MappedEdge:
    """Map one edge. Raises ValueError with the reason when the edge must be rejected."""
    tag = edge.get("confidence")
    if tag == "EXTRACTED":
        return MappedEdge(edge, "confirmed", 1.0)
    if tag == "AMBIGUOUS":
        return MappedEdge(edge, "hypothesis", HYPOTHESIS_CONFIDENCE)
    if tag == "INFERRED":
        score = edge.get("confidence_score")
        if not _valid_score(score):
            reason = "INFERRED edge has missing confidence_score" if score is None \
                else f"INFERRED edge has out-of-range confidence_score {score!r}"
            raise ValueError(reason)
        return MappedEdge(edge, "candidate", float(score))
    raise ValueError(f"unknown confidence tag {tag!r}")


def map_edges(edges: Iterable[dict]) -> tuple[list[MappedEdge], list[EdgeError]]:
    """Map every edge, rejecting bad ones with an error and continuing with the rest."""
    mapped: list[MappedEdge] = []
    errors: list[EdgeError] = []
    for edge in edges:
        try:
            mapped.append(map_edge(edge))
        except ValueError as exc:
            errors.append(EdgeError(edge_label(edge), str(exc)))
    return mapped, errors


def _valid_score(score: Any) -> bool:
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return False
    return math.isfinite(score) and 0.0 <= score <= 1.0
