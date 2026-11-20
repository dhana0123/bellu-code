# Bellu addition (not upstream): wrapper errors.
from __future__ import annotations


class DirtyTree(Exception):
    """The checkout has uncommitted changes and ``--allow-dirty`` was not supplied."""


class GuardFailure(Exception):
    """A bellu-graphify-check condition failed. ``violations`` holds one line per item."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__("\n".join(violations))
