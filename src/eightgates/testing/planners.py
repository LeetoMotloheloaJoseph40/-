"""Deterministic planners for tests, examples and attack simulations."""

from __future__ import annotations

from collections.abc import Sequence

from eightgates.core.models import ContextItem, ToolCallRequest


class ScriptedPlanner:
    """
    Replays a fixed script: step N returns steps[N], then [] when exhausted.
    Records the context it was shown at every step, so tests can assert what
    did (and did not) reach the model.
    """

    def __init__(self, steps: Sequence[Sequence[ToolCallRequest]]):
        self._steps = [list(s) for s in steps]
        self._i = 0
        self.seen_contexts: list[tuple[ContextItem, ...]] = []

    def plan(self, request: str, context: Sequence[ContextItem]) -> Sequence[ToolCallRequest]:
        self.seen_contexts.append(tuple(context))
        if self._i >= len(self._steps):
            return []
        batch = self._steps[self._i]
        self._i += 1
        return batch


class RepeatingPlanner:
    """Proposes the same call forever — useful for testing step limits."""

    def __init__(self, call: ToolCallRequest):
        self._call = call

    def plan(self, request: str, context: Sequence[ContextItem]) -> Sequence[ToolCallRequest]:
        return [self._call]
