"""
Runtime types for SecureAgent.run() (Stage 3).

The framework is model-agnostic: anything that can propose tool calls given a
request and the (already screened) context implements `Planner`. An LLM
adapter is just one implementation. The planner is treated as UNTRUSTED —
its proposals are requests, never authorizations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from eightgates.core.decisions import SecurityDecision
from eightgates.core.models import ApprovalRequest, ContextItem, ToolCallRequest


class Planner(Protocol):
    def plan(self, request: str, context: Sequence[ContextItem]) -> Sequence[ToolCallRequest]:
        """Return proposed tool calls for the next step; an empty sequence means 'done'."""
        ...


class Approver(Protocol):
    def decide(self, request: ApprovalRequest) -> bool:
        """
        Approve or deny ONE specific ApprovalRequest. The request carries the
        agent, action, resource, reason and full RiskAssessment (including why
        it was held, e.g. untrusted content) — a real implementation should
        show a human that context, not just a yes/no prompt.
        """
        ...


@dataclass
class ToolOutcome:
    call: ToolCallRequest
    executed: bool
    decision: SecurityDecision  # the decision that allowed the call, or the one that stopped it
    result: object | None = None
    error: str | None = None  # exception type name if the tool body raised


@dataclass
class RunResult:
    trace_id: str
    outcomes: list[ToolOutcome] = field(default_factory=list)
    quarantined_sources: list[str] = field(default_factory=list)
    steps: int = 0
    completed: bool = False  # False if max_steps was reached before the planner finished

    @property
    def executed(self) -> list[ToolOutcome]:
        return [o for o in self.outcomes if o.executed]

    @property
    def stopped(self) -> list[ToolOutcome]:
        return [o for o in self.outcomes if not o.executed]
