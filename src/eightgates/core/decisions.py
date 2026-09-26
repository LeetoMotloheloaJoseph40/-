"""
The security decision model (Stage 1).

Every gate produces exactly one SecurityDecision. Decisions are the only
currency gates trade in — a gate never mutates state or takes action
directly; the runtime (see eightgates.agent) is responsible for acting on
the decision (proceeding, raising GateDenied, escalating, etc).
"""

from __future__ import annotations

import datetime as _dt
import enum

from pydantic import BaseModel, Field

from eightgates.core.models import RiskLevel


class DecisionType(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ESCALATE = "ESCALATE"
    REAUTHENTICATE = "REAUTHENTICATE"


class SecurityDecision(BaseModel):
    """
    An explainable, structured verdict from a single gate.

    Fields deliberately mirror the "explainability" requirement in the
    spec (gate, subject, action, resource, policy, risk, decision, reason,
    trace id, timestamp) so a SecurityDecision can be logged, displayed to
    a human, or serialized for an audit trail with no extra translation.
    """

    trace_id: str
    gate: str
    agent_id: str
    action: str
    resource: str | None = None
    decision: DecisionType
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    policy: str | None = None
    timestamp: _dt.datetime = Field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc)
    )

    @property
    def is_allowed(self) -> bool:
        return self.decision == DecisionType.ALLOW

    def __str__(self) -> str:  # human-readable one-liner for logs/CLI
        return (
            f"[{self.gate}] {self.decision.value} "
            f"agent={self.agent_id} action={self.action} "
            f"risk={self.risk_level.value} reason={self.reason!r}"
        )
