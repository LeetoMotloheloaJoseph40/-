"""
Audit event model (Stage 1/2).

An AuditEvent is the durable record of a single gate decision. The audit
system is itself security-sensitive: this model deliberately has no field
for arbitrary free-text payloads, so a careless caller can't accidentally
write secrets or raw sensitive data into the audit trail.
"""

from __future__ import annotations

import datetime as _dt

from pydantic import BaseModel, Field

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel


class AuditEvent(BaseModel):
    trace_id: str
    gate: str
    agent_id: str
    action: str
    resource: str | None = None
    decision: DecisionType
    reason: str
    risk_level: RiskLevel
    policy: str | None = None
    timestamp: _dt.datetime = Field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc)
    )

    def __str__(self) -> str:
        return (
            f"[{self.gate}] {self.decision.value} "
            f"agent={self.agent_id} action={self.action} "
            f"risk={self.risk_level.value} reason={self.reason!r}"
        )

    @classmethod
    def from_decision(cls, decision: SecurityDecision) -> AuditEvent:
        return cls(
            trace_id=decision.trace_id,
            gate=decision.gate,
            agent_id=decision.agent_id,
            action=decision.action,
            resource=decision.resource,
            decision=decision.decision,
            reason=decision.reason,
            risk_level=decision.risk_level,
            policy=decision.policy,
            timestamp=decision.timestamp,
        )
