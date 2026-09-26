"""
Gate 1 — Identity Gate.

Responsibility: determine WHO is acting, and refuse to proceed if that
identity cannot be verified against a known registry. This gate does not
decide what the identity is allowed to do (that's the Permission Gate) —
mixing the two is exactly the conflation the spec warns against.
"""

from __future__ import annotations

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.identity.registry import IdentityRegistry


class IdentityGate(Gate):
    """Verifies that context.agent is a known, registered identity."""

    name = "identity"

    def __init__(self, registry: IdentityRegistry):
        self.registry = registry

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        known = self.registry.get(context.agent.id)

        if known is None:
            # Fail closed: an identity the registry has never seen is denied,
            # not silently trusted just because it showed up on the request.
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=context.resource,
                decision=DecisionType.DENY,
                reason=f"Unknown agent identity '{context.agent.id}' (not registered).",
                risk_level=RiskLevel.HIGH,
            )

        if known.owner != context.agent.owner or known.role != context.agent.role:
            # The caller claims an identity whose recorded attributes don't
            # match the registry — treat as a possible impersonation attempt.
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=context.resource,
                decision=DecisionType.DENY,
                reason="Identity attributes do not match registered identity.",
                risk_level=RiskLevel.CRITICAL,
            )

        return SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=context.resource,
            decision=DecisionType.ALLOW,
            reason="Agent identity verified against registry.",
            risk_level=RiskLevel.LOW,
        )
