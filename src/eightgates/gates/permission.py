"""
Gate 4 — Permission Gate.

Responsibility: given a verified identity (Gate 1 has already run) and a
requested action, decide whether that specific action is authorized under
the agent's policy. The fact that an agent produced a tool call or a
request does not by itself imply authorization — that judgement lives
entirely here and in PolicyEngine.
"""

from __future__ import annotations

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.policy.policy import PolicyEngine


class PermissionGate(Gate):
    """Authorizes context.action against the agent's policy."""

    name = "permission"

    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        policy_name = evidence.get("policy_name") or context.metadata.get("policy_name")

        if not policy_name:
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=context.resource,
                decision=DecisionType.DENY,
                reason="No policy associated with this agent; denying by default.",
                risk_level=RiskLevel.MEDIUM,
            )

        authorized = self.policy_engine.is_authorized(str(policy_name), context.action)

        if not authorized:
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=context.resource,
                decision=DecisionType.DENY,
                reason=(
                    f"Policy '{policy_name}' does not grant permission "
                    f"'{context.action}'."
                ),
                risk_level=RiskLevel.MEDIUM,
                policy=str(policy_name),
            )

        return SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=context.resource,
            decision=DecisionType.ALLOW,
            reason=f"Policy '{policy_name}' grants permission '{context.action}'.",
            risk_level=RiskLevel.LOW,
            policy=str(policy_name),
        )
