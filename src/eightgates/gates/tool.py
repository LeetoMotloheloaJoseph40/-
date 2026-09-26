"""
Gate 5 — Tool / Action Gate.

Responsibility: a tool call must never execute simply because an agent
(or the LLM driving it) requested it. This gate checks that the tool
exists in the registry and that the agent's policy grants the tool's
declared permission, and folds the tool's own declared risk level into
the decision. It composes with the Permission Gate rather than
duplicating its logic.
"""

from __future__ import annotations

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.gates.permission import PermissionGate
from eightgates.tools.registry import ToolRegistry


class ToolGate(Gate):
    """Authorizes a specific tool invocation."""

    name = "tool"

    def __init__(self, registry: ToolRegistry, permission_gate: PermissionGate):
        self.registry = registry
        self.permission_gate = permission_gate

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        tool_name = evidence.get("tool_name")
        if not tool_name:
            raise ValueError("ToolGate.evaluate requires a 'tool_name' evidence kwarg.")

        tool = self.registry.get(str(tool_name))
        if tool is None:
            # Fail closed: an unregistered tool is denied outright. The
            # runtime (SecureAgent.call_tool) checks registry membership
            # itself and raises UnknownToolError instead of GateDenied in
            # this specific case, so callers can distinguish "no such
            # tool" from an ordinary policy denial.
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=str(tool_name),
                decision=DecisionType.DENY,
                reason=f"Tool '{tool_name}' is not registered.",
                risk_level=RiskLevel.HIGH,
            )

        # Delegate the actual authorization check to the Permission Gate,
        # using the tool's declared permission as the action being checked.
        permission_context = context.model_copy(update={"action": tool.capability.permission})
        permission_decision = self.permission_gate.evaluate(
            permission_context, policy_name=evidence.get("policy_name")
        )

        if not permission_decision.is_allowed:
            return SecurityDecision(
                trace_id=context.trace_id,
                gate=self.name,
                agent_id=context.agent.id,
                action=context.action,
                resource=tool.name,
                decision=permission_decision.decision,
                reason=(
                    f"Tool '{tool.name}' requires permission "
                    f"'{tool.capability.permission}': {permission_decision.reason}"
                ),
                risk_level=tool.capability.risk_level,
                policy=permission_decision.policy,
            )

        return SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=tool.name,
            decision=DecisionType.ALLOW,
            reason=f"Tool '{tool.name}' authorized via permission '{tool.capability.permission}'.",
            risk_level=tool.capability.risk_level,
            policy=permission_decision.policy,
        )
