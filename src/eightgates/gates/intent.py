"""
Gate 2 — Intent Gate.

Responsibility: keep an agent inside the scope of what the USER actually
asked for. The user's request is classified into one of the intents the
agent is configured for, and every proposed tool call is checked against
that intent's tool scope. A tool call outside the scope is an intent/action
mismatch and is denied even if the agent's policy would otherwise permit it.

Fail-closed rules: an unrecognised request is DENIED; an ambiguous request
(matching several intents) is ESCALATED unless the policy opts in to unions.

Not implemented: LLM-based intent extraction, instruction-hierarchy analysis,
or detection of "suspicious" intent beyond scope matching.
"""

from __future__ import annotations

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.policy.intent import IntentPolicy


class IntentGate(Gate):
    name = "intent"

    def __init__(self, policy: IntentPolicy):
        self.policy = policy

    def _decision(self, context, decision, reason, risk, resource=None):
        return SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=resource,
            decision=decision,
            reason=reason,
            risk_level=risk,
            policy=self.policy.name,
        )

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        """Evidence: request (str, required); tool_name (str, optional)."""
        request = evidence.get("request")
        tool_name = evidence.get("tool_name")

        if not isinstance(request, str) or not request.strip():
            return self._decision(
                context, DecisionType.DENY, "No request text to classify.", RiskLevel.MEDIUM
            )

        matches = self.policy.classify(request)
        if not matches:
            return self._decision(
                context,
                DecisionType.DENY,
                "Request does not match any intent this agent is configured for.",
                RiskLevel.MEDIUM,
            )
        if len(matches) > 1 and not self.policy.allow_multiple_intents:
            return self._decision(
                context,
                DecisionType.ESCALATE,
                f"Ambiguous request: matches multiple intents ({', '.join(matches)}).",
                RiskLevel.MEDIUM,
            )

        scope = {t for label in matches for t in self.policy.intents[label].allowed_tools}
        if tool_name is None:
            return self._decision(
                context, DecisionType.ALLOW,
                f"Request classified as: {', '.join(matches)}.", RiskLevel.LOW,
            )
        if tool_name in scope:
            return self._decision(
                context, DecisionType.ALLOW,
                f"Tool '{tool_name}' is within the scope of intent: {', '.join(matches)}.",
                RiskLevel.LOW, resource=str(tool_name),
            )
        return self._decision(
            context,
            DecisionType.DENY,
            f"Intent/action mismatch: tool '{tool_name}' is outside the scope of "
            f"intent: {', '.join(matches)}.",
            RiskLevel.HIGH,
            resource=str(tool_name),
        )
