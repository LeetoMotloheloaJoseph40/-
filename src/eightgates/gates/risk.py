"""
Gate 7 — Risk / Approval Gate.

Produces a deterministic, inspectable RiskAssessment from declared tool
metadata and context (classification, taint), and converts it into a
decision: ALLOW for low/medium risk, REQUIRE_APPROVAL for high/critical.

The score is a POLICY INPUT, not an objective measure of danger (per the
spec's own caution about this) — it exists so the resulting decision is
explainable and reproducible, not so two different actions can be ranked
against each other with any precision.

This gate does not itself ask a human anything; SecureAgent is responsible
for taking a REQUIRE_APPROVAL decision to an Approver (see core/runtime.py)
and recording the outcome as a separate "approval" audit event.
"""

from __future__ import annotations

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import DataClassification, RiskAssessment, RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.tools.tool import Tool

_BASE_SCORE: dict[RiskLevel, int] = {
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 35,
    RiskLevel.HIGH: 60,
    RiskLevel.CRITICAL: 85,
}
_CLASSIFICATION_WEIGHT: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 0,
    DataClassification.CONFIDENTIAL: 5,
    DataClassification.SENSITIVE: 10,
    DataClassification.SECRET: 20,
    DataClassification.RESTRICTED: 25,
}
_EXTERNAL_EFFECT_WEIGHT = 15
_IRREVERSIBLE_WEIGHT = 15
_TAINT_WEIGHT = 10


def score_tool_call(
    tool: Tool,
    *,
    data_classification: DataClassification = DataClassification.INTERNAL,
    tainted: bool = False,
) -> RiskAssessment:
    cap = tool.capability
    score = _BASE_SCORE[cap.risk_level]
    reasons = [f"tool declared risk {cap.risk_level.value}"]

    if cap.external_effect:
        score += _EXTERNAL_EFFECT_WEIGHT
        reasons.append("tool has external effects")
    if not cap.reversible:
        score += _IRREVERSIBLE_WEIGHT
        reasons.append("action is not reversible")
    class_weight = _CLASSIFICATION_WEIGHT[data_classification]
    if class_weight:
        score += class_weight
        reasons.append(f"data classification {data_classification.value}")
    if tainted:
        score += _TAINT_WEIGHT
        reasons.append("this run has processed untrusted content")

    score = min(score, 100)
    if score < 30:
        level = RiskLevel.LOW
    elif score < 55:
        level = RiskLevel.MEDIUM
    elif score < 80:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    return RiskAssessment(
        score=score,
        level=level,
        reasons=reasons,
        requires_human_approval=level in (RiskLevel.HIGH, RiskLevel.CRITICAL),
    )


class RiskGate(Gate):
    name = "risk"

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
        )

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        """
        Evidence:
          tool:               Tool (required)
          data_classification: DataClassification (optional, default INTERNAL)
          tainted:             bool (optional, default False)
        """
        tool = evidence.get("tool")
        if not isinstance(tool, Tool):
            raise TypeError("RiskGate.evaluate requires a 'tool' evidence kwarg.")

        classification = evidence.get("data_classification", DataClassification.INTERNAL)
        if not isinstance(classification, DataClassification):
            classification = DataClassification.INTERNAL
        tainted = bool(evidence.get("tainted", False))

        assessment = score_tool_call(tool, data_classification=classification, tainted=tainted)
        reason = f"risk={assessment.level.value} (score={assessment.score}): " + "; ".join(
            assessment.reasons
        )

        if assessment.requires_human_approval:
            return self._decision(
                context, DecisionType.REQUIRE_APPROVAL, reason, assessment.level, resource=tool.name
            )
        return self._decision(context, DecisionType.ALLOW, reason, assessment.level, resource=tool.name)
