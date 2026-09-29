"""
Gate 3 — Trust Gate.

Responsibilities (all implemented deterministically, none of them magic):

1. Label every piece of context with a TrustLevel derived from its SOURCE.
2. Quarantine untrusted content that matches known injection patterns, so it
   never reaches the planner/LLM.
3. Refuse to let an untrusted-tainted run perform side-effecting actions
   without approval. This is the layer that still works when detection misses:
   an injection we failed to recognise cannot, by itself, trigger an email,
   a payment or a deletion.

Known limits (see SECURITY.md): taint is tracked coarsely per run — if ANY
untrusted content is in context, every later external-effect tool call is
treated as tainted; there is no per-value data-flow tracking. Content from a
TRUSTED source is not scanned.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import ContextItem, RiskLevel, SecurityContext, TrustLevel
from eightgates.gates.base import Gate
from eightgates.security.injection import InjectionFinding, PromptInjectionDetector
from eightgates.security.trust import TrustPolicy
from eightgates.tools.tool import Tool

_SEVERITY = {
    DecisionType.ALLOW: 0,
    DecisionType.REQUIRE_APPROVAL: 1,
    DecisionType.DENY: 1,
    DecisionType.QUARANTINE: 2,
    DecisionType.BLOCK: 3,
}


@dataclass(frozen=True)
class ItemAssessment:
    item: ContextItem
    trust: TrustLevel
    findings: tuple[InjectionFinding, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.trust == TrustLevel.MALICIOUS

    @property
    def quarantined(self) -> bool:
        return self.trust == TrustLevel.QUARANTINED or bool(self.findings)

    @property
    def rejected(self) -> bool:
        return self.blocked or self.quarantined


@dataclass(frozen=True)
class ScreenResult:
    decision: SecurityDecision
    accepted: tuple[ContextItem, ...]  # trust label resolved and stamped on each
    rejected: tuple[ItemAssessment, ...]


class TrustGate(Gate):
    name = "trust"

    def __init__(
        self,
        trust_policy: TrustPolicy | None = None,
        detector: PromptInjectionDetector | None = None,
        untrusted_side_effect_decision: DecisionType = DecisionType.REQUIRE_APPROVAL,
    ):
        self.trust_policy = trust_policy or TrustPolicy()
        self.detector = detector or PromptInjectionDetector()
        self.untrusted_side_effect_decision = untrusted_side_effect_decision

    def assess(self, items: Sequence[ContextItem]) -> list[ItemAssessment]:
        assessments = []
        for item in items:
            trust = item.trust if item.trust is not None else self.trust_policy.resolve(item.source)
            findings: tuple[InjectionFinding, ...] = ()
            if trust in (TrustLevel.UNTRUSTED, TrustLevel.PARTIALLY_TRUSTED):
                findings = tuple(self.detector.scan(item.content))
                if findings:
                    trust = TrustLevel.QUARANTINED
            assessments.append(ItemAssessment(item, trust, findings))
        return assessments

    def screen(self, context: SecurityContext, items: Sequence[ContextItem]) -> ScreenResult:
        """Assess a batch of context items and partition into accepted / rejected."""
        assessments = self.assess(items)
        rejected = tuple(a for a in assessments if a.rejected)
        accepted = tuple(
            a.item.model_copy(update={"trust": a.trust}) for a in assessments if not a.rejected
        )

        if any(a.blocked for a in rejected):
            kind, decision_type, risk = "Blocked", DecisionType.BLOCK, RiskLevel.CRITICAL
        elif rejected:
            kind, decision_type, risk = "Quarantined", DecisionType.QUARANTINE, RiskLevel.HIGH
        else:
            kind, decision_type, risk = "", DecisionType.ALLOW, RiskLevel.LOW

        if rejected:
            # Sources and rule names only — never the content itself.
            detail = "; ".join(
                f"source '{a.item.source}'"
                + (f" matched [{', '.join(f.rule for f in a.findings)}]" if a.findings else
                   f" is marked {a.trust.value}")
                for a in rejected
            )
            reason = f"{kind} {len(rejected)} context item(s): {detail}."
        elif items:
            reason = f"{len(items)} context item(s) assessed; none rejected."
        else:
            reason = "No context items to assess."

        decision = SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=context.resource,
            decision=decision_type,
            reason=reason,
            risk_level=risk,
        )
        return ScreenResult(decision, accepted, rejected)

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        """
        Evidence:
          items: Sequence[ContextItem] — the context the agent is operating on.
          tool:  Tool (optional) — if given, apply the tainted-run rule for that tool.
          tainted_sources: sources of untrusted content already seen in this run,
              INCLUDING content that was quarantined. Quarantining removes a payload
              from the context but must not clear the run's suspicion.
        """
        raw_items = evidence.get("items", ())
        items = list(raw_items) if isinstance(raw_items, (list, tuple)) else []
        result = self.screen(context, items)
        if result.decision.decision != DecisionType.ALLOW:
            return result.decision

        tool = evidence.get("tool")
        if isinstance(tool, Tool) and tool.capability.external_effect:
            carried = evidence.get("tainted_sources", ())
            untrusted_sources = sorted(
                {i.source for i in result.accepted if i.trust == TrustLevel.UNTRUSTED}
                | set(carried if isinstance(carried, (list, tuple, set, frozenset)) else ())
            )
            if untrusted_sources:
                return SecurityDecision(
                    trace_id=context.trace_id,
                    gate=self.name,
                    agent_id=context.agent.id,
                    action=context.action,
                    resource=tool.name,
                    decision=self.untrusted_side_effect_decision,
                    reason=(
                        f"This run has processed untrusted content (sources: "
                        f"{', '.join(untrusted_sources)}) and tool '{tool.name}' has "
                        f"external effects; it cannot proceed without approval."
                    ),
                    risk_level=RiskLevel.HIGH,
                )
        return result.decision
