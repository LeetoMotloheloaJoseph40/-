"""
Gate 6 — Data / Memory Gate.

Two responsibilities, both deterministic:

1. EGRESS DLP: before a tool with external effects runs, scan its arguments
   for secret-shaped content (see security/secrets.py) and block the call
   outright if any is found — a credential should never leave through a tool
   call just because the planner was tricked (or asked) to send it.
2. CLASSIFICATION CEILING: compare a tool's declared data sensitivity against
   the policy's ceiling and deny if the tool exceeds it.

A third method, `screen_result`, is used by SecureAgent (not by evaluate())
to redact secrets out of tool OUTPUT before it re-enters the model's context,
mirroring how the Trust Gate quarantines injected instructions in output.

Known limits (see SECURITY.md): detection is pattern-based, see
security/secrets.py for exactly what is and isn't caught. There is no
tracking of *where* a value in an argument came from — a secret is blocked
wherever it appears, but a non-secret-shaped value derived from sensitive
data is not traced.
"""

from __future__ import annotations

from dataclasses import dataclass

from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import DataClassification, RiskLevel, SecurityContext
from eightgates.gates.base import Gate
from eightgates.security.secrets import SecretFinding, SecretScanner
from eightgates.tools.tool import Tool

_CLASSIFICATION_RANK: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.SENSITIVE: 3,
    DataClassification.SECRET: 4,
    DataClassification.RESTRICTED: 5,
}


@dataclass(frozen=True)
class RedactionResult:
    text: str
    classification: DataClassification
    findings: tuple[SecretFinding, ...]

    @property
    def redacted(self) -> bool:
        return bool(self.findings)


class DataGate(Gate):
    name = "data"

    def __init__(
        self,
        scanner: SecretScanner | None = None,
        ceiling: DataClassification = DataClassification.RESTRICTED,  # RESTRICTED = no extra ceiling
    ):
        self.scanner = scanner or SecretScanner()
        self.ceiling = ceiling

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
          tool:      Tool (required) — the tool about to be invoked.
          arguments: dict (optional) — the call's proposed arguments, scanned for secrets
                     if the tool has external effects.
        """
        tool = evidence.get("tool")
        if not isinstance(tool, Tool):
            raise TypeError("DataGate.evaluate requires a 'tool' evidence kwarg.")

        if _CLASSIFICATION_RANK[tool.capability.data_sensitivity] > _CLASSIFICATION_RANK[self.ceiling]:
            return self._decision(
                context,
                DecisionType.DENY,
                f"Tool '{tool.name}' handles {tool.capability.data_sensitivity.value} data, "
                f"above this agent's ceiling of {self.ceiling.value}.",
                RiskLevel.HIGH,
                resource=tool.name,
            )

        arguments = evidence.get("arguments")
        if tool.capability.external_effect and isinstance(arguments, dict):
            findings = self.scanner.scan(" ".join(str(v) for v in arguments.values()))
            if findings:
                rules = ", ".join(f.rule for f in findings)
                return self._decision(
                    context,
                    DecisionType.BLOCK,
                    f"Call to '{tool.name}' blocked: arguments contain secret-shaped "
                    f"content [{rules}]. Secrets are never allowed to leave through a "
                    f"tool with external effects.",
                    RiskLevel.CRITICAL,
                    resource=tool.name,
                )

        return self._decision(
            context, DecisionType.ALLOW, f"No data-protection concerns for '{tool.name}'.",
            RiskLevel.LOW, resource=tool.name,
        )

    def screen_result(self, text: str, declared: DataClassification) -> RedactionResult:
        """Redact secret-shaped spans out of tool OUTPUT before it enters context."""
        findings = self.scanner.scan(text)
        if not findings:
            return RedactionResult(text, declared, ())
        rules = ", ".join(f.rule for f in findings)
        classification = max(declared, DataClassification.SECRET, key=lambda c: _CLASSIFICATION_RANK[c])
        redacted_text = f"[REDACTED by Data Gate: content matched {rules}]"
        return RedactionResult(redacted_text, classification, tuple(findings))
