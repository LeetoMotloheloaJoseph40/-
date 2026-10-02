"""
SecureAgent — the runtime that wires gates together (Stages 1-4).

Two entry points, with deliberately different guarantees:

call_tool(name, **kwargs)
    Direct, application-initiated invocation:
        Identity -> Tool (-> Permission) -> execution -> Audit.
    There is no user request, untrusted context, or model proposal here, so
    Intent, Trust, Data and Risk/Approval do not apply. Use this when YOUR
    OWN code, not a model, is choosing the call.

run(request, planner, ...)
    Model-driven loop, carrying the full gate chain for every proposed call:
        Identity -> Intent scope -> Trust taint rule
            -> Tool (-> Permission) -> Data (egress DLP + classification ceiling)
            -> Risk (score) -> [Approval if REQUIRE_APPROVAL] -> execute
    and every tool RESULT re-enters Trust (injection quarantine) and Data
    (secret redaction) before the planner sees it. Denied/blocked/withheld
    calls do not raise: they are recorded in the RunResult and the run
    continues.

Approval: a REQUIRE_APPROVAL decision (from Trust's taint rule or from Risk's
scoring) is resolved by calling `approver.decide(ApprovalRequest)`. The
default approver (DenyAllApprover) always declines, so by default a held
action stays held — "approval service unavailable -> do not execute" applies
equally to "no approver configured". The approval outcome is its own audit
event under gate="approval", separate from the decision that triggered it.
"""

from __future__ import annotations

from collections.abc import Sequence

from eightgates.approval.store import ApprovalStore
from eightgates.audit.logger import AuditLogger
from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.exceptions import GateDenied, UnknownToolError
from eightgates.core.models import (
    AgentIdentity,
    ApprovalRequest,
    ContextItem,
    RiskAssessment,
    RiskLevel,
    SecurityContext,
    ToolCallRequest,
    TrustLevel,
    UserIdentity,
)
from eightgates.core.runtime import Approver, Planner, RunResult, ToolOutcome
from eightgates.gates.audit import AuditGate
from eightgates.gates.data import DataGate
from eightgates.gates.identity import IdentityGate
from eightgates.gates.intent import IntentGate
from eightgates.gates.permission import PermissionGate
from eightgates.gates.risk import RiskGate
from eightgates.gates.tool import ToolGate
from eightgates.gates.trust import TrustGate
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.intent import IntentPolicy
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.testing.approvers import DenyAllApprover
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool

_SCORE_BY_LEVEL: dict[RiskLevel, int] = {
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 35,
    RiskLevel.HIGH: 60,
    RiskLevel.CRITICAL: 85,
}


class SecureAgent:
    def __init__(
        self,
        name: str,
        identity: AgentIdentity,
        policy: Policy,
        tools: list[Tool] | None = None,
        audit_logger: AuditLogger | None = None,
        *,
        intent_policy: IntentPolicy | None = None,
        trust_gate: TrustGate | None = None,
        data_gate: DataGate | None = None,
        risk_gate: RiskGate | None = None,
        approver: Approver | None = None,
    ):
        self.name = name
        self.identity = identity
        # Snapshot: later mutation of the caller's Policy object must not silently
        # change what this agent is authorized to do.
        self.policy = policy.model_copy(deep=True)

        # Each SecureAgent owns its own registries/engine so agents stay
        # isolated by default (least privilege at the object-graph level).
        self._identity_registry = IdentityRegistry()
        self._identity_registry.register(identity)
        self._policy_engine = PolicyEngine()
        self._policy_engine.register(self.policy)
        self._tool_registry = ToolRegistry()
        for tool in tools or []:
            self._tool_registry.register(tool)

        self.audit_logger = audit_logger or AuditLogger()
        self.approval_store = ApprovalStore()

        self._identity_gate = IdentityGate(self._identity_registry)
        self._permission_gate = PermissionGate(self._policy_engine)
        self._tool_gate = ToolGate(self._tool_registry, self._permission_gate)
        self._audit_gate = AuditGate(self.audit_logger)
        # Intent scoping is opt-in: without an IntentPolicy there is nothing to scope to.
        self._intent_gate = IntentGate(intent_policy) if intent_policy else None
        self._trust_gate = trust_gate or TrustGate()
        self._data_gate = data_gate or DataGate()
        self._risk_gate = risk_gate or RiskGate()
        # Fail closed: an unconfigured approver denies, exactly like an unavailable one.
        self.approver: Approver = approver or DenyAllApprover()

    # ------------------------------------------------------------------ helpers

    def _check(self, decision: SecurityDecision) -> SecurityDecision:
        self._audit_gate.record(decision)
        return decision

    def _resolve_approval(
        self, context: SecurityContext, held: SecurityDecision
    ) -> SecurityDecision:
        """Take a REQUIRE_APPROVAL decision to the configured Approver and audit the outcome."""
        risk = RiskAssessment(
            score=_SCORE_BY_LEVEL[held.risk_level],
            level=held.risk_level,
            reasons=[held.reason],
            requires_human_approval=True,
        )
        request = ApprovalRequest(
            trace_id=context.trace_id,
            agent_id=context.agent.id,
            user_id=context.user.id if context.user else None,
            action=held.action,
            resource=held.resource,
            reason=held.reason,
            risk=risk,
        )
        self.approval_store.add(request)
        approved = self.approver.decide(request)
        self.approval_store.resolve(request.id, approved)

        outcome = SecurityDecision(
            trace_id=context.trace_id,
            gate="approval",
            agent_id=context.agent.id,
            action=held.action,
            resource=held.resource,
            decision=DecisionType.ALLOW if approved else DecisionType.DENY,
            reason=(
                f"Approved by {type(self.approver).__name__} "
                f"(held by '{held.gate}': {held.reason})"
                if approved
                else f"Not approved (held by '{held.gate}': {held.reason})"
            ),
            risk_level=held.risk_level,
        )
        return self._check(outcome)

    def _authorize(
        self,
        context: SecurityContext,
        tool_name: str,
        *,
        request: str | None,
        items: Sequence[ContextItem],
        arguments: dict,
    ) -> SecurityDecision:
        """Run the full per-call gate chain. Returns the final ALLOW/DENY(/etc) decision."""
        call_ctx = context.model_copy(update={"action": f"tool.{tool_name}", "resource": tool_name})

        d = self._check(self._identity_gate.evaluate(call_ctx))
        if not d.is_allowed:
            return d

        if self._intent_gate is not None and request is not None:
            d = self._check(self._intent_gate.evaluate(call_ctx, request=request, tool_name=tool_name))
            if not d.is_allowed:
                return d

        tool = self._tool_registry.get(tool_name)
        tainted = any(i.trust == TrustLevel.UNTRUSTED for i in items)

        if items and tool is not None:
            d = self._check(self._trust_gate.evaluate(call_ctx, items=list(items), tool=tool))
            if d.decision == DecisionType.REQUIRE_APPROVAL:
                return self._resolve_approval(call_ctx, d)
            if not d.is_allowed:
                return d

        d = self._check(
            self._tool_gate.evaluate(call_ctx, tool_name=tool_name, policy_name=self.policy.name)
        )
        if not d.is_allowed:
            return d

        assert tool is not None  # ToolGate already confirmed this
        d = self._check(self._data_gate.evaluate(call_ctx, tool=tool, arguments=arguments))
        if not d.is_allowed:
            return d

        d = self._check(
            self._risk_gate.evaluate(
                call_ctx, tool=tool, data_classification=tool.capability.data_sensitivity, tainted=tainted
            )
        )
        if d.decision == DecisionType.REQUIRE_APPROVAL:
            return self._resolve_approval(call_ctx, d)
        return d

    def _execute(self, context: SecurityContext, tool: Tool, kwargs: dict) -> object:
        result = tool(**kwargs)
        self._audit_gate.evaluate(
            context.model_copy(update={"action": f"tool.{tool.name}.completed", "resource": tool.name})
        )
        return result

    # --------------------------------------------------------------- entry points

    def call_tool(self, tool_name: str, user: UserIdentity | None = None, **kwargs: object) -> object:
        """Direct tool invocation through Identity -> Tool/Permission -> Audit only."""
        context = SecurityContext(
            agent=self.identity, user=user, action=f"tool.{tool_name}", resource=tool_name
        )
        d = self._check(self._identity_gate.evaluate(context))
        if not d.is_allowed:
            raise GateDenied(d)
        d = self._check(
            self._tool_gate.evaluate(context, tool_name=tool_name, policy_name=self.policy.name)
        )
        if not d.is_allowed:
            if tool_name not in self._tool_registry:
                raise UnknownToolError(str(d))
            raise GateDenied(d)
        tool = self._tool_registry.get(tool_name)
        assert tool is not None
        return self._execute(context, tool, dict(kwargs))

    def run(
        self,
        request: str,
        planner: Planner,
        user: UserIdentity | None = None,
        *,
        context_items: Sequence[ContextItem] = (),
        max_steps: int = 5,
    ) -> RunResult:
        """
        Execute a model-driven request under all implemented gates.

        Raises GateDenied only if the run itself is refused up front (identity
        failure, or an intent decision other than ALLOW). Everything after that
        is recorded in the returned RunResult.
        """
        context = SecurityContext(agent=self.identity, user=user, action="agent.run")

        d = self._check(self._identity_gate.evaluate(context))
        if not d.is_allowed:
            raise GateDenied(d)

        if self._intent_gate is not None:
            d = self._check(self._intent_gate.evaluate(context, request=request))
            if not d.is_allowed:
                raise GateDenied(d)

        result = RunResult(trace_id=context.trace_id)

        screened = self._trust_gate.screen(
            context, [ContextItem(content=request, source="user"), *context_items]
        )
        self._check(screened.decision)
        accepted: list[ContextItem] = list(screened.accepted)
        result.quarantined_sources.extend(a.item.source for a in screened.rejected)

        for _ in range(max_steps):
            calls: Sequence[ToolCallRequest] = planner.plan(request, tuple(accepted))
            result.steps += 1
            if not calls:
                result.completed = True
                break
            for call in calls:
                self._handle_call(context, call, request, accepted, result)
        return result

    def _handle_call(
        self,
        context: SecurityContext,
        call: ToolCallRequest,
        request: str,
        accepted: list[ContextItem],
        result: RunResult,
    ) -> None:
        decision = self._authorize(
            context, call.tool_name, request=request, items=accepted, arguments=dict(call.arguments)
        )
        tool = self._tool_registry.get(call.tool_name)

        if not decision.is_allowed or tool is None:
            result.outcomes.append(ToolOutcome(call, executed=False, decision=decision))
            label = f"'{call.tool_name}'" if tool is not None else "an unregistered tool"
            accepted.append(
                ContextItem(
                    content=f"Tool call to {label} was not executed "
                    f"(gate: {decision.gate}, decision: {decision.decision.value}).",
                    source="system",
                )
            )
            return

        try:
            output = self._execute(context, tool, dict(call.arguments))
        except Exception as exc:  # noqa: BLE001 - planner-supplied args can make a tool body raise anything
            result.outcomes.append(
                ToolOutcome(call, executed=False, decision=decision, error=type(exc).__name__)
            )
            accepted.append(
                ContextItem(content=f"Tool '{tool.name}' failed with {type(exc).__name__}.", source="system")
            )
            return

        result.outcomes.append(ToolOutcome(call, executed=True, decision=decision, result=output))
        self._absorb_tool_result(context, tool, output, accepted, result)

    def _absorb_tool_result(
        self,
        context: SecurityContext,
        tool: Tool,
        output: object,
        accepted: list[ContextItem],
        result: RunResult,
    ) -> None:
        """Screen a tool's output for secrets (Data Gate) then injections (Trust Gate) before it re-enters context."""
        result_ctx = context.model_copy(
            update={"action": f"tool.{tool.name}.result", "resource": tool.name}
        )
        redaction = self._data_gate.screen_result(str(output), tool.capability.data_sensitivity)
        if redaction.redacted:
            rules = ", ".join(f.rule for f in redaction.findings)
            self._check(
                SecurityDecision(
                    trace_id=context.trace_id,
                    gate=self._data_gate.name,
                    agent_id=context.agent.id,
                    action=result_ctx.action,
                    resource=tool.name,
                    decision=DecisionType.QUARANTINE,
                    reason=f"Redacted secret-shaped content from '{tool.name}' output [{rules}].",
                    risk_level=RiskLevel.HIGH,
                )
            )

        item = ContextItem(
            content=redaction.text, source=f"tool:{tool.name}", trust=tool.capability.output_trust
        )
        screened = self._trust_gate.screen(result_ctx, [item])
        self._check(screened.decision)
        accepted.extend(screened.accepted)
        result.quarantined_sources.extend(a.item.source for a in screened.rejected)
