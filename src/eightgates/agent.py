"""
SecureAgent — the runtime that wires gates together (Stages 1-3).

Two entry points, with deliberately different guarantees:

call_tool(name, **kwargs)
    Direct, application-initiated invocation. Runs
        Identity -> Tool (-> Permission) -> execution -> Audit.
    There is no user request or untrusted context here, so the Intent and
    Trust gates do not apply. Use this when your own code (not a model) is
    choosing the call.

run(request, planner, ...)
    Model-driven loop. Runs Identity -> Intent -> Trust on the request and any
    supplied context, then repeatedly asks the (untrusted) planner for tool
    calls; every proposed call passes
        Identity -> Intent scope -> Trust taint rule -> Tool (-> Permission)
    and every tool RESULT re-enters the Trust Gate as new, untrusted content
    before the planner sees it. Denied calls do not raise: they are recorded
    in the RunResult and the run continues.

Still to come: Data/Memory gate, Risk/Approval gate (so REQUIRE_APPROVAL
currently means "not executed"), delegation, MCP, framework adapters.
"""

from __future__ import annotations

from collections.abc import Sequence

from eightgates.audit.logger import AuditLogger
from eightgates.core.decisions import SecurityDecision
from eightgates.core.exceptions import GateDenied, UnknownToolError
from eightgates.core.models import (
    AgentIdentity,
    ContextItem,
    SecurityContext,
    ToolCallRequest,
    TrustLevel,
    UserIdentity,
)
from eightgates.core.runtime import Planner, RunResult, ToolOutcome
from eightgates.gates.audit import AuditGate
from eightgates.gates.identity import IdentityGate
from eightgates.gates.intent import IntentGate
from eightgates.gates.permission import PermissionGate
from eightgates.gates.tool import ToolGate
from eightgates.gates.trust import ScreenResult, TrustGate
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.intent import IntentPolicy
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool


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

        self._identity_gate = IdentityGate(self._identity_registry)
        self._permission_gate = PermissionGate(self._policy_engine)
        self._tool_gate = ToolGate(self._tool_registry, self._permission_gate)
        self._audit_gate = AuditGate(self.audit_logger)
        # Intent scoping is opt-in: without an IntentPolicy there is nothing to scope to.
        self._intent_gate = IntentGate(intent_policy) if intent_policy else None
        self._trust_gate = trust_gate or TrustGate()

    # ------------------------------------------------------------------ helpers

    def _check(self, decision: SecurityDecision) -> SecurityDecision:
        self._audit_gate.record(decision)
        return decision

    def _authorize(
        self,
        context: SecurityContext,
        tool_name: str,
        *,
        request: str | None,
        items: Sequence[ContextItem],
        tainted: Sequence[str] = (),
    ) -> SecurityDecision:
        """Run the per-call gate chain. Returns the first non-ALLOW decision, else the tool gate's ALLOW."""
        call_ctx = context.model_copy(update={"action": f"tool.{tool_name}", "resource": tool_name})

        d = self._check(self._identity_gate.evaluate(call_ctx))
        if not d.is_allowed:
            return d

        if self._intent_gate is not None and request is not None:
            d = self._check(
                self._intent_gate.evaluate(call_ctx, request=request, tool_name=tool_name)
            )
            if not d.is_allowed:
                return d

        tool = self._tool_registry.get(tool_name)
        if (items or tainted) and tool is not None:
            d = self._check(
                self._trust_gate.evaluate(
                    call_ctx, items=list(items), tool=tool, tainted_sources=list(tainted)
                )
            )
            if not d.is_allowed:
                return d

        return self._check(
            self._tool_gate.evaluate(call_ctx, tool_name=tool_name, policy_name=self.policy.name)
        )

    @staticmethod
    def _note_taint(screened: ScreenResult, tainted: set[str]) -> None:
        """Record sources of untrusted content. Rejected items count: quarantine is not amnesty."""
        tainted.update(i.source for i in screened.accepted if i.trust == TrustLevel.UNTRUSTED)
        tainted.update(a.item.source for a in screened.rejected)

    def _execute(self, context: SecurityContext, tool: Tool, kwargs: dict) -> object:
        result = tool(**kwargs)
        self._audit_gate.evaluate(
            context.model_copy(update={"action": f"tool.{tool.name}.completed", "resource": tool.name})
        )
        return result

    # --------------------------------------------------------------- entry points

    def call_tool(
        self, tool_name: str, user: UserIdentity | None = None, **kwargs: object
    ) -> object:
        """Direct tool invocation through Identity -> Tool/Permission -> Audit."""
        context = SecurityContext(
            agent=self.identity, user=user, action=f"tool.{tool_name}", resource=tool_name
        )
        decision = self._authorize(context, tool_name, request=None, items=())
        if not decision.is_allowed:
            if tool_name not in self._tool_registry:
                raise UnknownToolError(str(decision))
            raise GateDenied(decision)
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
        tainted: set[str] = set()
        self._note_taint(screened, tainted)
        result.quarantined_sources.extend(a.item.source for a in screened.rejected)

        for _ in range(max_steps):
            calls: Sequence[ToolCallRequest] = planner.plan(request, tuple(accepted))
            result.steps += 1
            if not calls:
                result.completed = True
                break
            for call in calls:
                self._handle_call(context, call, request, accepted, tainted, result)
        return result

    def _handle_call(
        self,
        context: SecurityContext,
        call: ToolCallRequest,
        request: str,
        accepted: list[ContextItem],
        tainted: set[str],
        result: RunResult,
    ) -> None:
        decision = self._authorize(
            context, call.tool_name, request=request, items=accepted, tainted=sorted(tainted)
        )
        tool = self._tool_registry.get(call.tool_name)

        if not decision.is_allowed or tool is None:
            result.outcomes.append(ToolOutcome(call, executed=False, decision=decision))
            # The tool name comes from the (untrusted) planner, so only echo it back
            # into a TRUSTED system note if it is a name WE registered.
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
        except Exception as exc:  # noqa: BLE001 - intentional: planner-supplied args can make a tool body raise anything
            result.outcomes.append(
                ToolOutcome(call, executed=False, decision=decision, error=type(exc).__name__)
            )
            accepted.append(
                ContextItem(
                    content=f"Tool '{tool.name}' failed with {type(exc).__name__}.",
                    source="system",
                )
            )
            return

        result.outcomes.append(ToolOutcome(call, executed=True, decision=decision, result=output))

        # The tool's output is new content entering the context: screen it before
        # the planner ever sees it (indirect prompt injection lands here).
        item = ContextItem(
            content=str(output), source=f"tool:{tool.name}", trust=tool.capability.output_trust
        )
        screened = self._trust_gate.screen(
            context.model_copy(update={"action": f"tool.{tool.name}.result", "resource": tool.name}),
            [item],
        )
        self._check(screened.decision)
        accepted.extend(screened.accepted)
        self._note_taint(screened, tainted)
        result.quarantined_sources.extend(a.item.source for a in screened.rejected)

