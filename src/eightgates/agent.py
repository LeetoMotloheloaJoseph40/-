"""
SecureAgent — the runtime that wires gates together (Stage 1/2).

This is intentionally the smallest correct version of the "central
runtime model" from the spec, covering:

    Identity Gate -> Tool Gate (which itself calls the Permission Gate)
    -> execution -> Audit Gate

Trust, Intent, Data/Memory and Risk/Approval gates — and the LLM
reasoning step that would sit between Intent and Tool in the full
lifecycle — are later-stage work; `SecureAgent.run()` is a placeholder
that documents where that reasoning step will plug in, so the seam is
explicit rather than silently missing.
"""

from __future__ import annotations

from eightgates.audit.logger import AuditLogger
from eightgates.core.exceptions import GateDenied, UnknownToolError
from eightgates.core.models import AgentIdentity, SecurityContext, UserIdentity
from eightgates.gates.audit import AuditGate
from eightgates.gates.identity import IdentityGate
from eightgates.gates.permission import PermissionGate
from eightgates.gates.tool import ToolGate
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool


class SecureAgent:
    """
    A gated wrapper around a set of tools for one AgentIdentity.

    Every tool invocation goes through:
        Identity Gate -> Tool Gate (-> Permission Gate) -> execution -> Audit Gate
    and raises GateDenied (rather than executing) on anything but ALLOW.
    """

    def __init__(
        self,
        name: str,
        identity: AgentIdentity,
        policy: Policy,
        tools: list[Tool] | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.name = name
        self.identity = identity
        self.policy = policy

        # Each SecureAgent owns its own registries/engine so that agents
        # remain isolated from one another by default (least privilege at
        # the object-graph level, not just inside policy data).
        self._identity_registry = IdentityRegistry()
        self._identity_registry.register(identity)

        self._policy_engine = PolicyEngine()
        self._policy_engine.register(policy)

        self._tool_registry = ToolRegistry()
        for tool in tools or []:
            self._tool_registry.register(tool)

        self.audit_logger = audit_logger or AuditLogger()

        self._identity_gate = IdentityGate(self._identity_registry)
        self._permission_gate = PermissionGate(self._policy_engine)
        self._tool_gate = ToolGate(self._tool_registry, self._permission_gate)
        self._audit_gate = AuditGate(self.audit_logger)

    def call_tool(
        self,
        tool_name: str,
        user: UserIdentity | None = None,
        **kwargs: object,
    ) -> object:
        """
        Invoke a registered tool by name, enforcing the full gate chain.

        Raises GateDenied if identity or authorization fails, and
        UnknownToolError if `tool_name` was never registered. Every
        decision along the way — including denials — is written to the
        audit log before the exception is raised.
        """
        context = SecurityContext(
            agent=self.identity,
            user=user,
            action=f"tool.{tool_name}",
            resource=tool_name,
        )

        identity_decision = self._identity_gate.evaluate(context)
        self._audit_gate.record(identity_decision)
        if not identity_decision.is_allowed:
            raise GateDenied(identity_decision)

        tool_decision = self._tool_gate.evaluate(
            context, tool_name=tool_name, policy_name=self.policy.name
        )
        self._audit_gate.record(tool_decision)
        if not tool_decision.is_allowed:
            if tool_name not in self._tool_registry:
                raise UnknownToolError(str(tool_decision))
            raise GateDenied(tool_decision)

        tool = self._tool_registry.get(tool_name)
        assert tool is not None  # ToolGate already confirmed this
        result = tool(**kwargs)

        completion_context = context.model_copy(update={"action": f"tool.{tool_name}.completed"})
        self._audit_gate.evaluate(completion_context)

        return result

    def run(self, request: str, user: UserIdentity | None = None) -> str:
        """
        Placeholder for the full request lifecycle:

            Identity -> Intent -> Trust -> Permission -> [LLM reasoning]
            -> Tool -> Data -> Risk/Approval -> Execution -> Audit

        Only Identity/Permission/Tool/Audit are implemented so far (Stage
        2). Wiring in an LLM plus the Intent/Trust/Risk gates is Stage 3+
        work — see ARCHITECTURE.md. This method exists so the seam is
        explicit rather than silently absent.
        """
        raise NotImplementedError(
            "SecureAgent.run() (full LLM-driven request lifecycle) is not "
            "implemented yet — Intent, Trust, Data and Risk/Approval gates "
            "are Stage 3+ work. Use call_tool() directly for now."
        )
