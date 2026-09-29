"""
八門 (8 Gates) — a security-first control plane for AI agents.

Stages 1-3 of the roadmap in ARCHITECTURE.md are implemented in this package:
domain models; Identity, Intent, Trust, Permission, Tool and Audit gates; and a
model-agnostic SecureAgent.run().

Public API re-exports the pieces most developers need to get started:

    from eightgates import SecureAgent, AgentIdentity, Policy, secure_tool
"""

from eightgates.agent import SecureAgent
from eightgates.audit.events import AuditEvent
from eightgates.audit.logger import AuditLogger
from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.exceptions import GateDenied, UnknownAgentError, UnknownToolError
from eightgates.core.models import (
    AgentIdentity,
    ContextItem,
    Permission,
    RiskLevel,
    SecurityContext,
    ToolCallRequest,
    TrustLevel,
    UserIdentity,
)
from eightgates.core.runtime import Planner, RunResult, ToolOutcome
from eightgates.gates.intent import IntentGate
from eightgates.gates.trust import TrustGate
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.intent import IntentPolicy, IntentSpec
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.security.injection import PromptInjectionDetector
from eightgates.security.trust import TrustPolicy
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool, ToolCapability, secure_tool

__all__ = [
    "AgentIdentity",
    "AuditEvent",
    "AuditLogger",
    "ContextItem",
    "DecisionType",
    "GateDenied",
    "IdentityRegistry",
    "IntentGate",
    "IntentPolicy",
    "IntentSpec",
    "Permission",
    "Planner",
    "Policy",
    "PolicyEngine",
    "PromptInjectionDetector",
    "RiskLevel",
    "RunResult",
    "SecureAgent",
    "SecurityContext",
    "SecurityDecision",
    "Tool",
    "ToolCallRequest",
    "ToolCapability",
    "ToolOutcome",
    "ToolRegistry",
    "TrustGate",
    "TrustLevel",
    "TrustPolicy",
    "UnknownAgentError",
    "UnknownToolError",
    "UserIdentity",
    "secure_tool",
]

__version__ = "0.2.0"
