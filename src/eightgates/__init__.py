"""
八門 (8 Gates) — a security-first control plane for AI agents.

Stage 1 (domain models) and Stage 2 (Identity, Permission, Tool, Audit gates)
of the roadmap in ARCHITECTURE.md are implemented in this package.

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
    Permission,
    RiskLevel,
    TrustLevel,
    UserIdentity,
)
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool, ToolCapability, secure_tool

__all__ = [
    "AgentIdentity",
    "AuditEvent",
    "AuditLogger",
    "DecisionType",
    "GateDenied",
    "IdentityRegistry",
    "Permission",
    "Policy",
    "PolicyEngine",
    "RiskLevel",
    "SecureAgent",
    "SecurityDecision",
    "Tool",
    "ToolCapability",
    "ToolRegistry",
    "TrustLevel",
    "UnknownAgentError",
    "UnknownToolError",
    "UserIdentity",
    "secure_tool",
]

__version__ = "0.1.0"
