"""
八門 (8 Gates) — a security-first control plane for AI agents.

Stages 1-4 of the roadmap in ARCHITECTURE.md are implemented in this package:
domain models; Identity, Intent, Trust, Permission, Tool, Data, Risk and Audit
gates; a model-agnostic SecureAgent.run(); and a real human-approval flow.

Public API re-exports the pieces most developers need to get started:

    from eightgates import SecureAgent, AgentIdentity, Policy, secure_tool
"""

from eightgates.agent import SecureAgent
from eightgates.approval.store import ApprovalStore
from eightgates.audit.events import AuditEvent
from eightgates.audit.logger import AuditLogger
from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.exceptions import GateDenied, UnknownAgentError, UnknownToolError
from eightgates.core.models import (
    AgentIdentity,
    ApprovalRequest,
    ContextItem,
    DataClassification,
    Permission,
    RiskAssessment,
    RiskLevel,
    SecurityContext,
    ToolCallRequest,
    TrustLevel,
    UserIdentity,
)
from eightgates.core.runtime import Approver, Planner, RunResult, ToolOutcome
from eightgates.gates.data import DataGate
from eightgates.gates.intent import IntentGate
from eightgates.gates.risk import RiskGate
from eightgates.gates.trust import TrustGate
from eightgates.identity.registry import IdentityRegistry
from eightgates.policy.intent import IntentPolicy, IntentSpec
from eightgates.policy.policy import Policy, PolicyEngine
from eightgates.security.injection import PromptInjectionDetector
from eightgates.security.secrets import SecretScanner
from eightgates.security.trust import TrustPolicy
from eightgates.tools.registry import ToolRegistry
from eightgates.tools.tool import Tool, ToolCapability, secure_tool

__all__ = [
    "AgentIdentity",
    "ApprovalRequest",
    "ApprovalStore",
    "Approver",
    "AuditEvent",
    "AuditLogger",
    "ContextItem",
    "DataClassification",
    "DataGate",
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
    "RiskAssessment",
    "RiskGate",
    "RiskLevel",
    "RunResult",
    "SecretScanner",
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

__version__ = "0.3.0"
