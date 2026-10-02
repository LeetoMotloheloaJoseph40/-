"""
Gates implemented so far (Stages 2-4): Identity, Intent, Trust, Permission,
Tool, Data, Risk, Audit.

See ARCHITECTURE.md for the roadmap; Stage 5+ (delegation, MCP, framework
adapters) is not implemented yet.
"""

from eightgates.gates.audit import AuditGate
from eightgates.gates.base import Gate
from eightgates.gates.data import DataGate
from eightgates.gates.identity import IdentityGate
from eightgates.gates.intent import IntentGate
from eightgates.gates.permission import PermissionGate
from eightgates.gates.risk import RiskGate
from eightgates.gates.tool import ToolGate
from eightgates.gates.trust import TrustGate

__all__ = [
    "AuditGate",
    "DataGate",
    "Gate",
    "IdentityGate",
    "IntentGate",
    "PermissionGate",
    "RiskGate",
    "ToolGate",
    "TrustGate",
]
