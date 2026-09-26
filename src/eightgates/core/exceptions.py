"""
Structured exceptions.

A gate never executes an action itself — when a gate's decision is not
ALLOW, the runtime raises one of these so the failure is explicit and
carries the full SecurityDecision for logging/inspection, rather than
silently returning None or swallowing the denial.
"""

from __future__ import annotations

from eightgates.core.decisions import SecurityDecision


class GateError(Exception):
    """Base class for all 8 Gates errors."""


class GateDenied(GateError):
    """
    Raised when a gate returns anything other than ALLOW.

    Carries the originating SecurityDecision so callers can inspect gate,
    reason, risk level, etc. without parsing an error string.
    """

    def __init__(self, decision: SecurityDecision):
        self.decision = decision
        super().__init__(str(decision))


class UnknownAgentError(GateError):
    """Raised by the Identity Gate when the acting identity cannot be verified."""


class UnknownToolError(GateError):
    """Raised by the Tool Gate when a requested tool is not registered."""


class PolicyNotFoundError(GateError):
    """Raised when a gate is asked to evaluate against a policy that does not exist."""
