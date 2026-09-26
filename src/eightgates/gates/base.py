"""
The Gate interface (Stage 1).

Every gate — implemented now or in a later stage (Trust, Intent, Data,
Risk) — follows this same shape: it receives a SecurityContext plus
whatever extra evidence it needs, and returns exactly one SecurityDecision.
Gates are pure with respect to security state: they read policy/identity
data and decide, they do not execute actions or mutate the world.
"""

from __future__ import annotations

import abc

from eightgates.core.decisions import SecurityDecision
from eightgates.core.models import SecurityContext


class Gate(abc.ABC):
    """Base class for all security gates."""

    #: Short, stable name used in SecurityDecision.gate and audit events.
    name: str = "gate"

    @abc.abstractmethod
    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        """
        Evaluate one action and return a SecurityDecision.

        Implementations must fail closed: if the gate cannot reach a
        confident decision (missing data, internal error, unknown
        subject), it should return DENY rather than ALLOW.
        """
        raise NotImplementedError
