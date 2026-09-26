"""
Tool model (Stage 1/2).

Tools are security boundaries: every callable an agent can invoke must
declare what it needs (permission), how dangerous it is (risk_level), and
what kind of effect it has on the world (external_effect, reversible).
A tool call is only ever executed after it has passed through the Tool
Gate — see eightgates.gates.tool and eightgates.agent.SecureAgent.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from pydantic import BaseModel

from eightgates.core.models import DataClassification, RiskLevel


class ToolCapability(BaseModel):
    """Declared metadata describing what a tool does and how risky it is."""

    permission: str
    risk_level: RiskLevel = RiskLevel.LOW
    external_effect: bool = False
    reversible: bool = True
    network_access: bool = False
    data_sensitivity: DataClassification = DataClassification.INTERNAL


@dataclasses.dataclass
class Tool:
    """
    A registered, callable capability with explicit security metadata.

    A plain dataclass (rather than a pydantic model) on purpose: a Tool
    wraps a live Python callable, and we want simple, predictable
    attribute assignment for that rather than pydantic validation getting
    in the way of holding a function reference.
    """

    name: str
    capability: ToolCapability
    description: str = ""
    _func: Callable | None = dataclasses.field(default=None, repr=False)

    def bind(self, func: Callable) -> Tool:
        self._func = func
        return self

    def __call__(self, *args: object, **kwargs: object) -> object:
        if self._func is None:
            raise RuntimeError(f"Tool '{self.name}' has no bound implementation.")
        return self._func(*args, **kwargs)


def secure_tool(
    permission: str,
    risk: RiskLevel | str = RiskLevel.LOW,
    *,
    external_effect: bool = False,
    reversible: bool = True,
    network_access: bool = False,
    data_sensitivity: DataClassification | str = DataClassification.INTERNAL,
    description: str = "",
) -> Callable[[Callable], Tool]:
    """
    Decorator that turns a plain function into a Tool with declared
    security metadata, e.g.:

        @secure_tool(permission="database.read", risk="LOW")
        def get_customer(customer_id: str):
            ...

    The decorated object is a `Tool` (callable, and inspectable by the
    Tool Gate) rather than a bare function, so authorization can never be
    accidentally skipped by calling the underlying function directly from
    application code that imported it.
    """

    def decorator(func: Callable) -> Tool:
        capability = ToolCapability(
            permission=permission,
            risk_level=RiskLevel(risk) if isinstance(risk, str) else risk,
            external_effect=external_effect,
            reversible=reversible,
            network_access=network_access,
            data_sensitivity=(
                DataClassification(data_sensitivity)
                if isinstance(data_sensitivity, str)
                else data_sensitivity
            ),
        )
        tool = Tool(
            name=func.__name__,
            description=description or (func.__doc__ or "").strip(),
            capability=capability,
        )
        tool.bind(func)
        return tool

    return decorator
