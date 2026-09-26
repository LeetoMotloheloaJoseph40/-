"""
Policy model and evaluation (Stage 1/2).

A Policy is a declarative allow/deny list of permissions attached to a
role or agent. Evaluation rule, per the spec: explicit denial always
overrides implicit or explicit allow, and anything not explicitly allowed
is denied (secure default / least privilege).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from eightgates.core.models import Permission


class Policy(BaseModel):
    """A named, declarative set of allowed/denied permissions."""

    name: str
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    def permits(self, permission: str | Permission) -> bool:
        """
        True if `permission` is authorized under this policy.

        Denials are checked first and always win, matching the spec's
        "explicit denial must override implicit permission" rule.
        """
        name = str(permission)
        if name in self.deny:
            return False
        return name in self.allow


class PolicyEngine:
    """Resolves a policy by name; the single place gates ask "is X allowed?"."""

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}

    def register(self, policy: Policy) -> None:
        self._policies[policy.name] = policy

    def get(self, name: str) -> Policy | None:
        return self._policies.get(name)

    def is_authorized(self, policy_name: str, permission: str | Permission) -> bool:
        policy = self.get(policy_name)
        if policy is None:
            # Fail closed: no policy on file means nothing is authorized.
            return False
        return policy.permits(permission)
