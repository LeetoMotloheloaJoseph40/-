"""
The set of agent identities this deployment knows about.

A real deployment would back this with a database, secrets manager, or an
external IdP (see authentication.py / credentials.py, planned for a later
stage). This in-memory version is enough to make the gate pipeline
concrete and testable.
"""

from __future__ import annotations

from eightgates.core.models import AgentIdentity


class IdentityRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}

    def register(self, identity: AgentIdentity) -> None:
        self._agents[identity.id] = identity

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def __contains__(self, agent_id: str) -> bool:
        return agent_id in self._agents
