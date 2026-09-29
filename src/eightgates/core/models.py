"""
Core domain models (Stage 1).

These types are intentionally kept separate from one another per the
architectural constraint in the spec:

    identity is not permission; permission is not trust;
    trust is not risk; risk is not authorization.

Nothing in this module makes a security decision — it only describes the
world. Decisions are made by gates (see eightgates.gates).
"""

from __future__ import annotations

import enum
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TrustLevel(str, enum.Enum):
    """How much a piece of context or an external actor should be trusted."""

    TRUSTED = "TRUSTED"
    PARTIALLY_TRUSTED = "PARTIALLY_TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MALICIOUS = "MALICIOUS"
    QUARANTINED = "QUARANTINED"


class RiskLevel(str, enum.Enum):
    """How much scrutiny/autonomy an action should receive."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataClassification(str, enum.Enum):
    """Sensitivity classification for data flowing through the agent."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"
    RESTRICTED = "RESTRICTED"


class Permission(BaseModel):
    """
    A single, explicit capability grant, e.g. "database.read".

    Permissions are plain strings under the hood (dotted-path style) but are
    wrapped in a model so that policy code never has to compare raw strings
    by accident, and so we have a single place to add scoping/conditions
    later (e.g. resource-scoped permissions) without breaking callers.
    """

    name: str = Field(..., description='Dotted action name, e.g. "database.read".')

    def __hash__(self) -> int:  # allow use in sets
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Permission):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return NotImplemented

    def __str__(self) -> str:
        return self.name


class UserIdentity(BaseModel):
    """A human principal on whose behalf an agent may be acting."""

    id: str
    display_name: str | None = None
    organization: str | None = None


class AgentIdentity(BaseModel):
    """
    WHO the agent is. Deliberately contains no authorization data —
    see Policy/Permission for WHAT the agent may do.
    """

    id: str
    owner: str
    role: str
    organization: str | None = None
    environment: str = "production"
    trust_level: TrustLevel = TrustLevel.PARTIALLY_TRUSTED
    max_delegation_depth: int = 0


class SecurityContext(BaseModel):
    """
    Carries everything the gates need to evaluate a single request/action.
    One SecurityContext is created per top-level request and threaded
    through the gate pipeline; it accumulates decisions as it goes.
    """

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent: AgentIdentity
    user: UserIdentity | None = None
    action: str
    resource: str | None = None
    metadata: dict = Field(default_factory=dict)

    model_config = ConfigDict(arbitrary_types_allowed=True)


class RiskAssessment(BaseModel):
    """Structured output of the Risk Gate (or a manual override)."""

    score: int = Field(..., ge=0, le=100)
    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    requires_human_approval: bool = False


class ApprovalRequest(BaseModel):
    """A specific, scoped request for human sign-off on one action."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str
    agent_id: str
    user_id: str | None = None
    action: str
    resource: str | None = None
    reason: str
    risk: RiskAssessment
    approved: bool | None = None


class ContextItem(BaseModel):
    """
    One piece of content entering an agent's context window, with its origin.

    `source` is a developer-assigned label for where the content came from
    ("user", "system", "web", "email", "tool:fetch_page", ...). It is never
    derived from the content itself. `trust` may be set explicitly; if left
    as None the Trust Gate resolves it from the source via a TrustPolicy,
    defaulting to UNTRUSTED for unknown sources (fail closed).
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    content: str
    source: str
    trust: TrustLevel | None = None


class ToolCallRequest(BaseModel):
    """A tool invocation *proposed* by a planner (e.g. an LLM). Not yet authorized."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
