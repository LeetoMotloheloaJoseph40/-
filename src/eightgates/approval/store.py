"""
In-memory, append-only store of ApprovalRequests.

A real deployment would back this with something durable and queryable by a
human reviewer (a dashboard, a Slack approval bot, a ticket queue). This
version exists so SecureAgent has somewhere to record "this specific action,
for this specific reason, was held pending approval" — see core/models.py's
ApprovalRequest for the spec's "approve a specific action, not unlimited
authority" requirement.
"""

from __future__ import annotations

from eightgates.core.models import ApprovalRequest


class ApprovalStore:
    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

    def add(self, request: ApprovalRequest) -> None:
        self._requests[request.id] = request

    def resolve(self, request_id: str, approved: bool) -> None:
        existing = self._requests.get(request_id)
        if existing is not None:
            self._requests[request_id] = existing.model_copy(update={"approved": approved})

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._requests.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._requests.values() if r.approved is None]

    def all(self) -> list[ApprovalRequest]:
        return list(self._requests.values())
