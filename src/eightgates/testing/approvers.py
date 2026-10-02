"""Deterministic approvers for tests, examples and demos."""

from __future__ import annotations

from collections.abc import Callable

from eightgates.core.models import ApprovalRequest


class DenyAllApprover:
    """Fail closed: used as SecureAgent's default. 'Approval service unavailable -> do not execute.'"""

    def decide(self, request: ApprovalRequest) -> bool:
        return False


class ApproveAllApprover:
    """Approves everything. For tests/demos only — never use in production."""

    def decide(self, request: ApprovalRequest) -> bool:
        return True


class CallableApprover:
    """Wraps a plain function, so tests can express approval policy inline."""

    def __init__(self, fn: Callable[[ApprovalRequest], bool]):
        self._fn = fn

    def decide(self, request: ApprovalRequest) -> bool:
        return self._fn(request)
