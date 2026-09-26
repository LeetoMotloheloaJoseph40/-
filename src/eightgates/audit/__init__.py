"""Audit event model and append-only logger."""

from eightgates.audit.events import AuditEvent
from eightgates.audit.logger import AuditLogger

__all__ = ["AuditEvent", "AuditLogger"]
