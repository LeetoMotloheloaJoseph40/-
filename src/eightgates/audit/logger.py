"""
Append-only audit logger.

This in-memory + optional-JSONL-file logger is a Stage-2 placeholder for
whatever durable, tamper-evident audit store a real deployment would use
(e.g. an append-only table, a write-once object store, or a SIEM sink).
The important contract to preserve in any future backend: writes must be
append-only, and a logging failure must be surfaced rather than silently
swallowed (see AuditGate).
"""

from __future__ import annotations

from pathlib import Path

from eightgates.audit.events import AuditEvent


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._events: list[AuditEvent] = []

    def log(self, event: AuditEvent) -> None:
        self._events.append(event)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def events_for_trace(self, trace_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.trace_id == trace_id]
