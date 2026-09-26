"""
Gate 8 — Audit / Output Gate.

Responsibility: every decision made by every other gate must become an
observable, structured event — including denials, not just successful
executions. Unlike the other gates, AuditGate.evaluate always "allows"
(logging is not itself an authorization checkpoint); its job is to make
sure nothing that happened is invisible after the fact.
"""

from __future__ import annotations

from eightgates.audit.events import AuditEvent
from eightgates.audit.logger import AuditLogger
from eightgates.core.decisions import DecisionType, SecurityDecision
from eightgates.core.models import RiskLevel, SecurityContext
from eightgates.gates.base import Gate


class AuditGate(Gate):
    """Records a SecurityDecision (from any gate) as a durable AuditEvent."""

    name = "audit"

    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def record(self, decision: SecurityDecision) -> None:
        """Log an upstream decision. Call this after every gate in the chain."""
        self.logger.log(AuditEvent.from_decision(decision))

    def evaluate(self, context: SecurityContext, **evidence: object) -> SecurityDecision:
        """
        Present for interface consistency with other gates; also emits its
        own audit-of-the-audit-request event so "was this action logged?"
        is itself answerable from the trail.
        """
        decision = SecurityDecision(
            trace_id=context.trace_id,
            gate=self.name,
            agent_id=context.agent.id,
            action=context.action,
            resource=context.resource,
            decision=DecisionType.ALLOW,
            reason="Audit gate recorded the request.",
            risk_level=RiskLevel.LOW,
        )
        self.record(decision)
        return decision
