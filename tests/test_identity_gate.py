from eightgates.core.decisions import DecisionType
from eightgates.core.models import AgentIdentity, SecurityContext
from eightgates.gates.identity import IdentityGate
from eightgates.identity.registry import IdentityRegistry


def test_registered_identity_is_allowed(finance_identity):
    registry = IdentityRegistry()
    registry.register(finance_identity)
    gate = IdentityGate(registry)

    context = SecurityContext(agent=finance_identity, action="database.read")
    decision = gate.evaluate(context)

    assert decision.decision == DecisionType.ALLOW
    assert decision.gate == "identity"


def test_unknown_identity_is_denied(finance_identity):
    registry = IdentityRegistry()  # nothing registered
    gate = IdentityGate(registry)

    context = SecurityContext(agent=finance_identity, action="database.read")
    decision = gate.evaluate(context)

    assert decision.decision == DecisionType.DENY
    assert "not registered" in decision.reason


def test_mismatched_attributes_are_denied_as_possible_impersonation(finance_identity):
    registry = IdentityRegistry()
    registry.register(finance_identity)
    gate = IdentityGate(registry)

    spoofed = AgentIdentity(
        id=finance_identity.id,
        owner="attacker-controlled-owner",
        role=finance_identity.role,
    )
    context = SecurityContext(agent=spoofed, action="database.read")
    decision = gate.evaluate(context)

    assert decision.decision == DecisionType.DENY
    assert decision.risk_level.value == "CRITICAL"
