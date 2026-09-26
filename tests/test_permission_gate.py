from eightgates.core.decisions import DecisionType
from eightgates.core.models import SecurityContext
from eightgates.gates.permission import PermissionGate
from eightgates.policy.policy import Policy, PolicyEngine


def test_allowed_action_is_permitted(finance_identity, read_only_policy):
    engine = PolicyEngine()
    engine.register(read_only_policy)
    gate = PermissionGate(engine)

    context = SecurityContext(agent=finance_identity, action="database.read")
    decision = gate.evaluate(context, policy_name=read_only_policy.name)

    assert decision.decision == DecisionType.ALLOW


def test_action_not_in_allow_list_is_denied(finance_identity, read_only_policy):
    engine = PolicyEngine()
    engine.register(read_only_policy)
    gate = PermissionGate(engine)

    context = SecurityContext(agent=finance_identity, action="payment.transfer")
    decision = gate.evaluate(context, policy_name=read_only_policy.name)

    assert decision.decision == DecisionType.DENY


def test_explicit_deny_overrides_explicit_allow(finance_identity):
    # A misconfigured policy that (mistakenly) allows and denies the same
    # permission — deny must win, per least-privilege / fail-closed rules.
    policy = Policy(name="conflicting", allow=["database.delete"], deny=["database.delete"])
    engine = PolicyEngine()
    engine.register(policy)
    gate = PermissionGate(engine)

    context = SecurityContext(agent=finance_identity, action="database.delete")
    decision = gate.evaluate(context, policy_name=policy.name)

    assert decision.decision == DecisionType.DENY


def test_missing_policy_denies_by_default(finance_identity):
    engine = PolicyEngine()  # no policy registered at all
    gate = PermissionGate(engine)

    context = SecurityContext(agent=finance_identity, action="database.read")
    decision = gate.evaluate(context, policy_name="does-not-exist")

    assert decision.decision == DecisionType.DENY
