from eightgates import (
    DecisionType,
    IntentGate,
    IntentPolicy,
    IntentSpec,
    SecurityContext,
)

POLICY = IntentPolicy(
    name="support-intents",
    intents={
        "customer_lookup": IntentSpec(
            keywords=["look up", "find customer"], allowed_tools=["lookup_customer"]
        ),
        "notify": IntentSpec(keywords=["email", "notify"], allowed_tools=["send_email"]),
    },
)


def _ctx(identity):
    return SecurityContext(agent=identity, action="agent.run")


def test_single_intent_is_allowed(finance_identity):
    d = IntentGate(POLICY).evaluate(_ctx(finance_identity), request="Please look up customer 42")
    assert d.decision == DecisionType.ALLOW


def test_unrecognised_request_is_denied(finance_identity):
    d = IntentGate(POLICY).evaluate(_ctx(finance_identity), request="Tell me a joke")
    assert d.decision == DecisionType.DENY


def test_empty_request_fails_closed(finance_identity):
    d = IntentGate(POLICY).evaluate(_ctx(finance_identity), request="   ")
    assert d.decision == DecisionType.DENY


def test_ambiguous_request_escalates(finance_identity):
    d = IntentGate(POLICY).evaluate(
        _ctx(finance_identity), request="look up the customer and email them"
    )
    assert d.decision == DecisionType.ESCALATE


def test_ambiguity_can_opt_in_to_union_of_scopes(finance_identity):
    policy = POLICY.model_copy(update={"allow_multiple_intents": True})
    gate = IntentGate(policy)
    request = "look up the customer and email them"
    for tool in ("lookup_customer", "send_email"):
        d = gate.evaluate(_ctx(finance_identity), request=request, tool_name=tool)
        assert d.decision == DecisionType.ALLOW


def test_tool_outside_intent_scope_is_denied_as_mismatch(finance_identity):
    d = IntentGate(POLICY).evaluate(
        _ctx(finance_identity), request="look up customer 42", tool_name="send_email"
    )
    assert d.decision == DecisionType.DENY
    assert "mismatch" in d.reason.lower()


def test_keyword_match_is_whole_word(finance_identity):
    # "emailing" must not match the keyword "email"
    d = IntentGate(POLICY).evaluate(_ctx(finance_identity), request="I was emailing about nothing")
    assert d.decision == DecisionType.DENY
