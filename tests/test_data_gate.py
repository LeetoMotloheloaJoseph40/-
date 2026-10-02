from eightgates import DataClassification, DecisionType, SecurityContext, Tool, ToolCapability
from eightgates.gates.data import DataGate


def _ctx(identity):
    return SecurityContext(agent=identity, action="agent.run")


def _tool(**kw) -> Tool:
    defaults = {"permission": "x.y", "external_effect": True}
    defaults.update(kw)
    return Tool(name="t", capability=ToolCapability(**defaults))


def test_clean_arguments_to_an_external_tool_are_allowed(finance_identity):
    gate = DataGate()
    d = gate.evaluate(_ctx(finance_identity), tool=_tool(), arguments={"to": "a@b.com", "body": "hi"})
    assert d.decision == DecisionType.ALLOW


def test_secret_in_arguments_is_blocked(finance_identity):
    gate = DataGate()
    d = gate.evaluate(
        _ctx(finance_identity),
        tool=_tool(),
        arguments={"to": "a@b.com", "body": "here is AKIAABCDEFGHIJKLMNOP"},
    )
    assert d.decision == DecisionType.BLOCK
    assert "AKIA" not in d.reason  # payload never echoed into the decision/audit reason


def test_secret_scan_only_applies_to_external_effect_tools(finance_identity):
    gate = DataGate()
    d = gate.evaluate(
        _ctx(finance_identity),
        tool=_tool(external_effect=False),
        arguments={"body": "here is AKIAABCDEFGHIJKLMNOP"},
    )
    assert d.decision == DecisionType.ALLOW  # read-only tool: nothing can leave through it


def test_classification_above_ceiling_is_denied(finance_identity):
    gate = DataGate(ceiling=DataClassification.INTERNAL)
    d = gate.evaluate(
        _ctx(finance_identity),
        tool=_tool(data_sensitivity=DataClassification.SECRET, external_effect=False),
        arguments={},
    )
    assert d.decision == DecisionType.DENY


def test_classification_at_or_below_ceiling_is_allowed(finance_identity):
    gate = DataGate(ceiling=DataClassification.CONFIDENTIAL)
    d = gate.evaluate(
        _ctx(finance_identity),
        tool=_tool(data_sensitivity=DataClassification.INTERNAL, external_effect=False),
        arguments={},
    )
    assert d.decision == DecisionType.ALLOW


def test_default_ceiling_is_permissive_for_backward_compatibility(finance_identity):
    """RESTRICTED is the most permissive default ceiling -- Stage 1-3 tools are unaffected unless configured."""
    gate = DataGate()  # default ceiling
    d = gate.evaluate(
        _ctx(finance_identity),
        tool=_tool(data_sensitivity=DataClassification.SECRET, external_effect=False),
        arguments={},
    )
    assert d.decision == DecisionType.ALLOW


def test_screen_result_redacts_secret_shaped_output():
    gate = DataGate()
    result = gate.screen_result(
        "Here is the key: AKIAABCDEFGHIJKLMNOP, use it wisely.", DataClassification.INTERNAL
    )
    assert result.redacted
    assert "AKIA" not in result.text
    assert result.classification == DataClassification.SECRET


def test_screen_result_passes_through_clean_output():
    gate = DataGate()
    result = gate.screen_result("The weather is sunny today.", DataClassification.INTERNAL)
    assert not result.redacted
    assert result.text == "The weather is sunny today."
    assert result.classification == DataClassification.INTERNAL
