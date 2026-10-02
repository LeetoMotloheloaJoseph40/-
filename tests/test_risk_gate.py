from eightgates import DecisionType, RiskLevel, SecurityContext, Tool, ToolCapability
from eightgates.core.models import DataClassification
from eightgates.gates.risk import RiskGate, score_tool_call


def _ctx(identity):
    return SecurityContext(agent=identity, action="agent.run")


def _tool(**kw) -> Tool:
    defaults = {"permission": "x.y"}
    defaults.update(kw)
    return Tool(name="t", capability=ToolCapability(**defaults))


def test_low_risk_tool_is_allowed_outright(finance_identity):
    d = RiskGate().evaluate(_ctx(finance_identity), tool=_tool(risk_level=RiskLevel.LOW))
    assert d.decision == DecisionType.ALLOW


def test_critical_risk_irreversible_external_tool_requires_approval(finance_identity):
    tool = _tool(risk_level=RiskLevel.CRITICAL, external_effect=True, reversible=False)
    d = RiskGate().evaluate(_ctx(finance_identity), tool=tool)
    assert d.decision == DecisionType.REQUIRE_APPROVAL


def test_taint_pushes_a_borderline_tool_toward_approval(finance_identity):
    tool = _tool(risk_level=RiskLevel.MEDIUM, external_effect=True)
    clean = score_tool_call(tool, tainted=False)
    tainted = score_tool_call(tool, tainted=True)
    assert tainted.score > clean.score


def test_higher_data_classification_increases_score(finance_identity):
    tool = _tool(risk_level=RiskLevel.LOW)
    low = score_tool_call(tool, data_classification=DataClassification.PUBLIC)
    high = score_tool_call(tool, data_classification=DataClassification.SECRET)
    assert high.score > low.score


def test_assessment_reasons_are_human_readable_and_itemised(finance_identity):
    tool = _tool(risk_level=RiskLevel.HIGH, external_effect=True, reversible=False)
    assessment = score_tool_call(tool, data_classification=DataClassification.SENSITIVE, tainted=True)
    assert "tool declared risk HIGH" in assessment.reasons
    assert "tool has external effects" in assessment.reasons
    assert "action is not reversible" in assessment.reasons
    assert "data classification SENSITIVE" in assessment.reasons
    assert "this run has processed untrusted content" in assessment.reasons


def test_score_is_capped_at_100(finance_identity):
    tool = _tool(
        risk_level=RiskLevel.CRITICAL,
        external_effect=True,
        reversible=False,
        data_sensitivity=DataClassification.RESTRICTED,
    )
    assessment = score_tool_call(tool, data_classification=DataClassification.RESTRICTED, tainted=True)
    assert assessment.score == 100
    assert assessment.level == RiskLevel.CRITICAL
