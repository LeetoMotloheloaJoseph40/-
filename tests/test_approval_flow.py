"""Integration tests for the full Risk/Approval hand-off, including the ApprovalStore."""

from eightgates import AgentIdentity, Policy, RiskLevel, SecureAgent, ToolCallRequest, secure_tool
from eightgates.testing.approvers import ApproveAllApprover, CallableApprover, DenyAllApprover
from eightgates.testing.planners import ScriptedPlanner


def build_agent(approver=None):
    @secure_tool(permission="payment.transfer", risk=RiskLevel.CRITICAL, external_effect=True, reversible=False)
    def transfer_funds(amount: float, destination: str) -> str:
        return f"sent {amount} to {destination}"

    return SecureAgent(
        name="finance-agent",
        identity=AgentIdentity(id="finance-agent", owner="finance", role="analyst"),
        policy=Policy(name="finance", allow=["payment.transfer"]),
        tools=[transfer_funds],
        approver=approver,
    )


def test_default_approver_is_deny_all_and_fails_closed():
    agent = build_agent()
    planner = ScriptedPlanner([[ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 100, "destination": "x"})]])
    result = agent.run("transfer 100 to x", planner)
    assert not result.executed
    assert isinstance(agent.approver, DenyAllApprover)


def test_approved_request_executes_and_is_recorded_in_the_store():
    agent = build_agent(approver=ApproveAllApprover())
    planner = ScriptedPlanner([[ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 100, "destination": "x"})]])
    result = agent.run("transfer 100 to x", planner)

    assert result.executed
    assert result.executed[0].result == "sent 100 to x"
    requests = agent.approval_store.all()
    assert len(requests) == 1
    assert requests[0].approved is True
    assert requests[0].action == "tool.transfer_funds"
    assert requests[0].agent_id == "finance-agent"


def test_denied_request_is_recorded_as_denied_not_just_dropped():
    agent = build_agent(approver=DenyAllApprover())
    planner = ScriptedPlanner([[ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 100, "destination": "x"})]])
    agent.run("transfer 100 to x", planner)

    requests = agent.approval_store.all()
    assert len(requests) == 1
    assert requests[0].approved is False


def test_approval_request_is_scoped_to_the_specific_action_not_blanket_trust():
    """A CallableApprover can make a genuinely informed, per-request decision."""
    decisions_seen = []

    def policy(request):
        decisions_seen.append(request.action)
        return request.resource == "transfer_funds" and request.risk.score < 100

    agent = build_agent(approver=CallableApprover(policy))
    planner = ScriptedPlanner([[ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 1, "destination": "x"})]])
    agent.run("transfer 1 to x", planner)

    assert decisions_seen == ["tool.transfer_funds"]


def test_approval_outcome_is_a_separate_audited_gate_from_the_hold_that_triggered_it():
    agent = build_agent(approver=ApproveAllApprover())
    planner = ScriptedPlanner([[ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 1, "destination": "x"})]])
    result = agent.run("transfer 1 to x", planner)

    gates_seen = [e.gate for e in agent.audit_logger.events_for_trace(result.trace_id)]
    assert "risk" in gates_seen
    assert "approval" in gates_seen
