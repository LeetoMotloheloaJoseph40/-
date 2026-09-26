import pytest

from eightgates import SecureAgent
from eightgates.core.exceptions import GateDenied, UnknownToolError


def test_authorized_tool_call_executes(finance_identity, read_only_policy, get_balance_tool):
    agent = SecureAgent(
        name="finance-agent",
        identity=finance_identity,
        policy=read_only_policy,
        tools=[get_balance_tool],
    )

    result = agent.call_tool("get_balance", account_id="acct-1")

    assert result == {"account_id": "acct-1", "balance": 1000}


def test_unauthorized_tool_call_is_denied_and_not_executed(
    finance_identity, read_only_policy, transfer_funds_tool
):
    agent = SecureAgent(
        name="finance-agent",
        identity=finance_identity,
        policy=read_only_policy,
        tools=[transfer_funds_tool],
    )

    with pytest.raises(GateDenied) as exc_info:
        agent.call_tool("transfer_funds", amount=1000, destination="attacker-account")

    assert exc_info.value.decision.decision.value == "DENY"


def test_unregistered_tool_raises_unknown_tool_error(finance_identity, read_only_policy):
    agent = SecureAgent(name="finance-agent", identity=finance_identity, policy=read_only_policy)

    with pytest.raises(UnknownToolError):
        agent.call_tool("does_not_exist")


def test_every_call_is_audited_including_denials(
    finance_identity, read_only_policy, get_balance_tool, transfer_funds_tool
):
    agent = SecureAgent(
        name="finance-agent",
        identity=finance_identity,
        policy=read_only_policy,
        tools=[get_balance_tool, transfer_funds_tool],
    )

    agent.call_tool("get_balance", account_id="acct-1")
    with pytest.raises(GateDenied):
        agent.call_tool("transfer_funds", amount=1000, destination="attacker-account")

    events = agent.audit_logger.events()
    decisions = [e.decision.value for e in events]

    assert "ALLOW" in decisions
    assert "DENY" in decisions
    # Every tool call name should be traceable in the audit log.
    actions = [e.action for e in events]
    assert any("get_balance" in a for a in actions)
    assert any("transfer_funds" in a for a in actions)
