"""
Demo: Data/Memory and Risk/Approval gates (Stage 4).

    python examples/human_approval_demo.py

No LLM involved -- a ScriptedPlanner stands in for one, so the demo is
deterministic. Three scenarios:

  1. A CRITICAL-risk, irreversible transfer is held for approval by default
     (no approver configured) and never executes.
  2. The same transfer, with an Approver configured, is logged as a specific
     ApprovalRequest, approved, and THEN executes.
  3. A tool argument containing a secret-shaped string is blocked by the Data
     Gate before it ever reaches the Risk Gate -- permission and approval
     are irrelevant once a credential is about to leave via a tool call.
"""

from __future__ import annotations

from eightgates import AgentIdentity, Policy, RiskLevel, SecureAgent, ToolCallRequest, secure_tool
from eightgates.testing.approvers import ApproveAllApprover
from eightgates.testing.planners import ScriptedPlanner


@secure_tool(permission="payment.transfer", risk=RiskLevel.CRITICAL, external_effect=True, reversible=False)
def transfer_funds(amount: float, destination: str) -> str:
    """Move money (mock)."""
    return f"transferred {amount} to {destination}"


@secure_tool(permission="communication.email", external_effect=True)
def send_email(to: str, body: str) -> str:
    """Send an email (mock)."""
    return "sent"


def build_agent(approver=None) -> SecureAgent:
    return SecureAgent(
        name="finance-agent",
        identity=AgentIdentity(id="finance-agent", owner="finance-team", role="analyst"),
        policy=Policy(name="finance", allow=["payment.transfer", "communication.email"]),
        tools=[transfer_funds, send_email],
        approver=approver,
    )


def report(title: str, agent: SecureAgent, result) -> None:
    print(f"\n=== {title} ===")
    for outcome in result.outcomes:
        status = "EXECUTED" if outcome.executed else "STOPPED "
        print(f"  {status} {outcome.call.tool_name:<15} -> [{outcome.decision.gate}] {outcome.decision.decision.value}")
        if outcome.executed:
            print(f"           result: {outcome.result}")
    for req in agent.approval_store.all():
        print(f"  approval request: action={req.action} risk={req.risk.level.value} approved={req.approved}")


def main() -> None:
    call = ToolCallRequest(tool_name="transfer_funds", arguments={"amount": 5000, "destination": "acct-9"})

    agent = build_agent()  # default: DenyAllApprover
    report("Scenario 1: critical action, no approver (fail closed)", agent, agent.run("transfer funds", ScriptedPlanner([[call]])))

    agent = build_agent(approver=ApproveAllApprover())
    report("Scenario 2: critical action, approved", agent, agent.run("transfer funds", ScriptedPlanner([[call]])))

    leaky_call = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "ops@example.com", "body": "fyi our aws key is AKIAABCDEFGHIJKLMNOP"},
    )
    agent = build_agent(approver=ApproveAllApprover())  # would approve -- doesn't matter, never gets there
    report("Scenario 3: secret in arguments, blocked before risk/approval", agent, agent.run("email ops", ScriptedPlanner([[leaky_call]])))


if __name__ == "__main__":
    main()
