"""
Runnable example: a customer-service agent with a read-only policy.

    python examples/customer_service_agent.py

Demonstrates:
  * an authorized tool call executing normally
  * an unauthorized tool call being denied (not executed) and raising GateDenied
  * reading back the full audit trail for both calls
"""

from __future__ import annotations

from eightgates import (
    AgentIdentity,
    GateDenied,
    Policy,
    RiskLevel,
    SecureAgent,
    secure_tool,
)


@secure_tool(permission="database.read", risk=RiskLevel.LOW)
def get_customer(customer_id: str) -> dict:
    """Look up a customer record (mock)."""
    return {"customer_id": customer_id, "name": "Jane Doe", "plan": "Pro"}


@secure_tool(
    permission="database.delete",
    risk=RiskLevel.CRITICAL,
    external_effect=True,
    reversible=False,
)
def delete_customer(customer_id: str) -> dict:
    """Delete a customer record (mock). Deliberately NOT granted by the policy below."""
    return {"customer_id": customer_id, "status": "deleted"}


def main() -> None:
    identity = AgentIdentity(id="customer-agent", owner="support-team", role="customer-service")

    policy = Policy(
        name="customer-service-policy",
        allow=["database.read"],
        deny=["database.delete", "payment.transfer"],
    )

    agent = SecureAgent(
        name="customer-agent",
        identity=identity,
        policy=policy,
        tools=[get_customer, delete_customer],
    )

    print("Calling an authorized tool (database.read)...")
    result = agent.call_tool("get_customer", customer_id="12345")
    print(f"  -> {result}\n")

    print("Calling an unauthorized tool (database.delete)...")
    try:
        agent.call_tool("delete_customer", customer_id="12345")
        print("  -> executed (this should not happen!)")
    except GateDenied as e:
        print(f"  -> denied: {e.decision}\n")

    print("Full audit trail for this session:")
    for event in agent.audit_logger.events():
        print(f"  {event.timestamp.isoformat()} {event}")


if __name__ == "__main__":
    main()
