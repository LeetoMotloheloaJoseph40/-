import pytest

from eightgates import AgentIdentity, Policy, RiskLevel, secure_tool


@pytest.fixture
def finance_identity() -> AgentIdentity:
    return AgentIdentity(id="finance-agent", owner="finance-dept", role="financial-analyst")


@pytest.fixture
def read_only_policy() -> Policy:
    return Policy(
        name="finance-read-only",
        allow=["database.read", "tool.get_balance"],
        deny=["database.delete", "payment.transfer"],
    )


@pytest.fixture
def get_balance_tool():
    @secure_tool(permission="tool.get_balance", risk=RiskLevel.LOW)
    def get_balance(account_id: str) -> dict:
        """Return a mock balance for the given account."""
        return {"account_id": account_id, "balance": 1000}

    return get_balance


@pytest.fixture
def transfer_funds_tool():
    @secure_tool(
        permission="payment.transfer",
        risk=RiskLevel.CRITICAL,
        external_effect=True,
        reversible=False,
    )
    def transfer_funds(amount: float, destination: str) -> dict:
        """Move money to another account. Deliberately NOT in the read-only policy."""
        return {"amount": amount, "destination": destination, "status": "sent"}

    return transfer_funds
