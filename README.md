# 八門 — 8 Gates

**A security-first Python framework for AI agents.**

An AI agent should not be trusted merely because it is an AI agent. Every
meaningful operation must pass through appropriate security gates before
it is allowed to execute.

> **Status: early scaffold.** Stage 1 (domain models) and Stage 2
> (Identity, Permission, Tool, Audit gates) are implemented and tested.
> Trust, Intent, Data/Memory, Risk/Approval, multi-agent delegation, MCP
> integration, external framework adapters, red-team testing, and the CLI
> are planned — see [ARCHITECTURE.md](ARCHITECTURE.md) for the roadmap.
> Nothing below claims more than what's actually implemented.

## Install

```bash
pip install -e ".[dev]"
```

## Quickstart

```python
from eightgates import SecureAgent, AgentIdentity, Policy, secure_tool, RiskLevel

@secure_tool(permission="database.read", risk=RiskLevel.LOW)
def get_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id, "name": "Jane Doe"}

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
    tools=[get_customer],
)

result = agent.call_tool("get_customer", customer_id="12345")
print(result)  # {'customer_id': '12345', 'name': 'Jane Doe'}

# Every call — allowed or denied — is on the audit trail:
for event in agent.audit_logger.events():
    print(event)
```

Calling a tool the policy doesn't grant raises `GateDenied` with the full
`SecurityDecision` attached, and the denial is still recorded in the audit
log:

```python
from eightgates import GateDenied

try:
    agent.call_tool("delete_customer", customer_id="12345")
except GateDenied as e:
    print(e.decision)  # [tool] DENY agent=customer-agent action=... reason='...'
```

See [`examples/customer_service_agent.py`](examples/customer_service_agent.py)
for a runnable version of this, including a denied call and reading back
the audit trail.

## What's implemented right now

| Gate | Status | Responsibility |
|---|---|---|
| 1. Identity | ✅ Implemented | Verifies the acting identity against a registry; fails closed on unknown/mismatched identities |
| 2. Intent | 🔜 Planned (Stage 3) | Classify what the actor is attempting to do |
| 3. Trust | 🔜 Planned (Stage 3) | Classify trust of external content/context |
| 4. Permission | ✅ Implemented | Declarative allow/deny policy, deny always wins |
| 5. Tool / Action | ✅ Implemented | Tools are security boundaries; checks registration + delegates to Permission |
| 6. Data / Memory | 🔜 Planned (Stage 4) | PII/secret detection, memory isolation, classification |
| 7. Risk / Approval | 🔜 Planned (Stage 3/4) | Risk scoring, human-in-the-loop approval |
| 8. Audit / Output | ✅ Implemented | Every decision from every gate, including denials, becomes a structured event |

`SecureAgent.call_tool()` runs the implemented chain end to end:
**Identity → Tool (→ Permission) → execution → Audit**.

`SecureAgent.run()` — the full LLM-driven request lifecycle described in
the architecture — is intentionally a `NotImplementedError` stub right
now, not a silent no-op, because Intent/Trust/Risk aren't built yet.

## Project layout

```text
8gates/
├── pyproject.toml
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── examples/
│   └── customer_service_agent.py
├── src/eightgates/
│   ├── core/        # domain models, decision model, exceptions
│   ├── identity/     # identity registry
│   ├── policy/        # Policy + PolicyEngine
│   ├── tools/          # Tool, ToolCapability, @secure_tool, registry
│   ├── audit/           # AuditEvent, AuditLogger
│   ├── gates/            # Identity, Permission, Tool, Audit gates
│   ├── agent.py           # SecureAgent runtime
│   └── cli/                # placeholder console script
└── tests/
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/
```

## Non-goals

8 Gates is not a replacement for an LLM, not a general orchestration
framework, and not a guarantee that any given agent is secure. It's a set
of explicit, testable, fail-closed controls you compose around an agent.
See [SECURITY.md](SECURITY.md) for what is and isn't actually guaranteed
by the current implementation.
