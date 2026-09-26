# Architecture

## 1. Position

8 Gates is a security control plane that sits *around* an agent, not
another agent-orchestration framework. It is meant to compose with
whatever is driving the agent's reasoning (a hand-written loop today; a
framework adapter later):

```text
                 8 GATES SECURITY PLANE
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
      LangGraph        CrewAI         Custom Agent   (adapters: Stage 5, not built yet)
          │               │                │
          └───────────────┼────────────────┘
                          │
                     AI SYSTEM
```

Today, `SecureAgent` *is* the custom-agent case: you register tools and a
policy against it directly and call `agent.call_tool(...)`.

## 2. Component diagram (as implemented)

```text
                         ┌──────────────────┐
                         │   call_tool()    │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │   Gate 1 — Identity     │  IdentityRegistry
                    └────────────┬────────────┘
                                  │ ALLOW
                                  ▼
                    ┌────────────────────────┐
                    │   Gate 5 — Tool         │  ToolRegistry
                    │   (delegates to ↓)      │
                    │   Gate 4 — Permission   │  PolicyEngine
                    └────────────┬────────────┘
                                  │ ALLOW
                                  ▼
                          [ tool executes ]
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │   Gate 8 — Audit        │  AuditLogger
                    └────────────────────────┘
```

Every gate call — ALLOW or DENY — is written to the `AuditLogger` before
`call_tool` returns or raises. Denials short-circuit before the tool body
ever runs.

Gates 2, 3, 6, 7 (Intent, Trust, Data/Memory, Risk/Approval) are not yet
implemented; see §5.

## 3. Domain model separation

Per the architectural constraint in the original spec, these stay
independent objects rather than being folded into each other:

```text
AgentIdentity   — WHO is acting            (core/models.py)
Permission      — a named capability        (core/models.py)
Policy          — WHAT an identity may do   (policy/policy.py)
TrustLevel      — how much to trust context (core/models.py; not yet enforced by a gate)
Tool            — an executable capability  (tools/tool.py)
RiskAssessment  — how much scrutiny an
                  action needs              (core/models.py; not yet produced by a gate)
SecurityDecision— one gate's verdict        (core/decisions.py)
AuditEvent      — durable record of a
                  SecurityDecision          (audit/events.py)
```

`SecurityDecision` is the only thing gates return; nothing else in the
codebase makes an authorization call.

## 4. Threat model (current scope)

This covers what the *implemented* gates defend against. It intentionally
does not claim coverage for Intent/Trust/Data/Risk-only threats (prompt
injection, memory poisoning, exfiltration) until those gates exist —
see §6 for what's explicitly out of scope today.

| Asset | Threat | Attack path | Control(s) |
|---|---|---|---|
| Tool execution | An agent (or whatever is prompting it) requests a tool call it shouldn't be able to make | Caller invokes `agent.call_tool("transfer_funds", ...)` directly | Tool Gate → Permission Gate deny; audited |
| Tool execution | Identity spoofing — a request claims to be an agent it isn't | `AgentIdentity` fields don't match the registry | Identity Gate deny (`CRITICAL` risk) |
| Tool execution | Unregistered/unknown tool invoked | Typo'd or malicious tool name | Tool Gate deny → `UnknownToolError`, distinct from a policy denial |
| Authorization | Misconfigured policy that both allows and denies the same permission | Conflicting `Policy.allow`/`Policy.deny` entries | `Policy.permits()`: deny always wins |
| Accountability | An action happens with no record of the decision behind it | N/A — audit gate runs unconditionally | Audit Gate records every decision, including denials, before `call_tool` returns/raises |

## 5. Roadmap (stages, from the original spec)

- **Stage 1 — Foundation** ✅ done: domain models, gate interface, decision
  model, audit event model.
- **Stage 2 — Core security** ✅ done: Identity, Permission, Tool, Audit
  gates; `SecureAgent.call_tool()`.
- **Stage 3 — AI security**: Intent Gate, Trust Gate, prompt-injection
  detection, `SecureAgent.run()` wired to an LLM.
- **Stage 4 — Autonomy**: Data/Memory Gate, Risk/Approval Gate, human
  approval flow, `secure_memory`.
- **Stage 5 — Ecosystem**: multi-agent delegation, MCP integration,
  LangGraph/CrewAI/other framework adapters.
- **Stage 6 — Security testing**: adversarial test library, red-team
  mode (`8gates redteam`), regression suite.
- **Stage 7 — Developer platform**: real CLI (`init`, `validate`,
  `security scan`, `policy`, `audit`, `threat-model`, `inspect`),
  human-readable + machine-readable reports.

## 6. Known limitations (be explicit about these)

- No Trust Gate yet: `SecurityContext.input_trust` exists as a field but
  nothing currently reads or enforces it. Untrusted content is **not**
  currently being screened.
- No Risk Gate yet: `RiskAssessment` and `ApprovalRequest` models exist,
  but nothing computes a risk score or requires human approval — a tool's
  declared `risk_level` currently only flows into audit events, it does
  not gate execution.
- No prompt-injection defenses yet — there's no LLM in the loop at all
  right now (`run()` is unimplemented), so there's nothing to inject into,
  but this must be built before `run()` ships.
- `IdentityRegistry`/`PolicyEngine`/`ToolRegistry` are in-memory only; no
  persistence, no encryption, no distributed deployment story yet.
- No multi-agent delegation, no MCP support, no framework adapters.
- The CLI is a placeholder that only prints what's implemented.

Do not describe this project, in code comments or documentation, as
providing protection it does not yet implement.
