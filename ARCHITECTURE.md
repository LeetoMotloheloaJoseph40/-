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

`SecureAgent` is the custom-agent case: you register tools and a policy
against it directly, then either call `agent.call_tool(...)` for a
direct, application-chosen invocation, or `agent.run(...)` for a
model-driven request. The two paths enforce different things — see the
two diagrams below.

## 2. Component diagram — `call_tool()` (direct invocation)

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

There is no user request or untrusted context on this path, so Intent
and Trust do not apply to it — it is for calls your own application code
chooses, not a model.

## 2b. Component diagram — `run()` (model-driven, implemented in Stage 3)

```text
run(request, planner)
   │
   ├─ Gate 1 Identity    verify the acting identity           (deny → GateDenied)
   ├─ Gate 2 Intent      classify the request                 (opt-in; unknown → deny, ambiguous → escalate)
   ├─ Gate 3 Trust       screen request + supplied context     (quarantine known injections; record taint)
   │
   └─ loop (≤ max_steps)
        planner.plan(request, accepted_context)   ← untrusted proposer
        for each proposed call:
           Gate 1 Identity → Gate 2 Intent scope → Gate 3 Trust taint rule
              → Gate 5 Tool (→ Gate 4 Permission) → execute
           tool result → Gate 3 Trust screen → accepted context / quarantine
                                               (quarantine never clears taint)

 Gate 8 Audit records every decision above, from both paths, under one trace_id per run.
```

The planner (which stands in for an LLM) is untrusted: its proposed tool
calls are requests, not authorizations, and every one of them still goes
through the same gates a direct `call_tool()` invocation would. A denied
proposal does not raise — it is recorded in the returned `RunResult` and
the run continues, so one bad proposal from the model doesn't crash the
whole interaction.

Gates 6 and 7 (Data/Memory, Risk/Approval) are not yet implemented; see
§5. Until Risk/Approval exists, a `REQUIRE_APPROVAL` decision from the
Trust Gate means the action is simply not executed — there is no flow to
approve it yet.

## 3. Domain model separation

Per the architectural constraint in the original spec, these stay
independent objects rather than being folded into each other:

```text
AgentIdentity   — WHO is acting                     (core/models.py)
Permission      — a named capability                 (core/models.py)
Policy          — WHAT an identity may do             (policy/policy.py)
IntentPolicy    — WHAT the user asked for, as scope     (policy/intent.py)
ContextItem     — a piece of content + its SOURCE         (core/models.py)
TrustLevel      — how much a source is trusted              (core/models.py)
Tool            — an executable capability                    (tools/tool.py)
RiskAssessment  — how much scrutiny an action needs
                  (core/models.py; not yet produced by a gate)
SecurityDecision— one gate's verdict                             (core/decisions.py)
AuditEvent      — durable record of a SecurityDecision             (audit/events.py)
```

`SecurityDecision` is the only thing gates return; nothing else in the
codebase makes an authorization call.

## 4. Threat model (current scope)

This covers what the *implemented* gates defend against. It intentionally
does not claim coverage for Data/Risk-only threats (memory poisoning,
secret/PII leakage, no human-approval flow) until those gates exist —
see §6 for what's explicitly out of scope today.

| Asset | Threat | Attack path | Control(s) |
|---|---|---|---|
| Tool execution | An agent (or whatever is prompting it) requests a tool call it shouldn't be able to make | Caller invokes `agent.call_tool("transfer_funds", ...)` directly | Tool Gate → Permission Gate deny; audited |
| Tool execution | Identity spoofing — a request claims to be an agent it isn't | `AgentIdentity` fields don't match the registry | Identity Gate deny (`CRITICAL` risk) |
| Tool execution | Unregistered/unknown tool invoked | Typo'd or malicious tool name | Tool Gate deny → `UnknownToolError`, distinct from a policy denial |
| Authorization | Misconfigured policy that both allows and denies the same permission | Conflicting `Policy.allow`/`Policy.deny` entries | `Policy.permits()`: deny always wins |
| Authorization | Policy object mutated after being handed to an agent | Caller edits `Policy.allow`/`deny` post-construction | `SecureAgent` snapshots the policy at construction |
| Accountability | An action happens with no record of the decision behind it | N/A — audit gate runs unconditionally | Audit Gate records every decision, including denials, before `call_tool`/`run` returns/raises |
| Direct/indirect prompt injection (recognisable) | A web page, email, or tool output contains override phrasing ("ignore previous instructions", reveal-system-prompt, role reassignment, etc.) | Content enters context via `run()` or a tool result | Trust Gate: heuristic `PromptInjectionDetector` quarantines it before the planner ever sees it |
| Prompt injection that evades detection | Paraphrased/obfuscated override phrasing the pattern rules miss | Content enters context, is not flagged | Trust Gate: the *run* is tainted by any untrusted content it processed (even quarantined content); tools declared `external_effect=True` then require approval instead of executing |
| Hijacked out-of-scope action | A manipulated planner proposes a tool call unrelated to what the user asked for | `run()` loop, tool call proposal | Intent Gate: denies calls outside the classified intent's tool scope |
| Tool-name injection | Planner proposes a call to a name that is itself an injection string | `run()` loop | Unregistered tool names are denied and never echoed into context |
| Runaway planner | A compromised or buggy planner proposes calls forever | `run()` loop | `max_steps` bounds the loop; `RunResult.completed` reports whether it finished |

## 5. Roadmap (stages, from the original spec)

- **Stage 1 — Foundation** — Implemented: domain models, gate interface, decision
  model, audit event model.
- **Stage 2 — Core Security** — Implemented: Identity, Permission, Tool, Audit
  gates; `SecureAgent.call_tool()`.
- **Stage 3 — AI security** — Implemented: Intent Gate, Trust Gate, heuristic
  prompt-injection detection, `SecureAgent.run()` with a model-agnostic
  `Planner` protocol (any LLM adapter can implement it).
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

- **Injection detection is heuristic, not comprehensive.** `PromptInjectionDetector`
  catches known override/exfiltration phrasing and light obfuscation (zero-width
  characters, full-width Unicode), but paraphrased, translated, encoded or
  homoglyph-obfuscated attacks are not caught — this is a tested, documented gap,
  not an oversight. The real protection for a missed injection is the tainted-run
  rule below, not the detector.
- **Taint tracking is coarse.** One piece of untrusted content taints the whole
  run; there is no per-value data-flow tracking. A run that read anything
  untrusted cannot use tools declared `external_effect=True` without approval,
  even if that specific tool's arguments have nothing to do with the untrusted
  content. Mark genuinely internal tool output as `output_trust="TRUSTED"` to
  avoid over-tainting a run.
- **Side effects must be declared correctly.** The taint rule keys on
  `external_effect=True`. A tool that can exfiltrate data but is declared
  read-only is not protected by this rule.
- **No Risk Gate / human-approval flow yet.** `RiskAssessment` and
  `ApprovalRequest` models exist, but nothing computes a risk score or lets a
  human approve a held action — today, `REQUIRE_APPROVAL` from the Trust Gate
  means the action is simply not executed. A tool's declared `risk_level`
  reaches the audit log but does not itself gate execution.
- **Trusted sources are not scanned.** Content labelled `"user"` or `"system"`
  skips injection screening by design; mislabelling untrusted content as trusted
  defeats the Trust Gate.
- **`call_tool()` bypasses Intent and Trust** by design — it has no user request
  or untrusted context to evaluate.
- **Tool arguments are not validated by the framework.** Planner-supplied
  arguments reach your tool function as-is; validate them inside the tool.
- `IdentityRegistry`/`PolicyEngine`/`ToolRegistry` are in-memory only; no
  persistence, no encryption, no distributed deployment story yet.
- No Data/Memory Gate, no multi-agent delegation, no MCP support, no framework
  adapters yet.
- The audit log is in-memory and not tamper-evident.
- The CLI is a placeholder that only prints what's implemented.

Do not describe this project, in code comments or documentation, as
providing protection it does not yet implement.
