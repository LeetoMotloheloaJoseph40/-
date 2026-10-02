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

## 2b. Component diagram — `run()` (model-driven, implemented in Stages 3–4)

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
              → Gate 5 Tool (→ Gate 4 Permission)
              → Gate 6 Data   (egress DLP: block secret-shaped arguments; classification ceiling)
              → Gate 7 Risk   (score from declared metadata + taint; HIGH/CRITICAL → hold)
              → [ if held: Approver.decide(ApprovalRequest) — default denies, fails closed ]
              → execute
           tool result → Gate 6 Data (redact secrets) → Gate 3 Trust (quarantine injections)
                       → accepted context / quarantine (quarantine never clears taint)

 Gate 8 Audit records every decision above, from both paths plus every approval
 outcome, under one trace_id per run.
```

The planner (which stands in for an LLM) is untrusted: its proposed tool
calls are requests, not authorizations, and every one of them still goes
through the same gates a direct `call_tool()` invocation would. A denied
or held proposal does not raise — it is recorded in the returned
`RunResult` and the run continues, so one bad proposal from the model
doesn't crash the whole interaction.

A `REQUIRE_APPROVAL` decision — from Trust's taint rule or from Risk
scoring a tool HIGH/CRITICAL — is taken to the configured `Approver`
(`core/runtime.py`'s `Approver` protocol) and logged as its own
`ApprovalRequest` in `approval/store.py`, scoped to that one action, not
blanket authority for the agent. The default `Approver`,
`DenyAllApprover`, always declines: an unconfigured or unreachable
approver fails closed exactly like every other missing control here.

Gates 6 and 7 (Data/Memory, Risk/Approval) are implemented as of Stage 4.
Delegation, MCP and framework adapters (Stage 5) are not.

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
DataClassification — a tool/output's data sensitivity            (core/models.py)
RiskAssessment  — how much scrutiny an action needs,
                  produced by the Risk Gate                        (core/models.py, gates/risk.py)
ApprovalRequest — ONE specific held action, scoped,
                  never blanket agent authority                      (core/models.py, approval/store.py)
SecurityDecision— one gate's verdict                                   (core/decisions.py)
AuditEvent      — durable record of a SecurityDecision                   (audit/events.py)
```

`SecurityDecision` is the only thing gates return; nothing else in the
codebase makes an authorization call.

## 4. Threat model (current scope)

This covers what the *implemented* gates defend against. It intentionally
does not claim coverage for Stage-5+ threats (multi-agent privilege
escalation, MCP server compromise) until those gates exist — see §6 for
what's explicitly out of scope today.

| Asset | Threat | Attack path | Control(s) |
|---|---|---|---|
| Tool execution | An agent (or whatever is prompting it) requests a tool call it shouldn't be able to make | Caller invokes `agent.call_tool("transfer_funds", ...)` directly | Tool Gate → Permission Gate deny; audited |
| Tool execution | Identity spoofing — a request claims to be an agent it isn't | `AgentIdentity` fields don't match the registry | Identity Gate deny (`CRITICAL` risk) |
| Tool execution | Unregistered/unknown tool invoked | Typo'd or malicious tool name | Tool Gate deny → `UnknownToolError`, distinct from a policy denial |
| Authorization | Misconfigured policy that both allows and denies the same permission | Conflicting `Policy.allow`/`Policy.deny` entries | `Policy.permits()`: deny always wins |
| Authorization | Policy object mutated after being handed to an agent | Caller edits `Policy.allow`/`deny` post-construction | `SecureAgent` snapshots the policy at construction |
| Accountability | An action happens with no record of the decision behind it | N/A — audit gate runs unconditionally | Audit Gate records every decision, including denials and approval outcomes, before `call_tool`/`run` returns/raises |
| Direct/indirect prompt injection (recognisable) | A web page, email, or tool output contains override phrasing ("ignore previous instructions", reveal-system-prompt, role reassignment, etc.) | Content enters context via `run()` or a tool result | Trust Gate: heuristic `PromptInjectionDetector` quarantines it before the planner ever sees it |
| Prompt injection that evades detection | Paraphrased/obfuscated override phrasing the pattern rules miss | Content enters context, is not flagged | Trust Gate: the *run* is tainted by any untrusted content it processed (even quarantined content); tools declared `external_effect=True` then require approval instead of executing |
| Hijacked out-of-scope action | A manipulated planner proposes a tool call unrelated to what the user asked for | `run()` loop, tool call proposal | Intent Gate: denies calls outside the classified intent's tool scope |
| Tool-name injection | Planner proposes a call to a name that is itself an injection string | `run()` loop | Unregistered tool names are denied and never echoed into context |
| Runaway planner | A compromised or buggy planner proposes calls forever | `run()` loop | `max_steps` bounds the loop; `RunResult.completed` reports whether it finished |
| Credential exfiltration | A manipulated or careless planner puts a secret-shaped string into a side-effecting tool's arguments | `run()` loop, tool call with secret in arguments | Data Gate: `SecretScanner` blocks the call outright before Risk/Approval are even evaluated |
| Secret leakage via tool output | A tool's return value happens to contain a credential (e.g. echoed from a fetched page) | Tool result re-entering context | Data Gate: `screen_result` redacts secret-shaped spans before the Trust Gate's injection screen runs |
| Over-privileged data access | A tool handles data more sensitive than this agent should touch | Tool's declared `data_sensitivity` exceeds the agent's ceiling | Data Gate: classification-ceiling check denies |
| Unattended high-impact action | A HIGH/CRITICAL-risk, irreversible or externally-effectful tool call, from a model-driven run | Risk Gate scores the call | `REQUIRE_APPROVAL`; executes only if a configured `Approver` grants that specific `ApprovalRequest` |
| Approval service down / unconfigured | No `Approver` was wired up, or it can't be reached | Any held action | `DenyAllApprover` (the default) always declines — fails closed, matching the spec's "approval service unavailable → do not execute" rule |
| Blanket authority from one approval | A human approves one action; could that be read as approving everything? | N/A — by construction | Each `ApprovalRequest` is scoped to one action/resource/reason; approving it does not touch policy or any other request |

## 5. Roadmap (stages, from the original spec)

- **Stage 1 — Foundation** — Implemented: domain models, gate interface, decision
  model, audit event model.
- **Stage 2 — Core Security** — Implemented: Identity, Permission, Tool, Audit
  gates; `SecureAgent.call_tool()`.
- **Stage 3 — AI security** — Implemented: Intent Gate, Trust Gate, heuristic
  prompt-injection detection, `SecureAgent.run()` with a model-agnostic
  `Planner` protocol (any LLM adapter can implement it).
- **Stage 4 — Autonomy** — Implemented: Data Gate (egress secret/PII
  detection, classification ceiling, output redaction), Risk Gate
  (deterministic scoring), and a real human-approval flow (`Approver`
  protocol, `ApprovalStore`, fail-closed `DenyAllApprover` default).
  `secure_memory` (durable, cross-run memory) is not built — see §6.
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
- **Side effects must be declared correctly.** The taint rule, and the Risk
  Gate's scoring, both key on `external_effect`/`reversible`/`risk_level` being
  set honestly on the tool. A tool that can exfiltrate data but is declared
  low-risk and read-only is not protected by either rule.
- **Secret/PII detection is pattern-based, not comprehensive.** `SecretScanner`
  catches common credential shapes (cloud/provider tokens, PEM key blocks,
  `key: value` assignments, Luhn-valid card numbers) and a narrow,
  high-false-positive-rate US SSN pattern. Free-text PII that isn't a
  structured credential, or an unfamiliar token format, is not caught.
- **The risk score is a policy input, not an objective danger measure.** It's
  built from declared tool metadata (risk level, external effect, reversibility,
  data classification) plus run taint, deterministically and explainably — but
  two very different actions landing on the same score doesn't mean they're
  equally dangerous.
- **No real human-approval UI.** The `Approver` protocol and `ApprovalStore`
  exist; `DenyAllApprover`/`ApproveAllApprover` are test/demo stand-ins.
  Connecting a real reviewer (Slack bot, dashboard, ticket queue) is up to the
  integrator.
- **Taint tracking is coarse** (per-run, not per-value) and **classification
  tracking does not follow derived values** — a non-secret-shaped value
  computed from sensitive data is not traced. See the Data Gate's own
  docstring for specifics.
- **Trusted sources are not scanned.** Content labelled `"user"` or `"system"`
  skips injection and secret screening by design; mislabelling untrusted
  content as trusted defeats both the Trust Gate and the Data Gate.
- **`call_tool()` bypasses Intent, Trust, Data and Risk** by design — it has no
  user request or untrusted context to evaluate, and is meant for calls your
  own application code chooses, not a model.
- **Tool arguments are not validated by the framework.** Planner-supplied
  arguments reach your tool function as-is; validate them inside the tool.
- `IdentityRegistry`/`PolicyEngine`/`ToolRegistry`/`ApprovalStore` are
  in-memory only; no persistence, no encryption, no distributed deployment
  story yet.
- No `secure_memory` (durable, cross-run memory), no multi-agent delegation, no
  MCP support, no framework adapters yet.
- The audit log is in-memory and not tamper-evident.
- The CLI is a placeholder that only prints what's implemented.

Do not describe this project, in code comments or documentation, as
providing protection it does not yet implement.
