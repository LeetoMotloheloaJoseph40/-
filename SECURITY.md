# Security

## Reporting a vulnerability

This is an early project, not a hardened production system. If you find a security
issue, please open an issue describing it, and do not rely on the guarantees below in
production as-is.

## What is guaranteed today (each is covered by tests)

- **Fail-closed authorization.** No policy → deny. Explicit deny beats explicit allow.
  No wildcard "allow everything" default exists anywhere in the gate chain.
- **No execution without authorization.** A tool body only runs after every applicable
  gate returns ALLOW; this is enforced by control flow, not convention.
- **Policy snapshot.** `SecureAgent` copies the `Policy` it is given, so mutating your
  object afterwards cannot change what the agent is authorized to do.
- **The planner is untrusted.** In `run()`, model-proposed calls are checked against
  identity, intent scope, trust taint and permissions; a proposed tool name is never
  echoed into a trusted context unless it is a tool you registered.
- **Recognisable injections are quarantined** before the planner sees them, and
  audit entries record the *source label and rule names only*, never the payload.
- **Untrusted content cannot trigger declared side effects unattended.** Once a run has
  processed untrusted content (even content that was then quarantined), tools declared
  `external_effect=True` are not executed without approval.
- **Intent scoping (when configured).** Unrecognised requests are denied, ambiguous
  ones escalated, and tool calls outside the classified intent's scope denied.
- **Secrets never leave through a side-effecting tool call.** The Data Gate scans a
  tool's arguments for secret-shaped content (cloud/provider tokens, private key
  blocks, credential assignments, Luhn-valid card numbers) and blocks the call
  outright if any is found — before risk scoring or approval are even evaluated.
- **Secret-shaped content is redacted from tool output** before it re-enters context,
  same principle as injection quarantine, so a credential a tool happens to return
  can't propagate into the model's next step.
- **High-impact actions require approval, and fail closed without one.** The Risk Gate
  scores every proposed call from its declared metadata; HIGH/CRITICAL holds the
  action for approval. The default `Approver` (`DenyAllApprover`) always declines, so
  "no approver configured" behaves exactly like "approval service unavailable" — the
  action does not execute.
- **Approval is scoped to one action, not blanket authority.** Each held action
  becomes its own `ApprovalRequest` (agent, action, resource, reason, risk); granting
  one does not approve anything else, and every approval outcome is itself an audit
  event.
- **Complete audit trail.** Every gate decision, allowed or not, is recorded under one
  `trace_id` per run — including approval outcomes.

## What is NOT guaranteed

- **Detection is not comprehensive.** The heuristic injection detector misses
  paraphrased, translated, encoded, and homoglyph-obfuscated payloads. The test
  `test_KNOWN_LIMITATION_paraphrased_injection_is_not_detected` exists to keep this visible.
- **Side-effect declarations are trusted.** If a dangerous tool is registered with
  `external_effect=False`, the taint rule will not protect it. That judgment is yours.
- **Coarse taint.** No per-value data-flow tracking (see ARCHITECTURE.md §6).
- **Secret/PII detection is not comprehensive.** `SecretScanner` catches known
  credential shapes; free-text PII and unfamiliar token formats are not caught. The
  SSN-style rule is US-specific and intentionally narrow given its false-positive rate.
- **The risk score is a policy input, not an objective danger ranking** — it's
  deterministic and explainable, not a precision instrument (see ARCHITECTURE.md §6).
- **No real approval UI.** `DenyAllApprover`/`ApproveAllApprover` are test/demo
  stand-ins; wiring a real reviewer (Slack bot, dashboard, ticket queue) is on you.
- **Trusted sources are not scanned.** Content labelled `"user"` or `"system"` skips
  both injection and secret scanning. Mislabelling untrusted content as trusted
  defeats the Trust Gate and the Data Gate alike.
- **`call_tool()` bypasses Intent, Trust, Data and Risk** by design (it has no
  request or untrusted context to evaluate) — it's for calls your own code chooses.
- **Tool arguments are not validated by the framework.** Planner-supplied arguments go
  to your tool function as-is; validate them inside the tool.
- **No `secure_memory`** (durable, cross-run memory) and no memory-poisoning defenses.
- **No protection from a compromised policy/identity/approval store.** These are
  plain in-memory objects; whoever can call `.register()`/`.add()` can grant or
  fabricate anything.
- **The audit log is in-memory and not tamper-evident.**
- **Not a guarantee that any agent built with this is secure.**

If a docstring, README line or comment overstates what a control does, treat it as a bug.
