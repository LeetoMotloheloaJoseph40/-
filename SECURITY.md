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
- **Complete audit trail.** Every gate decision, allowed or not, is recorded under one
  `trace_id` per run.

## What is NOT guaranteed

- **Detection is not comprehensive.** The heuristic injection detector misses
  paraphrased, translated, encoded, and homoglyph-obfuscated payloads. The test
  `test_KNOWN_LIMITATION_paraphrased_injection_is_not_detected` exists to keep this visible.
- **Side-effect declarations are trusted.** If a dangerous tool is registered with
  `external_effect=False`, the taint rule will not protect it. That judgment is yours.
- **Coarse taint.** No per-value data-flow tracking (see ARCHITECTURE.md §6).
- **No human-approval flow.** `REQUIRE_APPROVAL` means "not executed"; nothing can approve it yet.
- **Trusted sources are not scanned.** Content labelled `"user"` or `"system"` skips
  injection scanning. Mislabelling untrusted content as trusted defeats the Trust gate.
- **`call_tool()` bypasses Intent and Trust** by design (it has no request or context).
- **Tool arguments are not validated by the framework.** Planner-supplied arguments go
  to your tool function as-is; validate them inside the tool.
- **No data-loss prevention, PII/secret detection, or memory security** (Stage 4).
- **No protection from a compromised policy/identity store.** Registries are plain
  in-memory objects; whoever can call `.register()` can grant anything.
- **The audit log is in-memory and not tamper-evident.**
- **Not a guarantee that any agent built with this is secure.**

If a docstring, README line or comment overstates what a control does, treat it as a bug.
