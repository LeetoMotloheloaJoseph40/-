# Security

## Reporting a vulnerability

This is an early scaffold, not a hardened production system. If you find
a security issue, please open an issue describing it rather than relying
on any of the guarantees below in production as-is.

## What is actually guaranteed today

- **Fail-closed authorization.** `PermissionGate` denies when no policy is
  registered, and `Policy.permits()` treats an explicit deny as always
  winning over an explicit allow. There is no wildcard/"allow everything"
  default anywhere in the gate chain.
- **No execution without authorization.** `SecureAgent.call_tool()` never
  invokes the underlying tool function unless both the Identity Gate and
  the Tool Gate (which itself calls the Permission Gate) return `ALLOW`.
  This is enforced by control flow (the call happens after both checks,
  guarded by early returns/raises), not by convention.
- **Complete audit trail for tool calls.** Every `SecurityDecision`
  produced during `call_tool()` — identity check, tool/permission check,
  and a completion event — is written to `AuditLogger` before the method
  returns or raises `GateDenied`/`UnknownToolError`. Denials are logged,
  not just successes.
- **Identity/permission/trust/risk stay separate types.** `AgentIdentity`
  never carries permissions; `Policy` never carries identity data. This is
  a design property you can rely on for auditing the code, not just a
  claim in prose.

## What is explicitly NOT guaranteed (see ARCHITECTURE.md §6 for the full list)

- **No prompt-injection defense.** There is no Trust Gate and no LLM
  integration yet. `SecurityContext.input_trust` is an unused field.
- **No risk-based approval.** A tool's `risk_level` is descriptive
  metadata that reaches the audit log; nothing currently blocks a
  `CRITICAL`-risk tool call pending human approval. If you need that
  today, implement it yourself at the call site until the Risk/Approval
  Gate (Stage 4) exists.
- **No data-loss prevention / PII or secret detection.** The Data/Memory
  Gate does not exist yet. Do not rely on this framework to redact
  sensitive output.
- **No memory security.** There is no memory subsystem at all yet.
- **No protection against a compromised policy or identity store.**
  `IdentityRegistry` and `PolicyEngine` are plain in-memory Python objects
  with no access control of their own; whoever can call `.register()` can
  grant any permission to any identity.
- **Not a guarantee that any agent built with this is "secure."** 8 Gates
  gives you explicit, testable control points. It cannot make a
  fundamentally unsafe tool (e.g. unrestricted shell execution registered
  with a `LOW` risk label) safe — that judgment call is still yours.

## Reporting policy claims that don't match implementation

If you find a docstring, README line, or comment that overstates what a
control actually does, treat that as a bug: security claims here must
correspond to real implementation behavior (see the Stage 2 development
rule this project follows).
