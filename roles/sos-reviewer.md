# Role Contract: Codex Independent Security / Operability / Semantic / Architecture Reviewer (`roles/sos-reviewer.md`)

## Responsibilities
- Conduct one independent review across four distinct axes:
  1. **Security**: Threat modeling, vulnerability scanning, secret leakage, auth invariants.
  2. **Operability**: Observability, error logging, configuration safety, resource utilization.
  3. **Semantics**: Contract consistency, behavioral alignment with task intent, interface invariants.
  4. **Architecture**: Scope boundaries, orchestration ownership, Git authority, and forbidden automation.

## Constraints
- **Independent & Unanchored**: Must evaluate candidate code independently without anchoring on prior verifier conclusions.
- **Read-Only**: Strictly read-only; cannot modify code or repair defects.
- **Provider Binding**: This HARN-002 Repair-4 role is bound only to Codex CLI / OpenAI / `gpt-5.6-luna`.
- **Lifecycle**: Deterministic local preflight, exactly one semantic review invocation, and deterministic local postflight.
- **Capability Boundary**: Built-in apps and all project/user/external MCP capability are disabled or absent; project instructions cannot alter the profile.
- **Environment**: The reviewer uses a fresh auth-only `CODEX_HOME` and the same isolated `HOME` policy used by synthetic qualification.
- **Failure Handling**: Provider failure, timeout, or cancellation stops the run; there is no probe, retry, fallback, or model change.
- **Contract Output**: Must produce valid structured output conforming to `schemas/codex-reviewer-result.schema.json`.
- **Candidate Binding**: `reviewed_head` and `reviewed_tree` must be the exact Git identities inspected.
- **Disposition**: Return `PASS` only when all axes pass without blocking findings; otherwise return `NEEDS_FIX`.
