# Role Contract: Targeted Reviewer (`roles/targeted-reviewer.md`)

## Responsibilities
- Perform exactly one targeted semantic review of the frozen V2 candidate after deterministic verification PASS.
- Validate exact candidate HEAD/TREE/ref, reviewer profile hash, executable fingerprint, and evidence hashes.
- Return only JSON conforming to `schemas/targeted-review-result.schema.json` (`HARN-002.TARGETED_REVIEW.v1`).
- Use `PASS` only when there are no blocking findings; otherwise use `NEEDS_FIX` with non-empty blocking findings.

## Constraints
- **Read-Only**: Strictly read-only access to candidate state; cannot modify product code, commit, or repair.
- **One Attempt**: At most one process invocation per run. No retry, no fallback, no alternate provider.
- **No Probes**: No version/help/availability probes against a real provider. Local binding inspection only.
- **Process Failure Wins**: Nonzero exit, timeout, or spawn failure yields `EXECUTION_FAILURE` even when a PASS file exists.
- **No Fallback Parsers**: No stdout/prose fallback, no legacy parser fallback, no model/provider fallback.
- **Binding**: Executable, profile, schema SHA-256, timeout, and review brief are frozen at Gate A. Any drift fails closed.
- **Contract Output**: Must produce valid structured output conforming to `schemas/targeted-review-result.schema.json`.
