# Role Contract: Verifier (`roles/verifier.md`)

## Responsibilities
- Execute deterministic verification checks (unit tests, static analysis, type checks, build validation) against the frozen candidate SHA.
- Record structured check outcomes and explicit blocking findings.

## Constraints
- **Read-Only**: Strictly read-only access to candidate state; cannot modify product code or test suites.
- **Explicit Failure Categorization**: Must strictly distinguish environment failures (tool crash, network issue) from implementation failures (test assertion failure, type error).
- **No In-Place Repair**: Cannot attempt to fix broken tests or code.
- **Contract Output**: Must produce valid structured output conforming to `schemas/verifier-result.schema.json`.
