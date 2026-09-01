# Role Contract: Security / Operability / Semantic Reviewer (`roles/sos-reviewer.md`)

## Responsibilities
- Conduct independent review across three distinct axes:
  1. **Security**: Threat modeling, vulnerability scanning, secret leakage, auth invariants.
  2. **Operability**: Observability, error logging, configuration safety, resource utilization.
  3. **Semantics**: Contract consistency, behavioral alignment with task intent, interface invariants.

## Constraints
- **Independent & Unanchored**: Must evaluate candidate code independently without anchoring on prior verifier conclusions.
- **Read-Only**: Strictly read-only; cannot modify code or repair defects.
- **Contract Output**: Must produce valid structured output conforming to `schemas/sos-result.schema.json`.
