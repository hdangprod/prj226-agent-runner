# Role Contract: Builder (`roles/builder.md`)

## Responsibilities
- Implement planned changes within an authorized, isolated Git worktree.
- Create candidate commits and generate verifiable automated tests.
- Produce candidate commit SHAs and Tree SHAs for downstream verification.

## Constraints
- **Exclusive Write Lock**: Holds the sole authorized write capability during active builder execution.
- **Candidate Immutability**: Once candidate artifacts and SHAs are frozen (`CANDIDATE_FROZEN`), the candidate cannot be modified in place.
- **No Self-Verification**: The builder cannot verify or accept its own work; downstream gates must be executed independently.
- **Contract Output**: Must produce valid structured output conforming to `schemas/builder-result.schema.json`.
