# Run Directory Specification (`templates/run/README.md`)

This document defines the filesystem layout and persistence invariants for all orchestration runs executed by `prj226-agent-runner`.

---

## Run Directory Structure

Each run executes within an isolated directory under `runs/<RUN_ID>/` with the following structure:

```
runs/<RUN_ID>/
├── manifest.json         # Immutable run identity, target repo snapshot, and agent configs
├── state.json            # Current lifecycle state snapshot (conforming to run-state schema)
├── events.ndjson         # Append-only chronological audit stream of all transitions/events
├── baseline/             # Pre-flight baseline verification artifacts (HEAD, tree, status)
├── planner/              # Planner output artifacts and planner-result.json
├── plan-review/          # Human / gate review artifacts and disposition records
├── builder/              # Builder output artifacts, diffs, and builder-result.json
├── verifier/             # Deterministic verification logs, test reports, and verifier-result.json
├── sos/                  # Security/Operability/Semantic review artifacts and sos-result.json
└── worktrees/            # Ephemeral isolated Git worktrees (ignored by version control)
```

---

## Artifact Definitions & Lifecycle Invariants

1. **`manifest.json`**:
   - Written at run creation (`CREATED`).
   - Immutable snapshot of run ID, task description, target repository path, canonical branch, expected baseline HEAD/Tree, and agent/tool bindings.
   - Must never be modified after creation.

2. **`state.json`**:
   - Atomic, mutable snapshot reflecting the current `RunState`.
   - Updated strictly by deterministic runner code during valid lifecycle transitions.

3. **`events.ndjson`**:
   - Append-only newline-delimited JSON stream recording all events, state transitions, timestamps, and error classifications.
   - Acts as the definitive chronological audit trail.

4. **Role Result Contracts (`*-result.json`)**:
   - Machine-readable JSON contracts produced by agents at completion of their respective phases.
   - Validated against strict schemas in `schemas/`.

5. **Raw Logs (`runs/*/logs/raw/`)**:
   - Ephemeral diagnostic output from subprocess tools.
   - Diagnostic only; governance decisions are made exclusively on structured result contracts.

6. **Historical Immutability**:
   - Historical run directories are permanent audit records and must never be deleted, overwritten, or cleaned.
