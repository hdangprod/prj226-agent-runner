# Agent Calibration Framework (`calibration/`)

This directory defines the calibration infrastructure used to verify that locally available AI agent CLIs (Codex CLI, Antigravity CLI, and OpenCode CLI) can be invoked unattended, safely, and deterministically by the Python runner.

---

## Phase Separation: 1A vs 1B

The calibration lifecycle is strictly split into two phases:

### Phase 1A — Harness Implementation (This Phase)
- Implements the deterministic calibration harness (`src/prj226_runner/calibration.py`).
- Establishes the synthetic fixture template (`calibration/fixture/`).
- Defines the normalized result contract (`schemas/calibration-result.schema.json`).
- Validates all harness logic via offline, deterministic unit tests (`tests/test_calibration.py`).
- **Zero live model invocations**: No model tasks are executed through Codex, Antigravity, or OpenCode during 1A.
- **No durable run directories**: No live calibration runs (`runs/CALIBRATION-*/`) are created in 1A.

### Phase 1B — Live Agent Smoke Tests (Later Phase)
- Separately authorized live execution against local CLI backends.
- Executes real read-only smoke tests and verifies synthetic token extraction (`CALIBRATION_KEY=alpha_7729`).
- Verifies live process-group timeouts, error classifications, and permission policies.
- Writes durable run records and audit streams into `runs/CALIBRATION-<ID>/`.

---

## Architecture & Invariants

1. **Deterministic 1:1 Invocation**: The Python runner spawns each CLI tool as an independent child process (`start_new_session=True`). No agent directly orchestrates another agent.
2. **Disposable Runtime Workspaces**: The committed fixture (`calibration/fixture/`) is an immutable template. Live tests copy it into disposable runtime workspaces (`runs/<CAL_ID>/workspace/`) and verify template immutability via pre/post SHA-256 tree hashing.
3. **Two-Layer Taxonomy**:
   - **Operational Status (`status`)**: `PASS`, `TASK_FAILURE`, `TOOL_FAILURE`, `TIMEOUT`, `OUTPUT_INVALID`, `PERMISSION_DENIED`.
   - **Runner Error Class (`error_class`)**: Mapped to existing runner `ErrorClass` (`ENVIRONMENT_ERROR`, `AGENT_EXECUTION_ERROR`, `ARTIFACT_VALIDATION_ERROR`, `IMPLEMENTATION_FAILURE`, `GOVERNANCE_BLOCKER`).
4. **Process-Tree Timeout Control**: Subprocesses are launched in dedicated process groups. On timeout, `SIGTERM` is sent to the entire process group, followed by bounded grace interval and `SIGKILL`.
5. **Zero Credential / Environment Dumping**: Durable evidence records (`result.json`, `events.ndjson`) contain sanitized metadata only. Raw subprocess stdout/stderr streams are kept in ephemeral diagnostic logs (`runs/*/logs/raw/`) ignored by Git.
