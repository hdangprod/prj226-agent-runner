# Agent Calibration Framework (`calibration/`)

This directory defines the calibration infrastructure used to verify that locally available AI agent CLIs (Codex CLI, Antigravity CLI, and OpenCode CLI) can be invoked unattended, safely, and deterministically by the Python runner.

---

## Phase Separation: 1A, 1B-PRE, and 1B-LIVE

The calibration lifecycle is strictly split into three phases:

### Phase 1A — Harness Implementation
- Implements the initial deterministic calibration harness (`src/prj226_runner/calibration.py`).
- Establishes the synthetic fixture template (`calibration/fixture/`).
- Defines the normalized result contract (`schemas/calibration-result.schema.json`).
- Validates harness logic via offline, deterministic unit tests (`tests/test_calibration.py`).
- **Zero live model invocations**: No model tasks are executed through Codex, Antigravity, or OpenCode during 1A.
- **No durable run directories**: No live calibration runs (`runs/CALIBRATION-*/`) are created in 1A.

### Phase 1B-PRE — Deterministic Hardening & Command Builders (This Phase)
- Implements pure command builders (`build_codex_invocation`, `build_agy_invocation`, `build_opencode_invocation`).
- Implements explicit tool discovery observability (`ToolDiscoveryRecord`, `DiscoveryStatus`).
- Implements strict symlink safety policies (`check_no_symlinks`, `scan_workspace_for_symlinks`) using `lstat` semantics.
- Implements child process environment policies with explicit allowlists and credential pattern rejection (`validate_environment_override_keys`).
- Establishes case-level evaluation semantics (`CalibrationCaseResult`, `CalibrationVerdict`) separating tool invocation outcomes from test case verdicts.
- Enforces runtime state invariants (closing `NB-SEM-001` and `NB-SEM-002`).
- Generates two-phase Human Gate payload (`HumanGatePayload`) verifying model pinning and baseline integrity before any live dispatch.
- Defines external contracts: `schemas/calibration-result.schema.json` and `schemas/calibration-case-result.schema.json`.
- Validates all invariants with zero model or network calls via deterministic unit tests.

### Phase 1B-LIVE — Separately Authorized Agent Smoke Tests (Future Phase)
- Separately authorized live execution against local CLI backends.
- Executes outside the repository inside disposable external runtime roots (`/tmp/prj226_runner_runtime/<RUN_ID>/`).
- Executes real read-only smoke tests and negative mutation cases (`CALIBRATION_KEY=alpha_7729`).
- Verifies live process-group timeouts, error classifications, and permission policies.
- Produces sanitized, immutable run records.

---

## Architecture & Invariants

1. **Deterministic 1:1 Invocation**: The Python runner spawns each CLI tool as an independent child process (`start_new_session=True`). No agent directly orchestrates another agent.
2. **Disposable Runtime Workspaces**: The committed fixture (`calibration/fixture/`) is an immutable template. Live tests copy it into disposable runtime workspaces (`/tmp/prj226_runner_runtime/<RUN_ID>/workspace/`) and verify template immutability via pre/post SHA-256 tree hashing.
3. **Invocation vs Case Verdict Separation**:
   - **Operational Invocation Status (`CalibrationResult.status`)**: `PASS`, `TASK_FAILURE`, `TOOL_FAILURE`, `TIMEOUT`, `OUTPUT_INVALID`, `PERMISSION_DENIED`.
   - **Case Verdict (`CalibrationCaseResult.verdict`)**: `PASS` or `FAIL`. An expected permission denial evaluates to case `PASS`. Any unexpected workspace mutation evaluates to case `FAIL` with `GOVERNANCE_BLOCKER`.
4. **Symlink Safety Policy**:
   - Source fixture trees containing any symlink raise `ARTIFACT_VALIDATION_ERROR` immediately without traversing target bytes.
   - Any runtime agent creating a symlink during read-only/smoke qualification is classified as a `GOVERNANCE_BLOCKER`.
5. **Environment Policy**: Child environments inherit `os.environ.copy()`. Runner-managed explicit overrides are strictly allowlisted and checked against credential patterns (`TOKEN`, `SECRET`, `PASSWORD`, `AUTH`, `API_KEY`). Only override key names are stored in metadata—never values.
6. **Two-Phase Human Gate**: The runner prepares frozen command argv, models, timeouts, permission summaries, and baseline hashes into a structured `HumanGatePayload`. If any model parameter is `None` or unresolved, `readiness` evaluates to `NOT_READY`.
