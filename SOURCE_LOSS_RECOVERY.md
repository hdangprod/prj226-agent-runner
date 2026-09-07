# SOURCE LOSS RECOVERY RECORD (M0R)

## 1. Executive Summary & Recovery Context

- **Decision**: Repair-15 recovery is permanently closed.
- **Historical Recovery Outcome**: `SOURCE_NOT_FOUND`.
- **Strategy**: Strategy B is approved and executed. The complete identified staged HARN-002 implementation is frozen as a fresh, independent migration baseline (`M0R`).
- **Identity & Qualification**: This baseline does NOT inherit Repair-15 identity, branch name, or qualification artifacts.
- **Approved V1 Execution Scope**: Trusted-local execution is the approved V1 scope. Strict confinement and ORCA are outside V1.
- **Review Policy**: Existing dual-review policy (DV + S/O/S reviewer sequence) remains unchanged in this baseline and serves as input to M1.
- **Runtime Behavior**: M0R makes zero runtime, source, schema, test, or config behavior changes.
- **Durable Evidence Location**: `/Users/dangnguyen/Desktop/prj226-agent-runner-recovery/M0R-SOURCE-LOSS-001`.

## 2. Lineage and Git Identifiers

- **Starting Parent Branch**: `main`
- **Starting Parent HEAD SHA**: `3fe916744a34a92552aa3ec64a4fb6ec9ea0f271`
- **Starting Parent Tree SHA**: `20d8fb080c33e3bb6b5813ad1f555a36fd1606c2`
- **Raw Preflight Index SHA-256**: `77b102c84859feba9cde1b7d9760de46f48d1bbace18148cac2fddfaaa8726fe`
- **M0R Snapshot Commit SHA**: `a1b3bd733c849291d3478b53291a593c75769e1a`
- **M0R Snapshot Tree SHA**: `5a72c48a2eb7e3ed80103759d56b008a686bcf18`
- **Recovery Branch**: `recovery/m0r-source-loss`

## 3. Staged Implementation Contents

The initial snapshot commit (`a1b3bd733c849291d3478b53291a593c75769e1a`) incorporates exactly the 27 authorized staged paths byte-for-byte from the verified preflight index:
- `AI_AGENT_HARNESS_VISION_AND_OPERATING_MODEL_V2.md`
- `README.md`
- `config/runner.example.toml`
- `roles/sos-reviewer.md`
- `schemas/codex-reviewer-result.schema.json`
- `schemas/controller-result.schema.json`
- `schemas/controller-state.schema.json`
- `schemas/design-contract.schema.json`
- `schemas/gate-b-authorization.schema.json`
- `schemas/gate-b-package.schema.json`
- `schemas/project-manifest.schema.json`
- `src/prj226_runner/__init__.py`
- `src/prj226_runner/calibration.py`
- `src/prj226_runner/cli.py`
- `src/prj226_runner/codex_reviewer.py`
- `src/prj226_runner/controller.py`
- `src/prj226_runner/errors.py`
- `src/prj226_runner/models.py`
- `src/prj226_runner/reviewer_profile.py`
- `src/prj226_runner/runner.py`
- `tests/test_codex_reviewer.py`
- `tests/test_controller.py`
- `tests/test_repair4.py`
- `tests/test_repair5.py`
- `tests/test_repair6.py`
- `tests/test_repair7.py`
- `tests/test_repair8.py`

## 4. Verification & Evidence Plan

- A dedicated deterministic validation pass using the normalized isolated Python 3.12 environment (`/Users/dangnguyen/.venvs/prj226-agent-runner-m0r`) runs across the complete test suite and schema set.
- All test outputs, raw logs, schema validation results, bundle verification, and checksums are persisted in durable storage at `/Users/dangnguyen/Desktop/prj226-agent-runner-recovery/M0R-SOURCE-LOSS-001`.
