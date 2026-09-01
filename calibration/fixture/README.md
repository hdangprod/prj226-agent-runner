# Synthetic Calibration Fixture (`calibration/fixture/`)

This directory contains the committed, immutable template files used for agent calibration tests.

---

## Immutable Template Invariant

- **Template Only**: Files in this directory are strictly a read-only template.
- **No Direct Execution**: No agent, tool, or calibration script may ever execute directly inside or modify this tracked directory.
- **Disposable Runtime Copy**: During calibration runs, the runner copies these files into an ephemeral workspace (e.g. `runs/<CALIBRATION_ID>/workspace/` or an OS temporary directory).
- **Integrity Verification**: The runner calculates the SHA-256 tree hash of this template before and after calibration to ensure it remains 100% bit-identical.
