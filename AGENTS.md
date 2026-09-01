# Operating Instructions for AI Agents (`AGENTS.md`)

This document defines strict operational rules and boundaries for any AI agent executing within or interacting with `prj226-agent-runner`.

---

## 1. Scope and Authority Boundaries

- **Runner Infrastructure Only**: This repository manages local orchestration infrastructure. Agents operating here must not modify product code in external repositories (e.g., `/Users/dangnguyen/Desktop/prj226-gen2`) unless an explicit, scoped run packet with authorized write permissions is active.
- **Agents Propose, Runner Validates**: Agents do not directly execute lifecycle state transitions or mutate runner state. Agents output structured proposals; deterministic runner code validates and transitions state.
- **No Agent-to-Agent Direct Orchestration**: Agents communicate exclusively through repository files, immutable artifacts, structured JSON contracts, and append-only event logs. Uncontrolled direct chat loops between agents are prohibited.

---

## 2. Integrity and Truth Invariants

- **No Synthetic or Hallucinated Hashes**: Never invent, estimate, or hallucinate Git commit SHAs, tree hashes, checksums, or test results. Repository and execution truth must always be derived from direct tool inspection.
- **Strict Schema Adherence**: Structured JSON outputs must conform strictly to their respective schemas in `schemas/`. Malformed structured output is treated as an `ARTIFACT_VALIDATION_ERROR`—never as permission to infer intent.
- **Immutable Run History**: Historical run directories in `runs/` must never be overwritten, modified, cleaned, or deleted. All runs are durable records.

---

## 3. Governance and Safety Gates

- **Human Gates are Mandatory**: Never attempt to bypass, automate around, or assume approval for human checkpoints (`HUMAN_GATE`).
- **No Automatic Git Push**: No agent or runner process may execute `git push` or publish commits without explicit human confirmation.
- **No Destructive Git Commands**: `git reset --hard`, `git clean -f`, force pushes, or history rewrites are strictly prohibited across both runner and target repositories.
- **No Hidden Retry or Repair Loops**: When a gate, test, or review fails, halt immediately and report the error classification. Do not spawn unauthorized internal repair loops.
- **Fail Closed**: In any scenario of state ambiguity, schema mismatch, or unexpected repository condition, fail closed immediately.
