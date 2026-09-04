# PRJ226 Agent Runner (`prj226-agent-runner`)

Deterministic local orchestration repository for external AI coding and review agents coordinating on PRJ226.

> **CRITICAL BOUNDARY NOTICE**  
> This repository contains **local orchestration infrastructure only**.  
> It is **NOT** product/runtime code, is **NOT** part of the Liam deployable architecture, and is **NOT** part of the PRJ226 Gen2 product repository.  
> Target repository paths (such as `/Users/dangnguyen/Desktop/prj226-gen2`) are purely external configurable inputs.  
> This runner does not execute any task packets (including ENG-012) at bootstrap.

---

## Core Architectural Principles

1. **Deterministic Orchestration**: Lifecycle transitions are owned strictly by deterministic runner code. No LLM/agent directly orchestrates another LLM/agent.
2. **Human Control**: Human approval gates must be explicitly satisfied before candidate dispatch. No autonomous bypass of governance checkpoints.
3. **Repository Truth Over Assumptions**: Actual Git repository state (HEAD, Tree, Working Tree) outranks all runner inferences or agent claims.
4. **Immutable Candidates**: Once a candidate commit or artifact is frozen, it cannot be modified in place.
5. **Isolated Worktrees**: Future builder and verification agents execute in dedicated, isolated Git worktrees.
6. **Structured Machine-Readable Results**: Agents communicate strictly through validated JSON schema contracts, repository state, and immutable artifacts—never uncontrolled conversational loops.
7. **Append-Only Event History**: Every lifecycle transition and agent invocation is recorded in an immutable, append-only `events.ndjson` audit stream.
8. **Fail-Closed Governance**: Any governance ambiguity, schema mismatch, or state invariant violation immediately halts execution.
9. **Environment vs. Implementation Separation**: Environmental failures (missing binaries, network timeouts, tool errors) are explicitly distinguished from implementation flaws.
10. **No Implicit Push**: The runner will never push to remote repositories automatically.
11. **No Automatic Repair Loops in V1**: Flawed candidates or verification failures stop for human assessment rather than entering unconstrained retry cycles.

---

## Repository Layout

```
prj226-agent-runner/
├── README.md               # Repository documentation and principles
├── AGENTS.md               # Operating instructions and constraints for AI agents
├── .gitignore              # Ephemeral runtime ignore rules
├── pyproject.toml          # Python package configuration (Python >= 3.12)
├── config/
│   └── runner.example.toml # Configuration template for runner and target repo
├── roles/                  # Role contract definitions (Planner, Builder, Verifier, SOS)
├── schemas/                # Strict JSON Schemas for manifest, state, and role outputs
├── templates/
│   └── run/README.md       # Directory layout documentation for future runs
├── src/
│   └── prj226_runner/      # Core models, paths, and error definitions
└── runs/
    └── .gitkeep            # Workspace for run artifacts
```

---

## Configuration

Runner configuration is defined in TOML (parsed using Python standard-library `tomllib`). See `config/runner.example.toml` for the external runtime root and role tool/model bindings.

## HARN-001 Runner V1

Runner V1 consumes a human-approved Task Packet and deliberately separates the
deterministic lifecycle from provider-specific command construction:

```text
Task Packet → preflight → --authorize → isolated Builder → candidate freeze
→ deterministic gates → read-only DV → read-only S/O/S → ACCEPTANCE_READY
```

Use `prj226-runner inspect task-packet.json` for a read-only preflight. It
creates no runtime directory or worktree and returns either
`READY_FOR_HUMAN_AUTHORIZATION` or a failure. Execute only with the explicit
human boundary: `prj226-runner run task-packet.json --authorize`.

The packet schema is [schemas/task-packet.schema.json](schemas/task-packet.schema.json).
Provider executables and models are configured only in `runner.toml`; they are
never accepted from a packet. Runtime evidence is immutable under the configured
external `runtime_root`. The runner never retries, repairs, merges, rebases,
cherry-picks, canonicalizes, or pushes a product repository.

HARN-002 Repair-4 binds the independent Security / Operability / Semantics /
Architecture reviewer to Codex CLI / OpenAI / `gpt-5.6-luna`. Its lifecycle is
deterministic local preflight → exactly one ordinary `codex exec` semantic
review → deterministic local postflight. The invocation is ephemeral,
read-only, isolated from user config and rules, and constrained by the closed
[Codex reviewer result schema](schemas/codex-reviewer-result.schema.json).
Provider failures stop without retry or fallback. Runner Git checks and a
path-sorted filesystem fingerprint bind the verifier worktree before and after
review, including ignored files, empty directories, symlinks, and modes.
Reviewer claims never authorize a candidate transition.

## HARN-002 single-project controller

HARN-002 adds a manifest-driven, read-only project inspection and next-work
discovery layer above Runner V1. It drafts a closed Design Contract, waits for
exact Human Gate A binding, derives the existing HARN-001 Task Packet, ingests
exact candidate/reviewer evidence, and stops at Human Gate B before canonical
integration. `ACCEPTANCE_READY` is accepted only with complete deterministic
Runner evidence, an exact candidate, a complete validated closed review
artifact, and matching pre/post worktree fingerprints. See [AI Agent Harness
Vision and Operating Model V2](AI_AGENT_HARNESS_VISION_AND_OPERATING_MODEL_V2.md)
and the contracts in `schemas/project-manifest.schema.json`,
`schemas/design-contract.schema.json`, `schemas/controller-state.schema.json`,
and `schemas/controller-result.schema.json`.

The smallest CLI commands are `inspect-project`, `discover-work`,
`draft-contract`, `derive-task-packet`, `ingest-result`, `prepare-gate-b`, and
`resume`. Controller state stores only orchestration facts; it never copies
project source, logs, or Git history.

Repair-5 closes the final pre-qualification trust boundary. Worktree
fingerprints fail closed on unsupported filesystem nodes, review artifacts are
hashed and validated from one no-follow byte snapshot, and `prepare-gate-b`
emits a deterministic evidence package. Canonical integration requires a
fresh six-field Human Gate-B authorization bound to that package; the
authorization is consumed by an exclusive attempt claim and is never a push
authorization. Use-time validation repeats the evidence, baseline, candidate,
and protected-worktree checks under the integration lock.
