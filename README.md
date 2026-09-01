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

Runner configuration is defined in TOML (parsed using Python standard-library `tomllib`). See `config/runner.example.toml` for configurable parameters including target repository location, canonical branch, baseline verification hashes, and tool/model bindings.
