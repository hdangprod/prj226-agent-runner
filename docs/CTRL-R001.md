# CTRL-R001 durable controller core

This increment adds a local, single-writer controller over an existing frozen
V3 Design Contract. It does not select arbitrary new product work or invoke a
real provider. Fakes live only in `tests/test_control.py`. The fake builder runs
the existing Runner against disposable Git fixtures and fake executables, so
result ingestion exercises actual candidate/evidence validation.

## Authority and state

The kernel follows START → DISCOVERY → PLANNING → Gate A → EXECUTION_PREP →
RUNNER_ACTIVE → RESULT_INGESTION → PLANNER_ASSESSMENT → Gate B →
CANONICAL_INTEGRATION_PREP → COMPLETE. Failure produces terminal BLOCKED.
COMPLETE means **integration preparation only**. No integration API is called.

Planner actions are PROPOSE_TASK, PREPARE_GATE_B, and BLOCK, each bound to the
exact controller, task, revision, phase, and context digest. They do not carry
commands, profiles, scope changes, or authorization. The standalone decision
schema serves future structured-output adapters; typed Python and closed
validators cover internal artifacts without adding redundant schemas.

The controller starts from one already-frozen task contract. DISCOVERY validates
that binding and baseline; goal decomposition and canonical frontier discovery
are CTRL-R002 work. Gate A permits one execution; Gate B permits preparation
only. Questions, original gate revision, complete bindings, literal response,
and resulting authorization are journaled. Replies require gate ID, revision,
binding digest, and literal `approve` or `deny`. Replays and stale replies fail.
Human origin is a trusted local CLI input, not authenticated Antigravity identity.

Only the planner and builder protocol implementations are injected. No provider
loader, plugin system, native Antigravity callback, or real adapter is included.
Builder input is frozen serialized data; output is a closed receipt pointing
to the exact Runner report. The kernel independently ingests it through the
existing V3 validator. In-process adapters are trusted code, not a sandbox for
hostile Python. Worker process/OS isolation belongs to CTRL-R002.

## Persistence and recovery

Each fresh session directory contains an immutable contract, an append-only
`events.ndjson`, atomic `state.json`, a local flock writer lock, and immutable
context/action/packet/package artifacts. The event hash chain and sequential
revisions detect inconsistent records; they are not signatures or protection
against an attacker who can rewrite the entire evidence root. Keep that root
under Runner ownership and outside the canonical repository.

Events contain validated state snapshots, are fsynced before publishing the
state cache, and have corresponding directory fsyncs. A missing or lagging
cache is reconstructible from complete events. Conflicting snapshots, malformed
records, and partial journals block without deletion or truncation. Interrupted
temporary files are retained. Historical runs are never imported or rewritten.

Every planner/builder call has a durable PREPARED claim, then a durable STARTED
record that consumes its invocation budget before calling the adapter. A
PREPARED claim can continue; STARTED with a valid immutable completion can be
ingested without another call. STARTED without completion is ambiguous and
blocks. A crash before actual invocation can therefore consume an attempt.
This conservative boundary prevents accidental replay, rather than promising
transparent recovery of every interrupted process.

Retry and fallback budgets are zero. Builder budget is one; planner default is
two, bounded at sixteen. Planner calls occur only at PLANNING and
PLANNER_ASSESSMENT. Persistence, verification, gate handling, reconciliation,
reporting, and mechanical transitions use no planner calls.

## Context and reports

Normal context is at most 32 KiB; separately supplied UTF-8 semantic attachments
are at most 64 KiB. Context records included/omitted sections, exact byte count,
and digest. Attachment digests bind their content into normal context. Missing
required evidence or oversized content blocks; it is never silently truncated.
The current loop assesses validated evidence summaries. It does not claim that
its planner performed a source-level review or replace frozen TARGETED review.

Reports expose RUNNING, HUMAN_GATE_REQUIRED, BLOCKED, or COMPLETE, plus task,
phase, gate details, verification, candidate, counters, and completion limits.
Token usage remains null. No environment variables, credentials, provider
configuration, or raw terminal logs are copied into controller state. Callers
must not place secrets into goal or rationale text.

## Host-facing CLI

```
prj226-runner control start --session PATH --id ID --goal TEXT \
  --contract V3_CONTRACT --planner-profile PROFILE --builder-profile PROFILE
prj226-runner control status --session PATH [--json]
prj226-runner control wait --session PATH [--timeout 30] [--json]
prj226-runner control reply --session PATH --gate-id ID --revision N \
  --binding-digest DIGEST --response approve
prj226-runner control resume --session PATH [--json]
```

Start creates durable state. Reply persists authorization but does not dispatch.
Resume advances safe deterministic steps and pauses when a required adapter is
not configured; the shipping CLI has no real adapters. Status/wait are observers,
and wait never resumes work. Wait is bounded to sixty seconds per call. Exit
codes follow M2: 0 success/running, 2 argparse usage, 10 human gate, 20 blocker.
CTRL-R002 will let the host carry exact bindings without human hash copying and
qualify real planner/builder execution, detached workers, and human attribution.

## Verification

The focused suite covers protocol rejection, crash/claim recovery, lock
exclusion, gate replay, authority isolation, budgets, context limits, CLI,
reports, and a full offline lifecycle preserving canonical HEAD. Run it first,
then `test_openhands_adapter.py`, then all existing `test_*.py` tests with
unittest's fail-fast flag. No live model/provider qualification or ENG-012
execution is authorized by CTRL-R001.
