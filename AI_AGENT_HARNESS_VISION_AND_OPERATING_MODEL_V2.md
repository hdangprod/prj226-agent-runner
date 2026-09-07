# AI Agent Harness Vision and Operating Model V2

## Purpose

HARN-002 is a single-project, human-gated control loop over the existing
HARN-001 Runner. Git and the target project's canonical documents remain the
source of truth; controller state is only a resumable orchestration cursor.

## Governed lifecycle

```text
project Git/docs inspection
  -> canonical next-work discovery
  -> deterministic work classification
  -> Design Contract proposal
  -> HUMAN_GATE_A
  -> exact HARN-001 Task Packet
  -> isolated Runner execution and frozen candidate
  -> exact result/review binding
  -> ACCEPTANCE_READY / HUMAN_GATE_B
  -> explicitly authorized integration and post-integration verification
  -> fresh project discovery
```

The controller has no multi-project scheduler, queue, background worker,
provider router, fallback, retry, repair, automatic merge, or push path.

## Authority and evidence

Gate A binds the Design Contract identity, baseline HEAD, and baseline TREE.
The derived Task Packet cannot add paths, criteria, tests, or authority. Human
dirty paths are captured before drafting and cannot be silently absorbed.
Candidate HEAD and TREE are immutable bindings for result and reviewer
evidence. A stale baseline, stale review, conflicting frontier, widened
packet, or controller/Git disagreement stops with a governance blocker.

Gate B is mandatory before canonical integration. Development qualification
ends before Gate B; no candidate is canonical merely because it reached
`ACCEPTANCE_READY`.

## Failure separation

The runner preserves the distinction between environment failure, agent
execution failure, artifact validation failure, implementation failure, and
governance blockage. No category authorizes an implicit retry, fallback, or
repair.
