"""Core models and enumerations for prj226-agent-runner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class RunState(str, Enum):
    """Lifecycle state definitions for an orchestration run."""

    CREATED = "CREATED"
    BASELINE_VERIFIED = "BASELINE_VERIFIED"
    PLANNING_RUNNING = "PLANNING_RUNNING"
    PLANNING_COMPLETE = "PLANNING_COMPLETE"
    PLAN_REVIEW_RUNNING = "PLAN_REVIEW_RUNNING"
    PLAN_READY = "PLAN_READY"
    HUMAN_GATE = "HUMAN_GATE"
    DISPATCH_READY = "DISPATCH_READY"
    BUILDER_RUNNING = "BUILDER_RUNNING"
    CANDIDATE_FROZEN = "CANDIDATE_FROZEN"
    DETERMINISTIC_GATES = "DETERMINISTIC_GATES"
    DV_RUNNING = "DV_RUNNING"
    DV_PASS = "DV_PASS"
    SOS_RUNNING = "SOS_RUNNING"
    SOS_PASS = "SOS_PASS"
    ACCEPTANCE_READY = "ACCEPTANCE_READY"
    STOPPED = "STOPPED"


class ErrorClass(str, Enum):
    """Failure classification taxonomy for deterministic state handling."""

    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    AGENT_EXECUTION_ERROR = "AGENT_EXECUTION_ERROR"
    ARTIFACT_VALIDATION_ERROR = "ARTIFACT_VALIDATION_ERROR"
    IMPLEMENTATION_FAILURE = "IMPLEMENTATION_FAILURE"
    GOVERNANCE_BLOCKER = "GOVERNANCE_BLOCKER"


@dataclass(frozen=True)
class AgentConfig:
    """Configuration binding for a single role agent."""

    tool: str
    model: str
    timeout_seconds: int = 300


@dataclass(frozen=True)
class RunManifest:
    """Immutable identity and configuration snapshot for an orchestration run."""

    run_id: str
    task: str
    created_at: str
    runner_version: str
    repo_path: str
    canonical_branch: str
    expected_head: str
    expected_tree: str
    phase: str
    agents: Mapping[str, AgentConfig]


@dataclass(frozen=True)
class RunStateSnapshot:
    """Current state snapshot of an orchestration run."""

    run_id: str
    state: RunState
    updated_at: str
    last_event: str
    stop_reason: str | None = None


@dataclass(frozen=True)
class EventRecord:
    """Append-only audit event log entry."""

    event_id: str
    run_id: str
    timestamp: str
    event_type: str
    from_state: RunState | None
    to_state: RunState | None
    payload: Mapping[str, Any]
