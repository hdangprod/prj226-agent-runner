"""Core models and enumerations for prj226-agent-runner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class RunState(str, Enum):
    """Lifecycle state definitions for an orchestration run."""

    CREATED = "CREATED"
    PREFLIGHT = "PREFLIGHT"
    HUMAN_AUTHORIZED = "HUMAN_AUTHORIZED"
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


class WorkShape(str, Enum):
    """The only work classifications accepted by HARN-002."""

    SPIKE = "SPIKE"
    BOUNDED = "BOUNDED"
    ARCHITECTURAL = "ARCHITECTURAL"


class ReviewMode(str, Enum):
    """Versioned V2 review-mode selection. Exactly NONE or TARGETED."""

    NONE = "NONE"
    TARGETED = "TARGETED"


class ReviewStatus(str, Enum):
    """Versioned V2 review outcome. Exactly four values, no fifth status."""

    NOT_REQUIRED = "NOT_REQUIRED"
    PASS = "PASS"
    NEEDS_FIX = "NEEDS_FIX"
    EXECUTION_FAILURE = "EXECUTION_FAILURE"


class ControllerPhase(str, Enum):
    """Explicit HARN-002 controller cursor phases."""

    PROJECT_DISCOVERY = "PROJECT_DISCOVERY"
    TASK_DISCOVERY = "TASK_DISCOVERY"
    WORK_CLASSIFICATION = "WORK_CLASSIFICATION"
    CONTRACT_DRAFT = "CONTRACT_DRAFT"
    WAITING_HUMAN_GATE_A = "WAITING_HUMAN_GATE_A"
    EXECUTION_PREP = "EXECUTION_PREP"
    RUNNER_ACTIVE = "RUNNER_ACTIVE"
    RESULT_INGESTION = "RESULT_INGESTION"
    ACCEPTANCE_READY = "ACCEPTANCE_READY"
    WAITING_HUMAN_GATE_B = "WAITING_HUMAN_GATE_B"
    CANONICAL_INTEGRATION = "CANONICAL_INTEGRATION"
    POST_INTEGRATION_VERIFY = "POST_INTEGRATION_VERIFY"
    STOPPED = "STOPPED"


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
