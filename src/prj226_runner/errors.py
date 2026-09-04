"""Typed exception hierarchy mapped to ErrorClass categories."""

from __future__ import annotations

from prj226_runner.models import ErrorClass


class RunnerError(Exception):
    """Base exception for all runner errors."""

    error_class: ErrorClass = ErrorClass.ENVIRONMENT_ERROR

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RunnerEnvironmentError(RunnerError):
    """Raised when external tooling, binaries, or runtime environment fail."""

    error_class = ErrorClass.ENVIRONMENT_ERROR


class AgentExecutionError(RunnerError):
    """Raised when an external agent invocation crashes or times out."""

    error_class = ErrorClass.AGENT_EXECUTION_ERROR


class ArtifactValidationError(RunnerError):
    """Raised when an artifact or result JSON violates its schema contract."""

    error_class = ErrorClass.ARTIFACT_VALIDATION_ERROR


class ImplementationFailureError(RunnerError):
    """Raised when candidate code fails deterministic tests or verification checks."""

    error_class = ErrorClass.IMPLEMENTATION_FAILURE


class GovernanceBlockerError(RunnerError):
    """Raised when a governance invariant, human gate, or permission boundary is breached."""

    error_class = ErrorClass.GOVERNANCE_BLOCKER


class ReviewStaleError(GovernanceBlockerError):
    """Raised when review evidence or candidate Git truth is no longer exact."""
