"""PRJ226 Agent Runner OpenHands Execution Adapter Contracts and Types.

Provides immutable contracts for OpenHands execution requests, results,
pinned runtime versions, and failure classifications.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Optional

# Qualified pinned package versions (OH-Q001 accepted authority)
OPENHANDS_AGENT_SERVER_VERSION = "1.47.0"
OPENHANDS_SDK_VERSION = "1.47.0"
OPENHANDS_TOOLS_VERSION = "1.47.0"
AGENT_CLIENT_PROTOCOL_VERSION = "0.10.1"
CODEX_ACP_VERSION = "1.10.0"
CODEX_VERSION = "0.153.3"
JS_ACP_SDK_VERSION = "1.4.0"

DEFAULT_PROVIDER_ROUTE = "NATIVE_CHATGPT_BUILTIN_DEFAULT"
DEFAULT_MODEL = "gpt-5.6-luna"

# Qualified OH-Q001 component hashes
QUALIFIED_CODEX_ACP_SHA256 = "1339ba533c8f1a4f8beadcd2685f93ff29d68ac62de71786e9631fefb7c7247e"
QUALIFIED_BOOTSTRAP_SERVER_SHA256 = "5216a8d2c4395196d0d9e70e5aa9d8440c32363ec5cea90994e5220bc2258079"
QUALIFIED_ACP_ENFORCEMENT_SHA256 = "5c670c00b9c04d4e6fb5cff84b960c7fd50d239c18d25ef35be542929b79fda1"
QUALIFIED_SITECUSTOMIZE_SHA256 = "687db7fa972bfdcc3f73c0782360955a449e167532e1050e0745fd3efbb38398"


@dataclass(frozen=True)
class ExpectedCandidateAuthority:
    """Expected candidate authority metadata for strict multi-vector validation."""
    expected_worktree_path: Path
    expected_candidate_ref: str
    expected_common_dir: Path
    expected_base_head: str
    expected_contract_hash: str


@dataclass(frozen=True)
class OpenHandsExecutionRequest:
    """Carries exact Runner-owned authority and execution requirements for one turn."""
    run_id: str
    task_id: str
    candidate_worktree: Path
    requested_model: str
    prompt: str
    timeout_seconds: float
    isolated_home: Path
    isolated_codex_home: Path
    contract_digest: str
    acp_command: List[str]
    server_executable: str
    expected_authority: ExpectedCandidateAuthority
    server_port: int = 0
    expected_acp_sha256: Optional[str] = None
    expected_server_sha256: Optional[str] = None
    server_env: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate request invariants before execution."""
        from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError

        if not self.run_id or not isinstance(self.run_id, str):
            raise ArtifactValidationError("run_id must be a non-empty string")
        if not self.task_id or not isinstance(self.task_id, str):
            raise ArtifactValidationError("task_id must be a non-empty string")
        if not self.candidate_worktree or not isinstance(self.candidate_worktree, Path):
            raise ArtifactValidationError("candidate_worktree must be a Path")
        resolved = self.candidate_worktree.resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise ArtifactValidationError(f"candidate_worktree does not exist: {self.candidate_worktree}")
        if not self.requested_model or not isinstance(self.requested_model, str):
            raise ArtifactValidationError("requested_model must be a non-empty string")
        if not self.prompt or not isinstance(self.prompt, str):
            raise ArtifactValidationError("prompt must be a non-empty string")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ArtifactValidationError(f"timeout_seconds must be positive: {self.timeout_seconds}")

        # Cryptographic contract digest check: lowercase 64-hex SHA-256
        if not self.contract_digest or not isinstance(self.contract_digest, str):
            raise GovernanceBlockerError("contract_digest must be a 64-character lowercase hex SHA-256")
        if len(self.contract_digest) != 64 or not all(c in "0123456789abcdef" for c in self.contract_digest):
            raise GovernanceBlockerError(f"contract_digest is not a valid 64-character lowercase hex SHA-256: {self.contract_digest}")

        # Mandatory candidate authority
        if not self.expected_authority or not isinstance(self.expected_authority, ExpectedCandidateAuthority):
            raise GovernanceBlockerError("expected_authority is mandatory for OpenHands execution")

        # Explicitly validate qualified ACP command: check original path before resolve()
        if not self.acp_command or not isinstance(self.acp_command, list) or len(self.acp_command) == 0:
            raise GovernanceBlockerError("acp_command must be an explicit non-empty list of arguments")
        raw_acp_path = Path(self.acp_command[0])
        if not raw_acp_path.is_absolute():
            raise GovernanceBlockerError(f"acp_command[0] must be an absolute path: {raw_acp_path}")
        exec_path = raw_acp_path.resolve()
        if not exec_path.exists():
            raise GovernanceBlockerError(f"acp_command[0] executable not found: {exec_path}")
        if not os.access(str(exec_path), os.X_OK):
            raise GovernanceBlockerError(f"acp_command[0] is not executable: {exec_path}")
        if self.expected_acp_sha256:
            import hashlib
            actual_acp_sha = hashlib.sha256(exec_path.read_bytes()).hexdigest()
            if actual_acp_sha != self.expected_acp_sha256:
                raise GovernanceBlockerError(
                    f"BLOCK_OPENHANDS_RUNTIME_AUTHORITY_MISSING: ACP executable SHA-256 mismatch (expected {self.expected_acp_sha256}, got {actual_acp_sha})"
                )

        # Explicitly validate server executable
        if not self.server_executable or not isinstance(self.server_executable, str):
            raise GovernanceBlockerError("BLOCK_OPENHANDS_RUNTIME_AUTHORITY_MISSING: server_executable is required")
        raw_srv_path = Path(self.server_executable)
        if not raw_srv_path.is_absolute():
            raise GovernanceBlockerError(f"server_executable must be an absolute path: {raw_srv_path}")
        srv_path = raw_srv_path.resolve()
        if not srv_path.exists():
            raise GovernanceBlockerError(f"server_executable not found: {srv_path}")
        if not os.access(str(srv_path), os.X_OK):
            raise GovernanceBlockerError(f"server_executable is not executable: {srv_path}")
        if self.expected_server_sha256:
            import hashlib
            actual_srv_sha = hashlib.sha256(srv_path.read_bytes()).hexdigest()
            if actual_srv_sha != self.expected_server_sha256:
                raise GovernanceBlockerError(
                    f"BLOCK_OPENHANDS_RUNTIME_AUTHORITY_MISSING: Server executable SHA-256 mismatch (expected {self.expected_server_sha256}, got {actual_srv_sha})"
                )


@dataclass(frozen=True)
class OpenHandsExecutionResult:
    """Authoritative result of executing one agent turn through OpenHands."""
    conversation_uuid: str
    requested_model: str
    submitted_model: str
    configured_model: Optional[str]
    observable_effective_model: Optional[str]
    model_evidence_source: Optional[str]
    configured_provider_route: str
    configured_provider_raw: Optional[str]
    remote_effective_provider: str
    remote_effective_provider_evidence_source: Optional[str]
    terminal_execution_state: str
    create_dispatch_count: int
    prompt_dispatch_count: int
    run_dispatch_count: int
    turn_start_count: int
    actual_permission_request_count: int
    permission_request_count: int
    client_dispatch_retry_count: int = 0
    configured_retry_policy: str = "FORBIDDEN"
    observed_retry_count: Optional[int] = None
    configured_fallback_policy: str = "FORBIDDEN"
    observed_fallback_count: Optional[int] = None
    title_count: int = 0
    reviewer_count: int = 0
    subagent_count: int = 0
    runtime_attestation_passed: bool = False
    runtime_identity_conflict: bool = False
    quiescence_passed: bool = False
    remaining_process_count: int = 0
    events_path: Optional[Path] = None
    ledger_path: Optional[Path] = None
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        """Predicate checking if execution completed successfully under all governance invariants."""
        return (
            self.terminal_execution_state == "COMPLETED"
            and self.observable_effective_model is not None
            and self.observable_effective_model == self.requested_model
            and self.actual_permission_request_count == 0
            and self.permission_request_count == 0
            and self.create_dispatch_count == 1
            and self.prompt_dispatch_count == 1
            and self.run_dispatch_count == 1
            and self.turn_start_count == 1
            and self.client_dispatch_retry_count == 0
            and self.runtime_attestation_passed is True
            and self.quiescence_passed is True
            and self.remaining_process_count == 0
            and not self.runtime_identity_conflict
            and self.title_count == 0
            and self.reviewer_count == 0
            and self.subagent_count == 0
            and self.error is None
        )
