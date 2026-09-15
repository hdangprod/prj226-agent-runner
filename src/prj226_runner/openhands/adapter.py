"""PRJ226 OpenHands Execution Adapter V1.

Implements the single-turn execution boundary:
1. Validates Runner-owned candidate worktree authority across all expected vectors.
2. Dynamically allocates loopback port and starts supervised server with anonymous key pipe.
3. Dispatches single agent turn via OpenHandsExactlyOnceClient with watermark-based reconciliation.
4. Observes execution events until terminal state or absolute timeout.
5. Authoritatively terminates process boundary and enforces quiescence via libproc & KERN_PROCARGS2.
6. Analyzes structured events with OpenHandsEventClassifier and returns OpenHandsExecutionResult.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, List, Mapping, Optional

from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError
from prj226_runner.openhands.client import OpenHandsExactlyOnceClient
from prj226_runner.openhands.event_classifier import OpenHandsEventClassifier
from prj226_runner.openhands.supervisor import OpenHandsProcessSupervisor
from prj226_runner.openhands.types import (
    DEFAULT_PROVIDER_ROUTE,
    ExpectedCandidateAuthority,
    OpenHandsExecutionRequest,
    OpenHandsExecutionResult,
)


def find_free_loopback_port() -> int:
    """Allocate an ephemeral port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# Dedicated Agent Server runtime directory name under isolated_home.
# Pinned OpenHands Agent Server 1.47.0 Config inspection (read-only):
#   openhands.agent_server.config.Config defines
#     conversations_path: Path = Path("workspace/conversations")  (RELATIVE)
#     workspace_path: Path = Path("workspace/project")            (RELATIVE)
#     bash_events_dir: Path = Path("workspace/bash_events")       (RELATIVE)
#     DEFAULT_CONFIG_PATH = Path("workspace/openhands_agent_server_config.json") (RELATIVE)
#   All relative server-state paths resolve against the server process cwd
#   (plain pathlib relative resolution; no chdir elsewhere in persistence or
#   conversation_service layers which consume config.conversations_path directly).
#   Pinned Config DOES support explicit absolute placement via
#   Config(conversations_path=<absolute>), OH_CONVERSATIONS_PATH env override
#   through load_config(), or /api/init conversations_path override.
#   However the QUAL-001 accepted bootstrap (server/bootstrap_server.py) bypasses
#   load_config()/env/file entirely via `Config(session_api_keys=[...])` with
#   defaults, exposing no clean explicit field through that bootstrap path.
#   Therefore the isolated server cwd is the authoritative isolation mechanism:
#   spawning the server with cwd=<isolated_home>/agent-server-runtime/ guarantees
#   `workspace/conversations/...` materializes under the runtime root, never
#   under the Runner-owned candidate worktree. StartConversationRequest workspace
#   (LocalWorkspace working_dir=candidate, worktree=false) is unchanged.
AGENT_SERVER_RUNTIME_DIR_NAME = "agent-server-runtime"


def _is_same_or_within(path: Path, ancestor: Path) -> bool:
    """Return True if path equals ancestor or is nested inside ancestor."""
    try:
        p = path.resolve()
    except Exception:
        p = Path(os.path.abspath(str(path)))
    try:
        a = ancestor.resolve()
    except Exception:
        a = Path(os.path.abspath(str(ancestor)))
    if p == a:
        return True
    try:
        return p.is_relative_to(a)
    except Exception:
        return False


class OpenHandsExecutionAdapter:
    """Production adapter for executing authorized agent turns through OpenHands."""

    def __init__(self, *, default_timeout: float = 300.0) -> None:
        self.default_timeout = default_timeout

    def _validate_candidate_worktree_authority(self, request: OpenHandsExecutionRequest) -> None:
        """Enforce worktree authority and reject canonical checkout across all authority fields."""
        candidate_dir = request.candidate_worktree.resolve()
        git_target = candidate_dir / ".git"
        if not git_target.exists():
            raise ArtifactValidationError(
                f"Candidate worktree is missing git metadata: {candidate_dir}. "
                "OpenHands adapter requires an already-initialized, Runner-owned candidate worktree."
            )

        # Linked worktrees have .git as a file pointing to gitdir, canonical checkout has .git as a directory
        if git_target.is_dir():
            raise GovernanceBlockerError(
                f"Candidate worktree points to canonical repository directory: {candidate_dir}. "
                "Execution directly in canonical checkout is strictly prohibited."
            )

        res_common = subprocess.run(
            ["git", "-C", str(candidate_dir), "rev-parse", "--git-common-dir"],
            capture_output=True, text=True, check=False,
        )
        if res_common.returncode != 0:
            raise ArtifactValidationError(f"Cannot resolve git-common-dir for candidate: {candidate_dir}")
        common_dir = Path(res_common.stdout.strip()).resolve()

        res_branch = subprocess.run(
            ["git", "-C", str(candidate_dir), "branch", "--show-current"],
            capture_output=True, text=True, check=False,
        )
        current_branch = res_branch.stdout.strip()

        res_head = subprocess.run(
            ["git", "-C", str(candidate_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
        current_head = res_head.stdout.strip()

        if request.expected_authority:
            auth = request.expected_authority
            if candidate_dir != auth.expected_worktree_path.resolve():
                raise GovernanceBlockerError(f"Candidate worktree path mismatch: {candidate_dir} != {auth.expected_worktree_path}")
            if current_branch != auth.expected_candidate_ref:
                raise GovernanceBlockerError(f"Candidate branch ref mismatch: {current_branch} != {auth.expected_candidate_ref}")
            if common_dir != auth.expected_common_dir.resolve():
                raise GovernanceBlockerError(f"Candidate common-dir mismatch: {common_dir} != {auth.expected_common_dir}")
            if current_head != auth.expected_base_head:
                raise GovernanceBlockerError(f"Candidate HEAD does not match expected base HEAD: {current_head} != {auth.expected_base_head}")
            if auth.expected_contract_hash != request.contract_digest:
                raise GovernanceBlockerError(f"Request contract digest mismatch: {request.contract_digest} != {auth.expected_contract_hash}")
            if auth.expected_contract_hash not in current_branch:
                raise GovernanceBlockerError(f"Candidate branch does not bind full contract hash: {current_branch}")

    def _validate_runtime_path_isolation(
        self,
        *,
        candidate_dir: Path,
        isolated_home: Path,
        isolated_codex_home: Path,
        agent_server_runtime_root: Path,
    ) -> None:
        """Fail-closed guard ensuring server state can never alias/nest into candidate.

        Raises GovernanceBlockerError(BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP) before
        any server spawn or dispatch when:
          - isolated_home == candidate_worktree
          - isolated_home inside candidate_worktree
          - isolated_codex_home ==/inside candidate_worktree
          - agent_server_runtime_root ==/inside candidate_worktree
          - candidate_worktree ==/inside agent_server_runtime_root (reverse nesting)
        Must be called BEFORE any filesystem writes under isolated_home and
        BEFORE server spawn so dispatch counts remain 0 on violation.
        """
        candidate = candidate_dir.resolve()
        home = isolated_home.resolve() if isinstance(isolated_home, Path) else Path(str(isolated_home)).resolve()
        codex = isolated_codex_home.resolve() if isinstance(isolated_codex_home, Path) else Path(str(isolated_codex_home)).resolve()
        runtime = (
            agent_server_runtime_root.resolve()
            if isinstance(agent_server_runtime_root, Path)
            else Path(str(agent_server_runtime_root)).resolve()
        )
        if not runtime.is_absolute():
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: agent server runtime root must be absolute: {agent_server_runtime_root}"
            )
        if _is_same_or_within(home, candidate):
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: isolated_home {home} must not equal or nest inside candidate_worktree {candidate}"
            )
        if _is_same_or_within(codex, candidate):
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: isolated_codex_home {codex} must not equal or nest inside candidate_worktree {candidate}"
            )
        if _is_same_or_within(runtime, candidate):
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: agent_server_runtime_root {runtime} must not equal or nest inside candidate_worktree {candidate}"
            )
        if _is_same_or_within(candidate, runtime):
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: candidate_worktree {candidate} must not equal or nest inside agent_server_runtime_root {runtime}"
            )

    def _prepare_agent_server_runtime_root(self, isolated_home: Path) -> Path:
        """Create the dedicated isolated server-runtime directory (outside candidate).

        Layout: <isolated_home>/agent-server-runtime/. Created before server spawn,
        absolute, owned by the current run, mode 0700 where possible, safe to delete
        after process quiescence. Caller must have already passed
        _validate_runtime_path_isolation for the computed path before mkdir to avoid
        polluting the candidate on violation.
        """
        home_resolved = isolated_home.resolve()
        runtime_root = home_resolved / AGENT_SERVER_RUNTIME_DIR_NAME
        if not runtime_root.is_absolute():
            raise GovernanceBlockerError(
                f"BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP: agent server runtime root must be absolute: {runtime_root}"
            )
        runtime_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(runtime_root, 0o700)
        except OSError:
            pass
        return runtime_root

    def execute_turn(self, request: OpenHandsExecutionRequest) -> OpenHandsExecutionResult:
        """Execute one authorized agent turn against OpenHands."""
        request.validate()
        self._validate_candidate_worktree_authority(request)

        candidate_dir = request.candidate_worktree.resolve()
        isolated_home = request.isolated_home
        isolated_codex_home = request.isolated_codex_home
        # Compute dedicated runtime root BEFORE any writes or spawn.
        prospective_runtime_root = isolated_home.resolve() / AGENT_SERVER_RUNTIME_DIR_NAME
        # Fail closed before server spawn and before any dispatch (counts stay 0).
        self._validate_runtime_path_isolation(
            candidate_dir=candidate_dir,
            isolated_home=isolated_home,
            isolated_codex_home=isolated_codex_home,
            agent_server_runtime_root=prospective_runtime_root,
        )
        # Create isolated server-runtime dir before spawn (absolute, outside candidate).
        agent_server_runtime_root = self._prepare_agent_server_runtime_root(isolated_home)

        session_key = secrets.token_hex(32)
        supervisor = OpenHandsProcessSupervisor(
            run_id=request.run_id,
            session_key=session_key,
            isolated_home=request.isolated_home,
            isolated_codex_home=request.isolated_codex_home,
        )

        evidence_dir = request.isolated_home / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = evidence_dir / "client_state_ledger.jsonl"
        events_path = evidence_dir / "raw_conversation_events.json"

        port = request.server_port or find_free_loopback_port()
        server_url = f"http://127.0.0.1:{port}"

        client = OpenHandsExactlyOnceClient(
            base_url=server_url,
            session_api_key=session_key,
            run_id=request.run_id,
            ledger_path=ledger_path,
            timeout=10.0,
        )

        server_spawned = False
        error_msg: Optional[str] = None
        raw_events: List[Mapping[str, Any]] = []
        attestation_passed = False

        try:
            self._materialize_ephemeral_auth(request.isolated_codex_home)

            if request.server_executable:
                cmd = [request.server_executable]
                # R4 isolation: Agent Server cwd is the dedicated runtime dir, NEVER
                # the Runner-owned candidate worktree. Candidate remains ONLY as
                # StartConversationRequest.workspace.working_dir (see below).
                supervisor.spawn_server_with_key_pipe(cmd, port, agent_server_runtime_root, request.server_env)
                server_spawned = True
                self._wait_for_server_ready(server_url, session_key, timeout=30.0)

            # Runtime attestation check: after /ready and BEFORE CREATE_INTENT
            self._verify_runtime_attestation(server_url, session_key, request)
            attestation_passed = True

            # Create conversation with explicit acp_command and requested model
            client.create_conversation(
                candidate_dir,
                acp_command=request.acp_command,
                acp_model=request.requested_model,
            )

            client.send_prompt(request.prompt)
            client.submit_run()

            raw_events = self._observe_turn(client, deadline_seconds=request.timeout_seconds)

        except Exception as exc:
            error_msg = str(exc)
        finally:
            if server_spawned:
                supervisor.terminate_boundary(timeout=5.0)

            quiescence_pass, remaining, inspection_ok = supervisor.verify_process_quiescence(timeout=5.0)
            self._cleanup_ephemeral_auth(request.isolated_codex_home)

        if raw_events:
            events_path.write_text(json.dumps(raw_events, indent=2), encoding="utf-8")

        analysis = OpenHandsEventClassifier.analyze_events(
            raw_events,
            configured_provider_route=DEFAULT_PROVIDER_ROUTE,
        )

        if error_msg:
            if "BLOCK_RUNTIME_ATTESTATION_FAILED" in error_msg:
                term_state = "BLOCKED_RUNTIME_ATTESTATION_FAILED"
            elif "BLOCK_" in error_msg:
                term_state = error_msg.split(":")[0].strip()
            else:
                term_state = f"ERROR: {error_msg}"
        elif not inspection_ok:
            term_state = "BLOCKED_PROCESS_INSPECTION_FAILED"
        elif not quiescence_pass or len(remaining) > 0:
            term_state = "BLOCKED_PROCESS_QUIESCENCE_FAILED"
        else:
            term_state = analysis.terminal_turn_status

        return OpenHandsExecutionResult(
            conversation_uuid=client.conversation_uuid,
            requested_model=request.requested_model,
            submitted_model=request.requested_model,
            configured_model=analysis.configured_model,
            observable_effective_model=analysis.effective_model,
            model_evidence_source=analysis.effective_model_evidence_source,
            configured_provider_route=DEFAULT_PROVIDER_ROUTE,
            configured_provider_raw=None,
            remote_effective_provider=analysis.remote_effective_provider,
            remote_effective_provider_evidence_source=analysis.remote_effective_provider_evidence_source,
            terminal_execution_state=term_state,
            create_dispatch_count=client.create_dispatch_count,
            prompt_dispatch_count=client.prompt_dispatch_count,
            run_dispatch_count=client.run_dispatch_count,
            turn_start_count=analysis.turn_start_count,
            actual_permission_request_count=analysis.actual_permission_request_count,
            permission_request_count=analysis.actual_permission_request_count,
            client_dispatch_retry_count=0,
            configured_retry_policy="FORBIDDEN",
            observed_retry_count=analysis.observed_retry_count,
            configured_fallback_policy="FORBIDDEN",
            observed_fallback_count=analysis.observed_fallback_count,
            title_count=analysis.title_count,
            reviewer_count=analysis.reviewer_count,
            subagent_count=analysis.subagent_count,
            runtime_attestation_passed=attestation_passed,
            runtime_identity_conflict=(analysis.terminal_turn_status == "BLOCKED_MODEL_EVIDENCE_CONFLICT"),
            quiescence_passed=(quiescence_pass and inspection_ok and len(remaining) == 0),
            remaining_process_count=len(remaining),
            events_path=events_path if raw_events else None,
            ledger_path=ledger_path if ledger_path.exists() else None,
            error=error_msg,
        )

    def _materialize_ephemeral_auth(self, isolated_codex_home: Path) -> None:
        """Ephemeral live auth setup modeled after OH-Q001 accepted authority."""
        isolated_codex_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        operator_codex = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
        for fname in ("auth.json", "config.toml", "version.json"):
            src = operator_codex / fname
            if src.exists() and src.is_file() and not src.is_symlink():
                dst = isolated_codex_home / fname
                shutil.copy2(src, dst)
                dst.chmod(0o600)

    def _cleanup_ephemeral_auth(self, isolated_codex_home: Path) -> None:
        """Securely clean up isolated auth material after quiescence."""
        for fname in ("auth.json", "config.toml", "version.json"):
            dst = isolated_codex_home / fname
            if dst.exists():
                try:
                    dst.unlink()
                except OSError:
                    pass

    def _verify_runtime_attestation(self, url: str, session_key: str, request: OpenHandsExecutionRequest) -> None:
        """Enforce strict runtime attestation before creating conversation."""
        req = urllib.request.Request(f"{url}/attestation", headers={"X-Session-API-Key": session_key})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status != 200:
                    raise GovernanceBlockerError(f"BLOCK_RUNTIME_ATTESTATION_FAILED: /attestation returned HTTP {resp.status}")
                raw = resp.read()
                data = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception as exc:
            if isinstance(exc, GovernanceBlockerError):
                raise
            raise GovernanceBlockerError(f"BLOCK_RUNTIME_ATTESTATION_FAILED: Failed to fetch /attestation: {exc}") from exc

        if not isinstance(data, dict):
            raise GovernanceBlockerError("BLOCK_RUNTIME_ATTESTATION_FAILED: /attestation response is not a dictionary")

        if not data.get("sitecustomize_loaded"):
            raise GovernanceBlockerError("BLOCK_RUNTIME_ATTESTATION_FAILED: sitecustomize not loaded in server runtime")

        if not data.get("acp_enforcement_loaded"):
            raise GovernanceBlockerError("BLOCK_RUNTIME_ATTESTATION_FAILED: acp_enforcement shim not loaded in server runtime")

        if data.get("acp_prompt_max_retries") != 0:
            raise GovernanceBlockerError(
                f"BLOCK_RUNTIME_ATTESTATION_FAILED: acp_prompt_max_retries is not 0 (got {data.get('acp_prompt_max_retries')})"
            )

        if request.expected_acp_sha256:
            attested_sha = data.get("acp_executable_sha256")
            if attested_sha and attested_sha != request.expected_acp_sha256:
                raise GovernanceBlockerError(
                    f"BLOCK_RUNTIME_ATTESTATION_FAILED: ACP SHA mismatch: expected {request.expected_acp_sha256}, got {attested_sha}"
                )

    def _wait_for_server_ready(self, url: str, session_key: str, timeout: float = 30.0) -> None:
        start = time.time()
        while time.time() - start < timeout:
            try:
                req = urllib.request.Request(f"{url}/ready", headers={"X-Session-API-Key": session_key})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                time.sleep(0.5)
        raise GovernanceBlockerError(f"OpenHands Agent Server failed to become ready within {timeout}s")

    def _observe_turn(self, client: OpenHandsExactlyOnceClient, deadline_seconds: float) -> List[Mapping[str, Any]]:
        start = time.time()
        while time.time() - start < deadline_seconds:
            events = client.get_events(limit=100)
            analysis = OpenHandsEventClassifier.analyze_events(events)
            if analysis.terminal_turn_status in ("COMPLETED", "BLOCKED_PERMISSION_REQUEST") or "BLOCKED_" in analysis.terminal_turn_status:
                return events
            time.sleep(1.0)
        return client.get_events(limit=100)
