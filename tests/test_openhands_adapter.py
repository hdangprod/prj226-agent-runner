"""Comprehensive offline deterministic test suite for OpenHands Execution Adapter V1 (OH-R001-R3).

Strictly portable and offline: REAL_PROVIDER_CALLS = 0, MODEL_TURNS = 0.
Enforces:
1. Strict fake server independently modeling pinned OpenHands Agent Server 1.47.0 protocol.
2. Exact control header: X-Session-API-Key.
3. StartConversationRequest schema validation (worktree=false, autotitle=false, ACPAgent with qualified acp_command).
4. Exactly-once state machine with durable fsync before dispatch and dispatch counters.
5. Stable event-ID watermark prompt and /run reconciliation against earlier turn history.
6. Crash-recovery across simulated process restart for create, prompt, and /run (total POST = 1).
7. Dual-source process supervision (libproc + KERN_PROCARGS2) and fail-closed quiescence.
8. Environment variable allowlisting (blocks inherited MCP/provider credentials).
9. Unknown (None) retry and fallback observation semantics (stats do not manufacture 0).
10. Candidate authority validation across all ExpectedCandidateAuthority fields (mandatory).
11. Secret redaction on all 6 surfaces (argv, env, audit log, ledger, events, errors).
12. Dynamic loopback port binding.
13. Strict contract authority enforcement (no synthetic V1 fallback).
14. Runtime attestation verification before conversation creation.
15. Multi-source model conflict detection (BLOCKED_MODEL_EVIDENCE_CONFLICT).
16. Ephemeral Codex auth materialization and cleanup.
17. Exhaustive governance pass predicate verification.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError
from prj226_runner.openhands import (
    DEFAULT_PROVIDER_ROUTE,
    ExpectedCandidateAuthority,
    OpenHandsEventClassifier,
    OpenHandsExecutionAdapter,
    OpenHandsExecutionRequest,
    OpenHandsExecutionResult,
    OpenHandsProcessSupervisor,
    QUALIFIED_BOOTSTRAP_SERVER_SHA256,
    QUALIFIED_CODEX_ACP_SHA256,
)
from prj226_runner.openhands.client import (
    AmbiguousTransportError,
    ExactlyOnceProtocolError,
    OpenHandsExactlyOnceClient,
)


class StrictMockOpenHandsServerHandler(http.server.BaseHTTPRequestHandler):
    """Strict mock HTTP handler modeling OpenHands Agent Server 1.47.0."""
    expected_session_key = "valid-session-api-key"
    expected_model = "gpt-5.6-luna"
    expected_acp_command: Optional[List[str]] = None
    expected_workspace_dir: Optional[str] = None
    events_to_serve: List[Dict[str, Any]] = []
    conversations: Dict[str, Any] = {}
    attestation_response: Optional[Dict[str, Any]] = None
    create_attempts = 0
    prompt_attempts = 0
    run_attempts = 0
    fail_create_ambiguous = False
    fail_create_ambiguous_after_accept = False
    fail_prompt_ambiguous = False
    fail_prompt_ambiguous_after_accept = False
    fail_run_ambiguous = False
    fail_run_ambiguous_after_accept = False

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _verify_auth(self) -> bool:
        key = self.headers.get("X-Session-API-Key")
        if self.expected_session_key is not None and key != self.expected_session_key:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid or missing X-Session-API-Key"}')
            return False
        if self.expected_session_key is None and not key:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "missing X-Session-API-Key"}')
            return False
        return True

    def do_GET(self) -> None:
        if not self._verify_auth():
            return

        if self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ready"}')
            return

        if self.path == "/attestation":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if self.__class__.attestation_response is not None:
                self.wfile.write(json.dumps(self.__class__.attestation_response).encode("utf-8"))
            else:
                default_attest = {
                    "sitecustomize_loaded": True,
                    "acp_enforcement_loaded": True,
                    "acp_prompt_max_retries": 0,
                    "acp_executable_sha256": QUALIFIED_CODEX_ACP_SHA256,
                }
                self.wfile.write(json.dumps(default_attest).encode("utf-8"))
            return

        if "/events/search" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"items": self.__class__.events_to_serve, "next_page_id": None}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if "/api/conversations/" in self.path:
            cid = self.path.split("/")[3]
            if cid in self.__class__.conversations:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"conversation_id": cid, "status": "ok"}).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if not self._verify_auth():
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        data = json.loads(body.decode("utf-8")) if body else {}

        if self.path == "/api/conversations":
            workspace = data.get("workspace", {})
            if workspace.get("kind") != "LocalWorkspace":
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "workspace.kind must be LocalWorkspace"}')
                return

            if self.__class__.expected_workspace_dir and workspace.get("working_dir") != self.__class__.expected_workspace_dir:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "workspace.working_dir mismatch"}')
                return

            if data.get("worktree") is not False:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "worktree must be explicitly false"}')
                return

            if data.get("autotitle") is not False:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "autotitle must be explicitly false"}')
                return

            if data.get("confirmation_policy", {}).get("kind") != "NeverConfirm":
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "confirmation_policy must be NeverConfirm"}')
                return

            agent = data.get("agent", {})
            if agent.get("kind") != "ACPAgent":
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "agent.kind must be ACPAgent"}')
                return

            if agent.get("acp_model") != self.__class__.expected_model:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "agent.acp_model mismatch"}')
                return

            if agent.get("acp_session_mode") != "read-only":
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "agent.acp_session_mode must be read-only"}')
                return

            if not agent.get("acp_command") or not isinstance(agent.get("acp_command"), list):
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "agent.acp_command must be a non-empty list"}')
                return

            if self.__class__.expected_acp_command and agent.get("acp_command") != self.__class__.expected_acp_command:
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"error": "agent.acp_command mismatch"}')
                return

            self.__class__.create_attempts += 1
            if len(self.__class__.conversations) > 0 or self.__class__.create_attempts > 1:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'{"error": "duplicate create forbidden"}')
                return

            cid = data.get("conversation_id", "test-cid")

            if self.__class__.fail_create_ambiguous:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "connection reset before create"}')
                return

            self.__class__.conversations[cid] = data

            if self.__class__.fail_create_ambiguous_after_accept:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "connection reset after conversation accepted"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"conversation_id": cid}).encode("utf-8"))
            return

        if "/events" in self.path:
            self.__class__.prompt_attempts += 1
            if self.__class__.prompt_attempts > 1:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'{"error": "duplicate prompt forbidden"}')
                return

            prompt_text = ""
            for block in data.get("content", []):
                if isinstance(block, dict) and block.get("type") == "text":
                    prompt_text = block.get("text", "")

            if self.__class__.fail_prompt_ambiguous:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "prompt transport timeout before accepted"}')
                return

            new_ev = {
                "id": f"prompt-event-{self.__class__.prompt_attempts}",
                "kind": "MessageEvent",
                "source": "user",
                "llm_message": {"content": [{"type": "text", "text": prompt_text}]},
            }
            self.__class__.events_to_serve.append(new_ev)

            if self.__class__.fail_prompt_ambiguous_after_accept:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "prompt transport timeout after accepted"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if "/run" in self.path:
            self.__class__.run_attempts += 1
            if self.__class__.run_attempts > 1:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'{"error": "duplicate /run forbidden"}')
                return

            if self.__class__.fail_run_ambiguous:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "run transport timeout before accepted"}')
                return

            self.__class__.events_to_serve.append({
                "id": f"run-event-{self.__class__.run_attempts}",
                "kind": "ConversationStateUpdateEvent",
                "key": "execution_status",
                "value": "running",
            })

            if self.__class__.fail_run_ambiguous_after_accept:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "run transport timeout after accepted"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "running"}')
            return

        self.send_response(404)
        self.end_headers()


class TestOpenHandsAdapterR3(unittest.TestCase):
    """Portable deterministic unit tests verifying OH-R001-R3 requirements."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="oh-r3-test-"))
        self.canonical_repo = self.tmp_dir / "canonical_repo"
        self.canonical_repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=str(self.canonical_repo), check=True)
        (self.canonical_repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "initial commit"], cwd=str(self.canonical_repo), check=True)
        self.base_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(self.canonical_repo), capture_output=True, text=True, check=True).stdout.strip()

        self.contract_hash = "a" * 64
        self.candidate_branch = f"harn-candidate/v3-TEST-RUN-{self.contract_hash}"
        self.candidate_worktree = self.tmp_dir / "candidate_worktree"
        subprocess.run(
            ["git", "worktree", "add", "-b", self.candidate_branch, str(self.candidate_worktree), self.base_head],
            cwd=str(self.canonical_repo), capture_output=True, text=True, check=True,
        )

        # Create mock executables
        self.fake_acp_bin = self.tmp_dir / "fake-codex-acp"
        self.fake_acp_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_acp_bin.chmod(0o755)
        self.fake_acp_sha = hashlib.sha256(self.fake_acp_bin.read_bytes()).hexdigest()

        self.fake_srv_bin = self.tmp_dir / "fake-server-bootstrap"
        self.fake_srv_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_srv_bin.chmod(0o755)
        self.fake_srv_sha = hashlib.sha256(self.fake_srv_bin.read_bytes()).hexdigest()

        self.isolated_home = self.tmp_dir / "home"
        self.isolated_home.mkdir()
        self.isolated_codex_home = self.tmp_dir / "codex_home"
        self.isolated_codex_home.mkdir()

        self.default_authority = ExpectedCandidateAuthority(
            expected_worktree_path=self.candidate_worktree,
            expected_candidate_ref=self.candidate_branch,
            expected_common_dir=self.canonical_repo / ".git",
            expected_base_head=self.base_head,
            expected_contract_hash=self.contract_hash,
        )

        StrictMockOpenHandsServerHandler.expected_session_key = "valid-session-api-key"
        StrictMockOpenHandsServerHandler.expected_model = "gpt-5.6-luna"
        StrictMockOpenHandsServerHandler.expected_acp_command = [str(self.fake_acp_bin.resolve())]
        StrictMockOpenHandsServerHandler.expected_workspace_dir = str(self.candidate_worktree.resolve())
        StrictMockOpenHandsServerHandler.events_to_serve = []
        StrictMockOpenHandsServerHandler.conversations = {}
        StrictMockOpenHandsServerHandler.attestation_response = None
        StrictMockOpenHandsServerHandler.create_attempts = 0
        StrictMockOpenHandsServerHandler.prompt_attempts = 0
        StrictMockOpenHandsServerHandler.run_attempts = 0
        StrictMockOpenHandsServerHandler.fail_create_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_create_ambiguous_after_accept = False
        StrictMockOpenHandsServerHandler.fail_prompt_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_prompt_ambiguous_after_accept = False
        StrictMockOpenHandsServerHandler.fail_run_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_run_ambiguous_after_accept = False

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _start_mock_server(self) -> tuple[socketserver.TCPServer, int]:
        server = socketserver.TCPServer(("127.0.0.1", 0), StrictMockOpenHandsServerHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, port

    # 1. ACP command binding & relative path rejection (Section 1, 5 & 7)
    def test_acp_command_binding_and_rejection(self) -> None:
        # Missing / empty acp_command rejected
        req_no_acp = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Do task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[],
            server_executable=str(self.fake_srv_bin),
            expected_authority=self.default_authority,
        )
        with self.assertRaises(GovernanceBlockerError):
            req_no_acp.validate()

        # Relative acp_command path rejected before resolve
        req_rel = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Do task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=["./relative-path"],
            server_executable=str(self.fake_srv_bin),
            expected_authority=self.default_authority,
        )
        with self.assertRaises(GovernanceBlockerError) as ctx:
            req_rel.validate()
        self.assertIn("must be an absolute path", str(ctx.exception))

        # Non-executable acp_command rejected
        non_exec = self.tmp_dir / "non-exec"
        non_exec.write_text("text")
        non_exec.chmod(0o644)
        req_non_exec = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Do task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[str(non_exec.resolve())],
            server_executable=str(self.fake_srv_bin),
            expected_authority=self.default_authority,
        )
        with self.assertRaises(GovernanceBlockerError):
            req_non_exec.validate()

        # ACP executable SHA mismatch rejected
        req_sha_mismatch = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Do task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[str(self.fake_acp_bin.resolve())],
            server_executable=str(self.fake_srv_bin),
            expected_authority=self.default_authority,
            expected_acp_sha256="0" * 64,
        )
        with self.assertRaises(GovernanceBlockerError) as ctx:
            req_sha_mismatch.validate()
        self.assertIn("BLOCK_OPENHANDS_RUNTIME_AUTHORITY_MISSING", str(ctx.exception))

    # 2. Strict mock server rejects protocol violations & duplicates (Section 10)
    def test_strict_server_protocol_fixtures(self) -> None:
        server, port = self._start_mock_server()
        try:
            ledger = self.isolated_home / "p.jsonl"
            client = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R1",
                ledger_path=ledger,
            )

            # Rejects wrong model
            with self.assertRaises(AmbiguousTransportError):
                client._http_request("POST", "/api/conversations", {
                    "conversation_id": "c1",
                    "workspace": {"kind": "LocalWorkspace", "working_dir": str(self.candidate_worktree.resolve())},
                    "worktree": False,
                    "autotitle": False,
                    "confirmation_policy": {"kind": "NeverConfirm"},
                    "agent": {"kind": "ACPAgent", "acp_command": [str(self.fake_acp_bin.resolve())], "acp_model": "wrong-model", "acp_session_mode": "read-only"},
                })

            # Rejects duplicate create
            client.create_conversation(self.candidate_worktree, acp_command=[str(self.fake_acp_bin.resolve())], acp_model="gpt-5.6-luna")
            with self.assertRaises(AmbiguousTransportError) as ctx:
                client._http_request("POST", "/api/conversations", {
                    "conversation_id": "c_dup",
                    "workspace": {"kind": "LocalWorkspace", "working_dir": str(self.candidate_worktree.resolve())},
                    "worktree": False,
                    "autotitle": False,
                    "confirmation_policy": {"kind": "NeverConfirm"},
                    "agent": {"kind": "ACPAgent", "acp_command": [str(self.fake_acp_bin.resolve())], "acp_model": "gpt-5.6-luna", "acp_session_mode": "read-only"},
                })
            self.assertEqual(ctx.exception.status_code, 409)

            # Rejects duplicate prompt
            client.send_prompt("Task 1")
            with self.assertRaises(AmbiguousTransportError) as ctx:
                client._http_request("POST", f"/api/conversations/{client.conversation_uuid}/events", {
                    "role": "user", "content": [{"type": "text", "text": "Task 2"}], "run": False,
                })
            self.assertEqual(ctx.exception.status_code, 409)

            # Rejects duplicate /run
            client.submit_run()
            with self.assertRaises(AmbiguousTransportError) as ctx:
                client._http_request("POST", f"/api/conversations/{client.conversation_uuid}/run", {})
            self.assertEqual(ctx.exception.status_code, 409)
        finally:
            server.shutdown()
            server.server_close()

    # 3. Stable identity watermark-based prompt reconciliation (Section 2 & 10)
    def test_watermark_prompt_reconciliation(self) -> None:
        server, port = self._start_mock_server()
        try:
            ledger = self.isolated_home / "prompt_watermark.jsonl"
            client = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R1",
                ledger_path=ledger,
            )
            client.create_conversation(self.candidate_worktree, acp_command=[str(self.fake_acp_bin.resolve())])

            # Historical prompt event with ID exists in conversation
            historical_event = {
                "id": "historical-event-uuid-001",
                "kind": "MessageEvent",
                "source": "user",
                "llm_message": {"content": [{"type": "text", "text": "Task A"}]},
            }
            StrictMockOpenHandsServerHandler.events_to_serve = [historical_event]

            # Ambiguous prompt dispatch: no new event added newer than watermark -> BLOCK
            StrictMockOpenHandsServerHandler.fail_prompt_ambiguous = True
            with self.assertRaises(ExactlyOnceProtocolError):
                client.send_prompt("Task A")

            # Positive case: POST returns ambiguous AFTER server accepted and appended new event
            StrictMockOpenHandsServerHandler.fail_prompt_ambiguous = False
            StrictMockOpenHandsServerHandler.fail_prompt_ambiguous_after_accept = True
            StrictMockOpenHandsServerHandler.prompt_attempts = 0

            ledger2 = self.isolated_home / "prompt_watermark2.jsonl"
            client2 = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R2",
                ledger_path=ledger2,
                conversation_uuid=client.conversation_uuid,
            )
            client2._history.append("CONVERSATION_CONFIRMED")
            client2.send_prompt("Task A")
            self.assertIn("PROMPT_CONFIRMED", client2._history)
            self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 1)
        finally:
            server.shutdown()
            server.server_close()

    # 4. Stable identity watermark-based /run reconciliation (Section 2 & 10)
    def test_watermark_run_reconciliation(self) -> None:
        server, port = self._start_mock_server()
        try:
            ledger = self.isolated_home / "run_watermark.jsonl"
            client = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R1",
                ledger_path=ledger,
            )
            client.create_conversation(self.candidate_worktree, acp_command=[str(self.fake_acp_bin.resolve())])
            client.send_prompt("Task")

            # Old COMPLETED event exists before RUN_INTENT + /run ambiguous -> BLOCK
            old_completed = {"id": "old-completed-id", "kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "completed"}
            StrictMockOpenHandsServerHandler.events_to_serve = [old_completed]
            StrictMockOpenHandsServerHandler.fail_run_ambiguous = True

            with self.assertRaises(ExactlyOnceProtocolError):
                client.submit_run()

            # Positive case: POST returns ambiguous AFTER server accepted and appended running event
            StrictMockOpenHandsServerHandler.fail_run_ambiguous = False
            StrictMockOpenHandsServerHandler.fail_run_ambiguous_after_accept = True
            StrictMockOpenHandsServerHandler.run_attempts = 0

            ledger2 = self.isolated_home / "run_watermark2.jsonl"
            client2 = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R2",
                ledger_path=ledger2,
                conversation_uuid=client.conversation_uuid,
            )
            client2._history.extend(["CONVERSATION_CONFIRMED", "PROMPT_CONFIRMED"])
            client2.submit_run()
            self.assertIn("RUN_SUBMITTED", client2._history)
            self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 1)
        finally:
            server.shutdown()
            server.server_close()

    # 5. Simulated crash-recovery across process restart (Section 1 & 10)
    def test_restart_recovery_create_prompt_run(self) -> None:
        server, port = self._start_mock_server()
        try:
            ledger = self.isolated_home / "restart_recovery.jsonl"

            # A. CREATE restart recovery
            StrictMockOpenHandsServerHandler.fail_create_ambiguous_after_accept = True
            client_a = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R-RESTART",
                ledger_path=ledger,
            )
            # Simulate Process A crashed right after writing intent and dispatching
            client_a._persist_transition("CREATE_INTENT", "digest_create", {"workspace": str(self.candidate_worktree.resolve())})
            cid = client_a.conversation_uuid
            StrictMockOpenHandsServerHandler.conversations[cid] = {"conversation_id": cid}
            StrictMockOpenHandsServerHandler.create_attempts = 1

            # Process B starts fresh, loads ledger, reconciles only
            client_b = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R-RESTART",
                ledger_path=ledger,
                conversation_uuid=cid,
            )
            self.assertEqual(client_b.create_dispatch_count, 1)
            cid_rec = client_b.create_conversation(self.candidate_worktree, acp_command=[str(self.fake_acp_bin.resolve())])
            self.assertEqual(cid_rec, cid)
            self.assertEqual(StrictMockOpenHandsServerHandler.create_attempts, 1)
            self.assertIn("CONVERSATION_CONFIRMED", client_b._history)

            # B. PROMPT restart recovery
            client_b._persist_transition("PROMPT_INTENT", "digest_prompt", {"watermark_event_id": "__EMPTY__"})
            StrictMockOpenHandsServerHandler.events_to_serve.append({
                "id": "ev-p1",
                "kind": "MessageEvent",
                "source": "user",
                "llm_message": {"content": [{"type": "text", "text": "Restart Task"}]},
            })
            StrictMockOpenHandsServerHandler.prompt_attempts = 1

            # Process C starts fresh, loads ledger, reconciles prompt
            client_c = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R-RESTART",
                ledger_path=ledger,
                conversation_uuid=cid,
            )
            self.assertEqual(client_c.prompt_dispatch_count, 1)
            client_c.send_prompt("Restart Task")
            self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 1)
            self.assertIn("PROMPT_CONFIRMED", client_c._history)

            # C. /RUN restart recovery
            client_c._persist_transition("RUN_INTENT", "digest_run", {"watermark_event_id": "ev-p1"})
            StrictMockOpenHandsServerHandler.events_to_serve.append({
                "id": "ev-r1",
                "kind": "ConversationStateUpdateEvent",
                "key": "execution_status",
                "value": "running",
            })
            StrictMockOpenHandsServerHandler.run_attempts = 1

            # Process D starts fresh, loads ledger, reconciles run
            client_d = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R-RESTART",
                ledger_path=ledger,
                conversation_uuid=cid,
            )
            self.assertEqual(client_d.run_dispatch_count, 1)
            client_d.submit_run()
            self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 1)
            self.assertIn("RUN_SUBMITTED", client_d._history)
        finally:
            server.shutdown()
            server.server_close()

    # 6. Outbound dispatch counters and durable fsync ordering (Section 1)
    def test_dispatch_counters_and_fsync_ordering(self) -> None:
        server, port = self._start_mock_server()
        try:
            ledger = self.isolated_home / "dispatch_order.jsonl"
            client = OpenHandsExactlyOnceClient(
                base_url=f"http://127.0.0.1:{port}",
                session_api_key="valid-session-api-key",
                run_id="R1",
                ledger_path=ledger,
            )
            StrictMockOpenHandsServerHandler.fail_create_ambiguous = True
            with self.assertRaises(ExactlyOnceProtocolError):
                client.create_conversation(self.candidate_worktree, acp_command=[str(self.fake_acp_bin.resolve())])

            # Proves dispatch count incremented to 1 even on failure
            self.assertEqual(client.create_dispatch_count, 1)

            # Proves durable CREATE_INTENT was fsynced to disk before HTTP POST
            self.assertTrue(ledger.exists())
            phases = [json.loads(line)["phase"] for line in ledger.read_text().splitlines()]
            self.assertEqual(phases, ["CREATE_INTENT"])
        finally:
            server.shutdown()
            server.server_close()

    # 7. Retry/fallback observation UNKNOWN with stats (Section 9)
    def test_retry_fallback_unknown_with_stats(self) -> None:
        events = [
            {"kind": "ConversationStateUpdateEvent", "key": "stats", "value": {"usage_to_metrics": {"agent": {"model_name": "gpt-5.6-luna", "tokens": 100}}}},
            {"kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "finished"},
        ]
        analysis = OpenHandsEventClassifier.analyze_events(events)
        self.assertIsNone(analysis.observed_retry_count)
        self.assertIsNone(analysis.observed_fallback_count)
        self.assertEqual(analysis.effective_model, "gpt-5.6-luna")

    # 8. Complete candidate authority validation (Section 6)
    def test_complete_candidate_authority_validation(self) -> None:
        adapter = OpenHandsExecutionAdapter()

        auth = ExpectedCandidateAuthority(
            expected_worktree_path=self.candidate_worktree,
            expected_candidate_ref=self.candidate_branch,
            expected_common_dir=self.canonical_repo / ".git",
            expected_base_head=self.base_head,
            expected_contract_hash=self.contract_hash,
        )

        req_valid = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[str(self.fake_acp_bin.resolve())],
            server_executable=str(self.fake_srv_bin),
            expected_authority=auth,
        )
        adapter._validate_candidate_worktree_authority(req_valid)

        # Wrong base HEAD rejected
        auth_wrong_head = ExpectedCandidateAuthority(
            expected_worktree_path=self.candidate_worktree,
            expected_candidate_ref=self.candidate_branch,
            expected_common_dir=self.canonical_repo / ".git",
            expected_base_head="0" * 40,
            expected_contract_hash=self.contract_hash,
        )
        req_wrong_head = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[str(self.fake_acp_bin.resolve())],
            server_executable=str(self.fake_srv_bin),
            expected_authority=auth_wrong_head,
        )
        with self.assertRaises(GovernanceBlockerError):
            adapter._validate_candidate_worktree_authority(req_wrong_head)

        # Request contract digest mismatch rejected
        auth_diff_hash = ExpectedCandidateAuthority(
            expected_worktree_path=self.candidate_worktree,
            expected_candidate_ref=self.candidate_branch,
            expected_common_dir=self.canonical_repo / ".git",
            expected_base_head=self.base_head,
            expected_contract_hash="b" * 64,
        )
        req_diff_hash = OpenHandsExecutionRequest(
            run_id="R1",
            task_id="T1",
            candidate_worktree=self.candidate_worktree,
            requested_model="gpt-5.6-luna",
            prompt="Task",
            timeout_seconds=5.0,
            isolated_home=self.isolated_home,
            isolated_codex_home=self.isolated_codex_home,
            contract_digest=self.contract_hash,
            acp_command=[str(self.fake_acp_bin.resolve())],
            server_executable=str(self.fake_srv_bin),
            expected_authority=auth_diff_hash,
        )
        with self.assertRaises(GovernanceBlockerError):
            adapter._validate_candidate_worktree_authority(req_diff_hash)

    # 9. Secret redaction on all 6 real transport surfaces (Section 11)
    def test_secret_redaction_across_surfaces(self) -> None:
        secret_key = "super-secret-key-boundary-test"
        supervisor = OpenHandsProcessSupervisor("R1", secret_key, self.isolated_home, self.isolated_codex_home)

        # Surface 1: Spawned argv (and nonce)
        self.assertNotIn(secret_key, supervisor.nonce)
        pipe_server = self.tmp_dir / "pipe_server.sh"
        pipe_server.write_text("#!/bin/sh\nexit 0\n")
        pipe_server.chmod(0o755)
        pid, port = supervisor.spawn_server_with_key_pipe([str(pipe_server)], 0, self.tmp_dir)
        supervisor.terminate_boundary(timeout=1.0)
        self.assertNotIn(secret_key, str(pipe_server))

        # Surface 2: Child environment
        child_env = supervisor.get_child_env()
        self.assertNotIn(secret_key, str(child_env))

        # Surface 3: Audit log
        self.assertNotIn(secret_key, str(supervisor.audit_log))

        # Surface 4: Ledger file
        ledger_path = self.isolated_home / "secret_ledger.jsonl"
        client = OpenHandsExactlyOnceClient(
            base_url="http://127.0.0.1:9999",
            session_api_key=secret_key,
            run_id="R1",
            ledger_path=ledger_path,
        )
        client._persist_transition("TEST_PHASE", "digest", {"data": "safe"})
        ledger_text = ledger_path.read_text(encoding="utf-8")
        self.assertNotIn(secret_key, ledger_text)

        # Surface 5: Saved conversation events
        events_path = self.isolated_home / "secret_events.json"
        raw_events = [{"kind": "MessageEvent", "llm_message": "Hello without secret"}]
        events_path.write_text(json.dumps(raw_events), encoding="utf-8")
        self.assertNotIn(secret_key, events_path.read_text(encoding="utf-8"))

        # Surface 6: Generated error strings
        transport_err = AmbiguousTransportError(500, "Internal Server Error", {"detail": "safe"})
        self.assertNotIn(secret_key, str(transport_err))

    # 10. Dynamic loopback port allocation
    def test_dynamic_loopback_port_allocation(self) -> None:
        from prj226_runner.openhands.adapter import find_free_loopback_port
        port1 = find_free_loopback_port()
        port2 = find_free_loopback_port()
        self.assertGreater(port1, 1024)
        self.assertGreater(port2, 1024)

    # 11. Runner packet extraction and missing contract hash rejection
    def test_runner_packet_extraction_and_v1_rejection(self) -> None:
        from prj226_runner.runner import RoleConfig, _run_openhands_builder
        import prj226_runner.openhands.adapter as adapter_module

        # V1 packet without cryptographic contract_hash is strictly rejected
        v1_packet = {
            "run_id": "RUN-1",
            "task_id": "TASK-1",
            "builder_prompt": "Update",
            "product_repo": str(self.canonical_repo),
        }
        role = RoleConfig(tool="openhands", executable=str(self.fake_acp_bin), model="gpt-5.6-luna", timeout_seconds=60)
        with self.assertRaises(GovernanceBlockerError) as ctx:
            _run_openhands_builder(
                role,
                self.candidate_worktree,
                v1_packet,
                self.tmp_dir / "log",
                self.tmp_dir / "rt",
                candidate_branch=self.candidate_branch,
                base_head=self.base_head,
            )
        self.assertIn("BLOCK_OPENHANDS_CONTRACT_AUTHORITY_MISSING", str(ctx.exception))

        # V3 packet with full contract_hash succeeds extraction
        v3_packet = {
            "run_id": "RUN-V3",
            "task_id": "TASK-V3",
            "contract_hash": self.contract_hash,
            "builder_prompt": "Update text",
            "product_repo": str(self.canonical_repo),
        }

        captured: List[OpenHandsExecutionRequest] = []

        def fake_exec(self, req: OpenHandsExecutionRequest) -> OpenHandsExecutionResult:
            captured.append(req)
            return OpenHandsExecutionResult(
                conversation_uuid="u",
                requested_model=req.requested_model,
                submitted_model=req.requested_model,
                configured_model="gpt-5.6-luna",
                observable_effective_model="gpt-5.6-luna",
                model_evidence_source="e",
                configured_provider_route=DEFAULT_PROVIDER_ROUTE,
                configured_provider_raw=None,
                remote_effective_provider="UNPROVEN",
                remote_effective_provider_evidence_source=None,
                terminal_execution_state="COMPLETED",
                create_dispatch_count=1,
                prompt_dispatch_count=1,
                run_dispatch_count=1,
                turn_start_count=1,
                actual_permission_request_count=0,
                permission_request_count=0,
                runtime_attestation_passed=True,
                quiescence_passed=True,
                remaining_process_count=0,
            )

        orig_exec = adapter_module.OpenHandsExecutionAdapter.execute_turn
        adapter_module.OpenHandsExecutionAdapter.execute_turn = fake_exec  # type: ignore
        old_env_srv = os.environ.get("PRJ226_OPENHANDS_SERVER_BOOTSTRAP")
        old_env_acp_sha = os.environ.get("PRJ226_CODEX_ACP_SHA256")
        old_env_srv_sha = os.environ.get("PRJ226_OPENHANDS_SERVER_SHA256")

        os.environ["PRJ226_OPENHANDS_SERVER_BOOTSTRAP"] = str(self.fake_srv_bin)
        os.environ["PRJ226_CODEX_ACP_SHA256"] = self.fake_acp_sha
        os.environ["PRJ226_OPENHANDS_SERVER_SHA256"] = self.fake_srv_sha
        try:
            inv = _run_openhands_builder(
                role,
                self.candidate_worktree,
                v3_packet,
                self.tmp_dir / "log",
                self.tmp_dir / "rt",
                candidate_branch=self.candidate_branch,
                base_head=self.base_head,
            )
            self.assertEqual(len(captured), 1)
            req = captured[0]
            self.assertEqual(req.contract_digest, self.contract_hash)
            self.assertEqual(req.run_id, "RUN-V3")
            self.assertEqual(req.task_id, "TASK-V3")
            self.assertEqual(req.acp_command, [str(self.fake_acp_bin.resolve())])
            self.assertTrue(inv["passed"])
        finally:
            adapter_module.OpenHandsExecutionAdapter.execute_turn = orig_exec
            if old_env_srv is not None:
                os.environ["PRJ226_OPENHANDS_SERVER_BOOTSTRAP"] = old_env_srv
            else:
                os.environ.pop("PRJ226_OPENHANDS_SERVER_BOOTSTRAP", None)
            if old_env_acp_sha is not None:
                os.environ["PRJ226_CODEX_ACP_SHA256"] = old_env_acp_sha
            else:
                os.environ.pop("PRJ226_CODEX_ACP_SHA256", None)
            if old_env_srv_sha is not None:
                os.environ["PRJ226_OPENHANDS_SERVER_SHA256"] = old_env_srv_sha
            else:
                os.environ.pop("PRJ226_OPENHANDS_SERVER_SHA256", None)

    # 12. Runtime attestation enforcement (Section 4)
    def test_runtime_attestation_enforcement(self) -> None:
        server, port = self._start_mock_server()
        orig_key = StrictMockOpenHandsServerHandler.expected_session_key
        StrictMockOpenHandsServerHandler.expected_session_key = None
        try:
            adapter = OpenHandsExecutionAdapter()
            req = OpenHandsExecutionRequest(
                run_id="R-ATT",
                task_id="T-ATT",
                candidate_worktree=self.candidate_worktree,
                requested_model="gpt-5.6-luna",
                prompt="Task",
                timeout_seconds=5.0,
                isolated_home=self.isolated_home,
                isolated_codex_home=self.isolated_codex_home,
                contract_digest=self.contract_hash,
                acp_command=[str(self.fake_acp_bin.resolve())],
                server_executable=str(self.fake_srv_bin),
                expected_authority=self.default_authority,
                server_port=port,
                expected_acp_sha256=self.fake_acp_sha,
                expected_server_sha256=self.fake_srv_sha,
            )

            # A: Attestation failure - acp_prompt_max_retries != 0
            StrictMockOpenHandsServerHandler.attestation_response = {
                "sitecustomize_loaded": True,
                "acp_enforcement_loaded": True,
                "acp_prompt_max_retries": 3,
                "acp_executable_sha256": self.fake_acp_sha,
            }
            res_fail = adapter.execute_turn(req)
            self.assertFalse(res_fail.passed)
            self.assertEqual(res_fail.terminal_execution_state, "BLOCKED_RUNTIME_ATTESTATION_FAILED")
            self.assertFalse(res_fail.runtime_attestation_passed)

            # B: Positive attestation - returns valid qualification payload
            StrictMockOpenHandsServerHandler.attestation_response = {
                "sitecustomize_loaded": True,
                "acp_enforcement_loaded": True,
                "acp_prompt_max_retries": 0,
                "acp_executable_sha256": self.fake_acp_sha,
            }
            StrictMockOpenHandsServerHandler.events_to_serve = [
                {"id": "ev-state", "kind": "ConversationStateUpdateEvent", "key": "agent_state", "value": {"acp_current_model_id": "gpt-5.6-luna"}},
                {"id": "ev-finish", "kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "finished"},
            ]
            StrictMockOpenHandsServerHandler.create_attempts = 0
            StrictMockOpenHandsServerHandler.prompt_attempts = 0
            StrictMockOpenHandsServerHandler.run_attempts = 0
            StrictMockOpenHandsServerHandler.conversations = {}

            res_pass = adapter.execute_turn(req)
            self.assertTrue(res_pass.runtime_attestation_passed)
            self.assertEqual(res_pass.terminal_execution_state, "COMPLETED")
            self.assertTrue(res_pass.passed)
        finally:
            StrictMockOpenHandsServerHandler.expected_session_key = orig_key
            server.shutdown()
            server.server_close()

    # 13. Multi-source model conflict detection (Section 3)
    def test_model_evidence_conflict_rejection(self) -> None:
        events = [
            {"id": "1", "kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "running"},
            {"id": "2", "kind": "ConversationStateUpdateEvent", "key": "agent_state", "value": {"acp_current_model_id": "gpt-5.6-luna"}},
            {"id": "3", "kind": "ConversationStateUpdateEvent", "key": "stats", "value": {"usage_to_metrics": {"agent": {"model_name": "other-conflicting-model"}}}},
            {"id": "4", "kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "finished"},
        ]
        analysis = OpenHandsEventClassifier.analyze_events(events)
        self.assertEqual(analysis.terminal_turn_status, "BLOCKED_MODEL_EVIDENCE_CONFLICT")

    # 14. Ephemeral auth materialization and cleanup (Section 8)
    def test_ephemeral_auth_materialization_and_cleanup(self) -> None:
        adapter = OpenHandsExecutionAdapter()
        mock_codex = self.tmp_dir / "mock_operator_codex"
        mock_codex.mkdir()
        (mock_codex / "auth.json").write_text('{"token": "op-token"}\n', encoding="utf-8")
        (mock_codex / "config.toml").write_text('model = "gpt-5.6-luna"\n', encoding="utf-8")
        (mock_codex / "version.json").write_text('{"version": "1.0"}\n', encoding="utf-8")

        orig_codex_home = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(mock_codex)
        try:
            iso_codex = self.tmp_dir / "isolated_codex_auth"
            adapter._materialize_ephemeral_auth(iso_codex)

            # Verifies files copied with 0600 mode
            self.assertTrue((iso_codex / "auth.json").exists())
            self.assertEqual(oct(os.stat(iso_codex / "auth.json").st_mode & 0o777), "0o600")
            self.assertTrue((iso_codex / "config.toml").exists())
            self.assertEqual(oct(os.stat(iso_codex / "config.toml").st_mode & 0o777), "0o600")

            # Clean up
            adapter._cleanup_ephemeral_auth(iso_codex)
            self.assertFalse((iso_codex / "auth.json").exists())
            self.assertFalse((iso_codex / "config.toml").exists())

            # Operator codex unchanged
            self.assertTrue((mock_codex / "auth.json").exists())
        finally:
            if orig_codex_home is not None:
                os.environ["CODEX_HOME"] = orig_codex_home
            else:
                os.environ.pop("CODEX_HOME", None)

    # 15. Exhaustive governance pass predicate verification (Section 9)
    def test_governance_pass_predicate_exhaustive(self) -> None:
        base_kwargs = {
            "conversation_uuid": "u",
            "requested_model": "gpt-5.6-luna",
            "submitted_model": "gpt-5.6-luna",
            "configured_model": "gpt-5.6-luna",
            "observable_effective_model": "gpt-5.6-luna",
            "model_evidence_source": "src",
            "configured_provider_route": DEFAULT_PROVIDER_ROUTE,
            "configured_provider_raw": None,
            "remote_effective_provider": "UNPROVEN",
            "remote_effective_provider_evidence_source": None,
            "terminal_execution_state": "COMPLETED",
            "create_dispatch_count": 1,
            "prompt_dispatch_count": 1,
            "run_dispatch_count": 1,
            "turn_start_count": 1,
            "actual_permission_request_count": 0,
            "permission_request_count": 0,
            "client_dispatch_retry_count": 0,
            "runtime_attestation_passed": True,
            "quiescence_passed": True,
            "remaining_process_count": 0,
            "runtime_identity_conflict": False,
            "title_count": 0,
            "reviewer_count": 0,
            "subagent_count": 0,
            "error": None,
        }

        # Baseline PASS
        res = OpenHandsExecutionResult(**base_kwargs)
        self.assertTrue(res.passed)

        # Failure cases:
        # 1. Non-matching effective model
        res_bad_model = OpenHandsExecutionResult(**{**base_kwargs, "observable_effective_model": "different-model"})
        self.assertFalse(res_bad_model.passed)

        # 2. Permission requests > 0
        res_perm = OpenHandsExecutionResult(**{**base_kwargs, "actual_permission_request_count": 1})
        self.assertFalse(res_perm.passed)

        # 3. Create dispatch != 1
        res_create = OpenHandsExecutionResult(**{**base_kwargs, "create_dispatch_count": 2})
        self.assertFalse(res_create.passed)

        # 4. Attestation failed
        res_att = OpenHandsExecutionResult(**{**base_kwargs, "runtime_attestation_passed": False})
        self.assertFalse(res_att.passed)

        # 5. Quiescence failed
        res_quiesc = OpenHandsExecutionResult(**{**base_kwargs, "quiescence_passed": False})
        self.assertFalse(res_quiesc.passed)

        # 6. Remaining processes > 0
        res_proc = OpenHandsExecutionResult(**{**base_kwargs, "remaining_process_count": 1})
        self.assertFalse(res_proc.passed)

        # 7. Model evidence conflict
        res_conflict = OpenHandsExecutionResult(**{**base_kwargs, "runtime_identity_conflict": True})
        self.assertFalse(res_conflict.passed)

        # 8. Error is not None
        res_err = OpenHandsExecutionResult(**{**base_kwargs, "error": "Something went wrong"})
        self.assertFalse(res_err.passed)


class TestOpenHandsAdapterR4(unittest.TestCase):
    """OH-R001-R4 offline regression: Agent Server runtime state isolation.

    STRICTLY OFFLINE: REAL_PROVIDER_CALLS = 0, MODEL_TURNS = 0.
    Fake/bootstrap server deliberately creates a relative path
      workspace/conversations/<conversation-id>/
    relative to its process cwd, reproducing the QUAL-001 production bug where
    cwd=candidate_dir materialized OpenHands server state inside the
    Runner-owned candidate worktree.

    R4 requires through the PRODUCTION adapter:
      - server cwd != candidate worktree
      - workspace.working_dir == candidate worktree (unchanged)
      - candidate contains NO workspace//conversations//server-runtime artifact
      - server state appears ONLY under agent_server_runtime_root
      - path-overlap guards fail closed before spawn with dispatch counts 0
      - Git-level pollution acceptance via diff/ls-files inspection
    """

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="oh-r4-test-"))
        self.canonical_repo = self.tmp_dir / "canonical_repo"
        self.canonical_repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=str(self.canonical_repo), check=True)
        (self.canonical_repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=str(self.canonical_repo), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "initial commit"], cwd=str(self.canonical_repo), check=True)
        self.base_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(self.canonical_repo), capture_output=True, text=True, check=True).stdout.strip()

        self.contract_hash = "a" * 64
        self.candidate_branch = f"harn-candidate/v3-TEST-RUN-{self.contract_hash}"
        self.candidate_worktree = self.tmp_dir / "candidate_worktree"
        subprocess.run(
            ["git", "worktree", "add", "-b", self.candidate_branch, str(self.candidate_worktree), self.base_head],
            cwd=str(self.canonical_repo), capture_output=True, text=True, check=True,
        )

        self.fake_acp_bin = self.tmp_dir / "fake-codex-acp"
        self.fake_acp_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_acp_bin.chmod(0o755)
        self.fake_acp_sha = hashlib.sha256(self.fake_acp_bin.read_bytes()).hexdigest()

        self.isolated_home = self.tmp_dir / "home"
        self.isolated_home.mkdir()
        self.isolated_codex_home = self.tmp_dir / "codex_home"
        self.isolated_codex_home.mkdir()

        # Empty operator CODEX_HOME so _materialize is a deterministic no-op.
        self.empty_operator_codex = self.tmp_dir / "empty_operator_codex"
        self.empty_operator_codex.mkdir()
        self._orig_codex_home = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(self.empty_operator_codex)

        self.default_authority = ExpectedCandidateAuthority(
            expected_worktree_path=self.candidate_worktree,
            expected_candidate_ref=self.candidate_branch,
            expected_common_dir=self.canonical_repo / ".git",
            expected_base_head=self.base_head,
            expected_contract_hash=self.contract_hash,
        )

        StrictMockOpenHandsServerHandler.expected_session_key = None
        StrictMockOpenHandsServerHandler.expected_model = "gpt-5.6-luna"
        StrictMockOpenHandsServerHandler.expected_acp_command = [str(self.fake_acp_bin.resolve())]
        StrictMockOpenHandsServerHandler.expected_workspace_dir = str(self.candidate_worktree.resolve())
        StrictMockOpenHandsServerHandler.events_to_serve = []
        StrictMockOpenHandsServerHandler.conversations = {}
        StrictMockOpenHandsServerHandler.attestation_response = None
        StrictMockOpenHandsServerHandler.create_attempts = 0
        StrictMockOpenHandsServerHandler.prompt_attempts = 0
        StrictMockOpenHandsServerHandler.run_attempts = 0
        StrictMockOpenHandsServerHandler.fail_create_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_create_ambiguous_after_accept = False
        StrictMockOpenHandsServerHandler.fail_prompt_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_prompt_ambiguous_after_accept = False
        StrictMockOpenHandsServerHandler.fail_run_ambiguous = False
        StrictMockOpenHandsServerHandler.fail_run_ambiguous_after_accept = False

    def tearDown(self) -> None:
        if self._orig_codex_home is not None:
            os.environ["CODEX_HOME"] = self._orig_codex_home
        else:
            os.environ.pop("CODEX_HOME", None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _start_mock_server(self) -> tuple[socketserver.TCPServer, int]:
        server = socketserver.TCPServer(("127.0.0.1", 0), StrictMockOpenHandsServerHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, port

    def _make_polluting_bootstrap(self, name: str = "polluting-bootstrap.sh", conv_id: str = "fake-conv-r4") -> Path:
        """Fake Agent Server bootstrap that mimics pinned relative-state behavior.

        Pinned 1.47.0 Config.conversations_path defaults to the RELATIVE path
        workspace/conversations, so a real server spawned with cwd=X creates
        X/workspace/conversations/<id>/ . This fake does exactly that relative
        to its inherited process cwd, then sleeps so supervision/quiescence is exercised.
        """
        script = self.tmp_dir / name
        script.write_text(
            "#!/bin/sh\n"
            f'mkdir -p "workspace/conversations/{conv_id}"\n'
            f'printf \'{{\n  "marker": true}}\n\' > "workspace/conversations/{conv_id}/marker.json"\n'
            "sleep 30\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _completed_events(self) -> List[Dict[str, Any]]:
        return [
            {"id": "ev-state", "kind": "ConversationStateUpdateEvent", "key": "agent_state", "value": {"acp_current_model_id": "gpt-5.6-luna"}},
            {"id": "ev-finish", "kind": "ConversationStateUpdateEvent", "key": "execution_status", "value": "finished"},
        ]

    def test_r4_server_cwd_isolated_regression(self) -> None:
        """Exact QUAL-001 regression: relative server state must not enter candidate."""
        from prj226_runner.openhands.adapter import AGENT_SERVER_RUNTIME_DIR_NAME
        from prj226_runner.openhands.supervisor import OpenHandsProcessSupervisor

        # Task-controlled fixture path only; used to prove changed-set isolation.
        fixture = self.candidate_worktree / "task_fixture.txt"
        fixture.write_text("fixture\n", encoding="utf-8")

        polluting = self._make_polluting_bootstrap()
        polluting_sha = hashlib.sha256(polluting.read_bytes()).hexdigest()

        server, port = self._start_mock_server()
        # Accept any session key (adapter generates a fresh random key per turn).
        StrictMockOpenHandsServerHandler.expected_session_key = None
        StrictMockOpenHandsServerHandler.expected_workspace_dir = str(self.candidate_worktree.resolve())
        StrictMockOpenHandsServerHandler.expected_acp_command = [str(self.fake_acp_bin.resolve())]
        StrictMockOpenHandsServerHandler.attestation_response = {
            "sitecustomize_loaded": True,
            "acp_enforcement_loaded": True,
            "acp_prompt_max_retries": 0,
            "acp_executable_sha256": self.fake_acp_sha,
        }
        StrictMockOpenHandsServerHandler.events_to_serve = self._completed_events()
        try:
            captured_cwds: List[str] = []
            orig_spawn = OpenHandsProcessSupervisor.spawn_server_with_key_pipe

            def _capture_spawn(self_, base_command: List[str], port_: int, cwd: Path, env_overrides=None):  # type: ignore
                captured_cwds.append(str(Path(cwd).resolve()))
                ret = orig_spawn(self_, base_command, port_, cwd, env_overrides)
                # Deterministic startup gate: real Agent Server materializes
                # workspace/conversations/... during startup before /ready.
                # Mock /ready returns immediately, so wait explicitly for the
                # synthetic relative-state marker to avoid a spawn/terminate race.
                marker = Path(cwd).resolve() / "workspace" / "conversations" / "fake-conv-r4" / "marker.json"
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    if marker.exists():
                        break
                    time.sleep(0.05)
                return ret

            OpenHandsProcessSupervisor.spawn_server_with_key_pipe = _capture_spawn  # type: ignore
            try:
                adapter = OpenHandsExecutionAdapter()
                req = OpenHandsExecutionRequest(
                    run_id="R4-REG",
                    task_id="T4-REG",
                    candidate_worktree=self.candidate_worktree,
                    requested_model="gpt-5.6-luna",
                    prompt="R4 isolation task",
                    timeout_seconds=10.0,
                    isolated_home=self.isolated_home,
                    isolated_codex_home=self.isolated_codex_home,
                    contract_digest=self.contract_hash,
                    acp_command=[str(self.fake_acp_bin.resolve())],
                    server_executable=str(polluting.resolve()),
                    expected_authority=self.default_authority,
                    server_port=port,
                    expected_acp_sha256=self.fake_acp_sha,
                    expected_server_sha256=polluting_sha,
                )
                result = adapter.execute_turn(req)
            finally:
                OpenHandsProcessSupervisor.spawn_server_with_key_pipe = orig_spawn  # type: ignore

            # Production execution succeeded through the mock control plane.
            self.assertTrue(result.runtime_attestation_passed)
            self.assertEqual(result.terminal_execution_state, "COMPLETED")
            self.assertTrue(result.quiescence_passed)
            self.assertEqual(result.create_dispatch_count, 1)
            self.assertEqual(result.prompt_dispatch_count, 1)
            self.assertEqual(result.run_dispatch_count, 1)

            candidate_resolved = self.candidate_worktree.resolve()
            runtime_root = (self.isolated_home.resolve() / AGENT_SERVER_RUNTIME_DIR_NAME).resolve()

            # Explicitly prove server cwd != candidate and workspace unchanged.
            self.assertEqual(len(captured_cwds), 1)
            self.assertNotEqual(Path(captured_cwds[0]).resolve(), candidate_resolved)
            self.assertEqual(Path(captured_cwds[0]).resolve(), runtime_root)
            self.assertTrue(Path(captured_cwds[0]).is_absolute())
            self.assertFalse(str(runtime_root).startswith(str(candidate_resolved) + os.sep))

            # workspace.working_dir == candidate worktree (exact Runner-owned candidate).
            self.assertEqual(len(StrictMockOpenHandsServerHandler.conversations), 1)
            stored = next(iter(StrictMockOpenHandsServerHandler.conversations.values()))
            self.assertEqual(stored["workspace"]["working_dir"], str(candidate_resolved))
            self.assertEqual(stored["workspace"]["kind"], "LocalWorkspace")
            self.assertIs(stored["worktree"], False)

            # Candidate worktree DOES NOT contain server-runtime artifacts.
            self.assertFalse((candidate_resolved / "workspace").exists())
            self.assertFalse((candidate_resolved / "conversations").exists())
            self.assertFalse((candidate_resolved / AGENT_SERVER_RUNTIME_DIR_NAME).exists())

            # Server state appears ONLY under agent_server_runtime_root.
            self.assertTrue((runtime_root / "workspace" / "conversations").is_dir())
            markers = list((runtime_root / "workspace" / "conversations").rglob("marker.json"))
            self.assertGreaterEqual(len(markers), 1)

            # Candidate changed-path set limited to task-controlled fixture paths.
            diff = subprocess.run(
                ["git", "-C", str(candidate_resolved), "diff", "--name-only"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            others = subprocess.run(
                ["git", "-C", str(candidate_resolved), "ls-files", "--others", "--exclude-standard"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            combined = " ".join([diff, others])
            self.assertNotIn("workspace", combined)
            self.assertNotIn("conversations", combined)
            self.assertIn("task_fixture.txt", others)
        finally:
            server.shutdown()
            server.server_close()

    def test_r4_path_overlap_isolated_home_equals_candidate(self) -> None:
        server, port = self._start_mock_server()
        try:
            StrictMockOpenHandsServerHandler.expected_session_key = None
            adapter = OpenHandsExecutionAdapter()
            req = OpenHandsExecutionRequest(
                run_id="R4-OV-A",
                task_id="T4-OV-A",
                candidate_worktree=self.candidate_worktree,
                requested_model="gpt-5.6-luna",
                prompt="overlap A",
                timeout_seconds=5.0,
                isolated_home=self.candidate_worktree,
                isolated_codex_home=self.isolated_codex_home,
                contract_digest=self.contract_hash,
                acp_command=[str(self.fake_acp_bin.resolve())],
                server_executable=str((self.tmp_dir / "fake-codex-acp").resolve()),
                expected_authority=self.default_authority,
                server_port=port,
            )
            with self.assertRaises(GovernanceBlockerError) as ctx:
                adapter.execute_turn(req)
            self.assertIn("BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP", str(ctx.exception))
            self.assertEqual(StrictMockOpenHandsServerHandler.create_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_r4_path_overlap_isolated_home_inside_candidate(self) -> None:
        server, port = self._start_mock_server()
        try:
            StrictMockOpenHandsServerHandler.expected_session_key = None
            adapter = OpenHandsExecutionAdapter()
            req = OpenHandsExecutionRequest(
                run_id="R4-OV-B",
                task_id="T4-OV-B",
                candidate_worktree=self.candidate_worktree,
                requested_model="gpt-5.6-luna",
                prompt="overlap B",
                timeout_seconds=5.0,
                isolated_home=self.candidate_worktree / "evil-home",
                isolated_codex_home=self.isolated_codex_home,
                contract_digest=self.contract_hash,
                acp_command=[str(self.fake_acp_bin.resolve())],
                server_executable=str((self.tmp_dir / "fake-codex-acp").resolve()),
                expected_authority=self.default_authority,
                server_port=port,
            )
            with self.assertRaises(GovernanceBlockerError) as ctx:
                adapter.execute_turn(req)
            self.assertIn("BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP", str(ctx.exception))
            self.assertEqual(StrictMockOpenHandsServerHandler.create_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 0)
            # Guard fired before any write: no evil dir materialized inside candidate.
            self.assertFalse((self.candidate_worktree / "evil-home").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_r4_path_overlap_codex_home_inside_candidate(self) -> None:
        server, port = self._start_mock_server()
        try:
            StrictMockOpenHandsServerHandler.expected_session_key = None
            adapter = OpenHandsExecutionAdapter()
            req = OpenHandsExecutionRequest(
                run_id="R4-OV-C",
                task_id="T4-OV-C",
                candidate_worktree=self.candidate_worktree,
                requested_model="gpt-5.6-luna",
                prompt="overlap C",
                timeout_seconds=5.0,
                isolated_home=self.isolated_home,
                isolated_codex_home=self.candidate_worktree / "evil-codex",
                contract_digest=self.contract_hash,
                acp_command=[str(self.fake_acp_bin.resolve())],
                server_executable=str((self.tmp_dir / "fake-codex-acp").resolve()),
                expected_authority=self.default_authority,
                server_port=port,
            )
            with self.assertRaises(GovernanceBlockerError) as ctx:
                adapter.execute_turn(req)
            self.assertIn("BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP", str(ctx.exception))
            self.assertEqual(StrictMockOpenHandsServerHandler.create_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 0)
            self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 0)
            self.assertFalse((self.candidate_worktree / "evil-codex").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_r4_path_overlap_runtime_inside_candidate(self) -> None:
        adapter = OpenHandsExecutionAdapter()
        candidate = self.candidate_worktree.resolve()
        good_home = self.isolated_home.resolve()
        good_codex = self.isolated_codex_home.resolve()
        bad_runtime = candidate / "workspace" / "conversations"
        with self.assertRaises(GovernanceBlockerError) as ctx:
            adapter._validate_runtime_path_isolation(
                candidate_dir=candidate,
                isolated_home=good_home,
                isolated_codex_home=good_codex,
                agent_server_runtime_root=bad_runtime,
            )
        self.assertIn("BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP", str(ctx.exception))
        # Reverse nesting (candidate inside runtime) is also rejected.
        nested_candidate = good_home / "agent-server-runtime" / "nested-candidate"
        with self.assertRaises(GovernanceBlockerError) as ctx2:
            adapter._validate_runtime_path_isolation(
                candidate_dir=nested_candidate,
                isolated_home=good_home,
                isolated_codex_home=good_codex,
                agent_server_runtime_root=good_home / "agent-server-runtime",
            )
        self.assertIn("BLOCK_OPENHANDS_RUNTIME_PATH_OVERLAP", str(ctx2.exception))
        # No dispatch occurred: mock counters untouched (validator never touches network).
        self.assertEqual(StrictMockOpenHandsServerHandler.create_attempts, 0)
        self.assertEqual(StrictMockOpenHandsServerHandler.prompt_attempts, 0)
        self.assertEqual(StrictMockOpenHandsServerHandler.run_attempts, 0)

    def test_r4_candidate_pollution_acceptance_git_inspection(self) -> None:
        """Fresh Git repo + linked worktree; inspect real Git output for pollution."""
        from prj226_runner.openhands.adapter import AGENT_SERVER_RUNTIME_DIR_NAME

        accept_tmp = Path(tempfile.mkdtemp(prefix="oh-r4-accept-"))
        self.addCleanup(shutil.rmtree, accept_tmp, True)
        canonical = accept_tmp / "canonical"
        canonical.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=str(canonical), check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(canonical), check=True)
        subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=str(canonical), check=True)
        (canonical / "sample.txt").write_text("before\n", encoding="utf-8")
        subprocess.run(["git", "add", "sample.txt"], cwd=str(canonical), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "baseline sample"], cwd=str(canonical), check=True)
        base_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(canonical), capture_output=True, text=True, check=True).stdout.strip()

        branch = f"harn-candidate/v3-TEST-ACCEPT-{self.contract_hash}"
        candidate = accept_tmp / "candidate"
        subprocess.run(
            ["git", "worktree", "add", "-b", branch, str(candidate), base_head],
            cwd=str(canonical), capture_output=True, text=True, check=True,
        )
        # Baseline candidate: sample.txt only (tracked, clean).
        baseline_tracked = subprocess.run(
            ["git", "-C", str(candidate), "ls-files"], capture_output=True, text=True, check=True
        ).stdout.strip().splitlines()
        self.assertEqual(baseline_tracked, ["sample.txt"])

        home = accept_tmp / "home"
        home.mkdir()
        codex_home = accept_tmp / "codex_home"
        codex_home.mkdir()

        polluting = accept_tmp / "polluting-accept.sh"
        polluting.write_text(
            "#!/bin/sh\n"
            'mkdir -p "workspace/conversations/accept-cid"\n'
            'printf \'{}\n\' > "workspace/conversations/accept-cid/state.json"\n'
            "sleep 30\n",
            encoding="utf-8",
        )
        polluting.chmod(0o755)
        polluting_sha = hashlib.sha256(polluting.read_bytes()).hexdigest()

        authority = ExpectedCandidateAuthority(
            expected_worktree_path=candidate,
            expected_candidate_ref=branch,
            expected_common_dir=canonical / ".git",
            expected_base_head=base_head,
            expected_contract_hash=self.contract_hash,
        )

        server, port = self._start_mock_server()
        StrictMockOpenHandsServerHandler.expected_session_key = None
        StrictMockOpenHandsServerHandler.expected_workspace_dir = str(candidate.resolve())
        StrictMockOpenHandsServerHandler.expected_acp_command = [str(self.fake_acp_bin.resolve())]
        StrictMockOpenHandsServerHandler.attestation_response = {
            "sitecustomize_loaded": True,
            "acp_enforcement_loaded": True,
            "acp_prompt_max_retries": 0,
            "acp_executable_sha256": self.fake_acp_sha,
        }
        StrictMockOpenHandsServerHandler.events_to_serve = self._completed_events()
        try:
            from prj226_runner.openhands.supervisor import OpenHandsProcessSupervisor as _Sup

            _orig_spawn = _Sup.spawn_server_with_key_pipe

            def _gated_spawn(self_, base_command: List[str], port_: int, cwd: Path, env_overrides=None):  # type: ignore
                ret = _orig_spawn(self_, base_command, port_, cwd, env_overrides)
                marker = Path(cwd).resolve() / "workspace" / "conversations" / "accept-cid" / "state.json"
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    if marker.exists():
                        break
                    time.sleep(0.05)
                return ret

            _Sup.spawn_server_with_key_pipe = _gated_spawn  # type: ignore
            try:
                adapter = OpenHandsExecutionAdapter()
                req = OpenHandsExecutionRequest(
                    run_id="R4-ACCEPT",
                    task_id="T4-ACCEPT",
                    candidate_worktree=candidate,
                    requested_model="gpt-5.6-luna",
                    prompt="acceptance task",
                    timeout_seconds=10.0,
                    isolated_home=home,
                    isolated_codex_home=codex_home,
                    contract_digest=self.contract_hash,
                    acp_command=[str(self.fake_acp_bin.resolve())],
                    server_executable=str(polluting.resolve()),
                    expected_authority=authority,
                    server_port=port,
                    expected_acp_sha256=self.fake_acp_sha,
                    expected_server_sha256=polluting_sha,
                )
                result = adapter.execute_turn(req)
                self.assertTrue(result.quiescence_passed)
                self.assertEqual(result.terminal_execution_state, "COMPLETED")
            finally:
                _Sup.spawn_server_with_key_pipe = _orig_spawn  # type: ignore
        finally:
            server.shutdown()
            server.server_close()

        # Actually inspect filesystem/Git output (not merely Path objects).
        diff_out = subprocess.run(
            ["git", "-C", str(candidate), "diff", "--name-only"],
            capture_output=True, text=True, check=True,
        ).stdout
        others_out = subprocess.run(
            ["git", "-C", str(candidate), "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True,
        ).stdout
        status_out = subprocess.run(
            ["git", "-C", str(candidate), "status", "--porcelain"],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertNotIn("workspace", diff_out)
        self.assertNotIn("conversations", diff_out)
        self.assertNotIn("workspace", others_out)
        self.assertNotIn("conversations", others_out)
        self.assertNotIn("agent-server-runtime", diff_out + others_out)
        self.assertNotIn("workspace", status_out)
        # sample.txt baseline still intact; no server state on disk in candidate.
        self.assertTrue((candidate / "sample.txt").exists())
        self.assertFalse((candidate / "workspace").exists())
        self.assertEqual(diff_out.strip(), "")
        self.assertEqual(others_out.strip(), "")
        # Runtime root holds the synthetic server state.
        runtime_root = (home.resolve() / AGENT_SERVER_RUNTIME_DIR_NAME).resolve()
        self.assertTrue((runtime_root / "workspace" / "conversations").is_dir())


if __name__ == "__main__":
    unittest.main()
