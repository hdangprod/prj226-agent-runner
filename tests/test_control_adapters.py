import hashlib
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from prj226_runner.control_adapters import (
    CodexExecutionAdapter,
    ROLE_CONTEXT_LIMITS,
    _validate_with_schema,
    canonical_json,
    evidence_digest_for_record,
)
from prj226_runner.control_attestation import SessionAttestationResult
from prj226_runner.control_environment import EphemeralApiKeyAuth
from prj226_runner.control_runtime import derived_profile_ref
from prj226_runner.errors import AgentExecutionError, ArtifactValidationError, GovernanceBlockerError
from prj226_runner.process_supervisor import ProcessResult, SupervisionEvidence


SESSION_ID = "adapter-session-001"
MODEL = "test-model"
TASK_ID = "task-001"
FIXED_INVOCATION_ID = "00000000-0000-4000-8000-000000000001"


def profile(role_name="builder"):
    value = {
        "role": role_name.upper(),
        "backend": "codex",
        "provider": "openai",
        "model": MODEL,
        "adapter": "test-adapter",
        "executable": "/usr/bin/fake-codex",
        "executable_sha256": "0" * 64,
        "version": "fake",
        "policy": {
            "sandbox": "workspace-write" if role_name == "builder" else "read-only",
            "approval": "never",
            "tool_capability": "candidate-write-only" if role_name == "builder" else "none",
            "shell_capability": "workspace-only" if role_name == "builder" else "prohibited",
            "repository_write_capability": "candidate-worktree-owned-paths" if role_name == "builder" else "none",
            "network_capability": "provider-api-only",
            "retry_count": 0,
            "fallback_count": 0,
            "fresh_home": True,
            "fresh_codex_home": True,
            "session_persistence": "session-bound-evidence-persisted",
            "environment_policy": "closed-allowlist-only",
            "authentication_policy": "no-auth-required",
            "timeout_seconds": 5,
            "context_policy": "frozen-task-context",
            "feature_disables": [],
        },
    }
    value["profile_ref"] = derived_profile_ref(value)
    return value


class FakeSupervisor:
    def __init__(
        self,
        events=None,
        *,
        error=None,
        completion=None,
        completion_raw=None,
        completion_symlink_target=None,
        completion_ancestor_symlink_target=None,
    ):
        self.events = events if events is not None else [
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
        ]
        self.error = error
        self.completion = completion
        self.completion_raw = completion_raw
        self.completion_symlink_target = completion_symlink_target
        self.completion_ancestor_symlink_target = completion_ancestor_symlink_target
        self.calls = 0
        self.last = None
        self.codex_home = None

    def run(self, argv, *, timeout, env, cwd, input):
        self.calls += 1
        self.last = {"argv": list(argv), "timeout": timeout, "env": dict(env), "cwd": cwd, "input": input}
        if self.error is not None:
            raise self.error
        self.codex_home = Path(env["CODEX_HOME"])
        sessions = self.codex_home / "sessions"
        sessions.mkdir()
        rollout = sessions / "rollout.jsonl"
        rollout.write_text(
            "".join(json.dumps(item) + "\n" for item in [
                {"type": "thread.started", "thread_id": SESSION_ID},
                {"type": "turn_context", "payload": {"model": MODEL}},
                {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_tokens": 5}}},
            ]),
            encoding="utf-8",
        )
        connection = sqlite3.connect(self.codex_home / "state_5.sqlite")
        connection.execute(
            "CREATE TABLE threads (id TEXT, model TEXT, model_provider TEXT, cli_version TEXT, "
            "rollout_path TEXT, tokens_used INTEGER, created_at TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
            (SESSION_ID, MODEL, "openai", "fake", str(rollout), 5, "now"),
        )
        connection.commit()
        connection.close()
        marker = b"PRJ226 INVOCATION_ID: "
        invocation_id = input.split(marker, 1)[1].splitlines()[0].decode("utf-8")
        if (
            self.completion is not None
            or self.completion_raw is not None
            or self.completion_symlink_target is not None
            or self.completion_ancestor_symlink_target is not None
        ):
            completion_path = Path(cwd) / ".prj226-control" / f"{invocation_id}.completion.json"
            if self.completion_ancestor_symlink_target is not None:
                outside_dir = Path(self.completion_ancestor_symlink_target)
                outside_dir.mkdir(parents=True, exist_ok=True)
                completion_path.parent.rmdir()
                completion_path.parent.symlink_to(outside_dir, target_is_directory=True)
                output_path = outside_dir / completion_path.name
            elif self.completion_symlink_target is not None:
                output_path = Path(self.completion_symlink_target)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                completion_path.symlink_to(output_path)
            else:
                output_path = completion_path
            if self.completion_raw is not None:
                output_path.write_text(self.completion_raw, encoding="utf-8")
            elif self.completion is not None:
                output_path.write_text(json.dumps(self.completion), encoding="utf-8")
        stdout = "".join(json.dumps(item) + "\n" for item in self.events).encode("utf-8")
        return ProcessResult(
            returncode=0,
            stdout=stdout,
            stderr=b"",
            supervision=SupervisionEvidence(1, 1, final_group_quiescent=True),
        )


class ControlAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.temp.name) / "candidate"
        self.cwd.mkdir()
        self.context = b"deterministic task context"

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, role_name, supervisor, **kwargs):
        selected_profile = kwargs.pop("profile", profile(role_name))
        selected_context = kwargs.pop("context_bytes", self.context)
        return CodexExecutionAdapter(supervisor=supervisor).execute_role(
            role_name=role_name,
            profile=selected_profile,
            task_id=TASK_ID,
            context_bytes=selected_context,
            cwd=self.cwd,
            **kwargs,
        )

    def completion(self, *, status="COMPLETED", invocation_id=FIXED_INVOCATION_ID, task_id=TASK_ID, summary="done", provider_output_declaration=None):
        return {
            "schema_version": "PRJ226.CONTROL_BUILDER_COMPLETION.v1",
            "invocation_id": invocation_id,
            "task_id": task_id,
            "status": status,
            "summary": summary,
            "blockers": [],
            "changed_paths": [],
            "provider_output_declaration": provider_output_declaration,
        }

    def assert_non_builder_capability_breach(self, event):
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name, event=event):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    event,
                ])
                expected = f"{role_name.upper()}_CAPABILITY_BREACH"
                with self.assertRaisesRegex(GovernanceBlockerError, expected):
                    self.execute(role_name, supervisor)

    def test_planner_executing_command_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "command_execution", "command": "echo unsafe"},
        ])
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            with self.assertRaisesRegex(GovernanceBlockerError, "PLANNER_CAPABILITY_BREACH"):
                self.execute("planner", supervisor)
        self.assertEqual(supervisor.calls, 1)

    def test_planner_mcp_execute_tool_call_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "mcp_tool_call", "tool": "execute", "arguments": {"script": "echo unsafe"}},
        ])
        with self.assertRaisesRegex(GovernanceBlockerError, "PLANNER_CAPABILITY_BREACH"):
            self.execute("planner", supervisor)

    def test_planner_nested_item_command_execution_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "command_execution", "command": "echo unsafe"}},
        ])
        with self.assertRaisesRegex(GovernanceBlockerError, "PLANNER_CAPABILITY_BREACH"):
            self.execute("planner", supervisor)

    def test_planner_nested_agent_message_is_informational(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
        ])
        receipt = self.execute("planner", supervisor)
        self.assertEqual(receipt.disposition, "SUCCESS")

    def test_unknown_typed_event_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "future_informational_event",
            "message": "status",
            "count": 1,
            "ok": True,
        })

    def test_shell_command_typed_node_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {"type": "shell_command", "content": "touch candidate.py"},
        })

    def test_future_remove_typed_node_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "response.completed",
            "response": {"output": [{"type": "future_remove", "path": "candidate.py"}]},
        })

    def test_case_variant_key_collision_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "Type": "message",
            "type": "future_remove",
        })

    def test_nested_case_variant_key_collision_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "response.completed",
            "response": {
                "output": [{"Type": "text", "type": "shell_command"}],
            },
        })

    def test_untyped_interpreter_name_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {"name": "bash"},
        })

    def test_untyped_path_interpreter_name_is_blocked_for_planner_and_reviewer(self):
        for payload in (
            {"name": "/bin/bash"},
            {"name": "/usr/local/bin/python3.12"},
        ):
            with self.subTest(payload=payload):
                self.assert_non_builder_capability_breach({
                    "type": "item.completed",
                    "item": payload,
                })

    def test_untyped_versioned_interpreter_name_is_blocked_for_planner_and_reviewer(self):
        for payload in (
            {"name": "python3.12"},
            {"name": "node20"},
        ):
            with self.subTest(payload=payload):
                self.assert_non_builder_capability_breach({
                    "type": "item.completed",
                    "item": payload,
                })

    def test_unknown_nested_name_token_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {"name": "future_executor"},
        })

    def test_safe_parent_with_unsafe_child_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {
                "type": "agent_message",
                "content": {"type": "shell_command"},
            },
        })

    def test_deeply_nested_unknown_typed_node_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "response.completed",
            "response": {
                "nested": {"type": "arbitrary_future_authority", "payload": "xyz"},
            },
        })

    def test_unknown_future_tool_typed_node_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "response.completed",
            "response": {"output": [{"type": "unknown_future_tool"}]},
        })

    def test_unknown_typed_node_with_only_scalars_is_blocked_for_planner_and_reviewer(self):
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {
                "type": "unrecognized_scalar_type",
                "message": "hello",
                "code": 123,
            },
        })

    def test_random_unknown_typed_node_is_blocked_for_planner_and_reviewer(self):
        random_type = f"unknown_type_{uuid.uuid4().hex}"
        self.assert_non_builder_capability_breach({
            "type": "item.completed",
            "item": {"type": random_type, "data": "value"},
        })

    def test_closed_allowlist_accepts_legitimate_informational_events(self):
        events = [
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "Plan complete."}},
            {"type": "turn.completed", "usage": {"input_tokens": 100, "output_tokens": 50}},
            {"type": "turn_context", "payload": {"model": "gpt-6-astra"}},
            {"type": "item.started", "item": {"type": "text", "text": "working"}},
            {"type": "response.created", "response": {"status": "in_progress"}},
            {
                "type": "response.completed",
                "response": {"output": [{"type": "output_text", "text": "done"}]},
            },
            {"type": "thread.completed", "reason": "done"},
        ]
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                receipt = self.execute(role_name, FakeSupervisor(events=events))
                self.assertEqual(receipt.disposition, "SUCCESS")

    def test_builder_activity_remains_accepted_under_builder_rules(self):
        supervisor = FakeSupervisor(
            events=[
                {"type": "thread.started", "thread_id": SESSION_ID},
                {"type": "command_execution", "command": "echo safe"},
                {"type": "future_builder_status", "message": "candidate work observed"},
            ],
            completion=self.completion(),
        )
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "SUCCESS")

    def test_unknown_command_or_tool_structure_is_blocked_for_planner_and_reviewer(self):
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    {
                        "type": "future_event",
                        "tool": "execute",
                        "arguments": {"script": "echo unsafe"},
                    },
                ])
                expected = f"{role_name.upper()}_CAPABILITY_BREACH"
                with self.assertRaisesRegex(GovernanceBlockerError, expected):
                    self.execute(role_name, supervisor)

    def test_nested_structural_authority_cases_block_planner_and_reviewer(self):
        cases = (
            {"type": "item.completed", "item": {"shell_command": "touch candidate.py"}},
            {
                "type": "item.completed",
                "item": {"mcp_tool_call": {"server": "x", "tool_name": "execute"}},
            },
            {"type": "response.completed", "response": {"function_call": {"arguments": "{}"}}},
            {
                "type": "response.completed",
                "response": {
                    "output": [{"type": "future_write", "path": "candidate.py", "content": "changed"}],
                },
            },
        )
        for event in cases:
            for role_name in ("planner", "reviewer"):
                with self.subTest(role_name=role_name, event=event):
                    supervisor = FakeSupervisor(events=[
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        event,
                    ])
                    expected = f"{role_name.upper()}_CAPABILITY_BREACH"
                    with self.assertRaisesRegex(GovernanceBlockerError, expected):
                        self.execute(role_name, supervisor)

    def test_deeply_nested_unknown_authority_structure_is_blocked(self):
        event = {
            "type": "item.completed",
            "item": {
                "metadata": {
                    "details": {
                        "future_payload": {
                            "next": {"action": {"payload": "write candidate.py"}},
                        },
                    },
                },
            },
        }
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    event,
                ])
                with self.assertRaisesRegex(
                    GovernanceBlockerError,
                    f"{role_name.upper()}_CAPABILITY_BREACH",
                ):
                    self.execute(role_name, supervisor)

    def test_unknown_primitive_metadata_and_informational_lifecycle_events_pass(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {
                "type": "item.updated",
                "item": {"metadata": {"phase": "planning", "count": 1, "complete": False}},
            },
            {"type": "item.completed", "item": {"type": "agent_message", "text": "planning complete"}},
            {"type": "turn.started", "turn_id": "turn-1"},
            {"type": "turn.completed", "status": "ok"},
            {"type": "thread.completed", "reason": "done"},
            {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_tokens": 5}}},
        ])
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                receipt = self.execute(role_name, supervisor)
                self.assertEqual(receipt.disposition, "SUCCESS")

    def test_planner_single_message_semantic_result(self):
        text = "Plan: task-1"
        receipt = self.execute("planner", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["text"], text)
        self.assertEqual(receipt.semantic_result["message_count"], 1)
        self.assertEqual(receipt.semantic_result["sha256"], hashlib.sha256(text.encode()).hexdigest())

    def test_reviewer_single_message_semantic_result(self):
        text = "Review: task-1 approved"
        receipt = self.execute("reviewer", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["text"], text)
        self.assertEqual(receipt.semantic_result["message_count"], 1)
        self.assertEqual(receipt.semantic_result["sha256"], hashlib.sha256(text.encode()).hexdigest())

    def test_multiple_agent_messages_selects_final(self):
        receipt = self.execute("planner", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "first"}},
            {"type": "item.updated", "item": {"type": "agent_message", "text": "   "}},
            {"type": "agent_message", "text": "final"},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "second"}},
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["message_count"], 3)
        self.assertEqual(receipt.semantic_result["text"], "second")

    def test_empty_agent_messages_fails_closed(self):
        events = [
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": ""}},
            {"type": "item.updated", "item": {"type": "agent_message", "text": " \t\n "}},
        ]
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                receipt = self.execute(role_name, FakeSupervisor(events=events))
                self.assertEqual(receipt.disposition, "BLOCKED")
                self.assertIsNone(receipt.semantic_result)

    def test_no_agent_message_fails_closed(self):
        events = [
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "turn.started", "turn_id": "turn-1"},
            {"type": "turn.completed", "status": "ok"},
            {"type": "thread.completed", "reason": "done"},
        ]
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                receipt = self.execute(role_name, FakeSupervisor(events=events))
                self.assertEqual(receipt.disposition, "BLOCKED")
                self.assertIsNone(receipt.semantic_result)

    def test_reasoning_text_excluded_from_semantic_result(self):
        receipt = self.execute("planner", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {
                "type": "item.completed",
                "item": {"type": "reasoning", "text": "hidden reasoning"},
            },
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "public plan"},
            },
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["text"], "public plan")
        self.assertEqual(receipt.semantic_result["message_count"], 1)
        self.assertNotIn("hidden reasoning", json.dumps(receipt.semantic_result))

    def test_tool_output_excluded_from_semantic_result(self):
        receipt = self.execute("reviewer", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {
                "type": "response.completed",
                "response": {
                    "output": [{"type": "output_text", "text": "tool output must not leak"}],
                },
            },
            {"type": "item.completed", "item": {"type": "agent_message", "text": "review verdict"}},
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["text"], "review verdict")
        self.assertEqual(receipt.semantic_result["message_count"], 1)
        self.assertNotIn("tool output must not leak", json.dumps(receipt.semantic_result))

    def test_capability_breach_fails_closed_without_semantic_success(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "command_execution", "command": "echo unsafe"}},
        ])
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(GovernanceBlockerError):
            self.execute("planner", supervisor, evidence_dir=evidence_dir)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertEqual(failure_record["disposition"], "BLOCKED")
        self.assertIsNone(failure_record["semantic_result"])

    def test_semantic_result_size_bound_exact(self):
        text = "x" * (64 * 1024)
        receipt = self.execute("planner", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
        ]))
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.semantic_result["text"], text)
        self.assertEqual(receipt.semantic_result["message_count"], 1)

    def test_semantic_result_size_bound_plus_one_blocked(self):
        text = "x" * (64 * 1024 + 1)
        receipt = self.execute("reviewer", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
        ]))
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertIsNone(receipt.semantic_result)
        self.assertEqual(receipt.record["completion"]["summary"], "semantic result exceeds 64 KiB size limit")

    def test_semantic_result_persisted_in_durable_evidence(self):
        text = "Persist this planner result"
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        receipt = self.execute("planner", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
        ]), evidence_dir=evidence_dir)
        evidence_path = evidence_dir / f"{receipt.invocation_id}.evidence.json"
        persisted = json.loads(evidence_path.read_text(encoding="utf-8"))
        _validate_with_schema(persisted, "control-invocation.v1.schema.json", "persisted invocation record")
        self.assertEqual(persisted["semantic_result"], receipt.semantic_result)

    def test_semantic_result_digest_integrity(self):
        receipt = self.execute("reviewer", FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "integrity check"}},
        ]))
        semantic_result = receipt.semantic_result
        self.assertEqual(
            hashlib.sha256(semantic_result["text"].encode("utf-8")).hexdigest(),
            semantic_result["sha256"],
        )

    def test_builder_completion_data_preserved_unaffected(self):
        supervisor = FakeSupervisor(completion=self.completion())
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.completion_data["status"], "COMPLETED")
        self.assertIsNone(receipt.semantic_result)
        self.assertIsNone(receipt.record["semantic_result"])

    def test_envelope_command_without_item_type_blocks_planner_and_reviewer(self):
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    {"type": "item.completed", "item": {"command": "touch candidate.py"}},
                ])
                expected = f"{role_name.upper()}_CAPABILITY_BREACH"
                with self.assertRaisesRegex(GovernanceBlockerError, expected):
                    self.execute(role_name, supervisor)

    def test_safe_response_envelope_nested_function_call_blocks_planner_and_reviewer(self):
        for role_name in ("planner", "reviewer"):
            with self.subTest(role_name=role_name):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    {
                        "type": "response.completed",
                        "response": {
                            "output": [{
                                "type": "function_call",
                                "name": "execute",
                                "arguments": "{}",
                            }],
                        },
                    },
                ])
                expected = f"{role_name.upper()}_CAPABILITY_BREACH"
                with self.assertRaisesRegex(GovernanceBlockerError, expected):
                    self.execute(role_name, supervisor)

    def test_planner_modifying_file_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "file_write", "path": "candidate.py"},
        ])
        with self.assertRaisesRegex(GovernanceBlockerError, "PLANNER_CAPABILITY_BREACH"):
            self.execute("planner", supervisor)

    def test_reviewer_writing_candidate_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "file_change", "path": "candidate.py"}},
        ])
        with self.assertRaisesRegex(GovernanceBlockerError, "REVIEWER_CAPABILITY_BREACH"):
            self.execute("reviewer", supervisor)

    def test_reviewer_nested_mcp_tool_call_is_blocked(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "mcp_tool_call", "tool": "execute"}},
        ])
        with self.assertRaisesRegex(GovernanceBlockerError, "REVIEWER_CAPABILITY_BREACH"):
            self.execute("reviewer", supervisor)

    def test_reviewer_nested_tool_and_function_calls_are_blocked(self):
        for item_type in ("tool_call", "function_call"):
            with self.subTest(item_type=item_type):
                supervisor = FakeSupervisor(events=[
                    {"type": "thread.started", "thread_id": SESSION_ID},
                    {"type": "item.completed", "item": {"type": item_type, "name": "execute"}},
                ])
                with self.assertRaisesRegex(GovernanceBlockerError, "REVIEWER_CAPABILITY_BREACH"):
                    self.execute("reviewer", supervisor)

    def test_reviewer_workspace_write_profile_is_rejected_after_profile_validation(self):
        reviewer_profile = profile("reviewer")
        reviewer_profile["policy"]["sandbox"] = "workspace-write"
        reviewer_profile["profile_ref"] = derived_profile_ref(reviewer_profile)
        with self.assertRaisesRegex(ArtifactValidationError, "reviewer role must use read-only sandbox"):
            CodexExecutionAdapter(supervisor=FakeSupervisor()).execute_role(
                role_name="reviewer",
                profile=reviewer_profile,
                task_id=TASK_ID,
                context_bytes=self.context,
                cwd=self.cwd,
            )

    def test_planner_workspace_write_profile_is_rejected_after_profile_validation(self):
        planner_profile = profile("planner")
        planner_profile["policy"]["sandbox"] = "workspace-write"
        planner_profile["profile_ref"] = derived_profile_ref(planner_profile)
        with self.assertRaisesRegex(ArtifactValidationError, "planner role must use read-only sandbox"):
            CodexExecutionAdapter(supervisor=FakeSupervisor()).execute_role(
                role_name="planner",
                profile=planner_profile,
                task_id=TASK_ID,
                context_bytes=self.context,
                cwd=self.cwd,
            )

    def test_mixed_case_role_names_are_normalized(self):
        for supplied_name in ("BUILDER", "Builder", "PLANNER", "Reviewer"):
            with self.subTest(role_name=supplied_name):
                canonical_name = supplied_name.lower()
                receipt = self.execute(canonical_name, FakeSupervisor())
                normalized_receipt = CodexExecutionAdapter(supervisor=FakeSupervisor()).execute_role(
                    role_name=supplied_name,
                    profile=profile(canonical_name),
                    task_id=TASK_ID,
                    context_bytes=self.context,
                    cwd=self.cwd,
                )
                self.assertEqual(normalized_receipt.role, canonical_name.upper())
                self.assertEqual(normalized_receipt.disposition, receipt.disposition)

    def test_role_context_limits_bind_to_submitted_context_payload(self):
        for role_name, limit in ROLE_CONTEXT_LIMITS.items():
            with self.subTest(role_name=role_name):
                with mock.patch(
                    "prj226_runner.control_adapters.uuid.uuid4",
                    return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID),
                ):
                    suffix = (
                        f"\n\nPRJ226 TASK_ID: {TASK_ID}\n"
                        f"PRJ226 INVOCATION_ID: {FIXED_INVOCATION_ID}\n"
                        f"PRJ226 COMPLETION_PATH: .prj226-control/{FIXED_INVOCATION_ID}.completion.json\n"
                    ).encode("utf-8")
                    self.execute(role_name, FakeSupervisor(), context_bytes=b"x" * (limit - len(suffix)))
                    with self.assertRaisesRegex(ArtifactValidationError, "context exceeds role limit"):
                        self.execute(role_name, FakeSupervisor(), context_bytes=b"x" * (limit - len(suffix) + 1))

    def test_unrecognized_context_policy_is_rejected(self):
        invalid_profile = profile("planner")
        invalid_profile["policy"]["context_policy"] = "unbounded"
        invalid_profile["profile_ref"] = derived_profile_ref(invalid_profile)
        with self.assertRaisesRegex(ArtifactValidationError, "unsupported context policy: unbounded"):
            self.execute("planner", FakeSupervisor(), profile=invalid_profile)

    def test_timeout_override_must_be_finite_positive_and_within_profile_limit(self):
        for timeout in (float("nan"), float("inf"), profile("planner")["policy"]["timeout_seconds"] + 10):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ArtifactValidationError):
                    self.execute("planner", FakeSupervisor(), timeout=timeout)

    def test_exception_supervision_evidence_is_persisted(self):
        supervision = SupervisionEvidence(1, 1, kill_event=True, final_group_quiescent=False)
        supervisor = FakeSupervisor(
            error=AgentExecutionError("supervisor failed", {"supervision": supervision}),
        )
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(AgentExecutionError):
            self.execute("builder", supervisor, evidence_dir=evidence_dir)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertTrue(failure_record["supervision"]["kill_event"])

    def test_output_flood_exception_is_persisted_as_output_flood(self):
        supervision = SupervisionEvidence(1, 1, final_group_quiescent=False)
        supervisor = FakeSupervisor(
            error=AgentExecutionError(
                "Process log limit exceeded while streaming",
                {"supervision": supervision},
            ),
        )
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(AgentExecutionError):
            self.execute("builder", supervisor, evidence_dir=evidence_dir)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertTrue(failure_record["supervision"]["output_flood"])

    def test_unrelated_supervision_exception_is_not_output_flood(self):
        supervision = SupervisionEvidence(1, 1, final_group_quiescent=False)
        supervisor = FakeSupervisor(
            error=AgentExecutionError("Some other process failure", {"supervision": supervision}),
        )
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(AgentExecutionError):
            self.execute("builder", supervisor, evidence_dir=evidence_dir)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertFalse(failure_record["supervision"]["output_flood"])

    def test_builder_valid_completion_succeeds(self):
        supervisor = FakeSupervisor(completion=self.completion())
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.completion_data["status"], "COMPLETED")
        self.assertTrue(receipt.invocation_id_in_context)
        self.assertIn(FIXED_INVOCATION_ID.encode("utf-8"), supervisor.last["input"])
        self.assertEqual(supervisor.last["argv"][-1], "-")
        self.assertFalse((self.cwd / ".prj226-control").exists())

    def test_builder_missing_completion_file_is_blocked(self):
        receipt = self.execute("builder", FakeSupervisor())
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertFalse((self.cwd / ".prj226-control").exists())

    def test_builder_malformed_completion_is_blocked(self):
        supervisor = FakeSupervisor(completion_raw="not-json")
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_completion_id_mismatch_is_blocked(self):
        value = self.completion(invocation_id="different-invocation")
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(completion=value))
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_completion_task_id_mismatch_is_blocked(self):
        value = self.completion(task_id="different-task")
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(completion=value))
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_completion_containment_is_checked_at_consumption(self):
        outside = Path(self.temp.name) / "outside-completion.json"
        supervisor = FakeSupervisor(
            completion=self.completion(),
            completion_symlink_target=outside,
        )
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertTrue(outside.exists())

    def test_builder_completion_ancestor_symlink_is_rejected(self):
        outside_dir = Path(self.temp.name) / "outside-completion-dir"
        supervisor = FakeSupervisor(
            completion=self.completion(),
            completion_ancestor_symlink_target=outside_dir,
        )
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor)
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertTrue((self.cwd / ".prj226-control").is_symlink())

    def test_builder_blocked_status_yields_blocked_disposition(self):
        value = self.completion(status="BLOCKED", summary="blocked by policy")
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(completion=value))
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertEqual(receipt.record["completion"]["summary"], "blocked by policy")

    def test_builder_does_not_accept_caller_completion_path(self):
        with self.assertRaises(TypeError):
            self.execute("builder", FakeSupervisor(), completion_output_path=self.cwd / "arbitrary.json")

    def test_adapter_zero_retry_and_zero_fallback_on_error(self):
        supervisor = FakeSupervisor(error=AgentExecutionError("one failure"))
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(AgentExecutionError):
            self.execute("builder", supervisor, evidence_dir=evidence_dir)
        self.assertEqual(supervisor.calls, 1)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertEqual(failure_record["disposition"], "FAILED")
        self.assertFalse(failure_record["attestation"]["attestation_passed"])

    def test_governance_failure_persists_blocked_evidence_before_reraising(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "item.completed", "item": {"type": "mcp_tool_call", "tool": "execute"}},
        ])
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        with self.assertRaises(GovernanceBlockerError):
            self.execute("reviewer", supervisor, evidence_dir=evidence_dir)
        evidence_files = list(evidence_dir.glob("*.evidence.json"))
        self.assertEqual(len(evidence_files), 1)
        failure_record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertEqual(failure_record["disposition"], "BLOCKED")

    def test_evidence_written_to_evidence_dir_before_cleanup(self):
        supervisor = FakeSupervisor()
        evidence_dir = Path(self.temp.name) / "evidence"
        evidence_dir.mkdir()
        receipt = self.execute("planner", supervisor, evidence_dir=evidence_dir)
        evidence_path = evidence_dir / f"{receipt.invocation_id}.evidence.json"
        self.assertTrue(receipt.record["evidence_digest"])
        self.assertFalse(supervisor.codex_home.exists())
        self.assertEqual(receipt.evidence_digest, receipt.record["evidence_digest"])
        self.assertEqual(json.loads(evidence_path.read_text(encoding="utf-8")), receipt.record)

    def test_evidence_dir_none_means_no_disk_write(self):
        evidence_dir = Path(self.temp.name) / "evidence"
        receipt = self.execute("planner", FakeSupervisor())
        self.assertIsNotNone(receipt.record)
        self.assertFalse(evidence_dir.exists())

    def test_durable_evidence_contains_zero_auth_secrets(self):
        secret = "test-api-secret-123"
        supervisor = FakeSupervisor(completion=self.completion(summary=secret))
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor, auth_source=EphemeralApiKeyAuth(secret))
        self.assertNotIn(secret, json.dumps(receipt.record, sort_keys=True))
        self.assertNotIn(secret, json.dumps(receipt.completion_data, sort_keys=True))

    def test_evidence_excludes_raw_attestation_data_when_sanitizer_is_bypassed(self):
        secret = "raw-auth-secret"
        attestation = SessionAttestationResult(
            session_id=SESSION_ID,
            configured_model=MODEL,
            session_model=MODEL,
            cli_version="fake",
            tokens_used=5,
            model_attestation_level="RUNTIME_SESSION_BOUND",
            provider_effective_model=None,
            attestation_passed=True,
            rollout_events_count=3,
        )
        with mock.patch("prj226_runner.control_adapters.attest_session", return_value=attestation), \
                mock.patch("prj226_runner.control_environment.IsolatedRoleEnvironment.sanitized", side_effect=lambda value: value):
            receipt = self.execute("planner", FakeSupervisor())
        self.assertNotIn(secret, json.dumps(receipt.record, sort_keys=True))

    def test_receipt_attestation_text_is_sanitized(self):
        secret = "receipt-cli-secret"
        attestation = SessionAttestationResult(
            session_id=SESSION_ID,
            configured_model=MODEL,
            session_model=MODEL,
            cli_version=secret,
            tokens_used=5,
            model_attestation_level="RUNTIME_SESSION_BOUND",
            provider_effective_model=None,
            attestation_passed=True,
            rollout_events_count=3,
        )
        with mock.patch("prj226_runner.control_adapters.attest_session", return_value=attestation):
            receipt = self.execute("planner", FakeSupervisor(), auth_source=EphemeralApiKeyAuth(secret))
        self.assertNotEqual(receipt.attestation_result.cli_version, secret)
        self.assertNotIn(secret, receipt.attestation_result.cli_version)

    def test_completion_secret_is_blocked_when_sanitizer_is_bypassed(self):
        secret = "raw-summary-secret"
        supervisor = FakeSupervisor(completion=self.completion(summary=secret))
        with mock.patch("prj226_runner.control_environment.IsolatedRoleEnvironment.sanitized", side_effect=lambda value: value):
            with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
                receipt = self.execute("builder", supervisor, auth_source=EphemeralApiKeyAuth(secret))
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertNotIn(secret, json.dumps(receipt.record, sort_keys=True))

    def test_evidence_digest_is_independently_recomputable(self):
        receipt = self.execute("planner", FakeSupervisor())
        record_without_digest = dict(receipt.record)
        record_without_digest.pop("evidence_digest")
        expected = hashlib.sha256(
            canonical_json(record_without_digest).encode("utf-8")
        ).hexdigest()
        self.assertEqual(receipt.evidence_digest, expected)
        self.assertEqual(receipt.record["evidence_digest"], expected)

    def test_attestation_failure_cannot_produce_success(self):
        attestation = SessionAttestationResult(
            session_id=SESSION_ID,
            configured_model=MODEL,
            session_model=MODEL,
            cli_version="fake",
            tokens_used=5,
            model_attestation_level="RUNTIME_SESSION_BOUND",
            provider_effective_model=None,
            attestation_passed=False,
            rollout_events_count=3,
        )
        with mock.patch("prj226_runner.control_adapters.attest_session", return_value=attestation):
            with self.assertRaisesRegex(ArtifactValidationError, "SUCCESS requires attestation passed"):
                self.execute("planner", FakeSupervisor())

    def test_durable_evidence_schema_validity(self):
        receipt = self.execute("planner", FakeSupervisor())
        _validate_with_schema(receipt.record, "control-invocation.v1.schema.json", "invocation record")

    def test_evidence_digest_stability(self):
        first = {"b": [2, 1], "a": {"z": True, "x": "value"}}
        second = {"a": {"x": "value", "z": True}, "b": [2, 1]}
        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertEqual(evidence_digest_for_record(first), evidence_digest_for_record(second))


if __name__ == "__main__":
    unittest.main()
