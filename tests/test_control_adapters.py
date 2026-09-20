import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from prj226_runner.control_adapters import (
    CodexExecutionAdapter,
    _validate_with_schema,
    canonical_json,
    evidence_digest_for_record,
)
from prj226_runner.control_environment import EphemeralApiKeyAuth
from prj226_runner.control_runtime import derived_profile_ref
from prj226_runner.errors import AgentExecutionError, ArtifactValidationError, GovernanceBlockerError
from prj226_runner.process_supervisor import ProcessResult, SupervisionEvidence


SESSION_ID = "adapter-session-001"
MODEL = "test-model"
TASK_ID = "task-001"
FIXED_INVOCATION_ID = "00000000-0000-4000-8000-000000000001"


def profile(role_name="builder", *, context_limit=None):
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
            "context_policy": "test",
            "feature_disables": [],
        },
    }
    if context_limit is not None:
        value["context_limit_bytes"] = context_limit
    value["profile_ref"] = derived_profile_ref(value)
    return value


class FakeSupervisor:
    def __init__(self, events=None, *, error=None, completion_secret=None):
        self.events = events or [{"type": "thread.started", "thread_id": SESSION_ID}]
        self.error = error
        self.completion_secret = completion_secret
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

    def completion(self, *, status="COMPLETED", invocation_id=FIXED_INVOCATION_ID, session_id=SESSION_ID, summary="done", output_digest=None):
        return {
            "schema_version": "PRJ226.CONTROL_BUILDER_COMPLETION.v1",
            "invocation_id": invocation_id,
            "session_id": session_id,
            "task_id": TASK_ID,
            "status": status,
            "summary": summary,
            "blockers": [],
            "changed_paths": [],
            "output_digest": output_digest,
        }

    def completion_path(self, value):
        path = self.cwd / "completion.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

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

    def test_unknown_primitive_event_is_informational(self):
        supervisor = FakeSupervisor(events=[
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "future_informational_event", "message": "status", "count": 1, "ok": True},
        ])
        receipt = self.execute("planner", supervisor)
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
                with self.assertRaisesRegex(GovernanceBlockerError, "UNRECOGNIZED_MUTATION_EVENT"):
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

    def test_role_specific_planner_context_limit_is_selected_first(self):
        planner_profile = profile("planner")
        planner_profile["planner_context_bytes"] = 100
        planner_profile["context_limit_bytes"] = 1
        planner_profile["profile_ref"] = derived_profile_ref(planner_profile)
        self.execute("planner", FakeSupervisor(), profile=planner_profile, context_bytes=b"x" * 100)
        with self.assertRaisesRegex(ArtifactValidationError, "context exceeds configured limit"):
            self.execute("planner", FakeSupervisor(), profile=planner_profile, context_bytes=b"x" * 101)

    def test_role_specific_builder_context_limit_is_selected_first(self):
        builder_profile = profile("builder")
        builder_profile["builder_context_bytes"] = 200
        builder_profile["context_limit_bytes"] = 1
        builder_profile["profile_ref"] = derived_profile_ref(builder_profile)
        self.execute("builder", FakeSupervisor(), profile=builder_profile, context_bytes=b"x" * 200)
        with self.assertRaisesRegex(ArtifactValidationError, "context exceeds configured limit"):
            self.execute("builder", FakeSupervisor(), profile=builder_profile, context_bytes=b"x" * 201)

    def test_generic_context_limit_remains_supported_without_role_specific_key(self):
        planner_profile = profile("planner", context_limit=4)
        self.execute("planner", FakeSupervisor(), profile=planner_profile, context_bytes=b"1234")
        with self.assertRaisesRegex(ArtifactValidationError, "context exceeds configured limit"):
            self.execute("planner", FakeSupervisor(), profile=planner_profile, context_bytes=b"12345")

    def test_builder_valid_completion_succeeds(self):
        supervisor = FakeSupervisor()
        completion_path = self.completion_path(self.completion())
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor, completion_output_path=completion_path)
        self.assertEqual(receipt.disposition, "SUCCESS")
        self.assertEqual(receipt.completion_data["status"], "COMPLETED")
        self.assertEqual(supervisor.last["input"], self.context)
        self.assertEqual(supervisor.last["argv"][-1], "-")

    def test_builder_missing_completion_file_is_blocked(self):
        receipt = self.execute("builder", FakeSupervisor(), completion_output_path=self.cwd / "missing.json")
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_malformed_completion_is_blocked(self):
        path = self.cwd / "completion.json"
        path.write_text("not-json", encoding="utf-8")
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(), completion_output_path=path)
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_completion_id_mismatch_is_blocked(self):
        value = self.completion(session_id="different-session")
        path = self.completion_path(value)
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(), completion_output_path=path)
        self.assertEqual(receipt.disposition, "BLOCKED")

    def test_builder_blocked_status_yields_blocked_disposition(self):
        value = self.completion(status="BLOCKED", summary="blocked by policy")
        path = self.completion_path(value)
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", FakeSupervisor(), completion_output_path=path)
        self.assertEqual(receipt.disposition, "BLOCKED")
        self.assertEqual(receipt.record["completion"]["summary"], "blocked by policy")

    def test_adapter_zero_retry_and_zero_fallback_on_error(self):
        supervisor = FakeSupervisor(error=AgentExecutionError("one failure"))
        with self.assertRaises(AgentExecutionError):
            self.execute("builder", supervisor)
        self.assertEqual(supervisor.calls, 1)

    def test_durable_evidence_finalized_before_environment_cleanup(self):
        supervisor = FakeSupervisor()
        receipt = self.execute("planner", supervisor)
        self.assertTrue(receipt.record["evidence_digest"])
        self.assertFalse(supervisor.codex_home.exists())
        self.assertEqual(receipt.evidence_digest, receipt.record["evidence_digest"])

    def test_durable_evidence_contains_zero_auth_secrets(self):
        secret = "test-api-secret-123"
        supervisor = FakeSupervisor()
        path = self.completion_path(self.completion(summary=secret))
        with mock.patch("prj226_runner.control_adapters.uuid.uuid4", return_value=mock.Mock(__str__=lambda _: FIXED_INVOCATION_ID)):
            receipt = self.execute("builder", supervisor, auth_source=EphemeralApiKeyAuth(secret), completion_output_path=path)
        self.assertNotIn(secret, json.dumps(receipt.record, sort_keys=True))
        self.assertNotIn(secret, json.dumps(receipt.completion_data, sort_keys=True))

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
