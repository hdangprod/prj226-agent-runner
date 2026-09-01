"""Deterministic unit tests for the calibration harness module."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from prj226_runner.calibration import (
    CalibrationCaseResult,
    CalibrationResult,
    CalibrationStatus,
    CalibrationVerdict,
    DiscoveryStatus,
    HumanGatePayload,
    InvocationSpec,
    ToolDiscoveryRecord,
    ToolSpec,
    build_agy_invocation,
    build_codex_invocation,
    build_human_gate_payload,
    build_opencode_config_dict,
    build_opencode_config_json,
    build_opencode_invocation,
    build_subprocess_env,
    check_no_symlinks,
    copy_fixture_to_workspace,
    discover_tools,
    hash_directory_tree,
    map_status_to_error_class,
    parse_agy_output,
    parse_codex_output,
    parse_opencode_output,
    prepare_runtime_root,
    run_calibration_subprocess,
    scan_workspace_for_symlinks,
    serialize_calibration_case_result,
    serialize_calibration_result,
    serialize_human_gate_payload,
    validate_calibration_case_result,
    validate_calibration_result,
    validate_environment_override_keys,
)
from prj226_runner.models import ErrorClass


class TestCalibrationHarness(unittest.TestCase):
    """Unit test suite for calibration harness logic with ZERO live model calls."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # NB-001: Mutation Governance & Status Mapping
    # -------------------------------------------------------------------------

    def test_map_status_to_error_class(self) -> None:
        """Verify deterministic mapping between CalibrationStatus and ErrorClass."""
        self.assertIsNone(map_status_to_error_class(CalibrationStatus.PASS))
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.TIMEOUT),
            ErrorClass.AGENT_EXECUTION_ERROR,
        )
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.OUTPUT_INVALID),
            ErrorClass.ARTIFACT_VALIDATION_ERROR,
        )
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.TASK_FAILURE),
            ErrorClass.IMPLEMENTATION_FAILURE,
        )
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.PERMISSION_DENIED),
            ErrorClass.GOVERNANCE_BLOCKER,
        )
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.TOOL_FAILURE, is_missing_binary=True),
            ErrorClass.ENVIRONMENT_ERROR,
        )
        self.assertEqual(
            map_status_to_error_class(CalibrationStatus.TASK_FAILURE, is_unexpected_mutation=True),
            ErrorClass.GOVERNANCE_BLOCKER,
        )

    def test_map_status_pass_with_unexpected_mutation_returns_governance_blocker(self) -> None:
        """Verify PASS + unexpected prohibited mutation returns GOVERNANCE_BLOCKER."""
        result = map_status_to_error_class(CalibrationStatus.PASS, is_unexpected_mutation=True)
        self.assertEqual(result, ErrorClass.GOVERNANCE_BLOCKER)

    # -------------------------------------------------------------------------
    # NB-SEM-001: CalibrationResult Invariants & PASS State Enforcement
    # -------------------------------------------------------------------------

    def test_pass_requires_structured_output_valid(self) -> None:
        """Verify PASS status strictly requires structured_output_valid=True (NB-SEM-001)."""
        valid_pass = CalibrationResult(
            calibration_id="CAL-001",
            tool="codex",
            executable_path="/path/to/codex",
            version="0.148.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=None,
            timed_out=False,
            duration_ms=100,
            structured_output_valid=True,
            exit_code=0,
        )
        validate_calibration_result(valid_pass)

        # PASS with structured_output_valid=False must be rejected
        invalid_pass = CalibrationResult(
            calibration_id="CAL-001",
            tool="codex",
            executable_path="/path/to/codex",
            version="0.148.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=None,
            timed_out=False,
            duration_ms=100,
            structured_output_valid=False,
            exit_code=0,
        )
        with self.assertRaises(ValueError) as ctx:
            validate_calibration_result(invalid_pass)
        self.assertIn("structured_output_valid=True", str(ctx.exception))

    def test_pass_status_contradictory_states_rejected(self) -> None:
        """Verify PASS status rejects exit_code != 0, timed_out=True, and error_class != None."""
        base_kwargs = {
            "calibration_id": "CAL-001",
            "tool": "codex",
            "executable_path": "/path/to/codex",
            "version": "0.148.0",
            "working_dir": "/tmp/workspace",
            "status": CalibrationStatus.PASS,
            "error_class": None,
            "timed_out": False,
            "duration_ms": 100,
            "structured_output_valid": True,
            "exit_code": 0,
        }

        # 1. PASS with exit_code=1
        with self.assertRaises(ValueError):
            validate_calibration_result(CalibrationResult(**{**base_kwargs, "exit_code": 1}))

        # 2. PASS with timed_out=True
        with self.assertRaises(ValueError):
            validate_calibration_result(CalibrationResult(**{**base_kwargs, "timed_out": True}))

        # 3. PASS with error_class set
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "error_class": ErrorClass.AGENT_EXECUTION_ERROR})
            )

    # -------------------------------------------------------------------------
    # NB-SEM-002: OpenCode Output Parsing Fail-Closed
    # -------------------------------------------------------------------------

    def test_opencode_terminal_event_without_supported_payload_fails_closed(self) -> None:
        """Verify OpenCode terminal event with only metadata fields fails closed."""
        metadata_only_stream = (
            '{"type": "init", "session": "s1"}\n'
            '{"type": "message", "session": "s1", "timestamp": 123456789, "id": "msg_001", "duration": 100, "metadata": {"foo": "bar"}}\n'
        )
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output(metadata_only_stream)
        self.assertIn("no recognized terminal", str(ctx.exception).lower())

    def test_opencode_supported_payload_forms_parsed(self) -> None:
        """Verify supported OpenCode terminal forms are parsed properly."""
        stream1 = '{"type": "message", "data": {"key": "alpha_7729"}}\n'
        self.assertEqual(parse_opencode_output(stream1), {"key": "alpha_7729"})

        stream2 = '{"type": "message", "message": {"text": "hello"}}\n'
        self.assertEqual(parse_opencode_output(stream2), {"text": "hello"})

        stream3 = '{"type": "final_response", "data": {"status": "ok"}}\n'
        self.assertEqual(parse_opencode_output(stream3), {"status": "ok"})

    def test_parse_opencode_output_invalid_and_incomplete_streams(self) -> None:
        """Verify rejection of empty, malformed, init-only, and intermediate-only streams."""
        with self.assertRaises(ValueError):
            parse_opencode_output("")
        with self.assertRaises(ValueError):
            parse_opencode_output("   \n\n  ")
        with self.assertRaises(ValueError):
            parse_opencode_output('{"type": "init"}\nnot valid json\n')
        with self.assertRaises(ValueError):
            parse_opencode_output('{"type": "init", "session": "s1"}\n')

    # -------------------------------------------------------------------------
    # NB-OP-002: Symlink Contract
    # -------------------------------------------------------------------------

    def test_symlink_in_source_fixture_rejected_without_following_target(self) -> None:
        """Verify check_no_symlinks / copy_fixture_to_workspace rejects symlinks in source fixture."""
        fixture_dir = self.test_root / "fixture_with_symlink"
        fixture_dir.mkdir()
        outside_file = self.test_root / "outside.txt"
        outside_file.write_text("secret outside data", encoding="utf-8")

        symlink_path = fixture_dir / "link_to_outside.txt"
        os.symlink(outside_file, symlink_path)

        with self.assertRaises(ValueError) as ctx:
            check_no_symlinks(fixture_dir)
        self.assertIn("Symlink detected", str(ctx.exception))

        target_ws = self.test_root / "target_ws"
        with self.assertRaises(ValueError):
            copy_fixture_to_workspace(fixture_dir, target_ws)
        self.assertFalse(target_ws.exists() and (target_ws / "link_to_outside.txt").exists())

        with self.assertRaises(ValueError):
            hash_directory_tree(fixture_dir)

    def test_post_run_symlink_detected(self) -> None:
        """Verify scan_workspace_for_symlinks detects newly introduced symlinks."""
        ws = self.test_root / "clean_ws"
        ws.mkdir()
        (ws / "file.txt").write_text("hello", encoding="utf-8")
        self.assertFalse(scan_workspace_for_symlinks(ws))

        os.symlink(ws / "file.txt", ws / "link.txt")
        self.assertTrue(scan_workspace_for_symlinks(ws))

    # -------------------------------------------------------------------------
    # NB-OP-001: Tool Discovery Observability
    # -------------------------------------------------------------------------

    def test_tool_discovery_record_statuses(self) -> None:
        """Verify ToolDiscoveryRecord statuses: DISCOVERED, NOT_FOUND, PROBE_FAILED."""
        good_bin = self.test_root / "good_tool"
        good_bin.write_text(f"#!{sys.executable}\nprint('good_tool v1.0.0')\n", encoding="utf-8")
        good_bin.chmod(0o755)

        bad_bin = self.test_root / "bad_tool"
        bad_bin.write_text(f"#!{sys.executable}\nimport sys; sys.exit(2)\n", encoding="utf-8")
        bad_bin.chmod(0o755)

        records = discover_tools(
            custom_paths={
                "good": str(good_bin),
                "bad": str(bad_bin),
                "missing": "/nonexistent/binary/path",
            },
            tool_names=["good", "bad", "missing"],
        )

        self.assertEqual(records["good"].discovery_status, DiscoveryStatus.DISCOVERED)
        self.assertEqual(records["good"].version, "good_tool v1.0.0")
        self.assertEqual(records["good"].version_exit_code, 0)

        self.assertEqual(records["bad"].discovery_status, DiscoveryStatus.PROBE_FAILED)
        self.assertEqual(records["bad"].version_exit_code, 2)
        self.assertIsNotNone(records["bad"].safe_error)

        self.assertEqual(records["missing"].discovery_status, DiscoveryStatus.NOT_FOUND)
        self.assertIsNone(records["missing"].resolved_path)

    # -------------------------------------------------------------------------
    # NB-SEC-001: Child Environment Policy & Credential Rejection
    # -------------------------------------------------------------------------

    def test_environment_policy_copy_and_overrides(self) -> None:
        """Verify environment copy semantics and allowed override keys."""
        orig_path = os.environ.get("PATH", "")
        env = build_subprocess_env({
            "OPENCODE_CONFIG_CONTENT": '{"share": "disabled"}',
            "XDG_CONFIG_HOME": "/tmp/custom_config",
        })
        self.assertEqual(env["PATH"], orig_path)
        self.assertEqual(env["OPENCODE_CONFIG_CONTENT"], '{"share": "disabled"}')
        self.assertEqual(env["XDG_CONFIG_HOME"], "/tmp/custom_config")

    def test_secret_looking_override_rejected(self) -> None:
        """Verify credential-like override keys are rejected with ValueError."""
        bad_keys = [
            "API_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "AUTH_SECRET",
            "PASSWORD",
            "MY_PASS",
        ]
        for key in bad_keys:
            with self.assertRaises(ValueError) as ctx:
                validate_environment_override_keys({key: "secret_value"})
            self.assertIn("rejected by credential policy", str(ctx.exception))

    def test_unauthorized_override_key_rejected(self) -> None:
        """Verify non-allowlisted override key is rejected."""
        with self.assertRaises(ValueError) as ctx:
            validate_environment_override_keys({"UNAUTHORIZED_CUSTOM_VAR": "val"})
        self.assertIn("not in allowed override list", str(ctx.exception))

    def test_override_values_not_in_invocation_metadata(self) -> None:
        """Verify InvocationSpec contains only override KEY NAMES, never values."""
        spec = build_codex_invocation(
            executable="/path/to/codex",
            workspace=str(self.test_root),
            prompt="test prompt",
            payload_schema_path=str(self.test_root / "schema.json"),
            output_path=str(self.test_root / "out.json"),
            overrides={"PYTHONPATH": "/custom/path"},
        )
        self.assertEqual(spec.env_override_keys, ["PYTHONPATH"])
        self.assertNotIn("/custom/path", str(spec.env_override_keys))

    # -------------------------------------------------------------------------
    # CalibrationCaseResult: Invocation vs Case Verdict Separation
    # -------------------------------------------------------------------------

    def test_expected_permission_denial_can_yield_case_pass(self) -> None:
        """Verify an expected PERMISSION_DENIED invocation status can evaluate to case PASS."""
        inv_result = CalibrationResult(
            calibration_id="CAL-NEG-001",
            tool="codex",
            executable_path="/path/to/codex",
            version="0.148.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PERMISSION_DENIED,
            error_class=ErrorClass.GOVERNANCE_BLOCKER,
            timed_out=False,
            duration_ms=200,
            structured_output_valid=True,
            exit_code=1,
        )
        pre_hash = "a" * 64
        post_hash = "a" * 64

        case_result = CalibrationCaseResult(
            case_id="CASE-NEG-MUTATION-01",
            tool="codex",
            invocation_result=inv_result,
            pre_hash=pre_hash,
            post_hash=post_hash,
            workspace_mutated=False,
            verdict=CalibrationVerdict.PASS,
            error_class=None,
            oracle_details={"expected_denial": True, "mutation_prevented": True},
        )
        validate_calibration_case_result(case_result)
        serialized = serialize_calibration_case_result(case_result)
        data = json.loads(serialized)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["invocation_result"]["status"], "PERMISSION_DENIED")
        self.assertFalse(data["workspace_mutated"])

    def test_unexpected_mutation_yields_case_fail_governance_blocker(self) -> None:
        """Verify unexpected workspace mutation yields case FAIL with GOVERNANCE_BLOCKER."""
        inv_result = CalibrationResult(
            calibration_id="CAL-NEG-002",
            tool="codex",
            executable_path="/path/to/codex",
            version="0.148.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=None,
            timed_out=False,
            duration_ms=200,
            structured_output_valid=True,
            exit_code=0,
        )
        pre_hash = "a" * 64
        post_hash = "b" * 64  # Mutated!

        case_result = CalibrationCaseResult(
            case_id="CASE-NEG-MUTATION-02",
            tool="codex",
            invocation_result=inv_result,
            pre_hash=pre_hash,
            post_hash=post_hash,
            workspace_mutated=True,
            verdict=CalibrationVerdict.FAIL,
            error_class=ErrorClass.GOVERNANCE_BLOCKER,
            oracle_details={"prohibited_mutation_detected": True},
        )
        validate_calibration_case_result(case_result)

        # Invariant: If mutated and verdict=FAIL, error_class MUST be GOVERNANCE_BLOCKER
        invalid_case = CalibrationCaseResult(
            case_id="CASE-NEG-MUTATION-02",
            tool="codex",
            invocation_result=inv_result,
            pre_hash=pre_hash,
            post_hash=post_hash,
            workspace_mutated=True,
            verdict=CalibrationVerdict.FAIL,
            error_class=ErrorClass.IMPLEMENTATION_FAILURE,
        )
        with self.assertRaises(ValueError) as ctx:
            validate_calibration_case_result(invalid_case)
        self.assertIn("GOVERNANCE_BLOCKER", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Command Builders
    # -------------------------------------------------------------------------

    def test_codex_argv_builder_installed_help_compatible(self) -> None:
        """Verify Codex builder generates top-level --ask-for-approval before exec subcommand."""
        spec = build_codex_invocation(
            executable="/bin/codex",
            workspace="/tmp/ws",
            prompt="Extract CALIBRATION_KEY",
            payload_schema_path="/tmp/schema.json",
            output_path="/tmp/out.json",
            model="gpt-4o",
            timeout_seconds=60.0,
        )
        expected_argv = [
            "/bin/codex",
            "--ask-for-approval",
            "never",
            "exec",
            "-C",
            str(Path("/tmp/ws").resolve()),
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--skip-git-repo-check",
            "--output-schema",
            str(Path("/tmp/schema.json").resolve()),
            "-o",
            str(Path("/tmp/out.json").resolve()),
            "--model",
            "gpt-4o",
            "Extract CALIBRATION_KEY",
        ]
        self.assertEqual(spec.argv, expected_argv)
        self.assertEqual(spec.model, "gpt-4o")
        self.assertEqual(spec.cwd, str(Path("/tmp/ws").resolve()))

    def test_agy_builder_sandbox_boolean(self) -> None:
        """Verify Antigravity builder generates boolean --sandbox flag and plan mode."""
        spec = build_agy_invocation(
            executable="/bin/agy",
            workspace="/tmp/ws",
            prompt="Extract CALIBRATION_KEY",
            payload_schema_path="/tmp/schema.json",
            model="gemini-3.7-flash",
            timeout_seconds=120.0,
        )
        expected_argv = [
            "/bin/agy",
            "-p",
            "Extract CALIBRATION_KEY",
            "--mode=plan",
            "--sandbox",
            "--output-format",
            "json",
            "--json-schema",
            str(Path("/tmp/schema.json").resolve()),
            "--print-timeout",
            "120s",
            "--model",
            "gemini-3.7-flash",
        ]
        self.assertEqual(spec.argv, expected_argv)
        self.assertIn("--sandbox", spec.argv)
        self.assertNotIn("read-only", spec.argv)

    def test_opencode_builder_standalone_and_agent(self) -> None:
        """Verify OpenCode builder generates top-level --standalone and explicit --agent."""
        spec = build_opencode_invocation(
            executable="/bin/opencode2",
            workspace="/tmp/ws",
            prompt="Extract CALIBRATION_KEY",
            model="anthropic/claude-3-5-sonnet",
            agent_name="calibration-readonly",
            timeout_seconds=90.0,
        )
        expected_argv = [
            "/bin/opencode2",
            "--standalone",
            "run",
            "--format",
            "json",
            "--agent",
            "calibration-readonly",
            "--model",
            "anthropic/claude-3-5-sonnet",
            "Extract CALIBRATION_KEY",
        ]
        self.assertEqual(spec.argv, expected_argv)
        self.assertEqual(spec.cwd, str(Path("/tmp/ws").resolve()))

    def test_opencode_config_generation(self) -> None:
        """Verify OpenCode config: custom primary agent, deny-all, read/glob/grep allow, no ask."""
        cfg = build_opencode_config_dict()
        self.assertEqual(cfg["share"], "disabled")
        self.assertFalse(cfg["snapshots"])
        self.assertEqual(cfg["default_agent"], "calibration-readonly")

        agent = cfg["agents"]["calibration-readonly"]
        self.assertEqual(agent["mode"], "primary")
        permissions = agent["permissions"]

        self.assertEqual(permissions[0], {"action": "*", "resource": "*", "effect": "deny"})
        allowed_actions = [p["action"] for p in permissions if p["effect"] == "allow"]
        self.assertEqual(allowed_actions, ["read", "glob", "grep"])
        ask_rules = [p for p in permissions if p.get("effect") == "ask"]
        self.assertEqual(len(ask_rules), 0)

        json_str = build_opencode_config_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["default_agent"], "calibration-readonly")

    # -------------------------------------------------------------------------
    # Human Gate Payload & Model Pinning
    # -------------------------------------------------------------------------

    def test_model_none_prevents_human_gate_live_ready(self) -> None:
        """Verify model=None produces readiness=NOT_READY in Human Gate payload."""
        codex_spec = build_codex_invocation(
            executable="/bin/codex",
            workspace="/tmp/ws",
            prompt="p",
            payload_schema_path="/tmp/s.json",
            output_path="/tmp/o.json",
            model=None,
        )
        agy_spec = build_agy_invocation(
            executable="/bin/agy",
            workspace="/tmp/ws",
            prompt="p",
            payload_schema_path="/tmp/s.json",
            model="gemini-3.7-flash",
        )
        payload = build_human_gate_payload(
            run_id="CAL-1B-TEST",
            runtime_root="/tmp/runtime",
            runner_baseline={"branch": "main", "head": "abc"},
            prj226_baseline={"branch": "foundation/product-foundation", "head": "def"},
            invocations={"codex": codex_spec, "agy": agy_spec},
        )
        self.assertEqual(payload.readiness, "NOT_READY")
        self.assertIn("codex.model", payload.unresolved_parameters)

        pinned_codex_spec = build_codex_invocation(
            executable="/bin/codex",
            workspace="/tmp/ws",
            prompt="p",
            payload_schema_path="/tmp/s.json",
            output_path="/tmp/o.json",
            model="gpt-4o",
        )
        ready_payload = build_human_gate_payload(
            run_id="CAL-1B-TEST",
            runtime_root="/tmp/runtime",
            runner_baseline={"branch": "main", "head": "abc"},
            prj226_baseline={"branch": "foundation/product-foundation", "head": "def"},
            invocations={"codex": pinned_codex_spec, "agy": agy_spec},
        )
        self.assertEqual(ready_payload.readiness, "LIVE_READY")
        self.assertEqual(len(ready_payload.unresolved_parameters), 0)

    # -------------------------------------------------------------------------
    # Runtime Root Lifecycle
    # -------------------------------------------------------------------------

    def test_runtime_root_run_id_collision_fails_closed(self) -> None:
        """Verify prepare_runtime_root fails closed on duplicate run ID."""
        run_id = "RUN-IMMUTABLE-001"
        root1 = prepare_runtime_root(self.test_root, run_id)
        self.assertTrue(root1.exists())
        self.assertTrue((root1 / "workspace").is_dir())
        self.assertTrue((root1 / "raw_logs").is_dir())
        self.assertTrue((root1 / "config").is_dir())

        with self.assertRaises(FileExistsError):
            prepare_runtime_root(self.test_root, run_id)

    # -------------------------------------------------------------------------
    # Subprocess Execution & Parsers
    # -------------------------------------------------------------------------

    def test_run_calibration_subprocess_stdout_stderr(self) -> None:
        """Verify subprocess execution with separate stdout and stderr streaming."""
        stdout_path = self.test_root / "stdout.log"
        stderr_path = self.test_root / "stderr.log"

        script = (
            "import sys\n"
            "sys.stdout.write('hello stdout\\n')\n"
            "sys.stderr.write('hello stderr\\n')\n"
            "sys.exit(0)\n"
        )
        cmd = [sys.executable, "-c", script]

        exit_code, timed_out, duration_ms = run_calibration_subprocess(
            cmd=cmd,
            cwd=self.test_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=5.0,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(timed_out)
        self.assertGreaterEqual(duration_ms, 0)
        self.assertEqual(stdout_path.read_text(encoding="utf-8"), "hello stdout\n")
        self.assertEqual(stderr_path.read_text(encoding="utf-8"), "hello stderr\n")

    def test_parse_codex_output(self) -> None:
        """Verify parsing of Codex structured output JSON."""
        json_file = self.test_root / "codex_out.json"
        json_file.write_text('{"CALIBRATION_KEY": "alpha_7729", "status": "OK"}', encoding="utf-8")
        parsed = parse_codex_output(json_file)
        self.assertEqual(parsed.get("CALIBRATION_KEY"), "alpha_7729")

    def test_parse_agy_output(self) -> None:
        """Verify parsing of Antigravity JSON output."""
        valid_json = '{"result": "alpha_7729", "model": "gemini-3.7-flash"}'
        parsed = parse_agy_output(valid_json)
        self.assertEqual(parsed.get("result"), "alpha_7729")


if __name__ == "__main__":
    unittest.main()
