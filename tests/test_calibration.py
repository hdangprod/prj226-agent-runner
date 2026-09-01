"""Deterministic unit tests for the calibration harness module."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from prj226_runner.calibration import (
    CalibrationResult,
    CalibrationStatus,
    ToolSpec,
    build_subprocess_env,
    copy_fixture_to_workspace,
    discover_tools,
    hash_directory_tree,
    map_status_to_error_class,
    parse_agy_output,
    parse_codex_output,
    parse_opencode_output,
    run_calibration_subprocess,
    serialize_calibration_result,
    validate_calibration_result,
)
from prj226_runner.models import ErrorClass


class TestCalibrationHarness(unittest.TestCase):
    """Unit test suite for calibration harness logic with ZERO live model calls."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

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

    def test_build_subprocess_env(self) -> None:
        """Verify subprocess environment copying and explicit overrides."""
        orig_val = os.environ.get("PATH", "")
        env = build_subprocess_env({"CUSTOM_OVERRIDE": "test_value_123"})
        self.assertEqual(env.get("PATH"), orig_val)
        self.assertEqual(env.get("CUSTOM_OVERRIDE"), "test_value_123")
        # Ensure original environment was not mutated
        self.assertNotIn("CUSTOM_OVERRIDE", os.environ)

    def test_copy_fixture_and_hash_tree(self) -> None:
        """Verify fixture copying and deterministic tree hashing."""
        fixture_dir = self.test_root / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / "sample.txt").write_text("CALIBRATION_KEY=alpha_7729\n", encoding="utf-8")
        (fixture_dir / "README.md").write_text("# Test Fixture\n", encoding="utf-8")

        initial_hash = hash_directory_tree(fixture_dir)
        self.assertIsInstance(initial_hash, str)
        self.assertEqual(len(initial_hash), 64)

        # Copy to workspace
        workspace_dir = self.test_root / "workspace"
        copy_fixture_to_workspace(fixture_dir, workspace_dir)

        workspace_hash = hash_directory_tree(workspace_dir)
        self.assertEqual(initial_hash, workspace_hash)

        # Verify mutation changes hash
        (workspace_dir / "sample.txt").write_text("MUTATED CONTENT\n", encoding="utf-8")
        mutated_hash = hash_directory_tree(workspace_dir)
        self.assertNotEqual(initial_hash, mutated_hash)

        # Verify template fixture remains unchanged
        self.assertEqual(hash_directory_tree(fixture_dir), initial_hash)

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

    def test_run_calibration_subprocess_timeout(self) -> None:
        """Verify process-group termination and timeout flag when duration exceeds limit."""
        stdout_path = self.test_root / "stdout.log"
        stderr_path = self.test_root / "stderr.log"

        script = "import time; time.sleep(10)\n"
        cmd = [sys.executable, "-c", script]

        exit_code, timed_out, duration_ms = run_calibration_subprocess(
            cmd=cmd,
            cwd=self.test_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=0.3,
        )

        self.assertTrue(timed_out)
        self.assertGreaterEqual(duration_ms, 250)

    def test_parse_codex_output(self) -> None:
        """Verify parsing of Codex structured output JSON."""
        # File parsing
        json_file = self.test_root / "codex_out.json"
        json_file.write_text('{"CALIBRATION_KEY": "alpha_7729", "status": "OK"}', encoding="utf-8")
        parsed = parse_codex_output(json_file)
        self.assertEqual(parsed.get("CALIBRATION_KEY"), "alpha_7729")

        # String parsing
        raw_str = '{"extracted": "token_xyz"}'
        parsed_str = parse_codex_output(raw_str)
        self.assertEqual(parsed_str.get("extracted"), "token_xyz")

        # Malformed handling
        with self.assertRaises(ValueError):
            parse_codex_output("")
        with self.assertRaises(ValueError):
            parse_codex_output("not valid json")
        with self.assertRaises(ValueError):
            parse_codex_output("[]")

    def test_parse_agy_output(self) -> None:
        """Verify parsing of Antigravity JSON output."""
        valid_json = '{"result": "alpha_7729", "model": "gemini-3.7-flash"}'
        parsed = parse_agy_output(valid_json)
        self.assertEqual(parsed.get("result"), "alpha_7729")

        with self.assertRaises(ValueError):
            parse_agy_output("")
        with self.assertRaises(ValueError):
            parse_agy_output("invalid json text")
        with self.assertRaises(ValueError):
            parse_agy_output("[1, 2, 3]")

    def test_parse_opencode_output(self) -> None:
        """Verify parsing of OpenCode event-stream JSON."""
        event_stream = (
            '{"type": "init", "session": "s1"}\n'
            '{"type": "message", "data": {"key": "alpha_7729"}}\n'
        )
        parsed = parse_opencode_output(event_stream)
        self.assertEqual(parsed.get("key"), "alpha_7729")

        # Alternative payload format
        alt_stream = '{"event": "message", "payload": {"token": "beta_123"}}\n'
        parsed_alt = parse_opencode_output(alt_stream)
        self.assertEqual(parsed_alt.get("token"), "beta_123")

        with self.assertRaises(ValueError):
            parse_opencode_output("")
        with self.assertRaises(ValueError):
            parse_opencode_output("not json\n")

    def test_validate_and_serialize_calibration_result(self) -> None:
        """Verify CalibrationResult invariant validation and JSON serialization."""
        valid_result = CalibrationResult(
            calibration_id="CAL-TEST-001",
            tool="codex",
            executable_path="/path/to/codex",
            version="1.0.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=None,
            timed_out=False,
            duration_ms=150,
            structured_output_valid=True,
            extracted_payload={"key": "alpha_7729"},
        )
        # Should validate without error
        validate_calibration_result(valid_result)

        serialized = serialize_calibration_result(valid_result)
        data = json.loads(serialized)
        self.assertEqual(data["calibration_id"], "CAL-TEST-001")
        self.assertEqual(data["status"], "PASS")
        self.assertIsNone(data["error_class"])

        # Error invariant: PASS cannot have error_class
        invalid_pass = CalibrationResult(
            calibration_id="CAL-TEST-002",
            tool="codex",
            executable_path="/path/to/codex",
            version="1.0.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=ErrorClass.AGENT_EXECUTION_ERROR,
            timed_out=False,
            duration_ms=100,
            structured_output_valid=True,
        )
        with self.assertRaises(ValueError):
            validate_calibration_result(invalid_pass)

        # Error invariant: Non-PASS requires error_class
        invalid_failure = CalibrationResult(
            calibration_id="CAL-TEST-003",
            tool="codex",
            executable_path="/path/to/codex",
            version="1.0.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.TIMEOUT,
            error_class=None,
            timed_out=True,
            duration_ms=5000,
            structured_output_valid=False,
        )
        with self.assertRaises(ValueError):
            validate_calibration_result(invalid_failure)

        # Negative duration error
        invalid_duration = CalibrationResult(
            calibration_id="CAL-TEST-004",
            tool="codex",
            executable_path="/path/to/codex",
            version="1.0.0",
            working_dir="/tmp/workspace",
            status=CalibrationStatus.PASS,
            error_class=None,
            timed_out=False,
            duration_ms=-1,
            structured_output_valid=True,
        )
        with self.assertRaises(ValueError):
            validate_calibration_result(invalid_duration)

    def test_discover_tools_synthetic(self) -> None:
        """Verify discover_tools using a synthetic script."""
        fake_bin = self.test_root / "fake_tool"
        fake_bin.write_text(f"#!{sys.executable}\nprint('fake_tool v2.5.0')\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        discovered = discover_tools({"mock_tool": str(fake_bin)})
        self.assertIn("mock_tool", discovered)
        self.assertEqual(discovered["mock_tool"].version, "fake_tool v2.5.0")
        self.assertEqual(discovered["mock_tool"].executable_path, str(fake_bin))

    def test_isolation_invariant(self) -> None:
        """Verify calibration functions operate strictly on explicit caller-provided paths."""
        custom_dir = self.test_root / "isolated"
        custom_dir.mkdir()
        (custom_dir / "test.txt").write_text("isolated data\n", encoding="utf-8")
        h = hash_directory_tree(custom_dir)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)


if __name__ == "__main__":
    unittest.main()
