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
    # Environment & Fixture Management
    # -------------------------------------------------------------------------

    def test_build_subprocess_env(self) -> None:
        """Verify subprocess environment copying and explicit overrides."""
        orig_val = os.environ.get("PATH", "")
        env = build_subprocess_env({"CUSTOM_OVERRIDE": "test_value_123"})
        self.assertEqual(env.get("PATH"), orig_val)
        self.assertEqual(env.get("CUSTOM_OVERRIDE"), "test_value_123")
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

    # -------------------------------------------------------------------------
    # NB-003: Deterministic Relative Directory Hashing
    # -------------------------------------------------------------------------

    def test_hash_directory_tree_relative_invariants(self) -> None:
        """Verify directory tree hashing is strictly relative path and content invariant."""
        root_a = self.test_root / "root_a"
        root_b = self.test_root / "root_b"
        root_a.mkdir()
        root_b.mkdir()

        # Same relative paths + same bytes under two different temporary roots -> same hash
        (root_a / "sub").mkdir()
        (root_a / "sub" / "file1.txt").write_text("content 1", encoding="utf-8")
        (root_a / "file2.txt").write_text("content 2", encoding="utf-8")

        (root_b / "sub").mkdir()
        (root_b / "sub" / "file1.txt").write_text("content 1", encoding="utf-8")
        (root_b / "file2.txt").write_text("content 2", encoding="utf-8")

        hash_a = hash_directory_tree(root_a)
        hash_b = hash_directory_tree(root_b)
        self.assertEqual(hash_a, hash_b)

        # Change file bytes -> different hash
        (root_b / "file2.txt").write_text("modified content 2", encoding="utf-8")
        hash_modified_bytes = hash_directory_tree(root_b)
        self.assertNotEqual(hash_a, hash_modified_bytes)

        # Rename/change relative path while preserving bytes -> different hash
        root_c = self.test_root / "root_c"
        root_c.mkdir()
        (root_c / "sub").mkdir()
        (root_c / "sub" / "file1.txt").write_text("content 1", encoding="utf-8")
        (root_c / "file2_renamed.txt").write_text("content 2", encoding="utf-8")
        hash_renamed_path = hash_directory_tree(root_c)
        self.assertNotEqual(hash_a, hash_renamed_path)

    # -------------------------------------------------------------------------
    # Subprocess & NB-002 Process Reaping
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

    def test_run_calibration_subprocess_timeout_and_reap(self) -> None:
        """Verify process-group termination, timeout flag, and child reaping upon timeout."""
        stdout_path = self.test_root / "stdout.log"
        stderr_path = self.test_root / "stderr.log"

        script = "import time; time.sleep(10)\n"
        cmd = [sys.executable, "-c", script]

        exit_code, timed_out, duration_ms = run_calibration_subprocess(
            cmd=cmd,
            cwd=self.test_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=0.2,
        )

        self.assertTrue(timed_out)
        self.assertIsNotNone(exit_code)
        self.assertGreaterEqual(duration_ms, 150)

    def test_run_calibration_subprocess_process_tree_cleanup(self) -> None:
        """Verify subprocess group cleanup when child spawns grandchild processes."""
        stdout_path = self.test_root / "stdout.log"
        stderr_path = self.test_root / "stderr.log"

        script = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])\n"
            "time.sleep(10)\n"
        )
        cmd = [sys.executable, "-c", script]

        exit_code, timed_out, duration_ms = run_calibration_subprocess(
            cmd=cmd,
            cwd=self.test_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=0.2,
        )

        self.assertTrue(timed_out)
        self.assertIsNotNone(exit_code)

    # -------------------------------------------------------------------------
    # Parsers
    # -------------------------------------------------------------------------

    def test_parse_codex_output(self) -> None:
        """Verify parsing of Codex structured output JSON."""
        json_file = self.test_root / "codex_out.json"
        json_file.write_text('{"CALIBRATION_KEY": "alpha_7729", "status": "OK"}', encoding="utf-8")
        parsed = parse_codex_output(json_file)
        self.assertEqual(parsed.get("CALIBRATION_KEY"), "alpha_7729")

        raw_str = '{"extracted": "token_xyz"}'
        parsed_str = parse_codex_output(raw_str)
        self.assertEqual(parsed_str.get("extracted"), "token_xyz")

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

    # -------------------------------------------------------------------------
    # B-001 & B-002: OpenCode Terminal Output Parsing
    # -------------------------------------------------------------------------

    def test_parse_opencode_output_valid_formats(self) -> None:
        """Verify parsing of authorized/supported OpenCode terminal payload formats."""
        # 1. Message event with data payload
        stream1 = (
            '{"type": "init", "session": "s1"}\n'
            '{"type": "step", "index": 1}\n'
            '{"type": "message", "data": {"key": "alpha_7729"}}\n'
        )
        self.assertEqual(parse_opencode_output(stream1), {"key": "alpha_7729"})

        # 2. Message event with message payload
        stream2 = (
            '{"type": "init", "session": "s1"}\n'
            '{"type": "message", "message": {"text": "hello"}}\n'
        )
        self.assertEqual(parse_opencode_output(stream2), {"text": "hello"})

        # 3. Message event with direct fields
        stream3 = '{"type": "message", "result": "val_123"}\n'
        self.assertEqual(parse_opencode_output(stream3), {"result": "val_123"})

        # 4. Event wrapper with payload dict
        stream4 = '{"event": "message", "payload": {"token": "beta_123"}}\n'
        self.assertEqual(parse_opencode_output(stream4), {"token": "beta_123"})

        # 5. Terminal/final_response event with data dict
        stream5 = '{"type": "final_response", "data": {"status": "success"}}\n'
        self.assertEqual(parse_opencode_output(stream5), {"status": "success"})

    def test_parse_opencode_output_invalid_and_incomplete_streams(self) -> None:
        """Verify rejection of empty, malformed, init-only, and intermediate-only streams."""
        # Empty stream
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output("")
        self.assertIn("empty", str(ctx.exception).lower())

        with self.assertRaises(ValueError):
            parse_opencode_output("   \n\n  ")

        # Malformed JSON
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output('{"type": "init"}\nnot valid json\n')
        self.assertIn("malformed", str(ctx.exception).lower())

        # Init-only stream (B-001 defect)
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output('{"type": "init", "session": "s1"}\n')
        self.assertIn("no recognized terminal", str(ctx.exception).lower())

        # Intermediate-only stream with no final response
        intermediate_stream = (
            '{"type": "init", "session": "s1"}\n'
            '{"type": "thought", "content": "thinking..."}\n'
            '{"type": "tool_call", "name": "read_file"}\n'
        )
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output(intermediate_stream)
        self.assertIn("no recognized terminal", str(ctx.exception).lower())

        # Syntactically valid but unsupported event stream
        unsupported_stream = '{"type": "custom_unsupported_event", "foo": "bar"}\n'
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output(unsupported_stream)
        self.assertIn("no recognized terminal", str(ctx.exception).lower())

        # Final event missing required payload dictionary
        empty_message = '{"type": "message"}\n'
        with self.assertRaises(ValueError) as ctx:
            parse_opencode_output(empty_message)
        self.assertIn("no recognized terminal", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # NB-004: CalibrationResult Invariants & Serialization
    # -------------------------------------------------------------------------

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
            exit_code=0,
            stdout_artifact="/tmp/stdout.log",
            stderr_artifact="/tmp/stderr.log",
            model="default-model",
            extracted_payload={"key": "alpha_7729"},
        )
        validate_calibration_result(valid_result)

        serialized = serialize_calibration_result(valid_result)
        data = json.loads(serialized)
        self.assertEqual(data["calibration_id"], "CAL-TEST-001")
        self.assertEqual(data["status"], "PASS")
        self.assertIsNone(data["error_class"])
        self.assertEqual(data["exit_code"], 0)
        self.assertEqual(data["stdout_artifact"], "/tmp/stdout.log")

    def test_validate_calibration_result_invariants_failures(self) -> None:
        """Verify rejection of contradictory or invalid CalibrationResult fields."""
        base_kwargs = {
            "calibration_id": "CAL-TEST-001",
            "tool": "codex",
            "executable_path": "/path/to/codex",
            "version": "1.0.0",
            "working_dir": "/tmp/workspace",
            "status": CalibrationStatus.PASS,
            "error_class": None,
            "timed_out": False,
            "duration_ms": 100,
            "structured_output_valid": True,
            "exit_code": 0,
        }

        # 1. PASS cannot have error_class
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "error_class": ErrorClass.AGENT_EXECUTION_ERROR})
            )

        # 2. PASS cannot have timed_out=True
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "timed_out": True})
            )

        # 3. PASS cannot have non-zero exit_code
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "exit_code": 1})
            )

        # 4. Non-PASS requires error_class
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "status": CalibrationStatus.TASK_FAILURE, "error_class": None})
            )

        # 5. Negative duration
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "duration_ms": -1})
            )

        # 6. Empty required identifiers
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "calibration_id": "  "})
            )
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "tool": ""})
            )
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "executable_path": ""})
            )
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "version": ""})
            )
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "working_dir": ""})
            )

        # 7. Blank artifact path strings when present
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "stdout_artifact": "   "})
            )
        with self.assertRaises(ValueError):
            validate_calibration_result(
                CalibrationResult(**{**base_kwargs, "stderr_artifact": ""})
            )

    # -------------------------------------------------------------------------
    # NB-005: Tool Discovery Portability
    # -------------------------------------------------------------------------

    def test_discover_tools_synthetic_and_custom_paths(self) -> None:
        """Verify discover_tools uses portable resolution and custom paths without hardcoded paths."""
        fake_bin = self.test_root / "fake_tool"
        fake_bin.write_text(f"#!{sys.executable}\nprint('fake_tool v2.5.0')\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        discovered = discover_tools(
            custom_paths={"mock_tool": str(fake_bin)},
            tool_names=["mock_tool"],
        )
        self.assertIn("mock_tool", discovered)
        self.assertEqual(discovered["mock_tool"].version, "fake_tool v2.5.0")
        self.assertEqual(discovered["mock_tool"].executable_path, str(fake_bin.resolve()))

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
