"""Deterministic calibration harness foundation for prj226-agent-runner."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from prj226_runner.models import ErrorClass


class CalibrationStatus(str, Enum):
    """Operational status classifications for calibration invocations."""

    PASS = "PASS"
    TASK_FAILURE = "TASK_FAILURE"
    TOOL_FAILURE = "TOOL_FAILURE"
    TIMEOUT = "TIMEOUT"
    OUTPUT_INVALID = "OUTPUT_INVALID"
    PERMISSION_DENIED = "PERMISSION_DENIED"


@dataclass(frozen=True)
class ToolSpec:
    """Immutable specification of an external agent CLI tool."""

    tool_name: str
    executable_path: str
    version: str
    default_model: str | None = None


@dataclass(frozen=True)
class CalibrationResult:
    """Normalized result record produced by the calibration runner."""

    calibration_id: str
    tool: str
    executable_path: str
    version: str
    working_dir: str
    status: CalibrationStatus
    error_class: ErrorClass | None
    timed_out: bool
    duration_ms: int
    structured_output_valid: bool
    model: str | None = None
    exit_code: int | None = None
    extracted_payload: dict[str, Any] | None = None
    stdout_artifact: str | None = None
    stderr_artifact: str | None = None


def map_status_to_error_class(
    status: CalibrationStatus,
    is_missing_binary: bool = False,
    is_unexpected_mutation: bool = False,
) -> ErrorClass | None:
    """
    Deterministically map operational CalibrationStatus to runner ErrorClass.

    Returns None if status is PASS.
    """
    if status == CalibrationStatus.PASS:
        return None

    if is_missing_binary:
        return ErrorClass.ENVIRONMENT_ERROR

    if is_unexpected_mutation:
        return ErrorClass.GOVERNANCE_BLOCKER

    match status:
        case CalibrationStatus.TIMEOUT:
            return ErrorClass.AGENT_EXECUTION_ERROR
        case CalibrationStatus.OUTPUT_INVALID:
            return ErrorClass.ARTIFACT_VALIDATION_ERROR
        case CalibrationStatus.TASK_FAILURE:
            return ErrorClass.IMPLEMENTATION_FAILURE
        case CalibrationStatus.PERMISSION_DENIED:
            return ErrorClass.GOVERNANCE_BLOCKER
        case CalibrationStatus.TOOL_FAILURE:
            return ErrorClass.AGENT_EXECUTION_ERROR
        case _:
            return ErrorClass.AGENT_EXECUTION_ERROR


def build_subprocess_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """
    Construct child process environment by copying current environment and applying overrides.

    Guarantees that full environment dumps are not serialized or logged.
    """
    env = os.environ.copy()
    if overrides:
        env.update(overrides)
    return env


def copy_fixture_to_workspace(fixture_dir: Path | str, target_dir: Path | str) -> Path:
    """
    Copy files from the committed fixture template into a disposable runtime workspace.

    The tracked fixture template remains untouched.
    """
    src = Path(fixture_dir).resolve()
    dst = Path(target_dir).resolve()
    dst.mkdir(parents=True, exist_ok=True)

    for item in src.rglob("*"):
        rel_path = item.relative_to(src)
        target_path = dst / rel_path
        if item.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        else:
            shutil.copy2(item, target_path)

    return dst


def hash_directory_tree(directory_path: Path | str) -> str:
    """
    Compute a deterministic SHA-256 tree hash of all files within a directory.

    Files are sorted by relative path and hashed deterministically.
    """
    root = Path(directory_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found for hashing: {root}")

    hasher = hashlib.sha256()
    files = sorted([p for p in root.rglob("*") if p.is_file()])

    for file_path in files:
        rel_path_bytes = str(file_path.relative_to(root)).encode("utf-8")
        hasher.update(rel_path_bytes)
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)

    return hasher.hexdigest()


def run_calibration_subprocess(
    cmd: list[str],
    cwd: Path | str,
    stdout_path: Path | str,
    stderr_path: Path | str,
    timeout_seconds: float = 30.0,
    env: dict[str, str] | None = None,
) -> tuple[int | None, bool, int]:
    """
    Execute a child CLI process within an isolated process group.

    Handles graceful SIGTERM + SIGKILL process-group cleanup on timeout.
    Streams stdout and stderr directly to disk files.
    Returns (exit_code, timed_out, duration_ms).
    """
    start_time = time.monotonic()
    timed_out = False
    exit_code: int | None = None

    sub_env = env if env is not None else build_subprocess_env()

    stdout_file = Path(stdout_path)
    stderr_file = Path(stderr_path)
    stdout_file.parent.mkdir(parents=True, exist_ok=True)
    stderr_file.parent.mkdir(parents=True, exist_ok=True)

    with open(stdout_file, "wb") as out_f, open(stderr_file, "wb") as err_f:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=out_f,
            stderr=err_f,
            env=sub_env,
            start_new_session=True,
        )

        try:
            exit_code = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass

            grace_start = time.monotonic()
            while time.monotonic() - grace_start < 2.0:
                if proc.poll() is not None:
                    break
                time.sleep(0.05)

            if proc.poll() is None:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.poll()

            exit_code = proc.returncode

    duration_ms = int((time.monotonic() - start_time) * 1000)
    return exit_code, timed_out, duration_ms


def parse_codex_output(raw_content_or_path: str | Path) -> dict[str, Any]:
    """
    Parse Codex structured JSON output from a file path or raw string.

    Raises ValueError if JSON is malformed or invalid.
    """
    content: str
    target = Path(raw_content_or_path)
    if target.is_file():
        content = target.read_text(encoding="utf-8")
    else:
        content = str(raw_content_or_path)

    if not content.strip():
        raise ValueError("Codex output is empty")

    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("Codex output must be a JSON object")
    return data


def parse_agy_output(raw_stdout: str) -> dict[str, Any]:
    """
    Parse Antigravity JSON output from raw stdout string.

    Raises ValueError if JSON is malformed or invalid.
    """
    text = raw_stdout.strip()
    if not text:
        raise ValueError("Antigravity output is empty")

    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Antigravity output must be a JSON object")
    return data


def parse_opencode_output(raw_json_events: str) -> dict[str, Any]:
    """
    Parse OpenCode event stream and extract the terminal/final response payload.

    Raises ValueError if event stream is malformed or contains no terminal payload.
    """
    lines = [line.strip() for line in raw_json_events.strip().splitlines() if line.strip()]
    if not lines:
        raise ValueError("OpenCode output is empty")

    terminal_payload: dict[str, Any] | None = None

    for line in lines:
        event = json.loads(line)
        if isinstance(event, dict):
            # Check for terminal event or response message
            if event.get("type") == "message" or event.get("event") == "message":
                payload = event.get("data") or event.get("message") or event.get("payload") or event
                if isinstance(payload, dict):
                    terminal_payload = payload
            elif "payload" in event and isinstance(event["payload"], dict):
                terminal_payload = event["payload"]
            elif "data" in event and isinstance(event["data"], dict):
                terminal_payload = event["data"]
            else:
                terminal_payload = event

    if terminal_payload is None:
        raise ValueError("No terminal message event found in OpenCode event stream")

    return terminal_payload


def validate_calibration_result(result: CalibrationResult) -> None:
    """
    Programmatically validate CalibrationResult invariants using Python standard library.

    Enforces required non-empty fields, enum memberships, duration bounds, and state consistency.
    Raises ValueError on validation failure.
    """
    if not isinstance(result.calibration_id, str) or not result.calibration_id.strip():
        raise ValueError("calibration_id must be a non-empty string")

    if not isinstance(result.tool, str) or not result.tool.strip():
        raise ValueError("tool must be a non-empty string")

    if not isinstance(result.executable_path, str) or not result.executable_path.strip():
        raise ValueError("executable_path must be a non-empty string")

    if not isinstance(result.version, str) or not result.version.strip():
        raise ValueError("version must be a non-empty string")

    if not isinstance(result.working_dir, str) or not result.working_dir.strip():
        raise ValueError("working_dir must be a non-empty string")

    if not isinstance(result.status, CalibrationStatus):
        raise ValueError(f"Invalid status: {result.status}")

    if result.duration_ms < 0:
        raise ValueError(f"duration_ms cannot be negative: {result.duration_ms}")

    if result.status == CalibrationStatus.PASS:
        if result.error_class is not None:
            raise ValueError(f"PASS status must have error_class=None, got {result.error_class}")
        if result.timed_out:
            raise ValueError("PASS status cannot have timed_out=True")
    else:
        if result.error_class is None:
            raise ValueError(f"Non-PASS status ({result.status}) must specify error_class")

    if result.timed_out and result.status != CalibrationStatus.TIMEOUT:
        raise ValueError(f"timed_out=True requires status=TIMEOUT, got {result.status}")


def serialize_calibration_result(result: CalibrationResult) -> str:
    """
    Validate and serialize CalibrationResult to formatted JSON string.
    """
    validate_calibration_result(result)
    raw_dict = asdict(result)

    # Convert Enums to string values
    raw_dict["status"] = result.status.value
    raw_dict["error_class"] = result.error_class.value if result.error_class else None

    return json.dumps(raw_dict, indent=2)


def discover_tools(custom_paths: Mapping[str, str] | None = None) -> dict[str, ToolSpec]:
    """
    Discover installed CLI tools and retrieve their version information safely.

    Does NOT execute model prompts or tasks.
    """
    tools: dict[str, ToolSpec] = {}
    paths_to_check = {
        "codex": "/Users/dangnguyen/.nvm/versions/node/v20.5.0/bin/codex",
        "agy": "/Users/dangnguyen/.local/bin/agy",
        "opencode2": "/Users/dangnguyen/.nvm/versions/node/v20.5.0/bin/opencode2",
    }
    if custom_paths:
        paths_to_check.update(custom_paths)

    for tool_name, exe_path in paths_to_check.items():
        if Path(exe_path).is_file() and os.access(exe_path, os.X_OK):
            try:
                res = subprocess.run(
                    [exe_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    check=False,
                )
                ver_str = res.stdout.strip() or res.stderr.strip() or "unknown"
                # Keep first line of version
                first_line = ver_str.splitlines()[0] if ver_str.splitlines() else "unknown"
                tools[tool_name] = ToolSpec(
                    tool_name=tool_name,
                    executable_path=exe_path,
                    version=first_line,
                )
            except Exception:
                pass

    return tools
