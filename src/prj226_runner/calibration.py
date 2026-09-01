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

    If an unexpected prohibited mutation occurs, GOVERNANCE_BLOCKER is returned unconditionally.
    Returns None only for PASS when no unexpected mutation occurred.
    """
    if is_unexpected_mutation:
        return ErrorClass.GOVERNANCE_BLOCKER

    if status == CalibrationStatus.PASS:
        return None

    if is_missing_binary:
        return ErrorClass.ENVIRONMENT_ERROR

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

    Traversal ordering sorts explicitly by normalized relative path.
    Hash identity depends strictly on relative path and file bytes, independent
    of absolute root, mtime, or filesystem directory traversal order.
    """
    root = Path(directory_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Directory not found for hashing: {root}")

    hasher = hashlib.sha256()
    # Collect all regular files and sort strictly by relative path string
    file_rel_pairs = [
        (str(p.relative_to(root).as_posix()), p)
        for p in root.rglob("*")
        if p.is_file()
    ]
    file_rel_pairs.sort(key=lambda pair: pair[0])

    for rel_path_str, file_path in file_rel_pairs:
        hasher.update(rel_path_str.encode("utf-8"))
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

    Handles graceful SIGTERM + SIGKILL process-group cleanup on timeout,
    ensuring bounded wait and complete reaping of the spawned child process.
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

        spawned_pid = proc.pid

        try:
            exit_code = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Safely identify the process group created for the spawned child
            try:
                pgid = os.getpgid(spawned_pid)
                # Verify pgid corresponds to child session before signaling group
                if pgid == spawned_pid:
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    proc.terminate()
            except ProcessLookupError:
                pass
            except Exception:
                proc.terminate()

            # Bounded grace period for graceful termination
            grace_start = time.monotonic()
            while time.monotonic() - grace_start < 2.0:
                try:
                    exit_code = proc.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    pass

            # Force kill process group if child is still alive
            if proc.poll() is None:
                try:
                    pgid = os.getpgid(spawned_pid)
                    if pgid == spawned_pid:
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                except Exception:
                    proc.kill()

                # Bounded wait to reap child process
                try:
                    exit_code = proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    # Final poll fallback
                    proc.poll()
                    exit_code = proc.returncode
            else:
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

    Safely parses JSONL, recognizes only explicitly supported terminal payload forms,
    ignores recognized non-terminal/intermediate events (e.g. init, step, thought),
    and rejects malformed JSON, empty streams, init-only streams, or streams with no
    recognized terminal payload.

    Raises ValueError if event stream is malformed or contains no terminal payload.
    """
    stripped = raw_json_events.strip()
    if not stripped:
        raise ValueError("OpenCode output is empty")

    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if not lines:
        raise ValueError("OpenCode output contains no non-empty lines")

    terminal_payload: dict[str, Any] | None = None

    for line in lines:
        try:
            event = json.loads(line)
        except Exception as e:
            raise ValueError(f"OpenCode output contains malformed JSON line: {line}") from e

        if not isinstance(event, dict):
            continue

        event_type = event.get("type") or event.get("event")

        # Explicitly supported terminal / final response message formats
        if event_type == "message":
            # Candidate payload forms under message event
            candidate = event.get("data") if "data" in event else (
                event.get("message") if "message" in event else event.get("payload")
            )
            if isinstance(candidate, dict):
                terminal_payload = candidate
            elif candidate is None and isinstance(event, dict):
                # If message event itself has direct payload fields
                payload_subset = {k: v for k, v in event.items() if k not in ("type", "event")}
                if payload_subset:
                    terminal_payload = payload_subset
        elif "payload" in event and isinstance(event["payload"], dict):
            # Direct payload wrapper
            terminal_payload = event["payload"]
        elif "data" in event and isinstance(event["data"], dict) and event_type in ("final_response", "result", "terminal"):
            terminal_payload = event["data"]

    if terminal_payload is None:
        raise ValueError("No recognized terminal response payload found in OpenCode event stream")

    return terminal_payload


def validate_calibration_result(result: CalibrationResult) -> None:
    """
    Programmatically validate CalibrationResult invariants using Python standard library.

    Enforces required non-empty fields, enum memberships, duration bounds, state consistency,
    and valid artifact path representations.
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

    if not isinstance(result.duration_ms, int) or result.duration_ms < 0:
        raise ValueError(f"duration_ms must be a non-negative integer: {result.duration_ms}")

    if result.stdout_artifact is not None:
        if not isinstance(result.stdout_artifact, str) or not result.stdout_artifact.strip():
            raise ValueError("stdout_artifact must be a non-empty string when present")

    if result.stderr_artifact is not None:
        if not isinstance(result.stderr_artifact, str) or not result.stderr_artifact.strip():
            raise ValueError("stderr_artifact must be a non-empty string when present")

    if result.model is not None:
        if not isinstance(result.model, str) or not result.model.strip():
            raise ValueError("model must be a non-empty string when present")

    if result.exit_code is not None and not isinstance(result.exit_code, int):
        raise ValueError("exit_code must be an integer when present")

    if result.status == CalibrationStatus.PASS:
        if result.error_class is not None:
            raise ValueError(f"PASS status must have error_class=None, got {result.error_class}")
        if result.timed_out:
            raise ValueError("PASS status cannot have timed_out=True")
        if result.exit_code is not None and result.exit_code != 0:
            raise ValueError(f"PASS status cannot have non-zero exit_code: {result.exit_code}")
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


def discover_tools(
    custom_paths: Mapping[str, str] | None = None,
    tool_names: list[str] | None = None,
) -> dict[str, ToolSpec]:
    """
    Discover installed CLI tools and retrieve their version information safely.

    Resolves executables dynamically via shutil.which() or explicit absolute paths.
    Does NOT execute model prompts or tasks.
    """
    tools: dict[str, ToolSpec] = {}

    # Target tool names to resolve
    names = tool_names if tool_names is not None else ["codex", "agy", "opencode2"]

    # Candidate lookup map: either custom path or resolution via shutil.which
    candidates: dict[str, str | None] = {}
    for name in names:
        if custom_paths and name in custom_paths:
            candidates[name] = custom_paths[name]
        else:
            resolved = shutil.which(name)
            candidates[name] = resolved

    # Also include any additional custom paths provided
    if custom_paths:
        for name, path in custom_paths.items():
            if name not in candidates:
                candidates[name] = path

    for tool_name, exe_path_or_none in candidates.items():
        if not exe_path_or_none:
            continue
        exe_path = str(Path(exe_path_or_none).resolve())
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
                # Keep first line of version output
                first_line = ver_str.splitlines()[0] if ver_str.splitlines() else "unknown"
                tools[tool_name] = ToolSpec(
                    tool_name=tool_name,
                    executable_path=exe_path,
                    version=first_line,
                )
            except Exception:
                pass

    return tools
