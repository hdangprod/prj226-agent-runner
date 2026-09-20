"""Controlled role execution adapters for the frozen CTRL-R002A runtime."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import shlex
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from prj226_runner.control_attestation import SessionAttestationResult, attest_session
from prj226_runner.control_environment import AuthSource, create_role_environment
from prj226_runner.control_runtime import derived_profile_ref
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    GovernanceBlockerError,
)
from prj226_runner.process_supervisor import SupervisedProcessRunner, SupervisionEvidence


@dataclass(frozen=True)
class InvocationReceipt:
    invocation_id: str
    session_id: str | None
    task_id: str
    role: str
    disposition: str
    exit_code: int
    supervision_evidence: SupervisionEvidence
    attestation_result: SessionAttestationResult | None
    completion_data: dict[str, Any] | None
    evidence_digest: str
    record: dict[str, Any]


# The runtime schema is intentionally frozen, but adapters only need the
# fields below to formulate and bind an invocation.  Additional immutable
# profile fields are still included in derived_profile_ref().
_REQUIRED_PROFILE_KEYS = {"role", "provider", "model", "executable", "profile_ref", "policy"}
_ROLE_NAMES = {"planner", "builder", "reviewer"}

_MUTATION_TYPES = {
    "command_execution",
    "file_change",
    "file_write",
    "file_write_tool_call",
    "apply_patch",
    "patch",
    "edit",
    "delete",
    "remove",
    "move",
    "rename",
    "mkdir",
    "rmdir",
}
_SAFE_EVENT_TYPES = {
    "thread.started",
    "thread.completed",
    "turn.started",
    "turn.completed",
    "turn_context",
    "event_msg",
    "token_count",
    "item.started",
    "item.completed",
    "item.updated",
    "agent_message",
    "assistant",
    "user",
    "system",
    "message",
    "reasoning",
    "text",
    "output_text",
    "input_text",
    "error",
    "warning",
    "usage",
    "model",
    "session_meta",
    "response.created",
    "response.output_text",
    "response.completed",
    "response.failed",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "tool_call",
    "mcp_tool_call",
    "function_call",
    "function_call_output",
}
_MUTATION_KEY_WORDS = (
    "file",
    "write",
    "change",
    "patch",
    "edit",
    "delete",
    "remove",
    "rename",
    "move",
    "mkdir",
)
_PATH_KEYS = {
    "path",
    "file_path",
    "target_path",
    "source_path",
    "destination_path",
    "cwd",
    "workdir",
    "working_directory",
    "directory",
}
_COMMAND_KEYS = {"command", "cmd", "argv", "args"}
_PATH_OPTIONS = {
    "-C",
    "--cwd",
    "--workdir",
    "--working-directory",
    "--output",
    "-o",
    "--file",
    "--path",
    "--target",
    "--destination",
    "--source",
}


def canonical_json(value: Any) -> str:
    """Serialize evidence deterministically for hashing and validation."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactValidationError("evidence is not canonical JSON") from exc


def evidence_digest_for_record(record_without_evidence_digest: Mapping[str, Any]) -> str:
    if "evidence_digest" in record_without_evidence_digest:
        raise ArtifactValidationError("record digest input must not contain evidence_digest")
    return hashlib.sha256(canonical_json(dict(record_without_evidence_digest)).encode("utf-8")).hexdigest()


def _reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _schema_path(filename: str) -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / filename


def _load_schema(filename: str) -> dict[str, Any]:
    try:
        value = json.loads(_schema_path(filename).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ArtifactValidationError(f"could not load schema {filename}") from exc
    if not isinstance(value, dict):
        raise ArtifactValidationError(f"schema {filename} is not an object")
    return value


def _validate_with_schema(value: Any, filename: str, label: str) -> None:
    schema = _load_schema(filename)
    try:
        import jsonschema
    except ImportError:
        _manual_schema_check(value, schema, label)
        return
    try:
        jsonschema.Draft7Validator(schema).validate(value)
    except jsonschema.ValidationError as exc:
        raise ArtifactValidationError(f"{label} does not conform to {filename}") from exc


def _manual_schema_check(value: Any, schema: Mapping[str, Any], label: str) -> None:
    """Small dependency-free Draft-07 subset for the two local closed schemas."""
    if not isinstance(schema, Mapping):
        raise ArtifactValidationError(f"{label} schema is invalid")
    if "const" in schema and value != schema["const"]:
        raise ArtifactValidationError(f"invalid {label}")
    if "enum" in schema and value not in schema["enum"]:
        raise ArtifactValidationError(f"invalid {label}")

    type_names = schema.get("type")
    allowed = type_names if isinstance(type_names, list) else ([type_names] if type_names else [])

    def matches(type_name: str) -> bool:
        if type_name == "null":
            return value is None
        if type_name == "object":
            return isinstance(value, dict)
        if type_name == "array":
            return isinstance(value, list)
        if type_name == "string":
            return isinstance(value, str)
        if type_name == "integer":
            return type(value) is int
        if type_name == "number":
            return type(value) in (int, float)
        if type_name == "boolean":
            return type(value) is bool
        return False

    if allowed and not any(matches(type_name) for type_name in allowed):
        raise ArtifactValidationError(f"invalid {label}")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ArtifactValidationError(f"invalid {label}")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            raise ArtifactValidationError(f"invalid {label}")
    if type(value) in (int, float) and "minimum" in schema and value < schema["minimum"]:
        raise ArtifactValidationError(f"invalid {label}")
    if isinstance(value, list) and isinstance(schema.get("items"), Mapping):
        for index, item in enumerate(value):
            _manual_schema_check(item, schema["items"], f"{label}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = set(schema.get("required", ()))
        if not required.issubset(value):
            raise ArtifactValidationError(f"{label} has missing fields")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise ArtifactValidationError(f"{label} has unknown fields")
        for key, rules in properties.items():
            if key in value:
                _manual_schema_check(value[key], rules, f"{label}.{key}")


def _validate_profile(role_name: str, profile: Mapping[str, Any]) -> None:
    if not isinstance(profile, Mapping):
        raise ArtifactValidationError("role profile must be a mapping")
    missing = _REQUIRED_PROFILE_KEYS - set(profile)
    if missing:
        raise ArtifactValidationError("role profile is missing required keys", {"missing": sorted(missing)})
    if profile["role"] != role_name.upper():
        raise ArtifactValidationError("role profile identity does not match role_name")
    for key in ("provider", "model", "executable", "profile_ref"):
        if not isinstance(profile[key], str) or not profile[key]:
            raise ArtifactValidationError(f"role profile {key} must be a non-empty string")
    try:
        expected_ref = derived_profile_ref(profile)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactValidationError("role profile cannot be canonically hashed") from exc
    if profile["profile_ref"] != expected_ref:
        raise ArtifactValidationError("role profile reference does not match canonical profile digest")
    policy = profile["policy"]
    if not isinstance(policy, Mapping):
        raise ArtifactValidationError("role profile policy must be a mapping")
    if policy.get("sandbox") not in {"read-only", "workspace-write"}:
        raise ArtifactValidationError("role profile sandbox policy is invalid")
    timeout = policy.get("timeout_seconds")
    if type(timeout) not in (int, float) or timeout <= 0:
        raise ArtifactValidationError("role profile timeout policy is invalid")


def _context_limit(profile: Mapping[str, Any]) -> int | None:
    names = (
        "context_limit_bytes",
        "max_context_bytes",
        "context_max_bytes",
        "max_context_size",
        "context_limit",
        "max_bytes",
        "limit_bytes",
        "max_size",
    )
    sources: list[Mapping[str, Any]] = [profile]
    policy = profile.get("policy")
    if isinstance(policy, Mapping):
        sources.append(policy)
        context_policy = policy.get("context_policy")
        if isinstance(context_policy, Mapping):
            sources.append(context_policy)
    for source in sources:
        for name in names:
            if name in source:
                value = source[name]
                if type(value) is not int or value < 0:
                    raise ArtifactValidationError("configured context limit is invalid")
                return value
    return None


def _jsonl_events(raw: bytes | str) -> list[dict[str, Any]]:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactValidationError("process stdout is not UTF-8 JSONL") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise ArtifactValidationError("process stdout must be bytes or text")
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ArtifactValidationError(f"process stdout has malformed JSONL at line {line_number}") from exc
        if not isinstance(event, dict):
            raise ArtifactValidationError(f"process event at line {line_number} is not an object")
        events.append(event)
    if not events:
        raise ArtifactValidationError("process stdout contains no JSON events")
    return events


def _iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _event_types(event: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for node in _iter_dicts(event):
        value = node.get("type")
        if isinstance(value, str):
            result.add(value)
    return result


def _event_has_mutation_shape(event: dict[str, Any]) -> bool:
    for node in _iter_dicts(event):
        for key in node:
            lowered = str(key).lower()
            if lowered in {"command", "cmd", "argv", "args"}:
                return True
            if lowered in _PATH_KEYS:
                return True
            if any(word in lowered for word in _MUTATION_KEY_WORDS):
                return True
        for key in ("name", "tool", "function"):
            value = node.get(key)
            if isinstance(value, str) and any(word in value.lower() for word in _MUTATION_KEY_WORDS):
                return True
    return False


def _mutation_types(types: set[str]) -> set[str]:
    return {value.lower() for value in types if value.lower() in _MUTATION_TYPES}


def _unknown_mutation_event(event: dict[str, Any], types: set[str]) -> bool:
    normalized = {value.lower() for value in types}
    unknown = normalized - _SAFE_EVENT_TYPES - _MUTATION_TYPES
    if any(any(word in value.lower() for word in _MUTATION_KEY_WORDS) for value in unknown):
        return True
    if normalized & {"tool_call", "mcp_tool_call", "function_call"} and _event_has_mutation_shape(event):
        return True
    return bool(unknown and _event_has_mutation_shape(event))


def _path_inside(value: Any, workspace: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        candidate = Path(value)
        resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        resolved.relative_to(workspace)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _explicit_paths(event: dict[str, Any]):
    for node in _iter_dicts(event):
        for key, value in node.items():
            if str(key).lower() in _PATH_KEYS:
                if isinstance(value, list):
                    yield from value
                else:
                    yield value


def _commands(event: dict[str, Any]):
    for node in _iter_dicts(event):
        for key, value in node.items():
            if str(key).lower() in _COMMAND_KEYS:
                yield value


def _command_texts(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        yield " ".join(value)


def _command_looks_mutating(command: str) -> bool:
    lowered = command.lower()
    if any(fragment in lowered for fragment in (
        "write_text(",
        "write_bytes(",
        "open(",
        "unlink(",
        "remove(",
        "rename(",
        "replace(",
        "apply_patch",
        "git apply",
        "git checkout",
        "git reset",
        "git clean",
    )):
        return True
    try:
        tokens = shlex.split(command)
    except ValueError:
        return True
    if any(token in {">", ">>", "1>", "1>>", "2>", "2>>"} or token.startswith(">") for token in tokens):
        return True
    return any(token.lower() in {"rm", "mv", "cp", "touch", "mkdir", "rmdir", "chmod", "chown", "install", "tee"} for token in tokens)


def _check_builder_command(command: str, workspace: Path, executable: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens:
        return True
    for index, token in enumerate(tokens):
        if token in _PATH_OPTIONS and index + 1 < len(tokens):
            if not _path_inside(tokens[index + 1], workspace):
                return False
        elif any(token.startswith(option + "=") for option in _PATH_OPTIONS):
            value = token.split("=", 1)[1]
            if not _path_inside(value, workspace):
                return False
        if token in {"cd", "pushd", "popd"} and index + 1 < len(tokens):
            if not _path_inside(tokens[index + 1], workspace):
                return False
        if token.startswith("/") and "://" not in token:
            if index == 0 and (token == executable or token.startswith("/bin/") or token.startswith("/usr/bin/") or token.startswith("/usr/local/bin/")):
                continue
            if not _path_inside(token, workspace):
                return False
        if token.startswith(("../", "..\\", "./", ".\\")) and not _path_inside(token, workspace):
            return False
    # Catch paths embedded in shell snippets such as `python -c open('/tmp/x')`.
    for match in re.findall(r"(?<![A-Za-z0-9_])/(?!/)[^\s'\";|&,)]+", command):
        if "://" not in match and not _path_inside(match.rstrip("."), workspace):
            return False
    for match in re.findall(r"(?<![A-Za-z0-9_])(?:\.\./|\.\\\\)[^\s'\";|&,)]+", command):
        if not _path_inside(match.rstrip("."), workspace):
            return False
    return True


def _validate_capabilities(role_name: str, events: list[dict[str, Any]], cwd: Path, executable: str) -> None:
    workspace = cwd.resolve()
    for event in events:
        types = _event_types(event)
        mutations = _mutation_types(types)
        if _unknown_mutation_event(event, types):
            raise GovernanceBlockerError("UNRECOGNIZED_MUTATION_EVENT")
        if role_name == "planner" and (mutations or _unknown_mutation_event(event, types)):
            raise GovernanceBlockerError("PLANNER_CAPABILITY_BREACH")
        if role_name == "reviewer":
            if mutations & {"file_change", "file_write", "file_write_tool_call", "apply_patch", "patch", "edit", "delete", "remove", "move", "rename", "mkdir", "rmdir"}:
                raise GovernanceBlockerError("REVIEWER_CAPABILITY_BREACH")
            if "command_execution" in mutations:
                command_texts = [text for command in _commands(event) for text in _command_texts(command)]
                if not command_texts or any(_command_looks_mutating(text) for text in command_texts):
                    raise GovernanceBlockerError("REVIEWER_CAPABILITY_BREACH")
        if role_name == "builder":
            command_texts = [text for command in _commands(event) for text in _command_texts(command)]
            if "command_execution" in mutations and not command_texts:
                raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
            explicit_paths = list(_explicit_paths(event))
            if mutations - {"command_execution"} and not explicit_paths:
                raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
            for value in explicit_paths:
                if not _path_inside(value, workspace):
                    raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
            for text in command_texts:
                if not _check_builder_command(text, workspace, executable):
                    raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")


def _session_id_from_events(events: list[dict[str, Any]]) -> str:
    session_id: str | None = None
    for event in events:
        if event.get("type") != "thread.started":
            continue
        observed = event.get("thread_id")
        if not isinstance(observed, str) or not observed:
            raise ArtifactValidationError("thread.started has no valid thread_id")
        if session_id is not None and observed != session_id:
            raise ArtifactValidationError("conflicting session IDs in process events")
        session_id = observed
    if session_id is None:
        raise ArtifactValidationError("process events contain no thread.started session")
    return session_id


def _object_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _supervision_record(result: Any) -> tuple[int, SupervisionEvidence, dict[str, Any]]:
    exit_code = _object_value(result, "returncode", _object_value(result, "exit_code"))
    evidence = _object_value(result, "supervision")
    if type(exit_code) is not int or evidence is None:
        raise AgentExecutionError("supervisor returned incomplete process evidence")
    quiescent = _object_value(evidence, "final_group_quiescent", _object_value(evidence, "quiescent", False))
    values = {
        "exit_code": exit_code,
        "quiescent": bool(quiescent),
        "timeout_event": bool(_object_value(evidence, "timeout_event", False)),
        "term_event": bool(_object_value(evidence, "term_event", False)),
        "kill_event": bool(_object_value(evidence, "kill_event", False)),
        "output_flood": bool(_object_value(result, "output_flood", False)),
    }
    return exit_code, evidence, values


@contextmanager
def _stdin_bytes(payload: bytes):
    """Feed frozen supervisors whose API has no explicit stdin parameter."""
    original_fd = os.dup(0)
    try:
        with tempfile.TemporaryFile() as source:
            source.write(payload)
            source.flush()
            source.seek(0)
            os.dup2(source.fileno(), 0)
            try:
                yield
            finally:
                os.dup2(original_fd, 0)
    finally:
        os.close(original_fd)


def _run_with_context(supervisor: Any, argv: list[str], *, context_bytes: bytes, timeout: float, env: dict[str, str], cwd: str) -> Any:
    run = supervisor.run
    try:
        parameters = inspect.signature(run).parameters
    except (TypeError, ValueError):
        parameters = {}
    accepts_kwargs = any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values())
    if "input" in parameters or accepts_kwargs:
        return run(argv, timeout=timeout, env=env, cwd=cwd, input=context_bytes)
    if "stdin" in parameters:
        return run(argv, timeout=timeout, env=env, cwd=cwd, stdin=context_bytes)
    if "stdin_bytes" in parameters:
        return run(argv, timeout=timeout, env=env, cwd=cwd, stdin_bytes=context_bytes)
    with _stdin_bytes(context_bytes):
        return run(argv, timeout=timeout, env=env, cwd=cwd)


def _safe_completion_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactValidationError("builder completion file is missing") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ArtifactValidationError("builder completion file must be a regular non-symlink file")
    if metadata.st_nlink != 1:
        raise ArtifactValidationError("builder completion file must have exactly one hard link")


def _load_completion(path: Path, invocation_id: str, session_id: str, task_id: str) -> dict[str, Any]:
    _safe_completion_file(path)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactValidationError("builder completion file is malformed") from exc
    if not isinstance(value, dict):
        raise ArtifactValidationError("builder completion must be a JSON object")
    _validate_with_schema(value, "control-builder-completion.v1.schema.json", "builder completion")
    if value["invocation_id"] != invocation_id or value["session_id"] != session_id or value["task_id"] != task_id:
        raise ArtifactValidationError("builder completion identity mismatch")
    return value


def _tokens_used(attestation: SessionAttestationResult) -> int | None:
    def find(value: Any) -> int | None:
        if isinstance(value, dict):
            for key in ("total_tokens", "tokens_used", "total"):
                observed = value.get(key)
                if type(observed) is int and observed >= 0:
                    return observed
            for key in ("total_token_usage", "usage", "info"):
                nested = value.get(key)
                result = find(nested)
                if result is not None:
                    return result
        return None

    observed = find(attestation.token_usage)
    if observed is not None:
        return observed
    row_value = attestation.sqlite_row.get("tokens_used")
    return row_value if type(row_value) is int and row_value >= 0 else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class CodexExecutionAdapter:
    def __init__(self, *, supervisor: SupervisedProcessRunner | None = None) -> None:
        self.supervisor = supervisor or SupervisedProcessRunner()

    def execute_role(
        self,
        *,
        role_name: str,
        profile: Mapping[str, Any],
        task_id: str,
        context_bytes: bytes,
        cwd: Path | str,
        auth_source: AuthSource | None = None,
        completion_output_path: Path | str | None = None,
        timeout: float | None = None,
    ) -> InvocationReceipt:
        if role_name not in _ROLE_NAMES:
            raise ArtifactValidationError("role_name must be planner, builder, or reviewer")
        if not isinstance(task_id, str) or not task_id:
            raise ArtifactValidationError("task_id must be a non-empty string")
        if not isinstance(context_bytes, bytes):
            raise ArtifactValidationError("context_bytes must be bytes")
        _validate_profile(role_name, profile)
        limit = _context_limit(profile)
        if limit is not None and len(context_bytes) > limit:
            raise ArtifactValidationError("context exceeds configured limit")
        if timeout is not None and (type(timeout) not in (int, float) or timeout < 0):
            raise ArtifactValidationError("timeout must be non-negative")

        invocation_id = str(uuid.uuid4())
        context_digest = hashlib.sha256(context_bytes).hexdigest()
        started_at = _utc_now()
        started_monotonic = time.monotonic()
        command = [
            profile["executable"],
            "--ask-for-approval",
            "never",
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--sandbox",
            profile["policy"]["sandbox"],
            "--model",
            profile["model"],
            "-C",
            str(cwd),
            "--json",
            "-",
        ]
        effective_timeout = timeout if timeout is not None else profile["policy"]["timeout_seconds"]

        with create_role_environment(auth_source=auth_source) as env:
            if env.codex_home is None:
                raise AgentExecutionError("isolated environment did not provide CODEX_HOME")
            try:
                result = _run_with_context(
                    self.supervisor,
                    command,
                    context_bytes=context_bytes,
                    timeout=effective_timeout,
                    env=env.environment,
                    cwd=str(cwd),
                )
            except (AgentExecutionError, GovernanceBlockerError, ArtifactValidationError):
                raise
            except Exception as exc:
                raise AgentExecutionError("controlled role execution failed") from exc

            exit_code, supervision_evidence, supervision = _supervision_record(result)
            stdout = _object_value(result, "stdout")
            events = _jsonl_events(stdout)
            _validate_capabilities(role_name, events, Path(cwd), profile["executable"])
            session_id = _session_id_from_events(events)
            attestation = attest_session(env.codex_home, session_id, profile["model"], profile["provider"])

            process_ok = (
                exit_code == 0
                and supervision["quiescent"]
                and not supervision["timeout_event"]
                and not supervision["kill_event"]
                and not supervision["output_flood"]
            )
            completion_data: dict[str, Any] | None = None
            if role_name == "builder" and completion_output_path is not None and process_ok:
                try:
                    completion_data = _load_completion(Path(completion_output_path), invocation_id, session_id, task_id)
                except ArtifactValidationError:
                    completion_data = None

            if not process_ok:
                disposition = "FAILED"
                completion_record = {
                    "status": "BLOCKED",
                    "summary": f"{role_name} execution did not complete successfully",
                    "output_digest": None,
                }
            elif role_name == "builder" and completion_data is None:
                disposition = "BLOCKED"
                completion_record = {
                    "status": "BLOCKED",
                    "summary": "builder completion artifact is missing or invalid",
                    "output_digest": None,
                }
            elif role_name == "builder":
                completion_data = env.sanitized(completion_data)
                completion_record = {
                    "status": completion_data["status"],
                    "summary": completion_data["summary"],
                    "output_digest": completion_data["output_digest"],
                }
                disposition = "BLOCKED" if completion_data["status"] == "BLOCKED" else "SUCCESS"
            else:
                completion_record = {
                    "status": "COMPLETED",
                    "summary": f"{role_name} execution completed",
                    "output_digest": None,
                }
                disposition = "SUCCESS" if process_ok else "FAILED"

            completed_at = _utc_now()
            duration_seconds = max(0.0, time.monotonic() - started_monotonic)
            record_without_digest: dict[str, Any] = {
                "schema_version": "PRJ226.CONTROL_INVOCATION.v1",
                "invocation_id": invocation_id,
                "session_id": session_id,
                "task_id": task_id,
                "role": role_name.upper(),
                "runtime_profile_ref": profile["profile_ref"],
                "configured_model": profile["model"],
                "session_model": attestation.session_model,
                "model_attestation_level": attestation.model_attestation_level,
                "provider_effective_model": None,
                "context_digest": context_digest,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration_seconds,
                "supervision": supervision,
                "attestation": {
                    "attestation_passed": attestation.attestation_passed,
                    "sqlite_verified": True,
                    "rollout_verified": True,
                    "tokens_used": _tokens_used(attestation),
                },
                "completion": completion_record,
                "disposition": disposition,
            }
            record_without_digest = env.sanitized(record_without_digest)
            digest = evidence_digest_for_record(record_without_digest)
            record = dict(record_without_digest)
            record["evidence_digest"] = digest
            _validate_with_schema(record, "control-invocation.v1.schema.json", "invocation record")

            return InvocationReceipt(
                invocation_id=invocation_id,
                session_id=session_id,
                task_id=task_id,
                role=role_name.upper(),
                disposition=disposition,
                exit_code=exit_code,
                supervision_evidence=supervision_evidence,
                attestation_result=attestation,
                completion_data=completion_data,
                evidence_digest=digest,
                record=record,
            )
