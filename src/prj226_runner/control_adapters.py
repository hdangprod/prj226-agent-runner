"""Controlled role execution adapters for the frozen CTRL-R002A runtime."""

from __future__ import annotations

import hashlib
import inspect
import json
import math
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
import prj226_runner.control_runtime as control_runtime
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
    invocation_id_in_context: bool = True
    semantic_result: dict[str, Any] | None = None


_ROLE_NAMES = {"planner", "builder", "reviewer"}
ROLE_CONTEXT_LIMITS: dict[str, int] = {
    "planner": 256 * 1024,
    "builder": 1024 * 1024,
    "reviewer": 512 * 1024,
}
SEMANTIC_RESULT_MAX_BYTES = 64 * 1024

SAFE_INFORMATIONAL_TYPES = {
    "agent_message",
    "assistant",
    "user",
    "system",
    "message",
    "reasoning",
    "text",
    "output_text",
    "input_text",
    "usage",
    "token_count",
    "model",
    "session_meta",
    "turn_context",
    "event_msg",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
}

LIFECYCLE_ENVELOPE_TYPES = {
    "thread.started",
    "thread.completed",
    "turn.started",
    "turn.completed",
    "item.started",
    "item.completed",
    "item.updated",
    "response.created",
    "response.completed",
}

_MUTATION_TYPES = frozenset({
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
})
ENVELOPE_TYPES = {
    "item.started",
    "item.completed",
    "item.updated",
    "turn.started",
    "turn.completed",
    "thread.started",
    "thread.completed",
    "turn_context",
    "event_msg",
}
SAFE_ITEM_TYPES = {
    "token_count",
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
}
AUTHORITY_ITEM_TYPES = {
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
    "tool_call",
    "mcp_tool_call",
    "function_call",
    "function_call_output",
}
KNOWN_SAFE = frozenset(ENVELOPE_TYPES | SAFE_ITEM_TYPES)
KNOWN_AUTHORITY = frozenset(AUTHORITY_ITEM_TYPES)
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
_COMMAND_KEYS = {"command", "cmd", "argv", "args", "script", "shell_command"}
_AUTHORITY_STRUCTURE_KEYS = _COMMAND_KEYS | _PATH_KEYS | {
    "arguments",
    "file",
    "file_name",
    "filename",
    "function",
    "function_call",
    "function_name",
    "tool",
    "tool_call",
    "tool_name",
}
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
    alternatives = schema.get("oneOf")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not alternatives:
            raise ArtifactValidationError(f"{label} schema is invalid")
        matches = 0
        for alternative in alternatives:
            if not isinstance(alternative, Mapping):
                raise ArtifactValidationError(f"{label} schema is invalid")
            try:
                _manual_schema_check(value, alternative, label)
            except ArtifactValidationError:
                continue
            matches += 1
        if matches != 1:
            raise ArtifactValidationError(f"invalid {label}")
        return
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
    try:
        control_runtime._validate_profile(role_name, profile, verify_executable=False)
    except ArtifactValidationError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ArtifactValidationError("role profile is invalid") from exc


def _context_limit(role_name: str, profile: Mapping[str, Any]) -> int:
    policy = profile.get("policy")
    context_policy = policy.get("context_policy") if isinstance(policy, Mapping) else None
    if context_policy != "frozen-task-context":
        raise ArtifactValidationError(f"unsupported context policy: {context_policy}")
    return ROLE_CONTEXT_LIMITS[role_name]


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


_AUTHORITY_COMMAND_KEYS = {"command", "cmd", "argv", "args"}
_AUTHORITY_KEY_FRAGMENTS = (
    "command",
    "cmd",
    "shell",
    "exec",
    "argv",
    "args",
    "tool",
    "function",
    "call",
    "patch",
    "write",
    "edit",
    "action",
    "script",
)
_AUTHORITY_TYPE_FRAGMENTS = ("write", "patch", "edit", "delete", "exec", "tool")
_PATH_MUTATION_KEYS = frozenset({"path", "file_path", "target_path"})
_CONTENT_CHANGE_KEY_FRAGMENTS = ("content", "change", "diff")
_TOOL_INVOCATION_NAME_HINTS = frozenset({
    "apply_patch",
    "bash",
    "command",
    "delete",
    "edit",
    "exec",
    "execute",
    "grep",
    "mkdir",
    "move",
    "patch",
    "python",
    "read_file",
    "remove",
    "rename",
    "rmdir",
    "run",
    "search",
    "shell",
    "sh",
    "touch",
    "write_file",
})


def _non_empty_string_or_list(value: Any) -> bool:
    return (isinstance(value, str) and bool(value)) or (isinstance(value, list) and bool(value))


def _non_empty_authority_value(value: Any) -> bool:
    """Return whether a JSON value carries non-empty authority-bearing data."""
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, (dict, list)):
        return bool(value)
    return False


def _type_has_authority(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower()
    return (
        normalized in AUTHORITY_ITEM_TYPES
        or normalized in _MUTATION_TYPES
        or any(fragment in normalized for fragment in _AUTHORITY_TYPE_FRAGMENTS)
    )


def _node_has_authority(node: Any) -> bool:
    """Recursively classify JSON event nodes that carry execution authority.

    This deliberately classifies by structure, rather than by a closed list of
    known event names. Providers can add new envelopes or item types without
    creating a capability-enforcement bypass.
    """
    if isinstance(node, dict):
        has_path = False
        has_content_or_changes = False
        for key, value in node.items():
            normalized_key = str(key).lower()
            if normalized_key == "type" and _type_has_authority(value):
                return True
            if any(fragment in normalized_key for fragment in _AUTHORITY_KEY_FRAGMENTS):
                if _non_empty_authority_value(value):
                    return True
            if normalized_key in _PATH_MUTATION_KEYS and _non_empty_authority_value(value):
                has_path = True
            if any(fragment in normalized_key for fragment in _CONTENT_CHANGE_KEY_FRAGMENTS):
                if _non_empty_authority_value(value):
                    has_content_or_changes = True
        if has_path and has_content_or_changes:
            return True
        return any(_node_has_authority(value) for value in node.values())
    if isinstance(node, list):
        return any(_node_has_authority(value) for value in node)
    return False


_SAFE_INFORMATIONAL_STRUCTURE_KEYS = frozenset({
    "content",
    "data",
    "delta",
    "details",
    "info",
    "item",
    "items",
    "metadata",
    "meta",
    "output",
    "payload",
    "parts",
    "response",
    "value",
})


def _is_safe_informational_type(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower()
    return (
        normalized in KNOWN_SAFE
        or normalized.startswith("turn.")
        or normalized.startswith("thread.")
        or normalized.startswith("content_block_")
    )


def _is_primitive_scalar(value: Any) -> bool:
    return type(value) in (str, int, float, bool) or value is None


def _is_primitive_tree(value: Any) -> bool:
    if _is_primitive_scalar(value):
        return True
    if isinstance(value, dict):
        return all(_is_primitive_tree(child) for child in value.values())
    if isinstance(value, list):
        return all(_is_primitive_tree(child) for child in value)
    return False


def _is_safe_informational_key(key: Any) -> bool:
    normalized = str(key).lower()
    return (
        normalized in KNOWN_SAFE
        or normalized in _SAFE_INFORMATIONAL_STRUCTURE_KEYS
        or normalized.startswith("content_block")
    )


def _is_builder_safe_informational_node(node: Any) -> bool:
    """Retain the builder's pre-existing informational-event validation."""
    if _is_primitive_scalar(node):
        return True
    if isinstance(node, list):
        return all(_is_builder_safe_informational_node(child) for child in node)
    if not isinstance(node, dict):
        return False

    for key, value in node.items():
        normalized_key = str(key).lower()
        if normalized_key == "type":
            if not _is_primitive_scalar(value):
                return False
            # Unknown type names remain compatible when all other fields are
            # scalar or proven informational by the checks below.
            continue
        if _is_primitive_scalar(value):
            continue
        if not _is_safe_informational_key(key):
            return False
        if normalized_key in {"metadata", "meta"} and _is_primitive_tree(value):
            continue
        if not _is_builder_safe_informational_node(value):
            return False
    return True


_EXECUTION_INDICATOR_KEY_TOKENS = (
    "tool",
    "func",
    "cmd",
    "command",
    "shell",
    "exec",
    "script",
    "call",
    "patch",
    "write",
    "remove",
    "delete",
    "action",
    "file",
    "path",
    "directory",
    "cwd",
    "workdir",
    "rename",
    "move",
    "mkdir",
    "rmdir",
)
_EXECUTION_INDICATOR_KEY_NAMES = frozenset({
    "argv",
    "args",
    "arguments",
    "parameters",
})
_INTERPRETER_OR_EXECUTOR_NAME_HINTS = frozenset({
    "apply_patch",
    "bash",
    "bun",
    "cargo",
    "cmd",
    "command",
    "csh",
    "deno",
    "delete",
    "edit",
    "exec",
    "execute",
    "fish",
    "git",
    "go",
    "grep",
    "java",
    "ksh",
    "make",
    "mkdir",
    "move",
    "node",
    "nodejs",
    "patch",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "read_file",
    "remove",
    "rename",
    "ruby",
    "run",
    "rmdir",
    "search",
    "sh",
    "shell",
    "tcsh",
    "touch",
    "write_file",
    "zsh",
})


def _key_indicates_execution(key: Any) -> bool:
    normalized = str(key).casefold()
    return normalized in _EXECUTION_INDICATOR_KEY_NAMES or any(
        token in normalized for token in _EXECUTION_INDICATOR_KEY_TOKENS
    )


def _name_indicates_interpreter_or_executor(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    raw = value.strip().lower()

    # Normalize paths before comparing executable names. This catches both
    # POSIX and Windows paths, as well as common executable extensions and
    # version suffixes such as ``python3.12`` and ``node20``.
    basename = raw.replace("\\", "/").rstrip("/").split("/")[-1]
    basename_no_ext = re.sub(r"\.(exe|bat|cmd|sh)$", "", basename)
    basename_no_ver = re.sub(r"[\d\._-]+$", "", basename_no_ext)

    if (
        raw in _INTERPRETER_OR_EXECUTOR_NAME_HINTS
        or basename in _INTERPRETER_OR_EXECUTOR_NAME_HINTS
        or basename_no_ext in _INTERPRETER_OR_EXECUTOR_NAME_HINTS
        or basename_no_ver in _INTERPRETER_OR_EXECUTOR_NAME_HINTS
    ):
        return True

    return any(
        token in raw
        for token in (
            "tool",
            "exec",
            "command",
            "shell",
            "script",
            "function",
            "call",
            "executor",
            "action",
        )
    )


def _is_safe_informational_node(node: Any) -> bool:
    """Return whether a node is structurally known-safe informational data.

    Planner and reviewer events use a closed allowlist. Unknown typed nodes are
    never made safe by scalar children, and untyped dictionaries may contain
    only recursively safe values without authority-bearing keys.
    """
    if _is_primitive_scalar(node):
        return True
    if isinstance(node, list):
        return all(_is_safe_informational_node(child) for child in node)
    if not isinstance(node, dict):
        return False

    canonical_keys: dict[str, Any] = {}
    for key in node:
        canonical_key = str(key).casefold()
        if canonical_key in canonical_keys:
            return False
        canonical_keys[canonical_key] = key
    if len(canonical_keys) != len(node):
        return False

    if any(_key_indicates_execution(key) for key in node):
        return False

    if "type" in canonical_keys:
        raw_type = node[canonical_keys["type"]]
        if not isinstance(raw_type, str) or not raw_type.strip():
            return False
        normalized_type = raw_type.strip().lower()
        if (
            normalized_type not in SAFE_INFORMATIONAL_TYPES
            and normalized_type not in LIFECYCLE_ENVELOPE_TYPES
        ):
            return False

        for canonical_key, original_key in canonical_keys.items():
            if canonical_key == "type":
                continue
            value = node[original_key]
            if (
                canonical_key == "name"
                and _name_indicates_interpreter_or_executor(value)
            ):
                return False
            if not _is_safe_informational_node(value):
                return False
        return True

    if "name" in canonical_keys:
        value = node[canonical_keys["name"]]
        if _name_indicates_interpreter_or_executor(value):
            return False

    return all(_is_safe_informational_node(value) for value in node.values())


def _name_indicates_tool_invocation(node: Mapping[str, Any], value: Any) -> bool:
    if not _non_empty_string_or_list(value):
        return False
    if any(str(key).lower() in _AUTHORITY_COMMAND_KEYS | {
        "arguments",
        "function",
        "function_call",
        "parameters",
        "tool",
        "tool_call",
    } for key in node):
        return True
    return isinstance(value, str) and value.strip().lower() in _TOOL_INVOCATION_NAME_HINTS


def _event_has_authority_indicator(event: dict[str, Any]) -> bool:
    for node in _iter_dicts(event):
        for key, value in node.items():
            normalized_key = str(key).lower()
            if normalized_key in _AUTHORITY_COMMAND_KEYS and _non_empty_string_or_list(value):
                return True
            if normalized_key in {"tool", "function"} and _non_empty_string_or_list(value):
                return True
            if normalized_key == "name" and _name_indicates_tool_invocation(node, value):
                return True
    return False


def _event_has_authority_structure(event: dict[str, Any]) -> bool:
    for node in _iter_dicts(event):
        if any(str(key).lower() in _AUTHORITY_STRUCTURE_KEYS for key in node):
            return True
    return False


def _event_has_only_primitive_values(event: dict[str, Any]) -> bool:
    def primitive(value: Any) -> bool:
        if type(value) in (str, int, float, bool) or value is None:
            return True
        if isinstance(value, dict):
            return all(primitive(child) for child in value.values())
        if isinstance(value, list):
            return all(primitive(child) for child in value)
        return False

    return primitive(event)


def _unknown_mutation_event(event: dict[str, Any], types: set[str]) -> bool:
    normalized = {value.lower() for value in types}
    unknown = normalized - KNOWN_SAFE - KNOWN_AUTHORITY
    if not normalized:
        unknown.add("")
    if not unknown:
        return False
    if _event_has_authority_structure(event):
        return True
    return not _event_has_only_primitive_values(event)


def _mutation_types(types: set[str]) -> set[str]:
    return {value.lower() for value in types if value.lower() in _MUTATION_TYPES}


def _authority_types(types: set[str]) -> set[str]:
    return {value.lower() for value in types if value.lower() in AUTHORITY_ITEM_TYPES}


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


def _observe_builder_command_confinement(command: str, workspace: Path, executable: str) -> bool:
    """HEURISTIC OBSERVABILITY ONLY. Not proven filesystem enforcement.

    Final scope authority belongs to Runner/R3C.
    """
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
    if role_name in ("planner", "reviewer"):
        breach = (
            "PLANNER_CAPABILITY_BREACH"
            if role_name == "planner"
            else "REVIEWER_CAPABILITY_BREACH"
        )
        for event in events:
            if not _is_safe_informational_node(event):
                raise GovernanceBlockerError(breach)
        return

    workspace = cwd.resolve()
    for event in events:
        if _node_has_authority(event):
            _validate_authority_event(
                role_name,
                event,
                _authority_types(_event_types(event)),
                workspace,
                executable,
            )
            continue
        if not _is_builder_safe_informational_node(event):
            raise GovernanceBlockerError("UNRECOGNIZED_MUTATION_EVENT")


def _validate_authority_event(
    role_name: str,
    event: dict[str, Any] | list[Any],
    authority_types: set[str],
    workspace: Path,
    executable: str,
) -> None:
    if role_name == "planner":
        raise GovernanceBlockerError("PLANNER_CAPABILITY_BREACH")
    if role_name == "reviewer":
        raise GovernanceBlockerError("REVIEWER_CAPABILITY_BREACH")
    if role_name != "builder":
        return

    event_mapping = event if isinstance(event, dict) else {"items": event}
    mutations = _mutation_types(authority_types)
    command_values = list(_commands(event_mapping))
    command_texts = [text for command in command_values for text in _command_texts(command)]
    if "command_execution" in mutations and not command_texts:
        raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
    if any(not list(_command_texts(command)) for command in command_values):
        raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
    explicit_paths = list(_explicit_paths(event_mapping))
    if mutations - {"command_execution"} and not explicit_paths:
        raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
    if not command_texts and not explicit_paths:
        # An authority-bearing future event is not safe merely because its
        # provider-specific type is unknown. It must expose an observable
        # command or path that can be checked against the candidate workspace.
        raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
    for value in explicit_paths:
        if not _path_inside(value, workspace):
            raise GovernanceBlockerError("BUILDER_CAPABILITY_BREACH")
    for text in command_texts:
        if not _observe_builder_command_confinement(text, workspace, executable):
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


def _exception_supervision(exc: BaseException) -> dict[str, Any] | None:
    """Extract only schema-supported supervision facts from an exception chain."""
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        is_flood = isinstance(current, AgentExecutionError) and (
            "log limit exceeded" in str(current).lower()
            or (
                bool(current.args)
                and "log limit exceeded" in str(current.args[0]).lower()
            )
        )
        evidence = getattr(current, "supervision", None)
        if evidence is None:
            details = getattr(current, "details", None)
            if isinstance(details, dict):
                evidence = details.get("supervision")
        if evidence is not None:
            values: dict[str, Any] = {}
            exit_code = _object_value(evidence, "returncode", _object_value(evidence, "exit_code"))
            if type(exit_code) is int:
                values["exit_code"] = exit_code
            quiescent = _object_value(evidence, "final_group_quiescent")
            if quiescent is None:
                quiescent = _object_value(evidence, "quiescent")
            if quiescent is not None:
                values["quiescent"] = bool(quiescent)
            for key in ("timeout_event", "term_event", "kill_event"):
                observed = _object_value(evidence, key)
                if observed is not None:
                    values[key] = bool(observed)
            values["output_flood"] = is_flood or bool(_object_value(evidence, "output_flood", False))
            return values
        current = current.__cause__ or current.__context__
    return None


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


def _verify_completion_directories(cwd: Path, directory: Path) -> None:
    cwd_path = Path(cwd)
    try:
        cwd_metadata = cwd_path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactValidationError("candidate cwd is unavailable") from exc
    if cwd_path.is_symlink() or not stat.S_ISDIR(cwd_metadata.st_mode):
        raise ArtifactValidationError("candidate cwd must be a regular non-symlink directory")
    try:
        relative = directory.relative_to(cwd_path)
    except ValueError as exc:
        raise ArtifactValidationError("builder completion directory escapes candidate cwd") from exc
    current = cwd_path
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except (FileNotFoundError, OSError) as exc:
            raise ArtifactValidationError("builder completion directory is missing") from exc
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactValidationError("builder completion directory must be a regular non-symlink directory")


def _verify_completion_location(path: Path, cwd: Path) -> Path:
    try:
        root = Path(cwd).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("candidate cwd cannot be resolved") from exc
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("builder completion path cannot be resolved") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArtifactValidationError("builder completion path escapes candidate cwd") from exc
    _verify_completion_directories(Path(cwd), path.parent)
    return resolved


def _governed_completion_path(cwd: Path, invocation_id: str) -> Path:
    completion_dir = Path(cwd) / ".prj226-control"
    _verify_completion_directories(Path(cwd), Path(cwd))
    try:
        try:
            completion_dir.lstat()
        except FileNotFoundError:
            completion_dir.mkdir()
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("builder completion directory is unavailable") from exc
    _verify_completion_directories(Path(cwd), completion_dir)
    return completion_dir / f"{invocation_id}.completion.json"


def _cleanup_completion_path(path: Path, cwd: Path) -> None:
    try:
        _verify_completion_directories(Path(cwd), path.parent)
    except (ArtifactValidationError, OSError):
        return
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError:
        return
    if metadata is not None:
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return
        try:
            path.unlink()
        except OSError:
            return
    try:
        path.parent.rmdir()
    except OSError:
        pass


def _load_completion(path: Path, invocation_id: str, task_id: str, cwd: Path) -> dict[str, Any]:
    _verify_completion_location(path, cwd)
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
    if value["invocation_id"] != invocation_id or value["task_id"] != task_id:
        raise ArtifactValidationError("builder completion identity mismatch")
    return value


def _completion_data_for_receipt(env: Any, value: Mapping[str, Any]) -> dict[str, Any]:
    summary = env.sanitized(value["summary"])
    provider_output_declaration = env.sanitized(value["provider_output_declaration"])
    if not isinstance(summary, str) or not isinstance(provider_output_declaration, (str, type(None))):
        raise ArtifactValidationError("builder completion output has invalid types")
    sensitive = getattr(env, "_sensitive", ())
    if _contains_sensitive(summary, sensitive) or _contains_sensitive(provider_output_declaration, sensitive):
        raise ArtifactValidationError("builder completion output contains credential material")
    return {
        "status": value["status"],
        "summary": summary,
        "provider_output_declaration": provider_output_declaration,
    }


def _semantic_result_for_events(
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, bool]:
    messages: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        item = event.get("item")
        if (
            isinstance(item, dict)
            and str(item.get("type", "")).lower() == "agent_message"
        ):
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                messages.append(text)
        elif str(event.get("type", "")).lower() == "agent_message":
            text = event.get("text")
            if isinstance(text, str) and text.strip():
                messages.append(text)

    if not messages:
        return None, False

    final_text = messages[-1]
    raw_bytes = final_text.encode("utf-8")
    if len(raw_bytes) > SEMANTIC_RESULT_MAX_BYTES:
        return None, True
    return {
        "kind": "TEXT",
        "text": final_text,
        "message_count": len(messages),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }, False


def _contains_sensitive(value: Any, sensitive: Any) -> bool:
    if isinstance(value, str):
        return any(isinstance(secret, str) and secret and secret in value for secret in sensitive)
    if isinstance(value, dict):
        return any(_contains_sensitive(key, sensitive) or _contains_sensitive(item, sensitive) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive(item, sensitive) for item in value)
    return False


def _validate_evidence_dir(value: Path | str) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError, OSError) as exc:
        raise ArtifactValidationError("evidence_dir must be an explicit existing directory") from exc
    if not path.is_absolute() or ".." in path.parts:
        raise ArtifactValidationError("evidence_dir must not use a relative or traversal path")
    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactValidationError("evidence_dir must be an existing directory") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ArtifactValidationError("evidence_dir must be a regular non-symlink directory")
    try:
        path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("evidence_dir cannot be resolved") from exc
    return path


def _persist_evidence(evidence_dir: Path, invocation_id: str, record: Mapping[str, Any]) -> None:
    target = evidence_dir / f"{invocation_id}.evidence.json"
    temporary: Path | None = None
    try:
        serialized = canonical_json(record)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{invocation_id}.",
            suffix=".tmp",
            dir=str(evidence_dir),
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
        _safe_completion_file(target)
        loaded = json.loads(
            target.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        if loaded != dict(record):
            raise ArtifactValidationError("persisted evidence did not round-trip")
        _validate_with_schema(loaded, "control-invocation.v1.schema.json", "persisted invocation record")
    except ArtifactValidationError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise ArtifactValidationError("evidence persistence failed") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _assert_disposition_invariants(
    disposition: str,
    supervision: Mapping[str, Any],
    attestation: SessionAttestationResult | None,
    completion_record: Mapping[str, Any],
    role_name: str,
    semantic_result: dict[str, Any] | None,
) -> None:
    if disposition != "SUCCESS":
        return
    if supervision.get("quiescent") is not True:
        raise ArtifactValidationError("SUCCESS requires quiescent")
    if supervision.get("timeout_event") is not False:
        raise ArtifactValidationError("SUCCESS requires no timeout")
    if supervision.get("kill_event") is not False:
        raise ArtifactValidationError("SUCCESS requires no kill")
    if supervision.get("output_flood") is not False:
        raise ArtifactValidationError("SUCCESS requires no output flood")
    if attestation is None or attestation.attestation_passed is not True:
        raise ArtifactValidationError("SUCCESS requires attestation passed")
    if completion_record.get("status") != "COMPLETED":
        raise ArtifactValidationError("SUCCESS requires non-blocked completion")
    if role_name in ("planner", "reviewer") and semantic_result is None:
        raise ArtifactValidationError("SUCCESS requires non-null semantic_result for non-builder")


def _tokens_used(attestation: SessionAttestationResult) -> int | None:
    return attestation.tokens_used


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _failure_record(
    *,
    role_name: str,
    invocation_id: str,
    task_id: str,
    profile: Mapping[str, Any],
    context_digest: str,
    started_at: str,
    started_monotonic: float,
    exc: Exception,
    supervision: Mapping[str, Any] | None = None,
    session_id: str | None = None,
    attestation: SessionAttestationResult | None = None,
    env: Any = None,
) -> dict[str, Any]:
    default_supervision = {
        "exit_code": -1,
        "quiescent": False,
        "timeout_event": False,
        "term_event": False,
        "kill_event": False,
        "output_flood": False,
    }
    if supervision is not None:
        default_supervision.update({key: supervision.get(key, value) for key, value in default_supervision.items()})
    observed_session_id = session_id or (attestation.session_id if attestation is not None else "unobserved")
    completion_failure = role_name == "builder" and "completion" in str(exc).lower()
    disposition = "BLOCKED" if isinstance(exc, GovernanceBlockerError) or completion_failure else "FAILED"
    record_without_digest: dict[str, Any] = {
        "schema_version": "PRJ226.CONTROL_INVOCATION.v1",
        "invocation_id": invocation_id,
        "session_id": observed_session_id,
        "task_id": task_id,
        "role": role_name.upper(),
        "runtime_profile_ref": profile["profile_ref"],
        "configured_model": profile["model"],
        "session_model": attestation.session_model if attestation is not None else profile["model"],
        "model_attestation_level": (
            attestation.model_attestation_level if attestation is not None else "RUNTIME_SESSION_BOUND"
        ),
        "provider_effective_model": None,
        "context_digest": context_digest,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "duration_seconds": max(0.0, time.monotonic() - started_monotonic),
        "supervision": default_supervision,
        "attestation": {
            "attestation_passed": False,
            "sqlite_verified": False,
            "rollout_verified": False,
            "tokens_used": None,
        },
        "completion": {
            "status": "BLOCKED",
            "summary": str(exc),
            "provider_output_declaration": None,
        },
        "semantic_result": None,
        "disposition": disposition,
    }
    if env is not None:
        record_without_digest = env.sanitized(record_without_digest)
    if not isinstance(record_without_digest, dict):
        raise ArtifactValidationError("failure evidence record must be an object")
    digest = evidence_digest_for_record(record_without_digest)
    record = dict(record_without_digest)
    record["evidence_digest"] = digest
    _validate_with_schema(record, "control-invocation.v1.schema.json", "failure invocation record")
    return record


def _sanitized_attestation_result(env: Any, attestation: SessionAttestationResult) -> SessionAttestationResult:
    return SessionAttestationResult(
        session_id=env.sanitized(attestation.session_id),
        configured_model=env.sanitized(attestation.configured_model),
        session_model=env.sanitized(attestation.session_model),
        cli_version=env.sanitized(attestation.cli_version),
        tokens_used=attestation.tokens_used,
        model_attestation_level=env.sanitized(attestation.model_attestation_level),
        provider_effective_model=env.sanitized(attestation.provider_effective_model),
        attestation_passed=attestation.attestation_passed,
        rollout_events_count=attestation.rollout_events_count,
    )


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
        evidence_dir: Path | str | None = None,
        timeout: float | None = None,
    ) -> InvocationReceipt:
        try:
            role_name = role_name.lower()
        except AttributeError as exc:
            raise ArtifactValidationError("role_name must be planner, builder, or reviewer") from exc
        if role_name not in _ROLE_NAMES:
            raise ArtifactValidationError("role_name must be planner, builder, or reviewer")
        if not isinstance(task_id, str) or not task_id:
            raise ArtifactValidationError("task_id must be a non-empty string")
        if not isinstance(context_bytes, bytes):
            raise ArtifactValidationError("context_bytes must be bytes")
        _validate_profile(role_name, profile)
        if role_name == "planner" and profile["policy"]["sandbox"] != "read-only":
            raise ArtifactValidationError("planner role must use read-only sandbox")
        if role_name == "reviewer" and profile["policy"]["sandbox"] != "read-only":
            raise ArtifactValidationError("reviewer role must use read-only sandbox")
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
                raise ArtifactValidationError("timeout must be a finite positive number")
            profile_timeout = profile["policy"]["timeout_seconds"]
            if timeout > profile_timeout:
                raise ArtifactValidationError(
                    f"timeout override ({timeout}) cannot exceed profile limit ({profile_timeout})"
                )
        evidence_path = _validate_evidence_dir(evidence_dir) if evidence_dir is not None else None
        invocation_id = str(uuid.uuid4())
        context_with_instructions = context_bytes + (
            f"\n\nPRJ226 TASK_ID: {task_id}\n"
            f"PRJ226 INVOCATION_ID: {invocation_id}\n"
            f"PRJ226 COMPLETION_PATH: .prj226-control/{invocation_id}.completion.json\n"
        ).encode("utf-8")
        invocation_id_in_context = invocation_id.encode("utf-8") in context_with_instructions
        context_digest = hashlib.sha256(context_with_instructions).hexdigest()
        started_at = _utc_now()
        started_monotonic = time.monotonic()
        try:
            limit = _context_limit(role_name, profile)
            if limit is not None and len(context_with_instructions) > limit:
                raise ArtifactValidationError("context exceeds role limit")
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
        except Exception as exc:
            if evidence_path is not None:
                _persist_evidence(
                    evidence_path,
                    invocation_id,
                    _failure_record(
                        role_name=role_name,
                        invocation_id=invocation_id,
                        task_id=task_id,
                        profile=profile,
                        context_digest=context_digest,
                        started_at=started_at,
                        started_monotonic=started_monotonic,
                        exc=exc,
                    ),
                )
            raise

        with create_role_environment(auth_source=auth_source) as env:
            completion_path = (
                Path(cwd) / ".prj226-control" / f"{invocation_id}.completion.json"
                if role_name == "builder"
                else None
            )
            session_id: str | None = None
            attestation: SessionAttestationResult | None = None
            supervision: dict[str, Any] | None = None
            supervision_evidence: SupervisionEvidence | None = None
            exit_code = -1
            try:
                if env.codex_home is None:
                    raise AgentExecutionError("isolated environment did not provide CODEX_HOME")
                if role_name == "builder":
                    completion_path = _governed_completion_path(Path(cwd), invocation_id)
                try:
                    result = _run_with_context(
                        self.supervisor,
                        command,
                        context_bytes=context_with_instructions,
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
                if role_name in ("planner", "reviewer"):
                    semantic_result, semantic_result_too_large = _semantic_result_for_events(events)
                else:
                    semantic_result, semantic_result_too_large = None, False
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
                if role_name == "builder" and process_ok:
                    try:
                        completion_data = _completion_data_for_receipt(
                            env,
                            _load_completion(completion_path, invocation_id, task_id, Path(cwd)),
                        )
                    except ArtifactValidationError:
                        completion_data = None

                if semantic_result_too_large:
                    disposition = "BLOCKED"
                    completion_record = {
                        "status": "BLOCKED",
                        "summary": "semantic result exceeds 64 KiB size limit",
                        "provider_output_declaration": None,
                    }
                elif not process_ok:
                    disposition = "FAILED"
                    completion_record = {
                        "status": "BLOCKED",
                        "summary": f"{role_name} execution did not complete successfully",
                        "provider_output_declaration": None,
                    }
                elif role_name in ("planner", "reviewer") and semantic_result is None:
                    disposition = "BLOCKED"
                    completion_record = {
                        "status": "BLOCKED",
                        "summary": "planner/reviewer semantic output is missing or empty",
                        "provider_output_declaration": None,
                    }
                elif role_name == "builder" and completion_data is None:
                    disposition = "BLOCKED"
                    completion_record = {
                        "status": "BLOCKED",
                        "summary": "builder completion artifact is missing or invalid",
                        "provider_output_declaration": None,
                    }
                elif role_name == "builder":
                    completion_record = {
                        "status": completion_data["status"],
                        "summary": completion_data["summary"],
                        "provider_output_declaration": completion_data["provider_output_declaration"],
                    }
                    disposition = "BLOCKED" if completion_data["status"] == "BLOCKED" else "SUCCESS"
                else:
                    completion_record = {
                        "status": "COMPLETED",
                        "summary": f"{role_name} execution completed",
                        "provider_output_declaration": None,
                    }
                    disposition = "SUCCESS"

                completed_at = _utc_now()
                duration_seconds = max(0.0, time.monotonic() - started_monotonic)
                _assert_disposition_invariants(
                    disposition,
                    supervision,
                    attestation,
                    completion_record,
                    role_name,
                    semantic_result,
                )
                record_without_digest: dict[str, Any] = {
                    "schema_version": "PRJ226.CONTROL_INVOCATION.v1",
                    "invocation_id": invocation_id,
                    "session_id": attestation.session_id,
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
                    "semantic_result": semantic_result,
                    "disposition": disposition,
                }
                record_without_digest = env.sanitized(record_without_digest)
                if not isinstance(record_without_digest, dict):
                    raise ArtifactValidationError("evidence record must be an object")
                digest = evidence_digest_for_record(record_without_digest)
                record = dict(record_without_digest)
                record["evidence_digest"] = digest
                _validate_with_schema(record, "control-invocation.v1.schema.json", "invocation record")
                if evidence_path is not None:
                    _persist_evidence(evidence_path, invocation_id, record)

                sanitized_record = env.sanitized(record)
                sanitized_completion_data = env.sanitized(completion_data)
                sanitized_attestation = _sanitized_attestation_result(env, attestation)
                return InvocationReceipt(
                    invocation_id=env.sanitized(invocation_id),
                    session_id=env.sanitized(session_id),
                    task_id=env.sanitized(task_id),
                    role=env.sanitized(role_name.upper()),
                    disposition=env.sanitized(disposition),
                    exit_code=exit_code,
                    supervision_evidence=supervision_evidence,
                    attestation_result=sanitized_attestation,
                    completion_data=sanitized_completion_data,
                    evidence_digest=env.sanitized(digest),
                    record=sanitized_record,
                    invocation_id_in_context=invocation_id_in_context,
                    semantic_result=semantic_result,
                )
            except Exception as exc:
                if evidence_path is not None:
                    failure_supervision = dict(supervision or {})
                    observed_supervision = _exception_supervision(exc)
                    if observed_supervision is not None:
                        failure_supervision.update(observed_supervision)
                    _persist_evidence(
                        evidence_path,
                        invocation_id,
                        _failure_record(
                            role_name=role_name,
                            invocation_id=invocation_id,
                            task_id=task_id,
                            profile=profile,
                            context_digest=context_digest,
                            started_at=started_at,
                            started_monotonic=started_monotonic,
                            exc=exc,
                            supervision=failure_supervision or None,
                            session_id=session_id,
                            attestation=attestation,
                            env=env,
                        ),
                    )
                raise
            finally:
                if completion_path is not None:
                    _cleanup_completion_path(completion_path, Path(cwd))
