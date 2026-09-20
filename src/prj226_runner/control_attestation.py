"""Runtime-bound session attestation for controlled Codex invocations."""

from __future__ import annotations

import json
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prj226_runner.errors import ArtifactValidationError


@dataclass(frozen=True)
class SessionAttestationResult:
    session_id: str
    configured_model: str
    session_model: str
    cli_version: str
    tokens_used: int | None
    model_attestation_level: str
    provider_effective_model: None
    attestation_passed: bool
    rollout_events_count: int


def _fail(message: str, details: dict[str, Any] | None = None) -> None:
    raise ArtifactValidationError(message, details)


def _resolved_inside(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("attestation path cannot be resolved") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArtifactValidationError("attestation path escapes its allowed root") from exc
    if resolved == root:
        raise ArtifactValidationError("attestation path must be a child of its allowed root")
    return resolved


def _require_unique_regular_file(path: Path, label: str, root: Path | None = None) -> Path:
    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactValidationError(f"{label} is missing") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} must be a regular non-symlink file")
    if metadata.st_nlink != 1:
        _fail(f"{label} must have exactly one hard link")
    if root is None:
        try:
            return path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ArtifactValidationError(f"{label} cannot be resolved") from exc
    return _resolved_inside(path, root)


def _reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _parse_rollout_line(line: str, line_number: int) -> dict[str, Any]:
    try:
        parsed = json.loads(
            line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactValidationError(f"malformed rollout JSONL at line {line_number}") from exc
    if not isinstance(parsed, dict):
        raise ArtifactValidationError(f"rollout record at line {line_number} is not an object")
    return parsed


def _check_session_observation(record: dict[str, Any], session_id: str) -> tuple[int, int]:
    """Return affirmative and contradictory session observations in one record."""
    def candidates(value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from candidates(child)
        elif isinstance(value, list):
            for child in value:
                yield from candidates(child)

    affirmative = 0
    contradictory = 0
    for candidate in candidates(record):
        for key in ("thread_id", "session_id"):
            if key not in candidate:
                continue
            if candidate[key] == session_id:
                affirmative += 1
            else:
                contradictory += 1
        if candidate.get("type") == "session_meta":
            payload = candidate.get("payload")
            if isinstance(payload, dict) and "id" in payload:
                if payload["id"] == session_id:
                    affirmative += 1
                else:
                    contradictory += 1
    if contradictory:
        _fail("conflicting session ID")
    return affirmative, contradictory


def _token_count_from_payload(payload: dict[str, Any]) -> int | None:
    """Extract only a non-negative scalar token count from common rollout shapes."""
    for key in ("total_tokens", "tokens_used", "total"):
        value = payload.get(key)
        if type(value) is int and value >= 0:
            return value
    for key in ("info", "token_usage", "tokens", "usage"):
        value = payload.get(key)
        if isinstance(value, dict):
            observed = _token_count_from_payload(value)
            if observed is not None:
                return observed
    return None


def _rollout_path(codex_home: Path, raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        _fail("SQLite rollout_path is invalid")
    supplied = Path(raw_path)
    candidate = supplied if supplied.is_absolute() else codex_home / supplied
    sessions_root = codex_home / "sessions"
    try:
        sessions_metadata = sessions_root.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ArtifactValidationError("Codex sessions directory is missing") from exc
    if sessions_root.is_symlink() or not stat.S_ISDIR(sessions_metadata.st_mode):
        _fail("Codex sessions directory must be a regular directory")
    try:
        sessions_resolved = sessions_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("Codex sessions directory cannot be resolved") from exc
    try:
        sessions_resolved.relative_to(codex_home)
    except ValueError as exc:
        raise ArtifactValidationError("Codex sessions directory escapes CODEX_HOME") from exc
    # Keep the un-resolved spelling so the caller can still reject a final
    # symlink or hard link with lstat(); the resolved path is only used for
    # containment proof here.
    try:
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(sessions_resolved)
    except (OSError, RuntimeError) as exc:
        raise ArtifactValidationError("rollout cannot be resolved") from exc
    except ValueError as exc:
        raise ArtifactValidationError("rollout path escapes CODEX_HOME/sessions") from exc
    return candidate


def attest_session(
    codex_home: Path | str,
    session_id: str,
    configured_model: str,
    expected_provider: str = "openai",
) -> SessionAttestationResult:
    """Verify the persisted session and rollout against the configured runtime."""
    if not isinstance(session_id, str) or not session_id:
        _fail("session_id must be a non-empty string")
    if not isinstance(configured_model, str) or not configured_model:
        _fail("configured_model must be a non-empty string")
    if not isinstance(expected_provider, str) or not expected_provider:
        _fail("expected_provider must be a non-empty string")

    supplied_home = Path(codex_home)
    try:
        home_metadata = supplied_home.stat()
        if not stat.S_ISDIR(home_metadata.st_mode):
            _fail("CODEX_HOME must be a directory")
        home = supplied_home.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise ArtifactValidationError("CODEX_HOME is unavailable") from exc

    sqlite_path = supplied_home / "state_5.sqlite"
    sqlite_file = _require_unique_regular_file(sqlite_path, "state_5.sqlite", home)

    columns = (
        "id",
        "model",
        "model_provider",
        "cli_version",
        "rollout_path",
        "tokens_used",
        "created_at",
    )
    try:
        connection = sqlite3.connect(f"file:{sqlite_file}?mode=ro", uri=True)
    except (sqlite3.Error, OSError) as exc:
        raise ArtifactValidationError("state_5.sqlite cannot be opened read-only") from exc
    try:
        try:
            rows = connection.execute(
                "SELECT id, model, model_provider, cli_version, rollout_path, tokens_used, created_at "
                "FROM threads WHERE id = ?",
                (session_id,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ArtifactValidationError("state_5.sqlite threads query failed") from exc
    finally:
        connection.close()

    if len(rows) != 1:
        _fail("session identity must match exactly one SQLite row", {"row_count": len(rows)})
    sqlite_row = dict(zip(columns, rows[0]))
    cli_version = sqlite_row["cli_version"]
    if not isinstance(cli_version, str) or re.fullmatch(r"[a-zA-Z0-9._ -]{1,100}", cli_version) is None:
        _fail("invalid cli_version format")
    if sqlite_row["id"] != session_id:
        _fail("SQLite session identity mismatch")
    if sqlite_row["model"] != configured_model:
        _fail("SQLite model does not match configured model")
    if sqlite_row["model_provider"] != expected_provider:
        _fail("SQLite provider does not match expected provider")

    rollout_candidate = _rollout_path(home, sqlite_row["rollout_path"])
    rollout = _require_unique_regular_file(rollout_candidate, "rollout", home / "sessions")

    rollout_events_count = 0
    session_observations = 0
    contradictory_session_observations = 0
    model_observations = 0
    contradictory_model_observations = 0
    rollout_tokens_used: int | None = None
    try:
        with rollout.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    raise ArtifactValidationError(f"malformed rollout JSONL at line {line_number}")
                record = _parse_rollout_line(line, line_number)
                rollout_events_count += 1
                affirmative, contradictory = _check_session_observation(record, session_id)
                session_observations += affirmative
                contradictory_session_observations += contradictory

                if record.get("type") == "turn_context":
                    payload = record.get("payload")
                    if isinstance(payload, dict) and "model" in payload:
                        if payload["model"] == configured_model:
                            model_observations += 1
                        else:
                            contradictory_model_observations += 1

                if record.get("type") == "event_msg":
                    payload = record.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "token_count":
                        observed_tokens = _token_count_from_payload(payload)
                        if observed_tokens is not None:
                            rollout_tokens_used = observed_tokens
    except ArtifactValidationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ArtifactValidationError("rollout cannot be read") from exc

    if contradictory_session_observations:
        _fail("conflicting session ID")
    if session_observations < 1:
        _fail("missing affirmative session observation in rollout")
    if contradictory_model_observations:
        _fail("conflicting model observation")
    if model_observations < 1:
        _fail("missing affirmative model observation in rollout")

    sqlite_tokens_used = sqlite_row["tokens_used"]
    if type(sqlite_tokens_used) is not int or sqlite_tokens_used < 0:
        sqlite_tokens_used = None

    return SessionAttestationResult(
        session_id=session_id,
        configured_model=configured_model,
        session_model=configured_model,
        cli_version=cli_version,
        tokens_used=rollout_tokens_used if rollout_tokens_used is not None else sqlite_tokens_used,
        model_attestation_level="RUNTIME_SESSION_BOUND",
        provider_effective_model=None,
        attestation_passed=True,
        rollout_events_count=rollout_events_count,
    )
