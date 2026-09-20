"""Runtime-bound session attestation for controlled Codex invocations."""

from __future__ import annotations

import json
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
    model_attestation_level: str
    provider_effective_model: None
    attestation_passed: bool
    sqlite_row: dict[str, Any]
    rollout_events_count: int
    token_usage: dict[str, Any] | None


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


def _check_session_observation(record: dict[str, Any], session_id: str) -> None:
    """Reject every explicit session identity that disagrees with the target."""
    def candidates(value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from candidates(child)
        elif isinstance(value, list):
            for child in value:
                yield from candidates(child)

    for candidate in candidates(record):
        for key in ("thread_id", "session_id"):
            if key in candidate and candidate[key] != session_id:
                _fail("conflicting session ID")
        if candidate.get("type") == "session_meta":
            payload = candidate.get("payload")
            for payload_candidate in candidates(payload):
                if "id" in payload_candidate and payload_candidate["id"] != session_id:
                    _fail("conflicting session ID")


def _token_usage_from_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a detached token usage object from common rollout shapes."""
    for key in ("info", "token_usage", "tokens", "usage"):
        value = payload.get(key)
        if isinstance(value, dict) and value:
            return dict(value)

    token_fields = {
        key: value
        for key, value in payload.items()
        if key != "type" and ("token" in key.lower() or key in {"input", "output", "total"})
    }
    return token_fields or None


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
    if "cli_version" in sqlite_row and (
        not isinstance(sqlite_row["cli_version"], str) or not sqlite_row["cli_version"]
    ):
        _fail("SQLite CLI version is invalid")
    if sqlite_row["id"] != session_id:
        _fail("SQLite session identity mismatch")
    if sqlite_row["model"] != configured_model:
        _fail("SQLite model does not match configured model")
    if sqlite_row["model_provider"] != expected_provider:
        _fail("SQLite provider does not match expected provider")

    rollout_candidate = _rollout_path(home, sqlite_row["rollout_path"])
    rollout = _require_unique_regular_file(rollout_candidate, "rollout", home / "sessions")

    rollout_events_count = 0
    model_observations = 0
    token_usage: dict[str, Any] | None = None
    try:
        with rollout.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    raise ArtifactValidationError(f"malformed rollout JSONL at line {line_number}")
                record = _parse_rollout_line(line, line_number)
                rollout_events_count += 1
                _check_session_observation(record, session_id)

                if record.get("type") == "turn_context":
                    payload = record.get("payload")
                    if not isinstance(payload, dict) or payload.get("model") != configured_model:
                        _fail("conflicting model observation")
                    model_observations += 1

                if record.get("type") == "event_msg":
                    payload = record.get("payload")
                    if isinstance(payload, dict) and payload.get("type") == "token_count":
                        observed_tokens = _token_usage_from_payload(payload)
                        if observed_tokens is not None:
                            token_usage = observed_tokens
    except ArtifactValidationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ArtifactValidationError("rollout cannot be read") from exc

    if model_observations < 1:
        _fail("missing affirmative model observation in rollout")

    return SessionAttestationResult(
        session_id=session_id,
        configured_model=configured_model,
        session_model=configured_model,
        model_attestation_level="RUNTIME_SESSION_BOUND",
        provider_effective_model=None,
        attestation_passed=True,
        sqlite_row=sqlite_row,
        rollout_events_count=rollout_events_count,
        token_usage=token_usage,
    )
