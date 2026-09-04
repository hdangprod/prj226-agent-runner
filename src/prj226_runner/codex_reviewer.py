"""The explicit Codex CLI independent reviewer adapter for HARN-002 Repair-2.

This module owns one provider binding only.  It deliberately has no fallback,
retry, repair, merge, push, or provider-selection behavior.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

from prj226_runner.calibration import run_calibration_subprocess
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    ReviewStaleError,
    ReviewerProviderUnavailableError,
    RunnerEnvironmentError,
)
from prj226_runner.paths import get_runner_root


CODEX_REVIEWER_PROVIDER = "OpenAI"
CODEX_REVIEWER_MODEL = "gpt-5.6-luna"
CODEX_REVIEWER_TOOL = "codex"
ZERO_OBJECT_ID = "0" * 40

REVIEW_KEYS = {
    "disposition",
    "reviewed_head",
    "reviewed_tree",
    "security",
    "operability",
    "semantics",
    "architecture",
    "blocking_findings",
    "non_blocking_findings",
}
REVIEW_AXIS_KEYS = {"status", "findings"}
REVIEW_STATUSES = {"PASS", "NEEDS_FIX"}


def _schema_path() -> Path:
    return get_runner_root() / "schemas" / "codex-reviewer-result.schema.json"


def _object_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 40:
        raise ArtifactValidationError(f"{field} must be a 40-character Git object ID")
    normalized = value.lower()
    if any(character not in "0123456789abcdef" for character in normalized):
        raise ArtifactValidationError(f"{field} must be a hexadecimal Git object ID")
    return normalized


def _strict_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ArtifactValidationError(f"{label} must contain exactly the closed reviewer fields")
    return value


def _findings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ArtifactValidationError(f"{field} must be an array of non-empty strings")
    return list(value)


def validate_codex_review(
    value: Mapping[str, Any],
    *,
    expected_head: str | None = None,
    expected_tree: str | None = None,
) -> dict[str, Any]:
    """Validate and normalize the closed Codex reviewer result contract."""
    if not isinstance(value, Mapping):
        raise ArtifactValidationError("Codex reviewer result must be a JSON object")
    data = _strict_object(dict(value), REVIEW_KEYS, "Codex reviewer result")
    disposition = data["disposition"]
    if disposition not in REVIEW_STATUSES:
        raise ArtifactValidationError("Codex reviewer disposition must be PASS or NEEDS_FIX")
    reviewed_head = _object_id(data["reviewed_head"], "reviewed_head")
    reviewed_tree = _object_id(data["reviewed_tree"], "reviewed_tree")
    if expected_head is not None and reviewed_head != _object_id(expected_head, "candidate_head"):
        raise ReviewStaleError("REVIEW_STALE: reviewer output HEAD does not match the immutable candidate")
    if expected_tree is not None and reviewed_tree != _object_id(expected_tree, "candidate_tree"):
        raise ReviewStaleError("REVIEW_STALE: reviewer output TREE does not match the immutable candidate")

    axes: dict[str, dict[str, Any]] = {}
    for axis in ("security", "operability", "semantics", "architecture"):
        axis_data = _strict_object(data[axis], REVIEW_AXIS_KEYS, f"Codex reviewer {axis}")
        if axis_data["status"] not in REVIEW_STATUSES:
            raise ArtifactValidationError(f"Codex reviewer {axis}.status is invalid")
        axes[axis] = {"status": axis_data["status"], "findings": _findings(axis_data["findings"], f"{axis}.findings")}

    blocking = _findings(data["blocking_findings"], "blocking_findings")
    non_blocking = _findings(data["non_blocking_findings"], "non_blocking_findings")
    has_blocking = bool(blocking) or any(axis["status"] == "NEEDS_FIX" for axis in axes.values())
    expected_disposition = "NEEDS_FIX" if has_blocking else "PASS"
    if disposition != expected_disposition:
        raise ArtifactValidationError("Codex reviewer disposition contradicts axis or blocking findings")

    return {
        "disposition": disposition,
        "reviewed_head": reviewed_head,
        "reviewed_tree": reviewed_tree,
        **axes,
        "blocking_findings": blocking,
        "non_blocking_findings": non_blocking,
    }


def parse_codex_reviewer_result(path: Path | str, *, expected_head: str | None = None, expected_tree: str | None = None) -> dict[str, Any]:
    """Read only the Codex final output file and validate its closed schema."""
    target = Path(path)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ArtifactValidationError(f"Codex reviewer final output is missing: {target}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Codex reviewer final output is not valid JSON: {exc.msg}") from exc
    return validate_codex_review(raw, expected_head=expected_head, expected_tree=expected_tree)


def build_codex_reviewer_invocation(
    executable: str,
    workspace: Path | str,
    prompt: str,
    output_schema: Path | str | None = None,
    output_path: Path | str | None = None,
    *,
    model: str = CODEX_REVIEWER_MODEL,
    skip_git_repo_check: bool = False,
) -> list[str]:
    """Build the ordinary `codex exec` argv for the fixed reviewer binding."""
    if model != CODEX_REVIEWER_MODEL:
        raise ArtifactValidationError(f"Codex reviewer model must be exactly {CODEX_REVIEWER_MODEL}")
    schema = Path(output_schema or _schema_path()).resolve()
    result = Path(output_path).resolve() if output_path is not None else None
    if result is None:
        raise ArtifactValidationError("Codex reviewer requires an explicit final output path")
    if not schema.is_file():
        raise RunnerEnvironmentError(f"Codex reviewer output schema is missing: {schema}")
    argv = [
        executable,
        "--ask-for-approval",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "-C",
        str(Path(workspace).resolve()),
        "--sandbox",
        "read-only",
        "--model",
        CODEX_REVIEWER_MODEL,
        "--output-schema",
        str(schema),
        "-o",
        str(result),
    ]
    if skip_git_repo_check:
        argv.append("--skip-git-repo-check")
    argv.append(prompt)
    return argv


_SAFE_INHERITED_ENV = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "CODEX_ACCESS_TOKEN",
    "OPENAI_API_KEY",
}


def build_codex_reviewer_env(
    evidence_dir: Path | str,
    *,
    source_codex_home: Path | str | None = None,
) -> dict[str, str]:
    """Create a clean child environment and copy only the Codex auth file."""
    evidence = Path(evidence_dir).resolve()
    isolated_home = evidence / "codex-home"
    isolated_home.mkdir(parents=True, exist_ok=True)
    source = Path(source_codex_home or os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    source_auth = source / "auth.json"
    destination_auth = isolated_home / "auth.json"
    if source_auth.is_symlink() or source_auth.exists():
        if source_auth.is_symlink() or not source_auth.is_file():
            raise RunnerEnvironmentError("Codex authentication material is not a regular file")
        try:
            shutil.copyfile(source_auth, destination_auth)
            destination_auth.chmod(0o600)
        except OSError as exc:
            raise RunnerEnvironmentError("Unable to copy isolated Codex authentication material") from exc
    child_env = {key: os.environ[key] for key in _SAFE_INHERITED_ENV if key in os.environ}
    child_env["CODEX_HOME"] = str(isolated_home)
    return child_env


def _git(repo: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to execute Git for reviewer binding: {exc}") from exc
    if result.returncode != 0:
        raise RunnerEnvironmentError(f"Reviewer Git binding inspection failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def _assert_candidate(repo: Path, expected_head: str, expected_tree: str, candidate_ref: str | None = None) -> None:
    actual_head = _git(repo, ["rev-parse", "HEAD"]).lower()
    actual_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    if actual_head != expected_head:
        raise ReviewStaleError("REVIEW_STALE: candidate HEAD changed during reviewer execution")
    if actual_tree != expected_tree:
        raise ReviewStaleError("REVIEW_STALE: candidate TREE changed during reviewer execution")
    if _git(repo, ["status", "--porcelain"]):
        raise ReviewStaleError("REVIEW_STALE: reviewer worktree is not clean")
    if candidate_ref is not None:
        ref_head = _git(repo, ["rev-parse", candidate_ref]).lower()
        if ref_head != expected_head:
            raise ReviewStaleError("REVIEW_STALE: candidate reference changed during reviewer execution")


def _run_once(argv: list[str], workspace: Path, evidence_dir: Path, timeout_seconds: int, env: dict[str, str]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / "stdout.log"
    stderr_path = evidence_dir / "stderr.log"
    try:
        exit_code, timed_out, duration_ms = run_calibration_subprocess(
            argv,
            workspace,
            stdout_path,
            stderr_path,
            timeout_seconds,
            env,
        )
    except OSError as exc:
        raise RunnerEnvironmentError(f"Codex reviewer process could not start: {exc}") from exc
    invocation = {
        "argv": argv,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "tool": CODEX_REVIEWER_TOOL,
        "provider": CODEX_REVIEWER_PROVIDER,
        "model": CODEX_REVIEWER_MODEL,
        "sandbox": "read-only",
        "ephemeral": True,
        "ignore_user_config": True,
        "ignore_rules": True,
    }
    try:
        (evidence_dir / "invocation.json").write_text(json.dumps(invocation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to persist Codex reviewer invocation evidence: {exc}") from exc
    if timed_out:
        raise AgentExecutionError(f"Codex reviewer timed out after {timeout_seconds} seconds")
    if exit_code != 0:
        raise AgentExecutionError(f"Codex reviewer process exited with {exit_code}")


def run_codex_startup_probe(
    executable: str,
    evidence_dir: Path | str,
    *,
    timeout_seconds: int,
    output_schema: Path | str | None = None,
    source_codex_home: Path | str | None = None,
) -> dict[str, Any]:
    """Perform exactly one non-review provider startup/config validation."""
    evidence = Path(evidence_dir).resolve()
    workspace = evidence / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    output_path = evidence / "startup-result.json"
    prompt = (
        "STARTUP_PROBE. This is a provider startup/configuration probe only. Do not inspect the workspace, any repository, "
        "or any task. Do not perform a code review. Return exactly the closed reviewer JSON schema with "
        f'disposition PASS, reviewed_head {ZERO_OBJECT_ID}, reviewed_tree {ZERO_OBJECT_ID}, '
        "all four axis statuses PASS, and empty findings arrays."
    )
    argv = build_codex_reviewer_invocation(
        executable,
        workspace,
        prompt,
        output_schema,
        output_path,
        skip_git_repo_check=True,
    )
    try:
        _run_once(argv, workspace, evidence, timeout_seconds, build_codex_reviewer_env(evidence, source_codex_home=source_codex_home))
        probe = parse_codex_reviewer_result(output_path, expected_head=ZERO_OBJECT_ID, expected_tree=ZERO_OBJECT_ID)
    except (AgentExecutionError, RunnerEnvironmentError) as exc:
        raise ReviewerProviderUnavailableError(f"REVIEWER_PROVIDER_UNAVAILABLE: {exc.message}") from exc
    except (ArtifactValidationError, ReviewStaleError) as exc:
        raise ReviewerProviderUnavailableError(f"REVIEWER_PROVIDER_UNAVAILABLE: startup schema probe failed: {exc.message}") from exc
    if probe["disposition"] != "PASS":
        raise ReviewerProviderUnavailableError("REVIEWER_PROVIDER_UNAVAILABLE: startup probe did not pass")
    return {
        "status": "PASS",
        "provider": CODEX_REVIEWER_PROVIDER,
        "model": CODEX_REVIEWER_MODEL,
        "artifact": str(output_path),
    }


def run_codex_review(
    executable: str,
    workspace: Path | str,
    evidence_dir: Path | str,
    *,
    candidate_head: str,
    candidate_tree: str,
    candidate_ref: str | None,
    prompt: str,
    timeout_seconds: int,
    output_schema: Path | str | None = None,
    source_codex_home: Path | str | None = None,
) -> dict[str, Any]:
    """Run exactly one Codex review against an immutable candidate worktree."""
    expected_head = _object_id(candidate_head, "candidate_head")
    expected_tree = _object_id(candidate_tree, "candidate_tree")
    candidate_workspace = Path(workspace).resolve()
    evidence = Path(evidence_dir).resolve()
    _assert_candidate(candidate_workspace, expected_head, expected_tree, candidate_ref)
    output_path = evidence / "raw-result.json"
    argv = build_codex_reviewer_invocation(
        executable,
        candidate_workspace,
        prompt,
        output_schema,
        output_path,
    )
    env = build_codex_reviewer_env(evidence, source_codex_home=source_codex_home)
    _run_once(argv, candidate_workspace, evidence, timeout_seconds, env)
    _assert_candidate(candidate_workspace, expected_head, expected_tree, candidate_ref)
    result = parse_codex_reviewer_result(output_path, expected_head=expected_head, expected_tree=expected_tree)
    normalized_path = evidence / "review.json"
    try:
        normalized_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to persist normalized Codex review artifact: {exc}") from exc
    return {
        "result": result,
        "artifact": str(normalized_path),
        "raw_artifact": str(output_path),
        "invocation": str(evidence / "invocation.json"),
    }


run_codex_reviewer = run_codex_review
