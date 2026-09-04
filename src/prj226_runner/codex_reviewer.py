"""The explicit Codex CLI independent reviewer adapter for HARN-002 Repair-4/5.

This module owns one provider binding only.  It deliberately has no fallback,
retry, repair, merge, push, or provider-selection behavior.
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, replace
from contextlib import contextmanager
import ntpath
from pathlib import Path
from typing import Any, Iterator, Mapping

from prj226_runner.calibration import run_calibration_subprocess
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    ReviewStaleError,
    RunnerEnvironmentError,
    WorktreeIntegrityError,
)
from prj226_runner.paths import get_runner_root


CODEX_REVIEWER_PROVIDER = "OpenAI"
CODEX_REVIEWER_MODEL = "gpt-5.6-luna"
CODEX_REVIEWER_TOOL = "codex"
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024

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


@dataclass(frozen=True)
class ArtifactSnapshot:
    """The bytes, digest, and semantic value from one opened artifact."""

    raw_bytes: bytes
    sha256: str
    value: Any = None

    @property
    def bytes(self) -> bytes:
        """Compatibility spelling for callers that need the exact byte snapshot."""
        return self.raw_bytes


def _safe_evidence_relative_path(value: str, field: str = "evidence path") -> str:
    """Validate a portable, root-relative evidence locator before opening it."""
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ArtifactValidationError(f"{field} must be a non-empty safe relative path")
    # Evidence locators use POSIX separators even when the runner is inspected
    # on another platform.  Reject Windows drive/UNC syntax explicitly rather
    # than relying on the host platform's Path implementation.
    drive, _ = ntpath.splitdrive(value)
    if drive or value.startswith(("/", "\\")) or "\\" in value:
        raise ArtifactValidationError(f"{field} must be root-relative")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ArtifactValidationError(f"{field} contains an unsafe path component")
    return "/".join(components)


class EvidenceRoot:
    """One trusted directory descriptor used for all reads in an operation.

    The root is opened once with no-follow semantics.  Every later component
    is opened relative to the already-open parent descriptor, so a symlink in
    any intermediate directory cannot escape the authorized evidence root.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        label: str = "Evidence root",
        failure_type: type[Exception] = ArtifactValidationError,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(root)))
        self.label = label
        self.failure_type = failure_type
        self._descriptor: int | None = None

    def _fail(self, message: str) -> None:
        raise self.failure_type(message)

    def __enter__(self) -> "EvidenceRoot":
        if not self.path.is_absolute():
            self._fail(f"{self.label} must be an absolute directory")
        required = ("O_NOFOLLOW", "O_DIRECTORY")
        if any(not hasattr(os, name) for name in required) or os.open not in getattr(os, "supports_dir_fd", set()):
            self._fail(f"{self.label} requires descriptor-relative no-follow filesystem primitives")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_DIRECTORY
        try:
            descriptor = os.open(os.fspath(self.path), flags)
            info = os.fstat(descriptor)
        except OSError as exc:
            self._fail(f"{self.label} cannot be opened as a trusted directory: {self.path}")
            raise AssertionError("unreachable") from exc
        if not stat.S_ISDIR(info.st_mode):
            os.close(descriptor)
            self._fail(f"{self.label} is not a directory: {self.path}")
        self._descriptor = descriptor
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            except OSError:
                pass
            self._descriptor = None

    def _root_fd(self) -> int:
        if self._descriptor is None:
            self._fail(f"{self.label} is not open")
        return self._descriptor  # type: ignore[return-value]

    def relative(self, value: str, field: str = "evidence path") -> str:
        return _safe_evidence_relative_path(value, field)

    def absolute_path(self, relative: str) -> Path:
        """Return a lexical path for APIs that require a worktree pathname."""
        return self.path / self.relative(relative)

    def _open_relative(self, relative: str, *, final_directory: bool) -> int:
        components = self.relative(relative)
        parent = os.dup(self._root_fd())
        try:
            for component in components.split("/")[:-1]:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_DIRECTORY
                try:
                    child = os.open(component, flags, dir_fd=parent)
                except OSError as exc:
                    self._fail(f"{self.label} path component cannot be opened safely: {relative}")
                    raise AssertionError("unreachable") from exc
                os.close(parent)
                parent = child
            final_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            if final_directory:
                final_flags |= os.O_DIRECTORY
            try:
                descriptor = os.open(components.split("/")[-1], final_flags, dir_fd=parent)
            except OSError as exc:
                self._fail(f"{self.label} path cannot be opened safely: {relative}")
                raise AssertionError("unreachable") from exc
            return descriptor
        finally:
            try:
                os.close(parent)
            except OSError:
                pass

    @contextmanager
    def directory(self, relative: str, field: str = "evidence directory") -> Iterator[int]:
        descriptor = self._open_relative(relative, final_directory=True)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                self._fail(f"{field} must be a directory: {relative}")
            yield descriptor
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def validate_directory(self, relative: str, field: str = "evidence directory") -> None:
        with self.directory(relative, field):
            return

    def snapshot(
        self,
        relative: str,
        *,
        label: str = "Evidence",
        max_bytes: int | None = MAX_ARTIFACT_BYTES,
        require_single_link: bool = True,
    ) -> ArtifactSnapshot:
        descriptor = self._open_relative(relative, final_directory=False)
        try:
            try:
                before = os.fstat(descriptor)
            except OSError as exc:
                self._fail(f"{label} metadata cannot be captured: {relative}")
                raise AssertionError("unreachable") from exc
            if not stat.S_ISREG(before.st_mode):
                self._fail(f"{label} must reference a regular file: {relative}")
            if require_single_link and before.st_nlink != 1:
                self._fail(f"{label} must have exactly one hard link: {relative}")
            if max_bytes is not None and before.st_size > max_bytes:
                self._fail(f"{label} exceeds the bounded snapshot size: {relative}")

            data = bytearray()
            while True:
                try:
                    chunk = os.read(descriptor, 1024 * 1024)
                except OSError as exc:
                    self._fail(f"{label} cannot be read: {relative}")
                    raise AssertionError("unreachable") from exc
                if not chunk:
                    break
                data.extend(chunk)
                if max_bytes is not None and len(data) > max_bytes:
                    self._fail(f"{label} exceeds the bounded snapshot size: {relative}")

            try:
                after = os.fstat(descriptor)
            except OSError as exc:
                self._fail(f"{label} metadata cannot be captured after read: {relative}")
                raise AssertionError("unreachable") from exc
            before_identity = (
                before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode), before.st_nlink,
                before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode),
                before.st_uid, before.st_gid,
            )
            after_identity = (
                after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode), after.st_nlink,
                after.st_size, after.st_mtime_ns, stat.S_IMODE(after.st_mode),
                after.st_uid, after.st_gid,
            )
            if before_identity != after_identity or len(data) != before.st_size:
                self._fail(f"{label} changed during snapshot acquisition: {relative}")
            raw_bytes = bytes(data)
            return ArtifactSnapshot(raw_bytes, hashlib.sha256(raw_bytes).hexdigest())
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def list_directory(self, relative: str, field: str = "evidence directory") -> list[str]:
        with self.directory(relative, field) as descriptor:
            try:
                names = os.listdir(descriptor)
            except OSError as exc:
                self._fail(f"{field} cannot be listed safely: {relative}")
                raise AssertionError("unreachable") from exc
        return sorted(names)


def read_artifact_snapshot(path: Path | str) -> ArtifactSnapshot:
    """Capture exact bytes and SHA-256 from one no-follow regular-file open."""
    target = Path(path)
    root_path = Path(os.path.abspath(os.fspath(target.parent)))
    with EvidenceRoot(root_path, label="Artifact parent root") as root:
        return root.snapshot(target.name, label="Artifact")


def _git_admin_paths(workspace: Path) -> set[str]:
    """Return only the worktree-local Git admin entry that must be ignored.

    A linked worktree has a ``.git`` *file*, while a primary worktree normally
    has a ``.git`` directory.  The common Git directory is outside the
    worktree and therefore cannot appear in this fingerprint.  We deliberately
    do not ignore arbitrary dot files, ignored paths, or directories.
    """
    admin: set[str] = set()
    git_entry = workspace / ".git"
    try:
        info = os.lstat(git_entry)
    except FileNotFoundError:
        return admin
    except OSError as exc:
        raise WorktreeIntegrityError(f"Unable to inspect reviewer worktree Git admin entry: {git_entry}") from exc
    if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
        admin.add(".git")
    else:
        raise WorktreeIntegrityError("WORKTREE_UNSUPPORTED_NODE: unsupported filesystem node at .git")
    return admin


def build_worktree_fingerprint_manifest(worktree: Path | str) -> list[dict[str, Any]]:
    """Build a deterministic, non-following filesystem manifest.

    The manifest intentionally describes directory entries as well as files.
    That makes empty-directory creation/deletion observable.  ``lstat`` and
    ``readlink`` ensure that symlink targets are recorded without traversing
    them.  Git's local administrative entry is the sole excluded path.
    """
    root = Path(worktree).absolute()
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Reviewer worktree is not accessible: {root}") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise RunnerEnvironmentError(f"Reviewer worktree is not a directory: {root}")
    admin = _git_admin_paths(root)
    manifest: list[dict[str, Any]] = []
    bound_root = EvidenceRoot(root, label="Reviewer worktree root", failure_type=WorktreeIntegrityError)

    def visit(directory: Path, relative_directory: str = "") -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise RunnerEnvironmentError(f"Unable to fingerprint reviewer worktree: {directory}") from exc
        for entry in entries:
            relative = f"{relative_directory}/{entry.name}" if relative_directory else entry.name
            if relative in admin or relative.startswith(".git/"):
                continue
            path = directory / entry.name
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise RunnerEnvironmentError(f"Unable to fingerprint reviewer worktree path: {relative}") from exc
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISREG(info.st_mode):
                raw_bytes = bound_root.snapshot(
                    relative,
                    label=f"Unable to fingerprint reviewer worktree file {relative}",
                    max_bytes=None,
                    require_single_link=False,
                ).raw_bytes
                manifest.append({"path": relative, "type": "file", "mode": mode, "sha256": hashlib.sha256(raw_bytes).hexdigest()})
            elif stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(path)
                except OSError as exc:
                    raise RunnerEnvironmentError(f"Unable to read reviewer worktree symlink: {relative}") from exc
                manifest.append({"path": relative, "type": "symlink", "mode": mode, "target": target})
            elif stat.S_ISDIR(info.st_mode):
                manifest.append({"path": relative, "type": "directory", "mode": mode})
                visit(path, relative)
            else:
                raise WorktreeIntegrityError(
                    f"WORKTREE_UNSUPPORTED_NODE: unsupported filesystem node at {relative}"
                )

    with bound_root:
        visit(root)
    return sorted(manifest, key=lambda item: (str(item["path"]), str(item["type"])))


def fingerprint_worktree(worktree: Path | str) -> str:
    """Return the SHA-256 identity of the normalized worktree manifest."""
    manifest = build_worktree_fingerprint_manifest(worktree)
    return fingerprint_manifest(manifest)


def fingerprint_manifest(manifest: list[dict[str, Any]]) -> str:
    """Hash a normalized manifest using the same definition as the live oracle."""
    if not isinstance(manifest, list):
        raise WorktreeIntegrityError("WORKTREE_UNSUPPORTED_NODE: fingerprint manifest is not an array")
    for entry in manifest:
        if not isinstance(entry, dict) or entry.get("type") not in {"file", "directory", "symlink"}:
            raise WorktreeIntegrityError("WORKTREE_UNSUPPORTED_NODE: fingerprint manifest contains an unsupported node type")
    ordered = sorted(manifest, key=lambda item: (str(item.get("path", "")), str(item.get("type", ""))))
    normalized = json.dumps(ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# Descriptive aliases make the oracle convenient for callers and tests while
# retaining one implementation and one digest definition.
worktree_fingerprint = fingerprint_worktree
compute_worktree_fingerprint = fingerprint_worktree


def _schema_path() -> Path:
    return get_runner_root() / "schemas" / "codex-reviewer-result.schema.json"


def _validate_schema_file(schema: Path) -> None:
    """Validate the configured output schema locally without invoking a provider."""
    try:
        value = json.loads(schema.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunnerEnvironmentError(f"Codex reviewer output schema cannot be read: {schema}") from exc
    except json.JSONDecodeError as exc:
        raise RunnerEnvironmentError(f"Codex reviewer output schema is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise RunnerEnvironmentError("Codex reviewer output schema must be a JSON object")


def _resolve_executable(executable: str) -> Path:
    """Resolve and validate an executable path using local filesystem inspection only."""
    configured = Path(executable).expanduser()
    resolved = configured if configured.is_file() else Path(shutil.which(executable) or "")
    if not resolved.is_file():
        raise RunnerEnvironmentError(f"Codex reviewer executable is not an existing file: {executable}")
    resolved = resolved.resolve()
    if not os.access(resolved, os.X_OK):
        raise RunnerEnvironmentError(f"Codex reviewer executable is not executable: {resolved}")
    return resolved


def check_codex_reviewer_binding(
    executable: str,
    *,
    model: str = CODEX_REVIEWER_MODEL,
    output_schema: Path | str | None = None,
) -> dict[str, str]:
    """Perform only deterministic local checks for the fixed reviewer binding."""
    if model != CODEX_REVIEWER_MODEL:
        raise ArtifactValidationError(f"Codex reviewer model must be exactly {CODEX_REVIEWER_MODEL}")
    resolved_executable = _resolve_executable(executable)
    schema = Path(output_schema or _schema_path()).resolve()
    if not schema.is_file():
        raise RunnerEnvironmentError(f"Codex reviewer output schema is missing: {schema}")
    _validate_schema_file(schema)
    return {"executable": str(resolved_executable), "model": CODEX_REVIEWER_MODEL, "output_schema": str(schema)}


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


def read_validated_artifact_snapshot(
    path: Path | str,
    *,
    expected_head: str | None = None,
    expected_tree: str | None = None,
) -> ArtifactSnapshot:
    """Read, hash, parse, and validate a review artifact from one byte snapshot."""
    snapshot = read_artifact_snapshot(path)
    try:
        parsed = json.loads(snapshot.raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError("Codex reviewer artifact is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Codex reviewer artifact is not valid JSON: {exc.msg}") from exc
    validated = validate_codex_review(parsed, expected_head=expected_head, expected_tree=expected_tree)
    return replace(snapshot, value=validated)


def parse_codex_reviewer_result(path: Path | str, *, expected_head: str | None = None, expected_tree: str | None = None) -> dict[str, Any]:
    """Read only the Codex final output file and validate its closed schema."""
    return read_validated_artifact_snapshot(
        path,
        expected_head=expected_head,
        expected_tree=expected_tree,
    ).value


def build_codex_reviewer_invocation(
    executable: str,
    workspace: Path | str,
    prompt: str,
    output_schema: Path | str | None = None,
    output_path: Path | str | None = None,
    *,
    model: str = CODEX_REVIEWER_MODEL,
) -> list[str]:
    """Build the ordinary `codex exec` argv for the fixed reviewer binding."""
    if model != CODEX_REVIEWER_MODEL:
        raise ArtifactValidationError(f"Codex reviewer model must be exactly {CODEX_REVIEWER_MODEL}")
    schema = Path(output_schema or _schema_path()).resolve()
    result = Path(output_path).resolve() if output_path is not None else None
    if result is None:
        raise ArtifactValidationError("Codex reviewer requires an explicit final output path")
    workspace_path = Path(workspace).resolve()
    try:
        result.relative_to(workspace_path)
    except ValueError:
        pass
    else:
        raise ArtifactValidationError("Codex reviewer output must be outside the verifier worktree")
    if not schema.is_file():
        raise RunnerEnvironmentError(f"Codex reviewer output schema is missing: {schema}")
    _validate_schema_file(schema)
    argv = [
        executable,
        "--ask-for-approval",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "-C",
        str(workspace_path),
        "--sandbox",
        "read-only",
        "--model",
        CODEX_REVIEWER_MODEL,
        "--output-schema",
        str(schema),
        "-o",
        str(result),
    ]
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
    # The auth-only home is ephemeral and deliberately outside durable review
    # evidence, so credentials cannot be mistaken for a review artifact.
    isolated_home = Path(tempfile.mkdtemp(prefix="prj226-review-codex-home-"))
    try:
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
        # Keep the child from discovering user-level configuration through HOME;
        # auth.json above is the only file copied into the isolated Codex home.
        child_env["HOME"] = str(isolated_home)
        return child_env
    except RunnerEnvironmentError:
        shutil.rmtree(isolated_home, ignore_errors=True)
        raise


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


def _assert_candidate(
    repo: Path,
    expected_head: str,
    expected_tree: str,
    candidate_ref: str | None = None,
    *,
    expected_fingerprint: str | None = None,
) -> str:
    actual_head = _git(repo, ["rev-parse", "HEAD"]).lower()
    actual_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    if actual_head != expected_head:
        raise ReviewStaleError("REVIEW_STALE: candidate HEAD changed during reviewer execution")
    if actual_tree != expected_tree:
        raise ReviewStaleError("REVIEW_STALE: candidate TREE changed during reviewer execution")
    if _git(repo, ["status", "--porcelain"]):
        raise ReviewStaleError("REVIEW_STALE: reviewer worktree is not clean")
    actual_fingerprint = fingerprint_worktree(repo)
    if expected_fingerprint is not None and actual_fingerprint != expected_fingerprint:
        raise ReviewStaleError("REVIEW_STALE: reviewer worktree filesystem fingerprint changed during reviewer execution")
    if candidate_ref is not None:
        ref_head = _git(repo, ["rev-parse", candidate_ref]).lower()
        if ref_head != expected_head:
            raise ReviewStaleError("REVIEW_STALE: candidate reference changed during reviewer execution")
    return actual_fingerprint


def _run_once(argv: list[str], workspace: Path, evidence_dir: Path, timeout_seconds: int, env: dict[str, str]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / "stdout.log"
    stderr_path = evidence_dir / "stderr.log"
    exit_code: int | None = None
    timed_out = False
    duration_ms: int | None = None
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
        # Persist a non-secret invocation record even for spawn failure.  This
        # makes the one-attempt boundary auditable without recording env data.
        invocation = {
            "argv": argv,
            "exit_code": None,
            "timed_out": False,
            "duration_ms": None,
            "spawn_error": type(exc).__name__,
            "tool": CODEX_REVIEWER_TOOL,
            "provider": CODEX_REVIEWER_PROVIDER,
            "model": CODEX_REVIEWER_MODEL,
            "sandbox": "read-only",
            "ephemeral": True,
            "ignore_user_config": True,
            "ignore_rules": True,
        }
        try:
            (evidence_dir / "invocation.json").write_text(
                json.dumps(invocation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except OSError as persist_exc:
            raise RunnerEnvironmentError(f"Unable to persist Codex reviewer invocation evidence: {persist_exc}") from persist_exc
        raise AgentExecutionError(f"Codex reviewer process could not start: {exc}") from exc
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
    """Run one semantic review between deterministic local pre/postflight checks."""
    expected_head = _object_id(candidate_head, "candidate_head")
    expected_tree = _object_id(candidate_tree, "candidate_tree")
    candidate_workspace = Path(workspace).resolve()
    evidence = Path(os.path.abspath(os.fspath(evidence_dir)))
    try:
        evidence.relative_to(candidate_workspace)
    except ValueError:
        pass
    else:
        raise GovernanceBlockerError("Review artifacts must be outside the verifier worktree")
    binding = check_codex_reviewer_binding(executable, model=CODEX_REVIEWER_MODEL, output_schema=output_schema)
    pre_fingerprint = _assert_candidate(candidate_workspace, expected_head, expected_tree, candidate_ref)
    evidence.mkdir(parents=True, exist_ok=True)
    with EvidenceRoot(evidence, label="Codex review evidence root"):
        pass
    fingerprint_manifest = build_worktree_fingerprint_manifest(candidate_workspace)
    try:
        (evidence / "fingerprint-pre.json").write_text(
            json.dumps({"fingerprint": pre_fingerprint, "manifest": fingerprint_manifest}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to persist pre-review worktree fingerprint: {exc}") from exc
    output_path = evidence / "raw-result.json"
    argv = build_codex_reviewer_invocation(
        binding["executable"],
        candidate_workspace,
        prompt,
        output_schema,
        output_path,
    )
    env = build_codex_reviewer_env(evidence, source_codex_home=source_codex_home)
    try:
        _run_once(argv, candidate_workspace, evidence, timeout_seconds, env)
    finally:
        shutil.rmtree(env["CODEX_HOME"], ignore_errors=True)
    # Capture and persist the post-review filesystem identity before the Git
    # cleanliness assertion can short-circuit on an ignored-only mutation.
    post_manifest = build_worktree_fingerprint_manifest(candidate_workspace)
    normalized_post_manifest = json.dumps(post_manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    post_fingerprint = hashlib.sha256(normalized_post_manifest.encode("utf-8")).hexdigest()
    try:
        (evidence / "fingerprint-post.json").write_text(
            json.dumps({"fingerprint": post_fingerprint, "manifest": post_manifest}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to persist post-review worktree fingerprint: {exc}") from exc
    if post_fingerprint != pre_fingerprint:
        raise ReviewStaleError("REVIEW_STALE: reviewer worktree filesystem fingerprint changed during reviewer execution")
    _assert_candidate(candidate_workspace, expected_head, expected_tree, candidate_ref)
    result = parse_codex_reviewer_result(output_path, expected_head=expected_head, expected_tree=expected_tree)
    normalized_path = evidence / "review.json"
    normalized_bytes = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        normalized_path.write_bytes(normalized_bytes)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to persist normalized Codex review artifact: {exc}") from exc
    return {
        "result": result,
        "artifact": str(normalized_path),
        "artifact_sha256": hashlib.sha256(normalized_bytes).hexdigest(),
        "raw_artifact": str(output_path),
        "invocation": str(evidence / "invocation.json"),
        "fingerprint": pre_fingerprint,
        "fingerprint_pre_artifact": str(evidence / "fingerprint-pre.json"),
        "fingerprint_post_artifact": str(evidence / "fingerprint-post.json"),
    }


run_codex_reviewer = run_codex_review
