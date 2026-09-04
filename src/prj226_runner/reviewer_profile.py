"""The canonical, non-executing Codex reviewer execution profile.

HARN-002 has one approved Codex reviewer binding.  This module contains the
small amount of data and validation needed to construct that binding for both
synthetic qualification and the live S/O/S review.  It intentionally contains
no subprocess, provider-health, retry, fallback, or MCP-management code.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from urllib.parse import urlsplit, urlunsplit
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from prj226_runner.errors import ArtifactValidationError, RunnerEnvironmentError


CODEX_REVIEWER_PROVIDER = "OpenAI"
CODEX_REVIEWER_MODEL = "gpt-5.6-luna"
CODEX_REVIEWER_TOOL = "codex"

_STRUCTURED_OUTPUT_MODE = "json-schema-to-output-file"
_CODEX_HOME_POLICY = "fresh-isolated-auth-only"
_HOME_POLICY = "fresh-isolated"

# These are the only fields which may identify a canonical reviewer profile.
# Runtime paths and prompt text are intentionally excluded from this set.
PROFILE_AUTHORITY_FIELDS = (
    "adapter",
    "provider",
    "model",
    "sandbox",
    "approval",
    "user_config",
    "rules",
    "apps",
    "codex_home_policy",
    "home_policy",
    "structured_output",
    "ephemeral",
    "external_process_count",
    "retry",
    "fallback",
    "provider_egress_required",
    "mcp",
    "project_instructions",
    "executable",
)


def _canonical_json(value: Any) -> str:
    """Serialize JSON deterministically for evidence identity."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_reviewer_executable(executable: str, *, strict: bool = True) -> Path:
    """Resolve a configured executable without invoking it.

    Resolution deliberately follows symlinks.  A direct path and a symlink to
    the same installed executable therefore have one normalized identity.
    """
    if not isinstance(executable, str) or not executable.strip():
        raise ArtifactValidationError("Codex reviewer executable must be a non-empty string")
    configured = Path(executable).expanduser()
    candidate = configured if configured.is_file() else Path(shutil.which(executable) or "")
    if not candidate.is_file():
        if strict:
            raise RunnerEnvironmentError(f"Codex reviewer executable is not an existing file: {executable}")
        return configured.absolute().resolve(strict=False)
    resolved = candidate.resolve()
    if not os.access(resolved, os.X_OK):
        raise RunnerEnvironmentError(f"Codex reviewer executable is not executable: {resolved}")
    return resolved


@dataclass(frozen=True)
class CodexReviewerProfile:
    """Immutable authority-relevant settings for the HARN-002 reviewer."""

    executable: str
    resolved_executable: str
    executable_sha256: str | None = None
    provider: str = CODEX_REVIEWER_PROVIDER
    model: str = CODEX_REVIEWER_MODEL
    adapter: str = "Codex CLI"
    sandbox: str = "read-only"
    approval: str = "never"
    user_config: str = "ignored"
    rules: str = "ignored"
    apps: str = "disabled"
    codex_home_policy: str = _CODEX_HOME_POLICY
    home_policy: str = _HOME_POLICY
    structured_output: str = _STRUCTURED_OUTPUT_MODE
    ephemeral: bool = True
    external_process_count: int = 1
    retry: str = "none"
    fallback: str = "none"
    provider_egress_required: bool = True
    mcp: str = "none-required"
    project_instructions: str = "non-authoritative"

    def authority_manifest(self) -> dict[str, Any]:
        """Return a sanitized deterministic manifest suitable for evidence."""
        return {
            "adapter": self.adapter,
            "provider": self.provider,
            "model": self.model,
            "sandbox": self.sandbox,
            "approval": self.approval,
            "user_config": self.user_config,
            "rules": self.rules,
            "apps": self.apps,
            "codex_home_policy": self.codex_home_policy,
            "home_policy": self.home_policy,
            "structured_output": {
                "required": True,
                "mode": self.structured_output,
                "schema_flag": "--output-schema",
                "destination_flag": "-o",
            },
            "ephemeral": self.ephemeral,
            "external_process_count": self.external_process_count,
            "retry": self.retry,
            "fallback": self.fallback,
            "provider_egress_required": self.provider_egress_required,
            "mcp": {
                "built_in_apps": False,
                "project_servers": False,
                "user_servers": False,
                "unrelated_tools": False,
                "capability": self.mcp,
            },
            "project_instructions": self.project_instructions,
            "executable": {
                "path_policy": "resolve-symlinks-before-identity",
                "resolved_path": self.resolved_executable,
                "installation_sha256": self.executable_sha256,
                "version_evidence": "resolved installation content; no startup probe",
            },
        }

    def validate(self) -> None:
        """Fail closed if a caller attempts to construct a non-canonical profile."""
        expected = {
            "adapter": "Codex CLI",
            "provider": CODEX_REVIEWER_PROVIDER,
            "model": CODEX_REVIEWER_MODEL,
            "sandbox": "read-only",
            "approval": "never",
            "user_config": "ignored",
            "rules": "ignored",
            "apps": "disabled",
            "codex_home_policy": _CODEX_HOME_POLICY,
            "home_policy": _HOME_POLICY,
            "structured_output": _STRUCTURED_OUTPUT_MODE,
            "ephemeral": True,
            "external_process_count": 1,
            "retry": "none",
            "fallback": "none",
            "provider_egress_required": True,
            "mcp": "none-required",
            "project_instructions": "non-authoritative",
        }
        if any(getattr(self, key) != value for key, value in expected.items()):
            raise ArtifactValidationError("Codex reviewer profile is not canonical")

    @property
    def manifest(self) -> dict[str, Any]:
        """Compatibility spelling for callers persisting profile evidence."""
        return self.authority_manifest()

    @property
    def reviewer_profile_hash(self) -> str:
        """SHA-256 identity of the canonical sanitized profile."""
        return _sha256_json(self.authority_manifest())

    @property
    def profile_hash(self) -> str:
        return self.reviewer_profile_hash


def build_codex_reviewer_profile(
    executable: str,
    *,
    model: str = CODEX_REVIEWER_MODEL,
    strict_executable: bool = True,
) -> CodexReviewerProfile:
    """Build the one canonical reviewer profile without executing Codex."""
    if model != CODEX_REVIEWER_MODEL:
        raise ArtifactValidationError(f"Codex reviewer model must be exactly {CODEX_REVIEWER_MODEL}")
    resolved = resolve_reviewer_executable(executable, strict=strict_executable)
    try:
        executable_sha256 = _sha256_file(resolved) if resolved.is_file() else None
    except OSError as exc:
        raise RunnerEnvironmentError(f"Codex reviewer executable cannot be fingerprinted: {resolved}") from exc
    return CodexReviewerProfile(
        executable=executable,
        resolved_executable=str(resolved),
        executable_sha256=executable_sha256,
        model=model,
    )


def build_codex_reviewer_argv(
    profile: CodexReviewerProfile,
    workspace: Path | str,
    prompt: str,
    output_schema: Path | str,
    output_path: Path | str,
) -> list[str]:
    """Build the production-compatible argv used by both review paths."""
    profile.validate()
    if not isinstance(prompt, str) or not prompt:
        raise ArtifactValidationError("Codex reviewer prompt must be a non-empty string")
    workspace_path = Path(workspace).resolve()
    schema_path = Path(output_schema).resolve()
    result_path = Path(output_path).resolve()
    try:
        result_path.relative_to(workspace_path)
    except ValueError:
        pass
    else:
        raise ArtifactValidationError("Codex reviewer output must be outside the verifier worktree")

    # Keep this construction literal and centralized.  In particular,
    # --disable apps is an argv authority setting, not an inference from
    # isolated config, HOME, or the prompt.
    return [
        profile.resolved_executable,
        "--ask-for-approval",
        "never",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--disable",
        "apps",
        "--ephemeral",
        "-C",
        str(workspace_path),
        "--sandbox",
        "read-only",
        "--model",
        profile.model,
        "--output-schema",
        str(schema_path),
        "-o",
        str(result_path),
        prompt,
    ]


def _single_option(argv: Sequence[str], option: str) -> tuple[int, str]:
    positions = [index for index, token in enumerate(argv) if token == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise ArtifactValidationError(f"Canonical Codex reviewer argv requires exactly one {option} option")
    value = argv[positions[0] + 1]
    if not isinstance(value, str) or not value:
        raise ArtifactValidationError(f"Canonical Codex reviewer argv has an invalid {option} value")
    return positions[0], value


def _required_flag(argv: Sequence[str], flag: str) -> None:
    if argv.count(flag) != 1:
        raise ArtifactValidationError(f"Canonical Codex reviewer argv requires exactly one {flag}")


def normalize_codex_reviewer_argv(
    argv: Sequence[str],
    *,
    profile: CodexReviewerProfile | None = None,
) -> dict[str, Any]:
    """Validate argv authority and remove only intentional runtime variance.

    The returned ``authority`` object is the parity oracle.  ``runtime`` is
    retained as evidence but is deliberately not compared between fixtures.
    """
    if not isinstance(argv, (list, tuple)) or len(argv) < 2 or not all(isinstance(item, str) for item in argv):
        raise ArtifactValidationError("Codex reviewer argv must be a non-empty string array")
    if profile is None:
        profile = build_codex_reviewer_profile(argv[0])
    profile.validate()

    observed_executable = resolve_reviewer_executable(argv[0])
    if str(observed_executable) != profile.resolved_executable:
        raise ArtifactValidationError("Codex reviewer executable identity differs from canonical profile")
    # Require the exact supported command shape. The only allowed variance is
    # the executable identity and four runtime values: cwd, schema path,
    # output path, and prompt.
    if len(argv) != 20:
        raise ArtifactValidationError("Canonical Codex reviewer argv has unexpected options")
    expected_literals = {
        1: "--ask-for-approval",
        2: "never",
        3: "exec",
        4: "--ignore-user-config",
        5: "--ignore-rules",
        6: "--disable",
        7: "apps",
        8: "--ephemeral",
        9: "-C",
        11: "--sandbox",
        12: "read-only",
        13: "--model",
        15: "--output-schema",
        17: "-o",
    }
    if any(argv[index] != value for index, value in expected_literals.items()):
        raise ArtifactValidationError("Canonical Codex reviewer argv contains unsupported security settings")
    _required_flag(argv, "--ignore-user-config")
    _required_flag(argv, "--ignore-rules")
    _required_flag(argv, "--ephemeral")
    if argv.count("--disable") != 1:
        raise ArtifactValidationError("Canonical Codex reviewer argv must explicitly disable apps")
    disable_index = argv.index("--disable")
    if disable_index + 1 >= len(argv) or argv[disable_index + 1] != "apps":
        raise ArtifactValidationError("Canonical Codex reviewer argv must use --disable apps")
    if "--enable" in argv or "--mcp" in argv or "--full-auto" in argv:
        raise ArtifactValidationError("Canonical Codex reviewer argv contains unauthorized app/MCP capability")

    approval_index, approval = _single_option(argv, "--ask-for-approval")
    if approval != "never":
        raise ArtifactValidationError("Codex reviewer approval must be never")
    sandbox_index, sandbox = _single_option(argv, "--sandbox")
    if sandbox != "read-only":
        raise ArtifactValidationError("Codex reviewer sandbox must be read-only")
    model_index, model = _single_option(argv, "--model")
    if model != CODEX_REVIEWER_MODEL or model != profile.model:
        raise ArtifactValidationError(f"Codex reviewer model must be exactly {CODEX_REVIEWER_MODEL}")
    cwd_index, cwd = _single_option(argv, "-C")
    schema_index, schema = _single_option(argv, "--output-schema")
    output_index, output = _single_option(argv, "-o")
    if "exec" not in argv or argv.count("exec") != 1:
        raise ArtifactValidationError("Canonical Codex reviewer argv requires the exec subcommand")
    if not argv[-1] or argv[-1].startswith("-"):
        raise ArtifactValidationError("Canonical Codex reviewer argv requires a final prompt")
    if len({approval_index, sandbox_index, model_index, cwd_index, schema_index, output_index}) != 6:
        raise ArtifactValidationError("Canonical Codex reviewer argv contains duplicate option positions")

    # The supported structured-output shape is shared by synthetic and
    # production construction.  Schema/output locations and the prompt are
    # intentionally runtime fields.
    authority = profile.authority_manifest()
    runtime = {
        "cwd": str(Path(cwd).resolve()),
        "output_schema": str(Path(schema).resolve()),
        "output_path": str(Path(output).resolve()),
        "prompt": argv[-1],
    }
    return {
        "authority": authority,
        "reviewer_profile_hash": profile.reviewer_profile_hash,
        "runtime": runtime,
    }


def _validate_reviewer_env(env: Mapping[str, str]) -> None:
    if not isinstance(env, Mapping):
        raise ArtifactValidationError("Codex reviewer environment must be a mapping")
    codex_home = env.get("CODEX_HOME")
    home = env.get("HOME")
    if not isinstance(codex_home, str) or not codex_home or not isinstance(home, str) or home != codex_home:
        raise ArtifactValidationError("Codex reviewer HOME must equal its fresh isolated CODEX_HOME")
    if not Path(codex_home).is_absolute():
        raise ArtifactValidationError("Codex reviewer CODEX_HOME must be absolute")
    capability_keys = [key for key in env if "MCP" in key.upper() or "APP" in key.upper()]
    if capability_keys:
        raise ArtifactValidationError("Codex reviewer environment contains unauthorized app/MCP capability")


def normalize_codex_reviewer_profile(
    argv: Sequence[str],
    *,
    profile: CodexReviewerProfile | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a sanitized normalized profile and validate its env policy."""
    normalized = normalize_codex_reviewer_argv(argv, profile=profile)
    if env is not None:
        _validate_reviewer_env(env)
    # Actual temp directory names are not authority identity and must not enter
    # the hash or parity comparison.
    normalized["environment"] = {
        "codex_home_policy": _CODEX_HOME_POLICY,
        "home_policy": _HOME_POLICY,
        "home_equals_codex_home": True,
    }
    return normalized


def assert_codex_reviewer_profile_parity(
    synthetic_argv: Sequence[str],
    production_argv: Sequence[str],
    *,
    synthetic_profile: CodexReviewerProfile | None = None,
    production_profile: CodexReviewerProfile | None = None,
    synthetic_env: Mapping[str, str] | None = None,
    production_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Require exact authority parity while allowing documented runtime paths."""
    synthetic = normalize_codex_reviewer_profile(synthetic_argv, profile=synthetic_profile, env=synthetic_env)
    production = normalize_codex_reviewer_profile(production_argv, profile=production_profile, env=production_env)
    if synthetic["authority"] != production["authority"]:
        raise ArtifactValidationError("Synthetic and production Codex reviewer profiles differ")
    if synthetic["reviewer_profile_hash"] != production["reviewer_profile_hash"]:
        raise ArtifactValidationError("Synthetic and production reviewer_profile_hash values differ")
    if synthetic["environment"] != production["environment"]:
        raise ArtifactValidationError("Synthetic and production Codex reviewer HOME policies differ")
    return {
        "authority": synthetic["authority"],
        "reviewer_profile_hash": synthetic["reviewer_profile_hash"],
        "synthetic_runtime": synthetic["runtime"],
        "production_runtime": production["runtime"],
        "intentional_runtime_differences": {
            "cwd": synthetic["runtime"]["cwd"] != production["runtime"]["cwd"],
            "prompt": synthetic["runtime"]["prompt"] != production["runtime"]["prompt"],
            "output_schema": synthetic["runtime"]["output_schema"] != production["runtime"]["output_schema"],
            "output_path": synthetic["runtime"]["output_path"] != production["runtime"]["output_path"],
        },
    }


def _sanitize_proxy_value(value: str) -> str | None:
    """Remove proxy URL userinfo before allowing an ambient value through."""
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        # Accessing these properties validates malformed bracketed hosts and
        # keeps malformed values from crossing the reviewer boundary.
        has_userinfo = parsed.username is not None or parsed.password is not None
    except ValueError:
        return None

    if has_userinfo:
        # urlsplit exposes the authority separately, so preserve the proxy
        # endpoint and remove only the ambient username/password component.
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, parsed.query, parsed.fragment))
    if "@" in parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, parsed.query, parsed.fragment))
    if "@" in value and "://" not in value:
        # Some clients accept a scheme-less host:port form.  Apply the same
        # userinfo rule to that form without broadening the accepted syntax.
        return value.rsplit("@", 1)[-1]
    return value


def _read_auth_snapshot(source_auth: Path) -> bytes | None:
    """Read auth.json from one no-follow descriptor, never by pathname twice."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(source_auth), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RunnerEnvironmentError("Codex authentication material cannot be opened safely") from exc

    try:
        try:
            before = os.fstat(descriptor)
        except OSError as exc:
            raise RunnerEnvironmentError("Codex authentication material metadata cannot be captured") from exc
        if not stat.S_ISREG(before.st_mode):
            raise RunnerEnvironmentError("Codex authentication material is not a regular file")

        data = bytearray()
        while True:
            try:
                chunk = os.read(descriptor, 1024 * 1024)
            except OSError as exc:
                raise RunnerEnvironmentError("Codex authentication material cannot be read") from exc
            if not chunk:
                break
            data.extend(chunk)

        try:
            after = os.fstat(descriptor)
        except OSError as exc:
            raise RunnerEnvironmentError("Codex authentication material metadata cannot be captured after read") from exc
        before_identity = (
            before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode), before.st_nlink,
            before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid,
        )
        after_identity = (
            after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode), after.st_nlink,
            after.st_size, after.st_mtime_ns, stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid,
        )
        if before_identity != after_identity or len(data) != before.st_size:
            raise RunnerEnvironmentError("Codex authentication material changed during snapshot acquisition")
        return bytes(data)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _write_private_auth(destination: Path, data: bytes) -> None:
    """Create the isolated auth file without following a destination symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(destination), flags, 0o600)
    except OSError as exc:
        raise RunnerEnvironmentError("Unable to create isolated Codex authentication material") from exc
    try:
        offset = 0
        while offset < len(data):
            try:
                written = os.write(descriptor, data[offset:])
            except OSError as exc:
                raise RunnerEnvironmentError("Unable to write isolated Codex authentication material") from exc
            if written <= 0:
                raise RunnerEnvironmentError("Unable to write isolated Codex authentication material")
            offset += written
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as exc:
            raise RunnerEnvironmentError("Unable to secure isolated Codex authentication material") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def build_codex_reviewer_env(
    *,
    source_codex_home: Path | str | None = None,
) -> dict[str, str]:
    """Create the canonical fresh isolated auth-only child environment."""
    isolated_home = Path(tempfile.mkdtemp(prefix="prj226-review-codex-home-"))
    try:
        source = Path(source_codex_home or os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
        source_auth = source / "auth.json"
        destination_auth = isolated_home / "auth.json"
        auth_snapshot = _read_auth_snapshot(source_auth)
        if auth_snapshot is not None:
            _write_private_auth(destination_auth, auth_snapshot)

        # Keep reviewer runtime propagation explicitly bounded.  Authentication
        # comes only from the copied auth.json in the fresh CODEX_HOME; ambient
        # provider credentials must never become child-process authority.
        safe_keys = {
            "PATH", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "NO_PROXY", "no_proxy",
        }
        child_env = {key: os.environ[key] for key in safe_keys if key in os.environ}
        for proxy_key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            if proxy_key in os.environ:
                sanitized = _sanitize_proxy_value(os.environ[proxy_key])
                if sanitized is not None:
                    child_env[proxy_key] = sanitized
        child_env["CODEX_HOME"] = str(isolated_home)
        child_env["HOME"] = str(isolated_home)
        return child_env
    except Exception:
        shutil.rmtree(isolated_home, ignore_errors=True)
        raise


# Descriptive aliases make the shared constructor discoverable to qualification
# code without introducing a second implementation.
build_synthetic_codex_reviewer_argv = build_codex_reviewer_argv
build_codex_reviewer_qualification_argv = build_codex_reviewer_argv
build_synthetic_codex_reviewer_env = build_codex_reviewer_env
build_codex_reviewer_qualification_env = build_codex_reviewer_env


def reviewer_profile_hash(profile: CodexReviewerProfile) -> str:
    """Return the deterministic evidence identity for a canonical profile."""
    return profile.reviewer_profile_hash
