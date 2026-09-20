"""Frozen, provider-neutral runtime profiles used before agent dispatch."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import re
from pathlib import Path
from typing import Any, Mapping

from prj226_runner.errors import ArtifactValidationError, RunnerEnvironmentError

ROLE_NAMES = ("planner", "builder", "reviewer")
ROLE_VALUES = ("PLANNER", "BUILDER", "REVIEWER")
POLICY_ENUMS = {
    "sandbox": ("read-only", "workspace-write"),
    "approval": ("never",),
    "tool_capability": ("none", "candidate-write-only"),
    "shell_capability": ("prohibited", "workspace-only"),
    "repository_write_capability": ("none", "candidate-worktree-owned-paths"),
    "network_capability": ("prohibited", "provider-api-only"),
    "session_persistence": ("ephemeral-isolated", "session-bound-evidence-persisted"),
    "environment_policy": ("closed-allowlist-only",),
    "authentication_policy": ("ephemeral-designated-auth-only", "no-auth-required"),
}
POLICY_KEYS = set(POLICY_ENUMS) | {
    "retry_count", "fallback_count", "fresh_home", "fresh_codex_home",
    "timeout_seconds", "context_policy", "feature_disables",
}
PROFILE_KEYS = {"role", "backend", "provider", "model", "adapter", "executable",
                "executable_sha256", "version", "profile_ref", "policy"}


def canonical_role_body(profile: Mapping[str, Any]) -> str:
    """Return deterministic canonical JSON for a role, excluding profile_ref."""
    body = {key: value for key, value in profile.items() if key != "profile_ref"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def derived_profile_ref(profile: Mapping[str, Any]) -> str:
    return "role-" + hashlib.sha256(canonical_role_body(profile).encode()).hexdigest()


def _fail(message: str, details: dict | None = None) -> None:
    raise ArtifactValidationError(message, details)


def _validate_profile(name: str, profile: Mapping[str, Any], verify_executable: bool) -> None:
    if set(profile) != PROFILE_KEYS:
        _fail(f"role {name} has an incomplete or open profile")
    if profile["role"] not in ROLE_VALUES or profile["role"] != name.upper():
        _fail(f"role {name} has an invalid role identity")
    for key in ("backend", "provider", "model", "adapter", "version", "profile_ref"):
        if not isinstance(profile[key], str) or not profile[key]:
            _fail(f"role {name}.{key} must be a non-empty string")
    if not re.fullmatch(r"[a-z0-9_-]+", profile["provider"]):
        _fail(f"role {name}.provider must be a lowercase machine-safe identifier")
    executable = profile["executable"]
    if not isinstance(executable, str) or not executable.startswith("/"):
        _fail(f"role {name}.executable must be absolute")
    if not isinstance(profile["executable_sha256"], str) or len(profile["executable_sha256"]) != 64:
        _fail(f"role {name}.executable_sha256 is invalid")
    try:
        int(profile["executable_sha256"], 16)
    except ValueError:
        _fail(f"role {name}.executable_sha256 is not hexadecimal")
    if profile["profile_ref"] != derived_profile_ref(profile):
        _fail(f"role {name}.profile_ref does not match canonical profile digest")
    policy = profile["policy"]
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        _fail(f"role {name}.policy is not closed")
    for key, allowed in POLICY_ENUMS.items():
        if policy[key] not in allowed:
            _fail(f"role {name}.policy.{key} is invalid")
    if policy["retry_count"] != 0 or policy["fallback_count"] != 0 or policy["approval"] != "never":
        _fail(f"role {name}.policy widens authority")
    if policy["fresh_home"] is not True or policy["fresh_codex_home"] is not True:
        _fail(f"role {name} requires fresh homes")
    if not isinstance(policy["timeout_seconds"], int) or policy["timeout_seconds"] <= 0:
        _fail(f"role {name}.policy.timeout_seconds must be positive")
    if not isinstance(policy["context_policy"], str) or not isinstance(policy["feature_disables"], list):
        _fail(f"role {name}.policy context fields are invalid")
    if verify_executable:
        path = Path(executable)
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            _fail(f"role {name}.executable is not a non-symlink executable")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != profile["executable_sha256"]:
            _fail(f"role {name}.executable_sha256 mismatch")
        try:
            observed = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                      timeout=5, check=False).stdout.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerEnvironmentError(f"could not observe runtime version for {name}") from exc
        if observed != profile["version"]:
            _fail(f"role {name}. observed version does not match expected version",
                  {"expected": profile["version"], "observed": observed})


def validate_runtime(runtime: Mapping[str, Any], *, verify_executables: bool = True) -> dict:
    """Validate and return a detached runtime bundle."""
    if not isinstance(runtime, Mapping) or set(runtime) != {"schema_version", "roles"}:
        _fail("runtime bundle must contain only schema_version and roles")
    if runtime["schema_version"] != "PRJ226.CONTROL_RUNTIME.v1" or not isinstance(runtime["roles"], Mapping):
        _fail("invalid runtime schema version or roles")
    if set(runtime["roles"]) != set(ROLE_NAMES):
        _fail("runtime must contain planner, builder, and reviewer roles")
    for name in ROLE_NAMES:
        _validate_profile(name, runtime["roles"][name], verify_executables)
    return json.loads(json.dumps(runtime))


def load_runtime(path: str | os.PathLike[str], *, verify_executables: bool = True) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError("could not load runtime bundle") from exc
    return validate_runtime(data, verify_executables=verify_executables)


def freeze_runtime(runtime: Mapping[str, Any]) -> dict:
    """Validate then return an immutable-by-convention normalized snapshot."""
    return validate_runtime(runtime)
