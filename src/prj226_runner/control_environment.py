"""Closed environment and explicit authentication boundary for role processes."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping


def sanitize_evidence(data: Any, sensitive_strings: list[str] | tuple[str, ...] | set[str]) -> Any:
    """Deeply redact designated secret values from evidence-shaped data."""
    secrets = [s for s in sensitive_strings if s]
    if isinstance(data, str):
        for secret in secrets:
            data = data.replace(secret, "[REDACTED]")
        return data
    if isinstance(data, dict):
        return {sanitize_evidence(k, secrets): sanitize_evidence(v, secrets) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_evidence(v, secrets) for v in data]
    if isinstance(data, tuple):
        return tuple(sanitize_evidence(v, secrets) for v in data)
    return data


class AuthSource:
    def provision(self, codex_home: Path) -> list[str]:
        raise NotImplementedError


class EphemeralApiKeyAuth(AuthSource):
    def __init__(self, api_key: str, variable: str = "OPENAI_API_KEY") -> None:
        self.api_key, self.variable = api_key, variable

    def provision(self, codex_home: Path) -> list[str]:
        return [self.api_key]

    def environment(self) -> dict[str, str]:
        return {self.variable: self.api_key}


class DesignatedFileAuth(AuthSource):
    def __init__(self, source_path: str | os.PathLike[str], destination_name: str = "designated-credential") -> None:
        self.source_path = Path(source_path)
        self.destination_name = destination_name
        self._contents = ""

    def provision(self, codex_home: Path) -> list[str]:
        if self.source_path.is_symlink() or not self.source_path.is_file():
            raise ValueError("designated auth source must be a regular file")
        self._contents = self.source_path.read_text(encoding="utf-8")
        destination = codex_home / self.destination_name
        destination.write_text(self._contents, encoding="utf-8")
        os.chmod(destination, 0o600)
        return [self._contents]


class IsolatedRoleEnvironment:
    def __init__(self, auth_source: AuthSource | None = None, *, parent_env: Mapping[str, str] | None = None) -> None:
        self.auth_source = auth_source
        self.parent_env = dict(parent_env or os.environ)
        self.root: Path | None = None
        self.home: Path | None = None
        self.codex_home: Path | None = None
        self._sensitive: list[str] = []

    def __enter__(self) -> "IsolatedRoleEnvironment":
        self.root = Path(tempfile.mkdtemp(prefix="prj226-role-"))
        self.home, self.codex_home = self.root / "home", self.root / "codex-home"
        for path in (self.root, self.home, self.codex_home):
            path.mkdir(mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
        if self.auth_source:
            self._sensitive = self.auth_source.provision(self.codex_home)
        return self

    @property
    def environment(self) -> dict[str, str]:
        if not self.root or not self.home or not self.codex_home:
            raise RuntimeError("environment is not active")
        env = {key: self.parent_env[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR") if key in self.parent_env}
        env.update({"HOME": str(self.home), "CODEX_HOME": str(self.codex_home)})
        if isinstance(self.auth_source, EphemeralApiKeyAuth):
            env.update(self.auth_source.environment())
        return env

    def sanitized(self, data: Any) -> Any:
        return sanitize_evidence(data, self._sensitive)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.root:
            shutil.rmtree(self.root, ignore_errors=True)


def create_role_environment(auth_source: AuthSource | None = None, *, parent_env: Mapping[str, str] | None = None) -> IsolatedRoleEnvironment:
    return IsolatedRoleEnvironment(auth_source, parent_env=parent_env)
