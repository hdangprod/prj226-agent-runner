"""Filesystem path constants and resolution helpers for prj226-agent-runner."""

from __future__ import annotations

from pathlib import Path

# Safe default configuration values
DEFAULT_TARGET_REPO: Path = Path("/Users/dangnguyen/Desktop/prj226-gen2")
DEFAULT_CANONICAL_BRANCH: str = "foundation/product-foundation"
DEFAULT_EXPECTED_HEAD: str = "c838e8fad91571a75152ddc7f3e8b4984ae2c92f"
DEFAULT_EXPECTED_TREE: str = "6cde18be3bbeb1df62f4e907c2984aeab2c4f7cf"


def get_runner_root() -> Path:
    """Return the absolute path to the runner repository root."""
    return Path(__file__).resolve().parent.parent.parent


def get_runs_dir() -> Path:
    """Return the path to the runs directory within the runner repository."""
    return get_runner_root() / "runs"


def get_run_dir(run_id: str) -> Path:
    """Return the directory path for a specific run ID."""
    return get_runs_dir() / run_id


def get_runtime_root(configured_path: str | Path | None = None) -> Path:
    """Return the external, immutable runtime evidence root for Runner V1."""
    return Path(configured_path).resolve() if configured_path else Path("/tmp/prj226_agent_runner")


def get_schemas_dir() -> Path:
    """Return the directory containing JSON schema contract definitions."""
    return get_runner_root() / "schemas"


def get_roles_dir() -> Path:
    """Return the directory containing role contracts."""
    return get_runner_root() / "roles"


def get_templates_dir() -> Path:
    """Return the directory containing run templates."""
    return get_runner_root() / "templates"


def get_config_dir() -> Path:
    """Return the directory containing configuration templates and files."""
    return get_runner_root() / "config"


def get_target_repo_path(configured_path: str | Path | None = None) -> Path:
    """
    Resolve the target product repository path.

    Returns the explicitly configured path or the default PRJ226 repository path.
    Does NOT mutate, clean, or create anything within the target repository.
    """
    if configured_path is not None:
        return Path(configured_path).resolve()
    return DEFAULT_TARGET_REPO
