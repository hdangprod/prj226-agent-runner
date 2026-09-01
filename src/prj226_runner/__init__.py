"""PRJ226 Agent Runner package."""

from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    GovernanceBlockerError,
    ImplementationFailureError,
    RunnerEnvironmentError,
    RunnerError,
)
from prj226_runner.models import (
    AgentConfig,
    ErrorClass,
    EventRecord,
    RunManifest,
    RunState,
    RunStateSnapshot,
)
from prj226_runner.paths import (
    DEFAULT_CANONICAL_BRANCH,
    DEFAULT_EXPECTED_HEAD,
    DEFAULT_EXPECTED_TREE,
    DEFAULT_TARGET_REPO,
    get_config_dir,
    get_roles_dir,
    get_run_dir,
    get_runner_root,
    get_runs_dir,
    get_schemas_dir,
    get_target_repo_path,
    get_templates_dir,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "RunState",
    "ErrorClass",
    "AgentConfig",
    "RunManifest",
    "RunStateSnapshot",
    "EventRecord",
    "RunnerError",
    "RunnerEnvironmentError",
    "AgentExecutionError",
    "ArtifactValidationError",
    "ImplementationFailureError",
    "GovernanceBlockerError",
    "DEFAULT_TARGET_REPO",
    "DEFAULT_CANONICAL_BRANCH",
    "DEFAULT_EXPECTED_HEAD",
    "DEFAULT_EXPECTED_TREE",
    "get_runner_root",
    "get_runs_dir",
    "get_run_dir",
    "get_schemas_dir",
    "get_roles_dir",
    "get_templates_dir",
    "get_config_dir",
    "get_target_repo_path",
]
