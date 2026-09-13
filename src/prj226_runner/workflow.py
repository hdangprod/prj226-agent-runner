"""M2 workflow/presentation orchestration around frozen M1 v2 lifecycle.

M2 is a thin workflow layer. It never reimplements provider execution,
never retries, never falls back, and never weakens M1 authority. All
execution goes through the frozen M1 v2 producers/consumers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from prj226_runner import controller as C
from prj226_runner import runner as R
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError, RunnerEnvironmentError, RunnerError
from prj226_runner.review_policy import select_review_mode


SCHEMA_VERSION_DEFAULTS = "PRJ226.PROJECT_DEFAULTS.v1"
SCHEMA_VERSION_SCOPE_CATALOG = "PRJ226.WORKFLOW_SCOPE_CATALOG.v1"
SCHEMA_VERSION_TASK = "PRJ226.WORKFLOW_TASK.v1"
SCHEMA_VERSION_CONTINUATION = "PRJ226.CONTINUATION.v1"

M2_SCOPE_REQUIRED = "M2_SCOPE_REQUIRED"
M2_SCOPE_UNKNOWN = "M2_SCOPE_UNKNOWN"
M2_SCOPE_CATALOG_INVALID = "M2_SCOPE_CATALOG_INVALID"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_STOPPED = 10
EXIT_BLOCKER = 20

_TASK_ID_RE = re.compile(r"^TASK-[A-Za-z0-9._-]{1,64}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class WorkflowError(Exception):
    """M2 workflow failure with a deterministic CLI exit code."""

    def __init__(self, message: str, exit_code: int = EXIT_STOPPED, error_code: str = "WORKFLOW_STOPPED") -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.error_code = error_code


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise WorkflowError(f"Cannot read file: {path}", EXIT_USAGE, "WORKFLOW_READ_ERROR") from exc
    except json.JSONDecodeError as exc:
        raise WorkflowError(f"File is not valid JSON: {path}", EXIT_USAGE, "WORKFLOW_READ_ERROR") from exc


def _write_atomic(path: Path, value: Any) -> None:
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
        tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(target)
    except OSError as exc:
        raise WorkflowError(f"Cannot write file: {target}", EXIT_BLOCKER, "WORKFLOW_WRITE_ERROR") from exc


def _write_text_atomic(path: Path, text: str) -> None:
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(target)
    except OSError as exc:
        raise WorkflowError(f"Cannot write file: {target}", EXIT_BLOCKER, "WORKFLOW_WRITE_ERROR") from exc


def _git(repo: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise WorkflowError(f"Unable to execute Git: {exc}", EXIT_BLOCKER, "WORKFLOW_GIT_ERROR") from exc
    if result.returncode != 0:
        message = (result.stderr.strip() or result.stdout.strip() or "unknown Git failure")
        raise WorkflowError(f"Git inspection failed: {message}", EXIT_BLOCKER, "WORKFLOW_GIT_ERROR")
    return result.stdout.strip()


def resolve_runtime_root(explicit: Path | str | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("PRJ226_RUNTIME_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return Path("/tmp/prj226_agent_runner").resolve()


def _defaults_path_for(runtime_root: Path, project_id: str) -> Path:
    return Path(runtime_root) / "projects" / project_id / "defaults.json"


def _active_project_path(runtime_root: Path) -> Path:
    return Path(runtime_root) / "active-project.json"


def _workflow_dir(runtime_root: Path, task_id: str) -> Path:
    return Path(runtime_root) / "workflow" / task_id


def _validate_scope_name(scope: str | None) -> str | None:
    if scope is None:
        return None
    if not isinstance(scope, str) or not scope.strip():
        raise WorkflowError("Scope must be a non-empty name", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    name = scope.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise WorkflowError(f"Scope name is invalid: {scope!r}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    return name


def _derive_project_id(manifest: Any) -> str:
    pid = str(getattr(manifest, "project_id", "") or "").strip()
    if not pid:
        raise WorkflowError("Project manifest has no project_id", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    # Sanitize to a safe path component while remaining stable.
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", pid).strip(".-")
    if not safe:
        # Fall back to a deterministic hash of the raw id.
        safe = "P-" + hashlib.sha256(pid.encode("utf-8")).hexdigest()[:12]
    return safe


def load_scope_catalog(path: Path | str) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise WorkflowError(f"Scope catalog file not found: {p}", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID)
    try:
        text = p.read_text(encoding="utf-8")
        data = json.loads(text)
    except OSError as exc:
        raise WorkflowError(f"Cannot read scope catalog file: {p}", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID) from exc
    except json.JSONDecodeError as exc:
        raise WorkflowError(f"Scope catalog file is not valid JSON: {p}", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID) from exc
    if not isinstance(data, dict):
        raise WorkflowError(f"Scope catalog must be a JSON object: {p}", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID)

    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "workflow-scope-catalog.schema.json"
    if not schema_path.is_file():
        raise WorkflowError(f"Scope catalog schema missing: {schema_path}", EXIT_BLOCKER, M2_SCOPE_CATALOG_INVALID)
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        import jsonschema
        validator_cls = jsonschema.validators.validator_for(schema)
        validator_cls(schema).validate(data)
    except Exception as exc:
        raise WorkflowError(f"Invalid scope catalog schema: {exc}", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID) from exc

    default_scope = data.get("default_scope")
    scopes = data.get("scopes", {})
    if default_scope is not None and default_scope not in scopes:
        raise WorkflowError(f"default_scope '{default_scope}' is not defined in scopes", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID)

    return {
        "schema_version": SCHEMA_VERSION_SCOPE_CATALOG,
        "default_scope": default_scope,
        "scopes": scopes,
    }


def init_project(
    manifest_path: Path | str,
    config_path: Path | str,
    scopes_path: Path | str | None = None,
) -> dict[str, Any]:
    """Establish durable project defaults. No provider execution."""
    manifest_p = Path(manifest_path).expanduser().resolve()
    config_p = Path(config_path).expanduser().resolve()
    if not manifest_p.is_file():
        raise WorkflowError(f"Manifest is not a file: {manifest_p}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    if not config_p.is_file():
        raise WorkflowError(f"Config is not a file: {config_p}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    try:
        manifest = C.load_project_manifest(manifest_p)
    except RunnerError as exc:
        raise WorkflowError(f"Invalid manifest: {exc.message}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    except Exception as exc:
        raise WorkflowError(f"Invalid manifest: {exc}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    try:
        config = R.load_config(config_p)
    except RunnerError as exc:
        raise WorkflowError(f"Invalid runner config: {exc.message}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    except Exception as exc:
        raise WorkflowError(f"Invalid runner config: {exc}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    # Identify Git repository and validate prerequisites (no providers).
    try:
        inspection = C.inspect_project(manifest)
    except GovernanceBlockerError as exc:
        raise WorkflowError(f"Project prerequisites blocked: {exc.message}", EXIT_BLOCKER, "WORKFLOW_PREREQUISITE_BLOCKER") from exc
    except RunnerError as exc:
        raise WorkflowError(f"Project prerequisites invalid: {exc.message}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    project_id = _derive_project_id(manifest)
    runtime_root = Path(config.runtime_root).resolve()
    product_repo = str(Path(manifest.repository_path).expanduser().resolve())
    canonical_branch = str(manifest.canonical_branch)

    if scopes_path is not None:
        catalog = load_scope_catalog(scopes_path)
        scopes_source: str | None = str(Path(scopes_path).expanduser().resolve())
        default_scope: str | None = catalog["default_scope"]
        scopes: dict[str, Any] = catalog["scopes"]
    else:
        scopes_source = None
        default_scope = None
        scopes = {}

    defaults: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION_DEFAULTS,
        "project_id": project_id,
        "product_repository": product_repo,
        "canonical_branch": canonical_branch,
        "runtime_root": str(runtime_root),
        "manifest_source": str(manifest_p),
        "config_source": str(config_p),
        "scopes_source": scopes_source,
        "default_scope": default_scope,
        "scopes": scopes,
    }

    defaults_schema_p = Path(__file__).resolve().parents[2] / "schemas" / "project-defaults.schema.json"
    if defaults_schema_p.is_file():
        try:
            d_schema = json.loads(defaults_schema_p.read_text(encoding="utf-8"))
            import jsonschema
            validator_cls = jsonschema.validators.validator_for(d_schema)
            validator_cls(d_schema).validate(defaults)
        except Exception as exc:
            raise WorkflowError(f"Project defaults schema validation failed: {exc}", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE") from exc

    dest = _defaults_path_for(runtime_root, project_id)
    _write_atomic(dest, defaults)
    _write_atomic(_active_project_path(runtime_root), {"project_id": project_id, "updated_at": _utc_now()})
    return {
        "project_id": project_id,
        "product_repository": product_repo,
        "canonical_branch": canonical_branch,
        "head": inspection.get("head"),
        "tree": inspection.get("tree"),
        "runtime_root": str(runtime_root),
        "defaults_path": str(dest),
        "manifest_source": str(manifest_p),
        "config_source": str(config_p),
        "scopes_source": scopes_source,
        "default_scope": default_scope,
        "scopes_count": len(scopes),
    }


def load_project_defaults(
    runtime_root: Path | str | None = None,
    project_id: str | None = None,
) -> tuple[dict[str, Any], Path]:
    rt = resolve_runtime_root(runtime_root)
    pid = project_id
    if pid is None:
        active = _active_project_path(rt)
        if active.is_file():
            try:
                data = json.loads(active.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("project_id"), str) and data["project_id"].strip():
                    pid = data["project_id"].strip()
            except (OSError, json.JSONDecodeError):
                pid = None
    if pid is None:
        base = rt / "projects"
        candidates: list[str] = []
        if base.is_dir():
            for child in base.iterdir():
                if child.is_dir() and (child / "defaults.json").is_file():
                    candidates.append(child.name)
        if not candidates:
            raise WorkflowError(
                f"No M2 project defaults found under {rt}/projects. Run init first.",
                EXIT_USAGE,
                "WORKFLOW_NO_DEFAULTS",
            )
        if len(candidates) == 1:
            pid = candidates[0]
        else:
            # Deterministic: lexicographically latest.
            pid = sorted(candidates)[-1]
    path = _defaults_path_for(rt, pid)
    if not path.is_file():
        raise WorkflowError(f"Project defaults not found: {path}", EXIT_USAGE, "WORKFLOW_NO_DEFAULTS")
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION_DEFAULTS:
        raise WorkflowError("Project defaults schema/version mismatch", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
    for field in ("project_id", "product_repository", "canonical_branch", "runtime_root", "manifest_source", "config_source"):
        if not isinstance(data.get(field), str) or not str(data[field]).strip():
            raise WorkflowError(f"Project defaults field invalid: {field}", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
    if not isinstance(data.get("scopes"), dict):
        raise WorkflowError("Project defaults scopes invalid", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
    return data, path


def _load_manifest_and_config(defaults: Mapping[str, Any]) -> tuple[Any, Any]:
    manifest_src = Path(str(defaults["manifest_source"]))
    config_src = Path(str(defaults["config_source"]))
    try:
        manifest = C.load_project_manifest(manifest_src)
    except RunnerError as exc:
        raise WorkflowError(f"Manifest reload failed: {exc.message}", EXIT_BLOCKER, "WORKFLOW_MANIFEST_STALE") from exc
    try:
        config = R.load_config(config_src)
    except RunnerError as exc:
        raise WorkflowError(f"Config reload failed: {exc.message}", EXIT_BLOCKER, "WORKFLOW_CONFIG_STALE") from exc
    # Runtime root authority must still agree (realpath to tolerate /tmp symlinks).
    try:
        config_root = os.path.realpath(os.fspath(config.runtime_root))
        defaults_root = os.path.realpath(os.fspath(str(defaults["runtime_root"])))
    except Exception as exc:
        raise WorkflowError(f"Runtime root resolution failed: {exc}", EXIT_BLOCKER, "WORKFLOW_RUNTIME_STALE") from exc
    if config_root != defaults_root:
        raise WorkflowError("Runner config runtime_root drift from project defaults", EXIT_BLOCKER, "WORKFLOW_RUNTIME_STALE")
    return manifest, config


def _extract_builder_binding(config: Any) -> dict[str, Any]:
    if hasattr(config, "agents") and "builder" in config.agents:
        builder = config.agents.get("builder")
    elif isinstance(config, dict) and "agents" in config:
        builder = config["agents"].get("builder")
    else:
        builder = None
    if not builder:
        raise WorkflowError("Runner config missing agents.builder", EXIT_BLOCKER, "WORKFLOW_CONFIG_ERROR")
    tool = getattr(builder, "tool", None) if hasattr(builder, "tool") else (builder.get("tool") if isinstance(builder, dict) else None)
    model = getattr(builder, "model", None) if hasattr(builder, "model") else (builder.get("model") if isinstance(builder, dict) else None)
    executable = getattr(builder, "executable", None) if hasattr(builder, "executable") else (builder.get("executable") if isinstance(builder, dict) else None)
    timeout = getattr(builder, "timeout_seconds", None) if hasattr(builder, "timeout_seconds") else (builder.get("timeout_seconds", 300) if isinstance(builder, dict) else 300)
    if not tool or not model or not executable or not isinstance(timeout, int) or timeout <= 0:
        raise WorkflowError("Runner config agents.builder is incomplete or invalid", EXIT_BLOCKER, "WORKFLOW_CONFIG_ERROR")
    return {
        "tool": str(tool),
        "model": str(model),
        "executable": str(executable),
        "timeout_seconds": int(timeout),
    }


def _create_execution_config_snapshot(
    wdir: Path,
    defaults: Mapping[str, Any],
    contract: Mapping[str, Any],
    builder_binding: Mapping[str, Any],
    live_config: Any,
) -> Path:
    """Snapshot execution configuration to ensure executed builder/reviewer authority matches Gate A."""
    exec_config_path = wdir / "execution_config.toml"
    runtime_root = str(defaults["runtime_root"])

    def _extract_role_tuple(agent: Any) -> tuple[str, str, str, int]:
        if agent is None:
            raise WorkflowError("Missing agent role in config", EXIT_BLOCKER, "WORKFLOW_CONFIG_ERROR")
        tool = getattr(agent, "tool", None) if hasattr(agent, "tool") else (agent.get("tool") if isinstance(agent, dict) else None)
        model = getattr(agent, "model", None) if hasattr(agent, "model") else (agent.get("model") if isinstance(agent, dict) else None)
        exe = getattr(agent, "executable", None) if hasattr(agent, "executable") else (agent.get("executable") if isinstance(agent, dict) else None)
        timeout = getattr(agent, "timeout_seconds", None) if hasattr(agent, "timeout_seconds") else (agent.get("timeout_seconds", 300) if isinstance(agent, dict) else 300)
        return str(tool), str(model), str(exe), int(timeout)

    # Builder role strictly from frozen builder_binding
    b_tool = str(builder_binding["tool"])
    b_model = str(builder_binding["model"])
    b_exe = str(builder_binding["executable"])
    b_timeout = int(builder_binding["timeout_seconds"])

    # SOS Reviewer: from contract if TARGETED, else from live_config
    if contract.get("review_policy", {}).get("review_mode") == "TARGETED" and contract.get("review_policy", {}).get("reviewer"):
        r_info = contract["review_policy"]["reviewer"]
        r_tool = str(r_info.get("tool", "codex"))
        r_model = str(r_info.get("model", "gpt-5.6-luna"))
        r_exe = str(r_info.get("executable"))
        r_timeout = int(r_info.get("timeout_seconds", 300))
    elif hasattr(live_config, "agents") and "sos_reviewer" in live_config.agents:
        r_tool, r_model, r_exe, r_timeout = _extract_role_tuple(live_config.agents["sos_reviewer"])
    elif isinstance(live_config, dict) and "agents" in live_config and "sos_reviewer" in live_config["agents"]:
        r_tool, r_model, r_exe, r_timeout = _extract_role_tuple(live_config["agents"]["sos_reviewer"])
    else:
        r_tool, r_model, r_exe, r_timeout = "codex", "gpt-5.6-luna", b_exe, 300

    # DV role: from live_config
    if hasattr(live_config, "agents") and "dv" in live_config.agents:
        dv_tool, dv_model, dv_exe, dv_timeout = _extract_role_tuple(live_config.agents["dv"])
    elif isinstance(live_config, dict) and "agents" in live_config and "dv" in live_config["agents"]:
        dv_tool, dv_model, dv_exe, dv_timeout = _extract_role_tuple(live_config["agents"]["dv"])
    else:
        dv_tool, dv_model, dv_exe, dv_timeout = "opencode2", "dv-default", b_exe, 300

    content = (
        f"[runner]\n"
        f"runtime_root = {json.dumps(runtime_root)}\n\n"
        f"[agents.builder]\n"
        f"tool = {json.dumps(b_tool)}\n"
        f"executable = {json.dumps(b_exe)}\n"
        f"model = {json.dumps(b_model)}\n"
        f"timeout_seconds = {b_timeout}\n\n"
        f"[agents.dv]\n"
        f"tool = {json.dumps(dv_tool)}\n"
        f"executable = {json.dumps(dv_exe)}\n"
        f"model = {json.dumps(dv_model)}\n"
        f"timeout_seconds = {dv_timeout}\n\n"
        f"[agents.sos_reviewer]\n"
        f"tool = {json.dumps(r_tool)}\n"
        f"executable = {json.dumps(r_exe)}\n"
        f"model = {json.dumps(r_model)}\n"
        f"timeout_seconds = {r_timeout}\n"
    )
    _write_text_atomic(exec_config_path, content)
    return exec_config_path


def derive_plan(defaults: Mapping[str, Any], description: str, scope: str | None) -> dict[str, Any]:
    if not isinstance(description, str) or not description.strip():
        raise WorkflowError("Task description must be a non-empty string", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    desc = description.strip()
    if len(desc) > 2000:
        raise WorkflowError("Task description is too long", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")

    scopes = dict(defaults.get("scopes") or {})
    default_scope = defaults.get("default_scope")

    if scope is not None:
        scope_name = _validate_scope_name(scope)
        if scope_name not in scopes:
            available = ", ".join(sorted(scopes.keys())) if scopes else "(none)"
            raise WorkflowError(
                f"Scope '{scope_name}' is not defined in project scope catalog. Available scopes: {available}",
                EXIT_USAGE,
                M2_SCOPE_UNKNOWN,
            )
    else:
        if default_scope is None or not isinstance(default_scope, str) or not default_scope.strip():
            raise WorkflowError(
                "No scope specified and no default_scope defined in project defaults. Specify --scope <name> or initialize with a default_scope.",
                EXIT_USAGE,
                M2_SCOPE_REQUIRED,
            )
        scope_name = default_scope.strip()
        if scope_name not in scopes:
            raise WorkflowError(
                f"Default scope '{scope_name}' is not defined in project scope catalog",
                EXIT_BLOCKER,
                M2_SCOPE_UNKNOWN,
            )

    scope_entry = scopes[scope_name]
    if not isinstance(scope_entry, dict):
        raise WorkflowError(f"Scope entry for '{scope_name}' is invalid", EXIT_BLOCKER, M2_SCOPE_CATALOG_INVALID)

    owned = list(scope_entry.get("owned_paths") or [])
    if not owned:
        raise WorkflowError(f"Scope '{scope_name}' defines no owned_paths", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID)

    raw_checks = scope_entry.get("checks") or []
    if not raw_checks:
        raise WorkflowError(f"Scope '{scope_name}' defines no checks", EXIT_USAGE, M2_SCOPE_CATALOG_INVALID)
    checks = [list(c) for c in raw_checks]
    for argv in checks:
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise WorkflowError("Deterministic checks are malformed", EXIT_BLOCKER, M2_SCOPE_CATALOG_INVALID)

    raw_cats = scope_entry.get("change_categories") or []
    categories = [str(c) for c in raw_cats] if isinstance(raw_cats, list) else []
    human_flag = bool(scope_entry.get("human_requested_targeted", False))
    raw_transient = scope_entry.get("transient_paths") or []
    transient_paths = [str(p) for p in raw_transient] if isinstance(raw_transient, list) else []
    uncertainties: list[str] = []

    manifest, config = _load_manifest_and_config(defaults)
    try:
        inspection = C.inspect_project(manifest)
    except GovernanceBlockerError as exc:
        raise WorkflowError(f"Project state blocked: {exc.message}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc
    except RunnerError as exc:
        raise WorkflowError(f"Project inspection failed: {exc.message}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc

    # Static review selection (frozen M1 semantics, no inference).
    try:
        mode = select_review_mode(list(categories), bool(human_flag))
    except RunnerError as exc:
        raise WorkflowError(f"Review selection failed: {exc.message}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc

    review_brief: str | None = None
    if mode == "TARGETED":
        custom_brief = scope_entry.get("review_brief")
        if isinstance(custom_brief, str) and custom_brief.strip():
            review_brief = custom_brief.strip()
        elif scope_name == "needs-fix":
            review_brief = f"FORCE_NEEDS_FIX Targeted semantic review for: {desc[:300]}"
        else:
            review_brief = f"Targeted semantic review for: {desc[:300]}"

    behavior = f"Implement requested change: {desc}"
    builder_binding = _extract_builder_binding(config)
    execution = {
        "builder_tool": builder_binding["tool"],
        "builder_model": builder_binding["model"],
        "builder_executable": builder_binding["executable"],
        "builder_timeout_seconds": builder_binding["timeout_seconds"],
        "config_source": str(defaults["config_source"]),
    }
    review_reason = ""
    if mode == "TARGETED":
        if human_flag and not categories:
            review_reason = "human requested targeted review"
        elif categories:
            review_reason = f"static policy: {', '.join(categories)}"
        else:
            review_reason = "static policy selected TARGETED"
        if scope_name == "needs-fix":
            review_reason += " (fixture expects NEEDS_FIX)"
    else:
        review_reason = "static policy: no targeted category"

    return {
        "project_id": str(defaults["project_id"]),
        "description": desc,
        "scope": scope_name,
        "behavior": behavior,
        "authorized_paths": list(owned),
        "checks": [list(c) for c in checks],
        "change_categories": list(categories),
        "human_requested_targeted": bool(human_flag),
        "review_mode": mode,
        "review_brief": review_brief,
        "review_reason": review_reason,
        "uncertainties": list(uncertainties),
        "builder_binding": builder_binding,
        "execution": dict(execution),
        "baseline_head": str(inspection.get("head")).lower(),
        "baseline_tree": str(inspection.get("tree")).lower(),
        "canonical_branch": str(inspection.get("canonical_branch")),
        "product_repository": str(inspection.get("repository_path")),
        "protected_dirty_paths": list(inspection.get("protected_dirty_paths") or []),
        "transient_paths": list(transient_paths),
        "runtime_root": str(defaults["runtime_root"]),
    }


def _next_task_id(runtime_root: Path, project_id: str) -> str:
    base = Path(runtime_root) / "workflow"
    existing: list[int] = []
    if base.is_dir():
        for child in base.iterdir():
            if child.is_dir() and child.name.startswith("TASK-"):
                suffix = child.name[len("TASK-"):]
                if suffix.isdigit():
                    try:
                        existing.append(int(suffix))
                    except ValueError:
                        continue
    nxt = (max(existing) + 1) if existing else 1
    return f"TASK-{nxt:03d}"


def _task_path(runtime_root: Path, task_id: str) -> Path:
    return _workflow_dir(Path(runtime_root), task_id) / "task.json"


def save_task_record(runtime_root: Path | str, record: Mapping[str, Any]) -> Path:
    rt = Path(runtime_root)
    task_id = str(record.get("task_id"))
    if not _TASK_ID_RE.fullmatch(task_id):
        raise WorkflowError(f"Task ID is invalid: {task_id!r}", EXIT_BLOCKER, "WORKFLOW_TASK_ID")
    dest = _task_path(rt, task_id)
    _write_atomic(dest, dict(record))
    return dest


def load_task_record(runtime_root: Path | str | None, task_id: str) -> dict[str, Any]:
    rt = resolve_runtime_root(runtime_root)
    if not isinstance(task_id, str) or not task_id.strip():
        raise WorkflowError("TASK_ID is required", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    tid = task_id.strip()
    path = _task_path(rt, tid)
    if not path.is_file():
        raise WorkflowError(f"Unknown TASK_ID: {tid}", EXIT_USAGE, "WORKFLOW_UNKNOWN_TASK")
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION_TASK:
        raise WorkflowError("Workflow task schema/version mismatch", EXIT_BLOCKER, "WORKFLOW_TASK_STALE")
    return data


def find_latest_task_id(runtime_root: Path | str | None = None, project_id: str | None = None) -> str:
    rt = resolve_runtime_root(runtime_root)
    base = rt / "workflow"
    if not base.is_dir():
        raise WorkflowError("No workflow tasks found", EXIT_USAGE, "WORKFLOW_NO_TASKS")
    candidates: list[str] = []
    for child in base.iterdir():
        if child.is_dir() and (child / "task.json").is_file():
            try:
                data = json.loads((child / "task.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            if project_id and data.get("project_id") != project_id:
                continue
            candidates.append(child.name)
    if not candidates:
        raise WorkflowError("No workflow tasks found", EXIT_USAGE, "WORKFLOW_NO_TASKS")
    # Deterministic: sort by numeric suffix when possible, else lexicographic.
    def _key(name: str) -> tuple[int, str]:
        suffix = name[len("TASK-"):] if name.startswith("TASK-") else name
        try:
            return (int(suffix), name)
        except ValueError:
            return (10**9, name)
    candidates.sort(key=_key)
    return candidates[-1]


def _new_task_record(
    plan: Mapping[str, Any],
    task_id: str,
    status: str,
    run_id: str | None,
    contract_path: str | None = None,
    contract_hash: str | None = None,
    builder_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    b_binding = None
    if builder_binding is not None:
        b_binding = dict(builder_binding)
    elif contract_hash is not None and "builder_binding" in plan and plan["builder_binding"] is not None:
        b_binding = dict(plan["builder_binding"])
    return {
        "schema_version": SCHEMA_VERSION_TASK,
        "task_id": task_id,
        "project_id": str(plan["project_id"]),
        "description": str(plan["description"]),
        "scope": plan.get("scope"),
        "behavior": str(plan["behavior"]),
        "authorized_paths": list(plan["authorized_paths"]),
        "checks": [list(c) for c in plan["checks"]],
        "review_mode": str(plan["review_mode"]),
        "run_id": run_id,
        "status": status,
        "created_at": now,
        "updated_at": now,
        "continuation_path": None,
        "acceptance_ref": None,
        "candidate_head": None,
        "candidate_tree": None,
        "candidate_ref": None,
        "review_status": None,
        "error_class": None,
        "error": None,
        "contract_path": contract_path,
        "contract_hash": contract_hash,
        "builder_binding": b_binding,
    }
    if plan.get("transient_paths"):
        rec["transient_paths"] = list(plan["transient_paths"])
    return rec


def task_requires_frozen_contract_binding(
    task_record: Mapping[str, Any],
    runtime_root: Path | str | None = None,
) -> bool:
    """Return True if this task record requires a valid frozen contract binding."""
    status = str(task_record.get("status") or "")
    if status in ("PREVIEW", "AWAITING_GATE_A", "ACCEPTANCE_READY", "ACCEPTED"):
        return True
    if task_record.get("run_id"):
        return True
    for field in ("candidate_head", "candidate_tree", "candidate_ref", "review_status"):
        if task_record.get(field) is not None:
            return True
    if task_record.get("contract_path") is not None or task_record.get("contract_hash") is not None:
        return True
    if runtime_root is not None:
        task_id = str(task_record.get("task_id") or "").strip()
        if task_id:
            try:
                rt = resolve_runtime_root(runtime_root)
                wdir = _workflow_dir(rt, task_id)
                if (wdir / "contract.json").is_file() or (wdir / "preview.json").is_file():
                    return True
            except Exception:
                pass
    return False


def task_requires_frozen_builder_binding(
    task_record: Mapping[str, Any],
    runtime_root: Path | str | None = None,
) -> bool:
    """Return True if this task record requires a valid frozen builder execution binding."""
    return task_requires_frozen_contract_binding(task_record, runtime_root)


def load_frozen_builder_binding_for_task(
    task_record: Mapping[str, Any],
    task_id: str,
    runtime_root: Path | str,
) -> dict[str, Any]:
    """Load and verify the builder execution binding frozen in the task record."""
    rt = resolve_runtime_root(runtime_root)
    if not task_requires_frozen_builder_binding(task_record, rt):
        return {}

    raw = task_record.get("builder_binding")
    if raw is None or not isinstance(raw, dict):
        raise WorkflowError(
            f"Task {task_id} missing required builder_binding (WORKFLOW_EXECUTION_BINDING_MISMATCH)",
            EXIT_BLOCKER,
            "WORKFLOW_EXECUTION_BINDING_MISMATCH",
        )

    for key in ("tool", "model", "executable", "timeout_seconds"):
        val = raw.get(key)
        if val is None:
            raise WorkflowError(
                f"Task {task_id} builder_binding missing field {key} (WORKFLOW_EXECUTION_BINDING_MISMATCH)",
                EXIT_BLOCKER,
                "WORKFLOW_EXECUTION_BINDING_MISMATCH",
            )
        if key == "timeout_seconds":
            if not isinstance(val, int) or val <= 0:
                raise WorkflowError(
                    f"Task {task_id} builder_binding timeout_seconds must be positive int (WORKFLOW_EXECUTION_BINDING_MISMATCH)",
                    EXIT_BLOCKER,
                    "WORKFLOW_EXECUTION_BINDING_MISMATCH",
                )
        else:
            if not isinstance(val, str) or not val.strip():
                raise WorkflowError(
                    f"Task {task_id} builder_binding field {key} must be non-empty string (WORKFLOW_EXECUTION_BINDING_MISMATCH)",
                    EXIT_BLOCKER,
                    "WORKFLOW_EXECUTION_BINDING_MISMATCH",
                )

    wdir = _workflow_dir(rt, task_id)
    preview_path = wdir / "preview.json"
    if preview_path.is_file():
        try:
            preview_data = json.loads(preview_path.read_text(encoding="utf-8"))
            p_binding = preview_data.get("builder_binding")
            if p_binding is not None:
                for key in ("tool", "model", "executable", "timeout_seconds"):
                    if p_binding.get(key) != raw.get(key):
                        raise WorkflowError(
                            f"Task {task_id} builder_binding field {key} mismatches preview.json (WORKFLOW_EXECUTION_BINDING_MISMATCH)",
                            EXIT_BLOCKER,
                            "WORKFLOW_EXECUTION_BINDING_MISMATCH",
                        )
        except (OSError, json.JSONDecodeError):
            pass

    return {
        "tool": str(raw["tool"]),
        "model": str(raw["model"]),
        "executable": str(raw["executable"]),
        "timeout_seconds": int(raw["timeout_seconds"]),
    }


def load_frozen_contract_for_task(
    task_record: Mapping[str, Any],
    task_id: str,
    runtime_root: Path | str,
) -> dict[str, Any]:
    """Load and verify that the task's contract is the exact contract frozen in the task record."""
    rt = resolve_runtime_root(runtime_root)
    persisted_path_str = task_record.get("contract_path")
    if not isinstance(persisted_path_str, str) or not persisted_path_str.strip():
        raise WorkflowError(
            f"Task {task_id} missing contract_path in task record (WORKFLOW_CONTRACT_BINDING_MISMATCH)",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        )
    wdir = _workflow_dir(rt, task_id)
    expected_contract_path = wdir / "contract.json"
    try:
        persisted_resolved = Path(persisted_path_str).resolve()
    except Exception as exc:
        raise WorkflowError(
            f"Task {task_id} contract_path cannot be resolved (WORKFLOW_CONTRACT_BINDING_MISMATCH): {exc}",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        ) from exc
    if persisted_resolved != expected_contract_path.resolve():
        raise WorkflowError(
            f"Task {task_id} contract_path {persisted_path_str!r} does not match expected workflow contract {expected_contract_path} (WORKFLOW_CONTRACT_BINDING_MISMATCH)",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        )

    persisted_hash = task_record.get("contract_hash")
    if not isinstance(persisted_hash, str) or not re.fullmatch(r"^[0-9a-f]{64}$", persisted_hash):
        raise WorkflowError(
            f"Task {task_id} has invalid or missing contract_hash in task record (WORKFLOW_CONTRACT_BINDING_MISMATCH): {persisted_hash!r}",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        )

    if not expected_contract_path.is_file():
        raise WorkflowError(
            f"Task {task_id} missing pre-approved contract: {expected_contract_path}",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_MISSING",
        )

    try:
        contract = C.load_design_contract(expected_contract_path)
    except RunnerError as exc:
        raise WorkflowError(f"Contract loading failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_ERROR") from exc

    loaded_hash = str(contract.get("contract_hash") or "")
    if loaded_hash != persisted_hash:
        raise WorkflowError(
            f"Task {task_id} contract hash mismatch (WORKFLOW_CONTRACT_BINDING_MISMATCH): loaded {loaded_hash} != persisted {persisted_hash}",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        )

    expected_id = f"design-{persisted_hash}"
    loaded_id = str(contract.get("contract_id") or "")
    if loaded_id != expected_id:
        raise WorkflowError(
            f"Task {task_id} contract id mismatch (WORKFLOW_CONTRACT_BINDING_MISMATCH): loaded {loaded_id} != expected {expected_id}",
            EXIT_BLOCKER,
            "WORKFLOW_CONTRACT_BINDING_MISMATCH",
        )

    return contract


def _gate_a_for_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    owned = list(contract.get("owned_paths") or [])
    protected = list(contract.get("protected_dirty_paths") or [])

    def _overlap(a: str, b: str) -> bool:
        return a == b or a.startswith(b + "/") or b.startswith(a + "/")

    overlap = sorted(p for p in protected if any(_overlap(p, o) for o in owned))
    return {
        "gate": "HUMAN_GATE_A",
        "decision": "APPROVED",
        "contract_id": contract["contract_id"],
        "contract_hash": contract["contract_hash"],
        "baseline_head": contract["baseline_head"],
        "baseline_tree": contract["baseline_tree"],
        "authorized_protected_dirty_paths": overlap,
    }


def create_task(
    description: str,
    scope: str | None = None,
    preview_only: bool = False,
    approval_text: str | None = None,
    runtime_root: Path | str | None = None,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Prepare, optionally execute, and persist one M2 task. No retries."""
    rt = resolve_runtime_root(runtime_root)
    defaults, _ = load_project_defaults(rt)

    if task_id is not None:
        if not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id):
            raise WorkflowError(f"Task ID is invalid: {task_id!r}", EXIT_BLOCKER, "WORKFLOW_TASK_ID")
        wdir = _workflow_dir(rt, task_id)
        record = load_task_record(rt, task_id)
        contract = load_frozen_contract_for_task(record, task_id, rt)
        frozen_builder = load_frozen_builder_binding_for_task(record, task_id, rt)
        contract_path = wdir / "contract.json"
        if record.get("status") not in ("PREVIEW", "AWAITING_GATE_A"):
            raise WorkflowError(f"Task {task_id} is in status {record.get('status')} and cannot be executed", EXIT_USAGE, "WORKFLOW_TASK_ALREADY_EXECUTED")
        if scope is not None and record.get("scope") is not None and scope != record.get("scope"):
            raise WorkflowError(f"Scope mismatch for existing task {task_id}: expected {record.get('scope')!r}, got {scope!r}", EXIT_BLOCKER, "WORKFLOW_AUTHORITY_DRIFT")
        if description and record.get("description") and description != record.get("description"):
            raise WorkflowError(f"Description mismatch for existing task {task_id}: expected {record.get('description')!r}, got {description!r}", EXIT_BLOCKER, "WORKFLOW_AUTHORITY_DRIFT")
        manifest, config = _load_manifest_and_config(defaults)
        try:
            inspection = C.inspect_project(manifest)
        except RunnerError as exc:
            raise WorkflowError(f"Project inspection failed: {exc}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc
        if str(inspection.get("head")).lower() != str(contract["baseline_head"]).lower() or str(inspection.get("tree")).lower() != str(contract["baseline_tree"]).lower():
            raise WorkflowError(f"Baseline drifted between preview and approval for {task_id}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE")

        # Validate builder execution authority against frozen binding
        live_builder = _extract_builder_binding(config)
        for key in ("tool", "model", "executable", "timeout_seconds"):
            if live_builder[key] != frozen_builder.get(key):
                raise WorkflowError(
                    f"Builder {key} drifted between preview and approval for {task_id}: expected {frozen_builder.get(key)!r}, got {live_builder[key]!r}",
                    EXIT_BLOCKER,
                    "WORKFLOW_EXECUTION_BINDING_MISMATCH",
                )

        if contract["review_policy"]["review_mode"] == "TARGETED":
            current_reviewer_exe = str(config.agents["sos_reviewer"].executable)
            contract_reviewer = contract["review_policy"]["reviewer"]
            if current_reviewer_exe != contract_reviewer.get("executable"):
                raise WorkflowError("Reviewer configuration drifted between preview and approval", EXIT_BLOCKER, "WORKFLOW_CONFIG_DRIFT")
            current_reviewer_model = getattr(config.agents["sos_reviewer"], "model", None)
            if current_reviewer_model is not None and contract_reviewer.get("model") is not None:
                if str(current_reviewer_model) != str(contract_reviewer.get("model")):
                    raise WorkflowError("Reviewer configuration drifted between preview and approval", EXIT_BLOCKER, "WORKFLOW_CONFIG_DRIFT")
            from prj226_runner.reviewer_profile import resolve_reviewer_executable
            resolved_exe = resolve_reviewer_executable(current_reviewer_exe)
            digest = hashlib.sha256()
            with resolved_exe.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            current_sha = digest.hexdigest()
            if current_sha != contract_reviewer.get("executable_sha256"):
                raise WorkflowError("Reviewer executable binary drifted between preview and approval", EXIT_BLOCKER, "WORKFLOW_EXECUTABLE_DRIFT")
        plan = {
            "project_id": contract["project_id"],
            "description": description or record.get("description", str(contract["work_item_title"])),
            "scope": scope or record.get("scope"),
            "behavior": record.get("behavior", f"Implement requested change: {contract['work_item_title']}"),
            "authorized_paths": list(contract["owned_paths"]),
            "checks": [list(c) for c in contract["acceptance_instruments"]],
            "change_categories": list(contract["review_policy"].get("change_categories", [])),
            "human_requested_targeted": bool(contract["review_policy"].get("human_requested_targeted", False)),
            "review_mode": str(contract["review_policy"]["review_mode"]),
            "review_brief": contract["review_policy"].get("reviewer", {}).get("review_brief") if contract["review_policy"].get("reviewer") else None,
            "review_reason": record.get("review_mode", ""),
            "uncertainties": [],
            "builder_binding": frozen_builder,
            "execution": {
                "builder_tool": frozen_builder["tool"],
                "builder_model": frozen_builder["model"],
                "builder_executable": frozen_builder["executable"],
                "builder_timeout_seconds": frozen_builder["timeout_seconds"],
                "config_source": str(defaults["config_source"]),
            },
            "baseline_head": str(contract["baseline_head"]).lower(),
            "baseline_tree": str(contract["baseline_tree"]).lower(),
            "canonical_branch": str(contract["canonical_branch"]),
            "product_repository": str(contract["repository_path"]),
            "protected_dirty_paths": list(contract.get("protected_dirty_paths", [])),
            "runtime_root": str(defaults["runtime_root"]),
        }
    else:
        plan = derive_plan(defaults, description, scope)
        task_id = _next_task_id(rt, str(defaults["project_id"]))
        wdir = _workflow_dir(rt, task_id)
        wdir.mkdir(parents=True, exist_ok=True)
        run_id = f"{task_id}-RUN"
        manifest, config = _load_manifest_and_config(defaults)
        try:
            inspection = C.inspect_project(manifest)
        except RunnerError as exc:
            record = _new_task_record(plan, task_id, "STOPPED", None, contract_path=None, contract_hash=None)
            record.update({"error_class": "GOVERNANCE_BLOCKER", "error": exc.message if hasattr(exc, "message") else str(exc)})
            save_task_record(rt, record)
            raise WorkflowError(f"Project inspection failed: {exc}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc
        work_item = {"work_item_id": task_id, "title": plan["description"]}
        draft_kwargs: dict[str, Any] = {
            "run_id": run_id,
            "owned_paths": list(plan["authorized_paths"]),
            "runtime_root": str(defaults["runtime_root"]),
            "change_categories": list(plan["change_categories"]),
            "human_requested_targeted": bool(plan["human_requested_targeted"]),
            "acceptance_instruments": [list(c) for c in plan["checks"]],
        }
        if plan.get("transient_paths"):
            draft_kwargs["transient_paths"] = list(plan["transient_paths"])
        if plan["review_mode"] == "TARGETED":
            reviewer_agent = config.agents.get("sos_reviewer")
            if reviewer_agent is None:
                raise WorkflowError("TARGETED review requires agents.sos_reviewer in config", EXIT_BLOCKER, "WORKFLOW_CONFIG_ERROR")
            reviewer_exe = str(reviewer_agent.executable)
            configured_model = getattr(reviewer_agent, "model", None)
            draft_kwargs.update(
                {
                    "reviewer_executable": reviewer_exe,
                    "reviewer_model": str(configured_model) if configured_model is not None else "gpt-5.6-luna",
                    "reviewer_timeout_seconds": int(reviewer_agent.timeout_seconds),
                    "review_brief": str(plan["review_brief"]),
                }
            )
        contract_path = wdir / "contract.json"
        try:
            contract = C.draft_design_contract_v3(manifest, work_item, inspection, output_path=contract_path, **draft_kwargs)
        except RunnerError as exc:
            record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=None, contract_hash=None)
            record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
            save_task_record(rt, record)
            raise WorkflowError(f"Contract draft failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_ERROR") from exc

    preview = {
        "task_id": task_id,
        "contract_hash": contract["contract_hash"],
        "contract_path": str(contract_path),
        "request": plan["description"],
        "behavior": plan["behavior"],
        "files": list(contract["owned_paths"]),
        "checks": [list(c) for c in contract["acceptance_instruments"]],
        "builder_binding": dict(plan["builder_binding"]),
        "execution": dict(plan["execution"]),
        "review_mode": contract["review_policy"]["review_mode"],
        "review_reason": plan["review_reason"],
        "reviewer": contract["review_policy"].get("reviewer"),
        "uncertainties": list(plan["uncertainties"]),
        "baseline_head": contract["baseline_head"],
        "baseline_tree": contract["baseline_tree"],
        "canonical_branch": contract["canonical_branch"],
        "product_repository": contract["repository_path"],
        "scope": plan["scope"],
    }
    if "transient_paths" in contract:
        preview["transient_paths"] = list(contract["transient_paths"])
    try:
        (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise WorkflowError(f"Cannot write preview: {exc}", EXIT_BLOCKER, "WORKFLOW_WRITE_ERROR") from exc

    if preview_only:
        record = _new_task_record(plan, task_id, "PREVIEW", None, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        save_task_record(rt, record)
        return {"task_id": task_id, "status": "PREVIEW", "preview": preview, "plan": plan, "record": record, "contract": contract}

    # Normal path requires explicit literal approval.
    approved = isinstance(approval_text, str) and approval_text.strip() == "approve"
    if not approved:
        record = _new_task_record(plan, task_id, "AWAITING_GATE_A", None, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        save_task_record(rt, record)
        raise WorkflowError(
            f"Gate A requires literal 'approve'. Task {task_id} preserved without execution.",
            EXIT_STOPPED,
            "WORKFLOW_GATE_A_DECLINED",
        )

    # Approved:
    run_id = f"{task_id}-RUN"
    gate_a = _gate_a_for_contract(contract)
    gate_path = wdir / "gate-a.json"
    packet_path = wdir / "packet.json"
    _write_atomic(gate_path, gate_a)
    contract_ver = contract.get("contract_version")
    if contract_ver == C.V3_CONTRACT_VERSION:
        derive_packet = C.derive_task_packet_v3
        run_packet = R.run_packet_v3
    elif contract_ver == C.V2_CONTRACT_VERSION:
        derive_packet = C.derive_task_packet_v2
        run_packet = R.run_packet_v2
    else:
        record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        record.update({"error_class": "ARTIFACT_VALIDATION_ERROR", "error": f"Unsupported contract version: {contract_ver}"})
        save_task_record(rt, record)
        raise WorkflowError(f"Unsupported contract version: {contract_ver}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_ERROR")

    try:
        packet = derive_packet(contract, gate_a, output_path=packet_path)
    except RunnerError as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
        save_task_record(rt, record)
        raise WorkflowError(f"Packet derivation failed: {exc}", EXIT_BLOCKER, "WORKFLOW_PACKET_ERROR") from exc

    exec_config_path = _create_execution_config_snapshot(wdir, defaults, contract, plan["builder_binding"], config)
    try:
        result = run_packet(packet_path, contract_path, gate_path, exec_config_path, authorize=True)
    except RunnerError as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
        record["authorized_paths"] = list(contract["owned_paths"])
        save_task_record(rt, record)
        raise WorkflowError(f"Execution blocked: {getattr(exc, 'message', str(exc))}", EXIT_BLOCKER, "WORKFLOW_EXECUTION_BLOCKED") from exc
    except Exception as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        record.update({"error_class": "ENVIRONMENT_ERROR", "error": f"Unexpected runner failure: {exc}"})
        save_task_record(rt, record)
        raise WorkflowError(f"Execution failed: {exc}", EXIT_BLOCKER, "WORKFLOW_EXECUTION_BLOCKED") from exc

    # Ingest for controller verification (validates evidence binding).
    run_root = Path(str(defaults["runtime_root"])) / run_id
    report_path = run_root / "report.json"
    outcome = str(result.get("result"))
    review_status = result.get("review_status")
    candidate_head = result.get("candidate_head")
    candidate_tree = result.get("candidate_tree")
    candidate_ref = result.get("candidate_ref")
    error_class = result.get("error_class")
    error_text = result.get("error")
    controller_phase = "STOPPED"
    ingested: dict[str, Any] | None = None
    ingest_error: str | None = None
    if report_path.is_file():
        try:
            ingested = C.ingest_runner_result_v2(contract, report_path)
            controller_phase = str(ingested.get("controller_phase"))
        except RunnerError as exc:
            ingested = None
            ingest_error = getattr(exc, "message", str(exc))
    else:
        ingest_error = f"M1 report missing: {report_path}"

    if ingested is not None:
        try:
            _write_atomic(wdir / "controller-result.json", ingested)
        except WorkflowError:
            pass
    if outcome == "ACCEPTANCE_READY" and controller_phase == "ACCEPTANCE_READY":
        status = "ACCEPTANCE_READY"
        acceptance_ref = str(wdir / "controller-result.json")
    elif outcome == "ACCEPTANCE_READY":
        record = _new_task_record(plan, task_id, "STOPPED", run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
        record.update(
            {
                "candidate_head": candidate_head,
                "candidate_tree": candidate_tree,
                "candidate_ref": candidate_ref,
                "review_status": review_status,
                "error_class": error_class or "ARTIFACT_VALIDATION_ERROR",
                "error": ingest_error or "Runner acceptance evidence failed controller validation",
                "acceptance_ref": None,
            }
        )
        save_task_record(rt, record)
        try:
            (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass
        raise WorkflowError(
            f"Acceptance evidence invalid for {task_id}: {ingest_error or 'controller validation failed'}",
            EXIT_BLOCKER,
            "WORKFLOW_EVIDENCE_INVALID",
        )
    else:
        status = "STOPPED"
        acceptance_ref = None

    record = _new_task_record(plan, task_id, status, run_id, contract_path=str(contract_path), contract_hash=contract["contract_hash"])
    record.update(
        {
            "candidate_head": candidate_head,
            "candidate_tree": candidate_tree,
            "candidate_ref": candidate_ref,
            "review_status": review_status,
            "error_class": error_class,
            "error": error_text,
            "acceptance_ref": acceptance_ref,
        }
    )
    save_task_record(rt, record)
    try:
        (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass
    if status == "STOPPED":
        raise WorkflowError(
            f"Task {task_id} STOPPED. Run {run_id} evidence preserved.",
            EXIT_STOPPED,
            "WORKFLOW_RUN_STOPPED",
        )
    return {
        "task_id": task_id,
        "status": status,
        "preview": preview,
        "plan": plan,
        "record": record,
        "result": result,
        "ingested": ingested,
        "run_id": run_id,
    }


def _load_m1_authority_for_task(task_record: Mapping[str, Any], defaults: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    """Load persisted contract + validate M1 evidence. Fail closed on any drift."""
    rt = Path(str(defaults["runtime_root"]))
    task_id = str(task_record.get("task_id"))
    contract = load_frozen_contract_for_task(task_record, task_id, rt)
    load_frozen_builder_binding_for_task(task_record, task_id, rt)
    run_id = task_record.get("run_id")
    if not run_id:
        return contract, None, None
    run_root = rt / str(run_id)
    report_path = run_root / "report.json"
    if not report_path.is_file():
        raise WorkflowError(
            f"Workflow claims run {run_id} but authoritative M1 result is missing",
            EXIT_BLOCKER,
            "WORKFLOW_EVIDENCE_MISSING",
        )
    try:
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"M1 result cannot be read: {exc}", EXIT_BLOCKER, "WORKFLOW_EVIDENCE_MISSING") from exc
    try:
        ingested = C.ingest_runner_result_v2(contract, report_path)
    except RunnerError as exc:
        raise WorkflowError(
            f"Workflow claims run {run_id} but authoritative M1 evidence cannot be validated: {getattr(exc, 'message', str(exc))}",
            EXIT_BLOCKER,
            "WORKFLOW_EVIDENCE_INVALID",
        ) from exc
    return contract, raw_report, ingested


def get_status(task_id: str | None = None, runtime_root: Path | str | None = None, as_json: bool = False) -> dict[str, Any]:
    """Read-only status reconstruction. Never mutates workflow state."""
    rt = resolve_runtime_root(runtime_root)
    defaults, _ = load_project_defaults(rt)
    tid = task_id.strip() if isinstance(task_id, str) and task_id.strip() else find_latest_task_id(rt)
    record = load_task_record(rt, tid)
    # Revalidate M1 evidence when a run is claimed (read-only, no writes).
    contract: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    ingested: dict[str, Any] | None = None
    if record.get("run_id"):
        contract, report, ingested = _load_m1_authority_for_task(record, defaults)
    elif task_requires_frozen_contract_binding(record, rt):
        contract = load_frozen_contract_for_task(record, tid, rt)
        load_frozen_builder_binding_for_task(record, tid, rt)
        # Cross-check cached candidate/review against authoritative evidence.
        if report is not None:
            for field in ("candidate_head", "candidate_tree", "candidate_ref", "review_status"):
                cached = record.get(field)
                live = report.get(field)
                # Allow cached None vs live None; otherwise require exact match.
                if cached != live and not (cached is None and live is None):
                    # For STOPPED with partial evidence, be strict: any mismatch fails closed.
                    raise WorkflowError(
                        f"Workflow record for {tid} disagrees with authoritative M1 evidence ({field})",
                        EXIT_BLOCKER,
                        "WORKFLOW_RECORD_DRIFT",
                    )
    elif task_requires_frozen_contract_binding(record, rt):
        contract = load_frozen_contract_for_task(record, tid, rt)
        load_frozen_builder_binding_for_task(record, tid, rt)
    # Derive human-facing status fields without mutation.
    status = str(record.get("status"))
    candidate_head = record.get("candidate_head")
    candidate_tree = record.get("candidate_tree")
    candidate_ref = record.get("candidate_ref")
    checks = list(record.get("checks") or [])
    review_mode = str(record.get("review_mode") or "UNKNOWN")
    review_status = record.get("review_status")
    error_text = record.get("error")
    error_class = record.get("error_class")
    run_id = record.get("run_id")
    # Check results from authoritative report when available.
    check_details: list[dict[str, Any]] = []
    if report is not None and isinstance(report.get("tests"), list):
        for idx, entry in enumerate(report["tests"], start=1):
            argv = entry.get("argv") if isinstance(entry, dict) else None
            code = entry.get("exit_code") if isinstance(entry, dict) else None
            check_details.append({"index": idx, "argv": argv, "exit_code": code, "passed": code == 0})
    elif checks:
        for idx, argv in enumerate(checks, start=1):
            check_details.append({"index": idx, "argv": argv, "exit_code": None, "passed": None})
    # First failure.
    first_failure: str | None = None
    if error_text:
        first_failure = str(error_text)
    elif report is not None and report.get("result") == "STOPPED":
        first_failure = str(report.get("error") or "Run STOPPED")
    # Next action (deterministic).
    if status == "ACCEPTANCE_READY":
        next_action = f"prj226-runner accept {tid}"
    elif status == "ACCEPTED":
        next_action = f"prj226-runner status {tid}"
    elif status in ("PREVIEW", "AWAITING_GATE_A"):
        next_action = f"prj226-runner task (re-request) or approve {tid} via new task"
    else:
        next_action = f"prj226-runner status {tid} or prj226-runner resume {tid} --handoff"
    return {
        "task_id": tid,
        "project_id": record.get("project_id"),
        "description": record.get("description"),
        "scope": record.get("scope"),
        "status": status,
        "run_id": run_id,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "candidate_ref": candidate_ref,
        "checks": checks,
        "check_details": check_details,
        "review_mode": review_mode,
        "review_status": review_status,
        "error": error_text,
        "error_class": error_class,
        "first_failure": first_failure,
        "next_action": next_action,
        "record": dict(record),
        "report": dict(report) if isinstance(report, dict) else None,
        "ingested": dict(ingested) if isinstance(ingested, dict) else None,
        "runtime_root": str(rt),
    }


def build_continuation(task_id: str, runtime_root: Path | str | None = None) -> dict[str, Any]:
    """Derive handoff continuation only from persisted verified facts."""
    rt = resolve_runtime_root(runtime_root)
    defaults, _ = load_project_defaults(rt)
    record = load_task_record(rt, task_id.strip())
    tid = str(record.get("task_id"))
    # Must validate authoritative evidence when a run is claimed.
    contract: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    ingested: dict[str, Any] | None = None
    if record.get("run_id"):
        contract, report, ingested = _load_m1_authority_for_task(record, defaults)
    elif task_requires_frozen_contract_binding(record, rt):
        contract = load_frozen_contract_for_task(record, tid, rt)
        load_frozen_builder_binding_for_task(record, tid, rt)
    status = str(record.get("status"))
    run_id = record.get("run_id")
    candidate_head = record.get("candidate_head")
    candidate_tree = record.get("candidate_tree")
    candidate_ref = record.get("candidate_ref")
    checks = [list(c) for c in (record.get("checks") or [])]
    review_mode = str(record.get("review_mode") or "UNKNOWN")
    review_status = record.get("review_status")
    error_text = record.get("error")
    # Evidence references required for inspection (root-relative where possible).
    evidence_refs: list[str] = []
    if run_id:
        run_root = rt / str(run_id)
        evidence_refs.append(str(run_root / "report.json"))
        evidence_refs.append(str(run_root / "manifest.json"))
        evidence_refs.append(str(run_root / "state.json"))
        evidence_refs.append(str(run_root / "events.ndjson"))
        if report is not None and isinstance(report.get("evidence_paths"), dict):
            for key in sorted(report["evidence_paths"]):
                val = report["evidence_paths"][key]
                if isinstance(val, str) and val:
                    # Keep as stored locator (root-relative for V2).
                    evidence_refs.append(val)
        evidence_refs.append(str(_workflow_dir(rt, tid) / "contract.json"))
        evidence_refs.append(str(_workflow_dir(rt, tid) / "task.json"))
    else:
        evidence_refs.append(str(_workflow_dir(rt, tid) / "task.json"))
        evidence_refs.append(str(_workflow_dir(rt, tid) / "preview.json"))
    # Deduplicate deterministically.
    evidence_refs = sorted(set(evidence_refs))
    # Actions that MUST NOT be repeated (single-attempt rule).
    must_not_repeat: list[str] = []
    if run_id:
        must_not_repeat.append(f"Do not rerun builder for {tid} (one-attempt rule; run {run_id} already executed).")
        if review_mode == "TARGETED":
            must_not_repeat.append("Do not invoke a second targeted review (max-one-attempt rule).")
        else:
            must_not_repeat.append("Do not invoke any reviewer for NONE (zero-invocation rule).")
        must_not_repeat.append("Do not retry, fallback, or auto-rewrite the task.")
    else:
        must_not_repeat.append("Do not treat preview as execution authority.")
    # Exact next legitimate action + fresh authorization flag.
    if status == "ACCEPTANCE_READY":
        next_action = f"prj226-runner accept {tid}"
        fresh_auth = True
        blocking: str | None = None
    elif status == "ACCEPTED":
        next_action = f"prj226-runner status {tid}"
        fresh_auth = False
        blocking = None
    elif status in ("PREVIEW", "AWAITING_GATE_A"):
        next_action = f"prj226-runner task \"<description>\" (fresh Gate A required)"
        fresh_auth = True
        blocking = str(error_text) if error_text else "Gate A was not approved."
    else:  # STOPPED
        next_action = f"prj226-runner resume {tid} --handoff (inspect evidence; fresh task required for any retry)"
        fresh_auth = True
        blocking = str(error_text) if error_text else "Run STOPPED."
    continuation: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION_CONTINUATION,
        "task_id": tid,
        "project_id": str(record.get("project_id")),
        "description": str(record.get("description")),
        "scope": record.get("scope"),
        "status": status,
        "run_id": run_id,
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "candidate_ref": candidate_ref,
        "checks": checks,
        "review_mode": review_mode,
        "review_status": review_status,
        "blocking_failure": blocking,
        "evidence_references": evidence_refs,
        "must_not_repeat": must_not_repeat,
        "next_action": next_action,
        "fresh_authorization_required": bool(fresh_auth),
    }
    return continuation


def write_handoff(task_id: str, runtime_root: Path | str | None = None) -> tuple[dict[str, Any], Path]:
    rt = resolve_runtime_root(runtime_root)
    continuation = build_continuation(task_id.strip(), rt)
    tid = str(continuation["task_id"])
    dest = _workflow_dir(rt, tid) / "continuation.json"
    _write_atomic(dest, continuation)
    # Update task record's continuation pointer (handoff creation is the only resume mutation).
    try:
        record = load_task_record(rt, tid)
        record["continuation_path"] = str(dest)
        record["updated_at"] = _utc_now()
        save_task_record(rt, record)
    except WorkflowError:
        pass
    return continuation, dest


def get_acceptance_data(task_id: str, runtime_root: Path | str | None = None) -> dict[str, Any]:
    """Collect verified acceptance facts for display before Gate B."""
    st = get_status(task_id.strip() if isinstance(task_id, str) else None, runtime_root)
    if st["status"] != "ACCEPTANCE_READY":
        raise WorkflowError(
            f"Task {st['task_id']} is not ACCEPTANCE_READY (observed {st['status']})",
            EXIT_STOPPED,
            "WORKFLOW_NOT_ACCEPTANCE_READY",
        )
    report = st["report"] or {}
    # Changed paths + diff summary from product repo.
    rt = Path(st["runtime_root"])
    defaults, _ = load_project_defaults(rt)
    contract_path = _workflow_dir(rt, st["task_id"]) / "contract.json"
    try:
        contract = C.load_design_contract(contract_path)
    except RunnerError as exc:
        raise WorkflowError(f"Contract reload failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_STALE") from exc
    repo = Path(contract["repository_path"])
    baseline = str(contract["baseline_head"])
    candidate = str(st["candidate_head"] or "")
    changed = list(report.get("changed_paths") or [])
    diff_summary = ""
    try:
        diff_summary = _git(repo, ["diff", "--stat", f"{baseline}..{candidate}"]).strip()
    except WorkflowError:
        diff_summary = ""
    if not diff_summary and changed:
        diff_summary = f"{len(changed)} path(s) changed."
    # Check details already in st.
    return {
        "task_id": st["task_id"],
        "description": st["description"],
        "changed_paths": changed,
        "diff_summary": diff_summary,
        "report": report,
        "check_details": st["check_details"],
        "review_mode": st["review_mode"],
        "review_status": st["review_status"],
        "candidate_head": st["candidate_head"],
        "candidate_tree": st["candidate_tree"],
        "candidate_ref": st.get("record", {}).get("candidate_ref"),
        "run_id": st["run_id"],
        "runtime_root": st["runtime_root"],
        "contract": contract,
    }


def perform_accept(task_id: str, approval_text: str | None, runtime_root: Path | str | None = None) -> dict[str, Any]:
    """Fresh Gate B authorization + frozen M1 integration. No push."""
    rt = resolve_runtime_root(runtime_root)
    tid = task_id.strip() if isinstance(task_id, str) else ""
    if not tid:
        raise WorkflowError("TASK_ID is required", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    # Must be genuinely ACCEPTANCE_READY (revalidated).
    try:
        acc = get_acceptance_data(tid, rt)
    except WorkflowError as exc:
        if exc.exit_code == EXIT_STOPPED:
            raise WorkflowError(str(exc), EXIT_STOPPED, "WORKFLOW_NOT_ACCEPTANCE_READY") from exc
        raise
    approved = isinstance(approval_text, str) and approval_text.strip() == "approve"
    if not approved:
        raise WorkflowError(
            f"Gate B requires literal 'approve'. Task {tid} was not integrated.",
            EXIT_STOPPED,
            "WORKFLOW_GATE_B_DECLINED",
        )
    defaults, _ = load_project_defaults(rt)
    wdir = _workflow_dir(rt, tid)
    contract_path = wdir / "contract.json"
    try:
        contract = C.load_design_contract(contract_path)
    except RunnerError as exc:
        raise WorkflowError(f"Contract reload failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_STALE") from exc
    run_id = str(acc["run_id"])
    run_root = rt / run_id
    report_path = run_root / "report.json"
    try:
        ingested = C.ingest_runner_result_v2(contract, report_path)
    except RunnerError as exc:
        raise WorkflowError(f"Acceptance evidence revalidation failed: {exc}", EXIT_BLOCKER, "WORKFLOW_EVIDENCE_INVALID") from exc
    if ingested.get("controller_phase") != "ACCEPTANCE_READY":
        raise WorkflowError(f"Task {tid} is not ACCEPTANCE_READY", EXIT_STOPPED, "WORKFLOW_NOT_ACCEPTANCE_READY")
    # Fresh Gate B package using frozen M1 semantics (revalidates branch/head/tree/evidence).
    try:
        package = C.prepare_gate_b_v2(contract, ingested)
    except GovernanceBlockerError as exc:
        raise WorkflowError(f"Gate B preparation blocked (stale?): {exc.message}", EXIT_BLOCKER, "WORKFLOW_GATE_B_STALE") from exc
    except RunnerError as exc:
        raise WorkflowError(f"Gate B preparation failed: {getattr(exc, 'message', str(exc))}", EXIT_BLOCKER, "WORKFLOW_GATE_B_STALE") from exc
    # Fresh exact authorization (never reuse old).
    import time as _time

    fresh_id = f"{tid}-B-{run_id}-{int(_time.time() * 1000) % 1000000:06d}"
    # Ensure uniqueness against existing claims (deterministic increment).
    try:
        evidence_root = Path(package["evidence_root"])
        gateb_dir = evidence_root / "gate-b"
        counter = 0
        candidate_id = fresh_id
        while (gateb_dir / f"attempt-{candidate_id}.json").exists() or (gateb_dir / f"attempt-{candidate_id}.result.json").exists():
            counter += 1
            candidate_id = f"{fresh_id}-{counter}"
            if counter > 100:
                break
        fresh_id = candidate_id
    except Exception:
        pass
    authorization = {
        "authorization_id": fresh_id,
        "gate_b_package_hash": package["gate_b_package_hash"],
        "candidate_head": package["candidate_head"],
        "candidate_tree": package["candidate_tree"],
        "expected_canonical_head": package["expected_canonical_head"],
        "expected_canonical_tree": package["expected_canonical_tree"],
    }
    try:
        integrated = C.integrate_after_gate_b_v2(contract, authorization, package=package, perform=True)
    except GovernanceBlockerError as exc:
        raise WorkflowError(f"Integration blocked (stale?): {exc.message}", EXIT_BLOCKER, "WORKFLOW_INTEGRATION_STALE") from exc
    except RunnerError as exc:
        raise WorkflowError(f"Integration failed: {getattr(exc, 'message', str(exc))}", EXIT_BLOCKER, "WORKFLOW_INTEGRATION_STALE") from exc
    # Mark accepted (local integration only, no push).
    try:
        record = load_task_record(rt, tid)
        record["status"] = "ACCEPTED"
        record["updated_at"] = _utc_now()
        # Persist package reference for audit.
        try:
            _write_atomic(wdir / "gate-b-package.json", package)
            _write_atomic(wdir / "gate-b-authorization.json", authorization)
        except WorkflowError:
            pass
        save_task_record(rt, record)
    except WorkflowError:
        pass
    return {
        "task_id": tid,
        "run_id": run_id,
        "candidate_head": package["candidate_head"],
        "candidate_tree": package["candidate_tree"],
        "authorization_id": fresh_id,
        "integrated": integrated,
        "package": package,
    }
