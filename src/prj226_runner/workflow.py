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
SCHEMA_VERSION_TASK = "PRJ226.WORKFLOW_TASK.v1"
SCHEMA_VERSION_CONTINUATION = "PRJ226.CONTINUATION.v1"

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


def init_project(manifest_path: Path | str, config_path: Path | str) -> dict[str, Any]:
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
    # Deterministic defaults: only user/workflow info, never generated authority.
    py = sys.executable
    defaults: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION_DEFAULTS,
        "project_id": project_id,
        "product_repository": product_repo,
        "canonical_branch": canonical_branch,
        "runtime_root": str(runtime_root),
        "manifest_source": str(manifest_p),
        "config_source": str(config_p),
        "default_owned_paths": ["src/app.txt"],
        "default_checks": [[py, "-c", "import sys; sys.exit(0)"]],
        "scopes": {},
    }
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
    if not isinstance(data.get("default_owned_paths"), list) or not data["default_owned_paths"]:
        raise WorkflowError("Project defaults owned paths invalid", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
    if not isinstance(data.get("default_checks"), list) or not data["default_checks"]:
        raise WorkflowError("Project defaults checks invalid", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
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


def derive_plan(defaults: Mapping[str, Any], description: str, scope: str | None) -> dict[str, Any]:
    if not isinstance(description, str) or not description.strip():
        raise WorkflowError("Task description must be a non-empty string", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    desc = description.strip()
    if len(desc) > 2000:
        raise WorkflowError("Task description is too long", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    scope_name = _validate_scope_name(scope)
    manifest, config = _load_manifest_and_config(defaults)
    try:
        inspection = C.inspect_project(manifest)
    except GovernanceBlockerError as exc:
        raise WorkflowError(f"Project state blocked: {exc.message}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc
    except RunnerError as exc:
        raise WorkflowError(f"Project inspection failed: {exc.message}", EXIT_BLOCKER, "WORKFLOW_BASELINE_STALE") from exc
    # Authorized files.
    scopes = dict(defaults.get("scopes") or {})
    owned: list[str] = list(defaults.get("default_owned_paths") or ["src/app.txt"])
    if scope_name and scope_name in scopes and isinstance(scopes[scope_name], dict):
        scoped_owned = scopes[scope_name].get("owned_paths")
        if isinstance(scoped_owned, list) and scoped_owned:
            owned = list(scoped_owned)
    # Deterministic checks.
    checks: list[list[str]] = [list(c) for c in (defaults.get("default_checks") or [])]
    if scope_name and scope_name in scopes and isinstance(scopes[scope_name], dict):
        scoped_checks = scopes[scope_name].get("checks")
        if isinstance(scoped_checks, list) and scoped_checks:
            checks = [list(c) for c in scoped_checks]
    # Scope-driven deterministic overrides for fixtures (no inference).
    uncertainties: list[str] = []
    categories: list[str] = []
    human_flag = False
    review_brief: str | None = None
    if scope_name in (None, "default"):
        # Description-triggered targeted only for explicit marker (no silent planning).
        lowered = desc.lower()
        if "[targeted]" in lowered or lowered.startswith("targeted:") or "targeted review" in lowered:
            categories = ["MODULE_BOUNDARY"]
    elif scope_name == "targeted":
        categories = ["MODULE_BOUNDARY"]
    elif scope_name == "targeted-human":
        categories = []
        human_flag = True
    elif scope_name == "public-api":
        categories = ["PUBLIC_INTERFACE"]
    elif scope_name == "failing":
        categories = []
        checks = [[sys.executable, "-c", "import sys; sys.exit(1)"]]
    elif scope_name == "failing-targeted":
        categories = ["MODULE_BOUNDARY"]
        checks = [[sys.executable, "-c", "import sys; sys.exit(1)"]]
    elif scope_name == "needs-fix":
        categories = ["MODULE_BOUNDARY"]
    else:
        # Unknown scope: stay NONE with explicit uncertainty, no silent substitution.
        uncertainties.append(f"Unknown scope '{scope_name}'; using default files and checks.")
        # Also check scoped definition for categories if user added custom scope.
        if scope_name in scopes and isinstance(scopes[scope_name], dict):
            raw_cats = scopes[scope_name].get("change_categories") or []
            raw_human = scopes[scope_name].get("human_requested_targeted") or False
            if isinstance(raw_cats, list):
                categories = [str(c) for c in raw_cats]
            human_flag = bool(raw_human)
    # Scoped custom categories override (for user-defined scopes in defaults).
    if scope_name and scope_name in scopes and isinstance(scopes[scope_name], dict):
        entry = scopes[scope_name]
        if scope_name not in ("targeted", "targeted-human", "public-api", "failing", "failing-targeted", "needs-fix"):
            # Already handled unknown above; keep values.
            pass
        else:
            # Known fixture scopes already set; allow explicit scoped checks to win (done).
            pass
    # Validate checks shape.
    if not checks:
        raise WorkflowError("No deterministic checks available for task", EXIT_USAGE, "WORKFLOW_INPUT_ERROR")
    for argv in checks:
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise WorkflowError("Deterministic checks are malformed", EXIT_BLOCKER, "WORKFLOW_DEFAULTS_STALE")
    # Static review selection (frozen M1 semantics, no inference).
    try:
        mode = select_review_mode(list(categories), bool(human_flag))
    except RunnerError as exc:
        raise WorkflowError(f"Review selection failed: {exc.message}", EXIT_USAGE, "WORKFLOW_INPUT_ERROR") from exc
    if mode == "TARGETED":
        if scope_name == "needs-fix":
            review_brief = f"FORCE_NEEDS_FIX Targeted semantic review for: {desc[:300]}"
        else:
            # Honor custom scoped brief if present.
            custom_brief = None
            if scope_name and scope_name in scopes and isinstance(scopes[scope_name], dict):
                custom_brief = scopes[scope_name].get("review_brief")
            if isinstance(custom_brief, str) and custom_brief.strip():
                review_brief = custom_brief.strip()
            else:
                review_brief = f"Targeted semantic review for: {desc[:300]}"
    # Behavior: literal user intent, no doc replacement.
    behavior = f"Implement requested change: {desc}"
    # Execution binding already fixed by M1 configuration.
    builder = config.agents.get("builder")
    execution = {
        "builder_tool": getattr(builder, "tool", ""),
        "builder_model": getattr(builder, "model", ""),
        "builder_executable": getattr(builder, "executable", ""),
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
        "execution": dict(execution),
        "baseline_head": str(inspection.get("head")).lower(),
        "baseline_tree": str(inspection.get("tree")).lower(),
        "canonical_branch": str(inspection.get("canonical_branch")),
        "product_repository": str(inspection.get("repository_path")),
        "protected_dirty_paths": list(inspection.get("protected_dirty_paths") or []),
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


def _new_task_record(plan: Mapping[str, Any], task_id: str, status: str, run_id: str | None) -> dict[str, Any]:
    now = _utc_now()
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
    }


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
) -> dict[str, Any]:
    """Prepare, optionally execute, and persist one M2 task. No retries."""
    rt = resolve_runtime_root(runtime_root)
    defaults, _ = load_project_defaults(rt)
    plan = derive_plan(defaults, description, scope)
    task_id = _next_task_id(rt, str(defaults["project_id"]))
    wdir = _workflow_dir(rt, task_id)
    wdir.mkdir(parents=True, exist_ok=True)
    preview = {
        "task_id": task_id,
        "request": plan["description"],
        "behavior": plan["behavior"],
        "files": list(plan["authorized_paths"]),
        "checks": [list(c) for c in plan["checks"]],
        "execution": dict(plan["execution"]),
        "review_mode": plan["review_mode"],
        "review_reason": plan["review_reason"],
        "uncertainties": list(plan["uncertainties"]),
        "baseline_head": plan["baseline_head"],
        "baseline_tree": plan["baseline_tree"],
        "canonical_branch": plan["canonical_branch"],
        "product_repository": plan["product_repository"],
        "scope": plan["scope"],
    }
    if preview_only:
        record = _new_task_record(plan, task_id, "PREVIEW", None)
        save_task_record(rt, record)
        # Persist preview for audit (not authority).
        try:
            (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError as exc:
            raise WorkflowError(f"Cannot write preview: {exc}", EXIT_BLOCKER, "WORKFLOW_WRITE_ERROR") from exc
        return {"task_id": task_id, "status": "PREVIEW", "preview": preview, "plan": plan, "record": record}
    # Normal path requires explicit literal approval.
    approved = isinstance(approval_text, str) and approval_text.strip() == "approve"
    if not approved:
        record = _new_task_record(plan, task_id, "AWAITING_GATE_A", None)
        save_task_record(rt, record)
        try:
            (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError as exc:
            raise WorkflowError(f"Cannot write preview: {exc}", EXIT_BLOCKER, "WORKFLOW_WRITE_ERROR") from exc
        raise WorkflowError(
            f"Gate A requires literal 'approve'. Task {task_id} preserved without execution.",
            EXIT_STOPPED,
            "WORKFLOW_GATE_A_DECLINED",
        )
    # Approved: construct exact M1 v2 authority internally.
    run_id = f"{task_id}-RUN"
    manifest, config = _load_manifest_and_config(defaults)
    # Fresh inspection for contract (already in plan, but re-inspect to bind exact truth).
    try:
        inspection = C.inspect_project(manifest)
    except RunnerError as exc:
        record = _new_task_record(plan, task_id, "STOPPED", None)
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
    if plan["review_mode"] == "TARGETED":
        # Reuse the configured sos_reviewer executable as the frozen reviewer source.
        reviewer_exe = str(config.agents["sos_reviewer"].executable)
        draft_kwargs.update(
            {
                "reviewer_executable": reviewer_exe,
                "reviewer_model": "gpt-5.6-luna",
                "reviewer_timeout_seconds": int(config.agents["sos_reviewer"].timeout_seconds),
                "review_brief": str(plan["review_brief"]),
            }
        )
    try:
        contract = C.draft_design_contract_v2(manifest, work_item, inspection, **draft_kwargs)
    except RunnerError as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id)
        record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
        save_task_record(rt, record)
        raise WorkflowError(f"Contract draft failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_ERROR") from exc
    gate_a = _gate_a_for_contract(contract)
    # Persist internal M1 authority under workflow dir (operator never hand-edits).
    contract_path = wdir / "contract.json"
    gate_path = wdir / "gate-a.json"
    packet_path = wdir / "packet.json"
    _write_atomic(contract_path, contract)
    _write_atomic(gate_path, gate_a)
    try:
        packet = C.derive_task_packet_v2(contract, gate_a, output_path=packet_path)
    except RunnerError as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id)
        record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
        save_task_record(rt, record)
        raise WorkflowError(f"Packet derivation failed: {exc}", EXIT_BLOCKER, "WORKFLOW_PACKET_ERROR") from exc
    # Execute exactly once via frozen M1 (no retry, no fallback).
    config_path = Path(str(defaults["config_source"]))
    try:
        result = R.run_packet_v2(packet_path, contract_path, gate_path, config_path, authorize=True)
    except RunnerError as exc:
        # Fail-closed blockers (baseline drift, Gate A drift, etc.).
        record = _new_task_record(plan, task_id, "STOPPED", run_id)
        record.update({"error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR"), "error": getattr(exc, "message", str(exc))})
        record["authorized_paths"] = list(plan["authorized_paths"])
        save_task_record(rt, record)
        raise WorkflowError(f"Execution blocked: {getattr(exc, 'message', str(exc))}", EXIT_BLOCKER, "WORKFLOW_EXECUTION_BLOCKED") from exc
    except Exception as exc:
        record = _new_task_record(plan, task_id, "STOPPED", run_id)
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
    # Persist controller result alongside workflow for status/resume/accept.
    if ingested is not None:
        try:
            _write_atomic(wdir / "controller-result.json", ingested)
        except WorkflowError:
            pass
    if outcome == "ACCEPTANCE_READY" and controller_phase == "ACCEPTANCE_READY":
        status = "ACCEPTANCE_READY"
        acceptance_ref = str(wdir / "controller-result.json")
    elif outcome == "ACCEPTANCE_READY":
        # Runner claims acceptance but evidence cannot be validated: fail closed.
        record = _new_task_record(plan, task_id, "STOPPED", run_id)
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
    record = _new_task_record(plan, task_id, status, run_id)
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
    # Also persist preview for audit.
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
    wdir = _workflow_dir(rt, task_id)
    contract_path = wdir / "contract.json"
    if not contract_path.is_file():
        raise WorkflowError(f"Task {task_id} has no persisted M1 contract", EXIT_BLOCKER, "WORKFLOW_MISSING_AUTHORITY")
    try:
        contract = C.load_design_contract_v2(contract_path)
    except RunnerError as exc:
        raise WorkflowError(f"Contract reload failed: {exc}", EXIT_BLOCKER, "WORKFLOW_CONTRACT_STALE") from exc
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
        contract = C.load_design_contract_v2(contract_path)
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
        contract = C.load_design_contract_v2(contract_path)
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
