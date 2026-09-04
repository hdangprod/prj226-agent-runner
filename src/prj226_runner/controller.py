"""HARN-002 single-project autonomous control loop.

The controller owns discovery, contract binding, and orchestration facts.  It
does not copy project source or replace the HARN-001 runner's worktree,
candidate, verifier, or reviewer mechanisms.  Every operation that could
execute a project task requires an exact human-gated contract binding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - the supported runner platform provides fcntl
    fcntl = None  # type: ignore[assignment]

from prj226_runner.calibration import validate_run_id
from prj226_runner.errors import (
    ArtifactValidationError,
    GovernanceBlockerError,
    RunnerEnvironmentError,
)
from prj226_runner.codex_reviewer import (
    fingerprint_manifest,
    fingerprint_worktree,
    read_artifact_snapshot,
    read_validated_artifact_snapshot,
    validate_codex_review,
)
from prj226_runner.models import ControllerPhase, ErrorClass, WorkShape
from prj226_runner.runner import TaskPacket, candidate_branch_name, parse_task_packet, run_packet


SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
PATH_KEYS = ("current", "engineering_plan", "governance", "project")
DISCOVERY_KEYS = (
    "current_next_work_marker",
    "plan_task_column",
    "plan_state_column",
    "eligible_plan_states",
    "task_id_pattern",
    "task_file_glob",
)
TASK_PACKET_MISSING = "MISSING / TO_BE_DERIVED_OR_CANONICALIZED_AFTER_GATE_A"
TASK_PACKET_PRESENT = "PRESENT / EXECUTION_AUTHORITY_EVIDENCE"
EXECUTION_NOT_AUTHORIZED = "NOT AUTHORIZED"
RUNNER_NOT_INVOKED = "NOT INVOKED"
MANIFEST_KEYS = {
    "project_id",
    "repository_path",
    "canonical_branch",
    "canonical_docs",
    "discovery_rules",
}
CONTRACT_KEYS = {
    "contract_id",
    "contract_hash",
    "contract_version",
    "project_id",
    "repository_path",
    "canonical_branch",
    "run_id",
    "work_item_id",
    "work_item_title",
    "work_shape",
    "intent",
    "success_criteria",
    "scope",
    "non_goals",
    "baseline_head",
    "baseline_tree",
    "owned_paths",
    "protected_dirty_paths",
    "assumptions",
    "risks",
    "dependencies",
    "acceptance_instruments",
    "discriminating_acceptance_controls",
    "failure_conditions",
    "exact_authority_boundary",
    "readiness",
}
READINESS_KEYS = {"task_packet", "execution", "runner"}
GATE_A_KEYS = {
    "gate",
    "decision",
    "contract_id",
    "contract_hash",
    "baseline_head",
    "baseline_tree",
    "authorized_protected_dirty_paths",
}
RUNNER_EVIDENCE_PATH_KEYS = {
    "manifest",
    "state",
    "events",
    "builder",
    "deterministic",
    "dv",
    "sos",
    "worktree",
    "review_worktree",
}
REVIEWER_DISPOSITION_KEYS = {"dv_result", "sos_result", "review_disposition"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GATE_B_PACKAGE_KEYS = {
    "gate",
    "decision",
    "package_version",
    "project_id",
    "repository_path",
    "canonical_branch",
    "expected_canonical_head",
    "expected_canonical_tree",
    "contract_id",
    "contract_hash",
    "run_id",
    "baseline_head",
    "baseline_tree",
    "candidate_head",
    "candidate_tree",
    "candidate_ref",
    "expected_changed_paths",
    "design_contract_id",
    "design_contract_hash",
    "task_packet_id",
    "task_packet_hash",
    "runner_acceptance_evidence_sha256",
    "review_artifact",
    "review_artifact_sha256",
    "review_disposition",
    "review_section_pass_states",
    "blocking_findings",
    "required_integrity_evidence",
    "evidence_references",
    "runner_acceptance_evidence",
    "gate_b_package_hash",
}
GATE_B_AUTHORIZATION_KEYS = {
    "authorization_id",
    "gate_b_package_hash",
    "candidate_head",
    "candidate_tree",
    "expected_canonical_head",
    "expected_canonical_tree",
}


def _read_json(path: Path | str) -> Any:
    target = Path(path)
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot read controller artifact: {target}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Controller artifact is not valid JSON: {exc.msg}") from exc


def _read_json_snapshot(path: Path | str, label: str) -> tuple[Any, str]:
    """Parse JSON from one no-follow byte snapshot and return its digest."""
    snapshot = read_artifact_snapshot(path)
    try:
        value = json.loads(snapshot.raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError(f"{label} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"{label} is not valid JSON: {exc.msg}") from exc
    return value, snapshot.sha256


def _write_json(path: Path | str, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(target)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot write controller artifact: {target}") from exc


def _strict_object(value: Any, required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactValidationError(f"{label} must contain exactly the HARN-002 contract fields")
    return value


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactValidationError(f"{field} must be a non-empty string")
    return value


def _safe_relative_path(value: Any, field: str) -> str:
    value = _non_empty_string(value, field)
    path = Path(value)
    if path.is_absolute() or "\\" in value or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise ArtifactValidationError(f"{field} contains an unsafe path: {value!r}")
    return value


def _path_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ArtifactValidationError(f"{field} must be an array of safe relative paths")
    paths = [_safe_relative_path(item, field) for item in value]
    if len(paths) != len(set(paths)):
        raise ArtifactValidationError(f"{field} must not contain duplicates")
    return paths


def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ArtifactValidationError(f"{field} must be an array of strings")
    return [_non_empty_string(item, field) for item in value]


def _argv_list(value: Any, field: str) -> list[list[str]]:
    if not isinstance(value, list):
        raise ArtifactValidationError(f"{field} must be an array of argv arrays")
    result: list[list[str]] = []
    for command in value:
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg for arg in command):
            raise ArtifactValidationError(f"{field} must contain non-empty argv arrays")
        result.append(list(command))
    return result


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_object_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise ArtifactValidationError(f"{field} must be a 40-character Git object ID")
    return value.lower()


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


@dataclass(frozen=True)
class ProjectManifest:
    project_id: str
    repository_path: str
    canonical_branch: str
    canonical_docs: dict[str, str | list[str]]
    discovery_rules: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProjectManifest":
        data = _strict_object(dict(value), MANIFEST_KEYS, "Project manifest")
        project_id = _non_empty_string(data["project_id"], "project_id")
        repository_path = _non_empty_string(data["repository_path"], "repository_path")
        canonical_branch = _non_empty_string(data["canonical_branch"], "canonical_branch")
        docs = _strict_object(data["canonical_docs"], set(PATH_KEYS), "canonical_docs")
        normalized_docs: dict[str, str | list[str]] = {}
        for key in ("current", "engineering_plan"):
            normalized_docs[key] = _safe_relative_path(docs[key], f"canonical_docs.{key}")
        for key in ("governance", "project"):
            normalized_docs[key] = _path_list(docs[key], f"canonical_docs.{key}", allow_empty=False)
        rules = _strict_object(data["discovery_rules"], set(DISCOVERY_KEYS), "discovery_rules")
        for key in ("current_next_work_marker", "plan_task_column", "plan_state_column", "task_id_pattern", "task_file_glob"):
            _non_empty_string(rules[key], f"discovery_rules.{key}")
        states = _string_list(rules["eligible_plan_states"], "discovery_rules.eligible_plan_states", allow_empty=False)
        if len(states) != len(set(states)):
            raise ArtifactValidationError("discovery_rules.eligible_plan_states must not contain duplicates")
        try:
            re.compile(rules["task_id_pattern"])
        except re.error as exc:
            raise ArtifactValidationError("discovery_rules.task_id_pattern is not a valid regular expression") from exc
        if "{task_id}" not in rules["task_file_glob"]:
            raise ArtifactValidationError("discovery_rules.task_file_glob must contain {task_id}")
        glob_path = Path(rules["task_file_glob"].replace("{task_id}", "TASK-ID"))
        if glob_path.is_absolute() or "\\" in rules["task_file_glob"] or any(part in {"", ".", "..", ".git"} for part in glob_path.parts):
            raise ArtifactValidationError("discovery_rules.task_file_glob must stay inside the repository")
        return cls(project_id, repository_path, canonical_branch, normalized_docs, {**rules, "eligible_plan_states": states})

    @classmethod
    def load(cls, path: Path | str) -> "ProjectManifest":
        return cls.from_mapping(_read_json(path))


def load_project_manifest(path: Path | str) -> ProjectManifest:
    """Load and strictly validate a project manifest."""
    return ProjectManifest.load(path)


def _git(repo: Path, args: Sequence[str], *, governance: bool = True) -> str:
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
        raise RunnerEnvironmentError(f"Unable to execute Git: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown Git failure"
        error = GovernanceBlockerError if governance else RunnerEnvironmentError
        raise error(f"Git inspection failed: {message}")
    return result.stdout.strip()


def _dirty_paths(repo: Path) -> list[str]:
    raw = _git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    paths: list[str] = []
    records = raw.split("\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4:
            continue
        status, path = record[:2], record[3:]
        if status.strip():
            paths.append(path)
        if status[0] in {"R", "C"} and index < len(records) and records[index]:
            paths.append(records[index])
            index += 1
    return sorted(set(paths))


def _worktrees(repo: Path) -> list[dict[str, Any]]:
    raw = _git(repo, ["worktree", "list", "--porcelain"])
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in raw.splitlines() + [""]:
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value
        elif key == "HEAD":
            current["head"] = value.lower()
        elif key == "branch":
            current["branch"] = value.removeprefix("refs/heads/")
        elif key == "detached":
            current["detached"] = True
        elif key == "prunable":
            current["prunable"] = value
    return records


def inspect_project(manifest: ProjectManifest | Mapping[str, Any] | Path | str) -> dict[str, Any]:
    """Read project Git/docs truth without creating files, worktrees, or processes."""
    manifest = manifest if isinstance(manifest, ProjectManifest) else (
        ProjectManifest.load(manifest) if isinstance(manifest, (Path, str)) else ProjectManifest.from_mapping(manifest)
    )
    repo = Path(manifest.repository_path).expanduser().resolve()
    if not repo.is_dir():
        raise RunnerEnvironmentError(f"repository_path is not a directory: {repo}")
    try:
        _git(repo, ["rev-parse", "--git-dir"])
    except GovernanceBlockerError as exc:
        raise RunnerEnvironmentError(f"repository_path is not a Git worktree: {repo}") from exc
    branch = _git(repo, ["branch", "--show-current"])
    if branch != manifest.canonical_branch:
        raise GovernanceBlockerError(f"Canonical branch drift: expected {manifest.canonical_branch}, observed {branch or '<detached>'}")
    head = _git(repo, ["rev-parse", "HEAD"]).lower()
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    document_records: list[dict[str, str]] = []
    document_contents: dict[str, str] = {}
    all_docs: list[tuple[str, str]] = []
    for role in ("current", "engineering_plan"):
        all_docs.append((role, str(manifest.canonical_docs[role])))
    for role in ("governance", "project"):
        all_docs.extend((role, item) for item in manifest.canonical_docs[role])  # type: ignore[union-attr]
    for role, relative in all_docs:
        path = repo / relative
        if not path.is_file():
            raise GovernanceBlockerError(f"Canonical document is missing: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise GovernanceBlockerError(f"Canonical document cannot be read as UTF-8: {relative}") from exc
        document_contents[relative] = content
        document_records.append({"role": role, "path": relative, "sha256": _sha256_text(content)})
    dirty = _dirty_paths(repo)
    return {
        "result": "PROJECT_INSPECTED",
        "project_id": manifest.project_id,
        "repository_path": str(repo),
        "canonical_branch": branch,
        "head": head,
        "tree": tree,
        "dirty_paths": dirty,
        "protected_dirty_paths": dirty,
        "worktrees": _worktrees(repo),
        "canonical_documents": document_records,
        "_document_contents": document_contents,
    }


def _inspection_contents(inspection: Mapping[str, Any], relative: str) -> str:
    contents = inspection.get("_document_contents")
    if not isinstance(contents, dict) or not isinstance(contents.get(relative), str):
        raise ArtifactValidationError("Project inspection is missing canonical document content")
    return contents[relative]


def _extract_current_frontier(content: str, marker: str, task_pattern: str) -> tuple[str, str]:
    pattern = re.compile(re.escape(marker) + r"[^\n]*?(" + task_pattern + r")(?:\s*[—-]\s*(.*))?", re.IGNORECASE)
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        raise GovernanceBlockerError("CURRENT canonical evidence does not identify exactly one next task")
    task_id, title = matches[0].group(1), matches[0].group(2)
    normalized_title = (title or "").strip()
    if "`" in normalized_title:
        normalized_title = normalized_title.split("`", 1)[0].rstrip()
    return task_id.upper(), normalized_title


def _extract_plan_frontier(content: str, rules: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    task_pattern = str(rules["task_id_pattern"])
    task_re = re.compile(r"^" + task_pattern + r"$", re.IGNORECASE)
    eligible = {str(item).upper() for item in rules["eligible_plan_states"]}
    results: list[tuple[str, str, str]] = []
    task_index: int | None = None
    state_index: int | None = None
    for line in content.splitlines():
        if "|" not in line:
            continue
        cells = [cell.strip().strip("`") for cell in line.split("|")]
        if cells and cells[0] == "":
            cells.pop(0)
        if cells and cells[-1] == "":
            cells.pop()
        if str(rules["plan_task_column"]).lower() in {cell.lower() for cell in cells} and str(rules["plan_state_column"]).lower() in {cell.lower() for cell in cells}:
            task_index = next(index for index, cell in enumerate(cells) if cell.lower() == str(rules["plan_task_column"]).lower())
            state_index = next(index for index, cell in enumerate(cells) if cell.lower() == str(rules["plan_state_column"]).lower())
            continue
        if task_index is None or state_index is None or max(task_index, state_index) >= len(cells):
            continue
        task_id = cells[task_index]
        state = cells[state_index].upper()
        if not task_re.fullmatch(task_id) or state not in eligible:
            continue
        description = cells[1] if len(cells) > 1 else ""
        results.append((task_id.upper(), description, state))
    return results


def _canonical_task_evidence(
    repository: Path,
    task_glob: str,
    current_id: str,
    task_pattern: str,
    current_title: str,
    plan_description: str,
) -> tuple[str, str | None, str | None]:
    """Read optional current-task evidence without making it a frontier input.

    The canonical CURRENT and Engineering Plan identify the frontier.  A task
    artifact can add execution-authority evidence, but it cannot be required to
    bootstrap discovery.  When such an artifact exists, its identity is still
    checked strictly so a contradictory packet cannot be treated as harmless
    optional context.
    """
    task_matches = sorted(repository.glob(task_glob))
    if len(task_matches) > 1:
        raise GovernanceBlockerError(f"Canonical task evidence for {current_id} is not unique")
    if not task_matches:
        return TASK_PACKET_MISSING, None, current_title or plan_description or current_id

    task_path = task_matches[0]
    try:
        task_content = task_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GovernanceBlockerError(f"Canonical task evidence cannot be read: {task_path}") from exc
    heading_pattern = re.compile(r"^#\s+(" + task_pattern + r")\s+[—-]\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
    headings = list(heading_pattern.finditer(task_content))
    if len(headings) != 1:
        raise GovernanceBlockerError(f"Canonical task evidence for {current_id} has no unique task identity")
    task_id, title = headings[0].group(1), headings[0].group(2)
    if task_id.upper() != current_id:
        raise GovernanceBlockerError(
            f"Canonical task evidence contradicts frontier: CURRENT/Engineering Plan say {current_id}, packet says {task_id.upper()}"
        )
    return TASK_PACKET_PRESENT, str(task_path.relative_to(repository)), task_content


def discover_next_work(
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    inspection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Discover the one frontier agreed by CURRENT and the canonical plan.

    CURRENT is the deterministic precedence authority for selecting the next
    item when the plan contains multiple eligible rows.  The plan must still
    represent that exact item exactly once; no task packet is required for this
    discovery step.
    """
    manifest = manifest if isinstance(manifest, ProjectManifest) else (
        ProjectManifest.load(manifest) if isinstance(manifest, (Path, str)) else ProjectManifest.from_mapping(manifest)
    )
    inspection = inspection or inspect_project(manifest)
    current_path = str(manifest.canonical_docs["current"])
    plan_path = str(manifest.canonical_docs["engineering_plan"])
    task_pattern = str(manifest.discovery_rules["task_id_pattern"])
    current_id, current_title = _extract_current_frontier(
        _inspection_contents(inspection, current_path),
        str(manifest.discovery_rules["current_next_work_marker"]),
        task_pattern,
    )
    plan_candidates = _extract_plan_frontier(_inspection_contents(inspection, plan_path), manifest.discovery_rules)
    if not plan_candidates:
        raise GovernanceBlockerError("Engineering Plan canonical evidence has no eligible next task")
    matching_candidates = [candidate for candidate in plan_candidates if candidate[0] == current_id]
    if len(matching_candidates) != 1:
        plan_ids = ", ".join(candidate[0] for candidate in plan_candidates)
        raise GovernanceBlockerError(
            f"GOVERNANCE_BLOCKER: CURRENT says {current_id}, Engineering Plan eligible frontier is {plan_ids or '<none>'}"
        )
    if len({candidate[0] for candidate in plan_candidates}) != len(plan_candidates):
        raise GovernanceBlockerError("GOVERNANCE_BLOCKER: Engineering Plan contains duplicate eligible frontier identities")
    plan_id, plan_description, plan_state = matching_candidates[0]
    task_glob = str(manifest.discovery_rules["task_file_glob"]).replace("{task_id}", current_id)
    repository = Path(manifest.repository_path).expanduser().resolve()
    task_status, task_path, task_content_or_title = _canonical_task_evidence(
        repository, task_glob, current_id, task_pattern, current_title, plan_description
    )
    if task_status == TASK_PACKET_PRESENT:
        task_content = task_content_or_title
        title_match = re.search(r"^#\s+" + re.escape(current_id) + r"\s+[—-]\s+(.+?)\s*$", task_content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else current_title or plan_description or current_id
    else:
        task_content = None
        title = task_content_or_title
    return {
        "result": "NEXT_WORK_DISCOVERED",
        "work_item_id": current_id,
        "title": title,
        "plan_state": plan_state,
        "task_path": task_path,
        "task_packet_status": task_status,
        "execution_status": EXECUTION_NOT_AUTHORIZED,
        "runner_status": RUNNER_NOT_INVOKED,
        "source_documents": [current_path, plan_path],
        "_task_content": task_content,
    }


def classify_work(work_item: Mapping[str, Any]) -> dict[str, str]:
    """Apply deterministic promotion rules and return exactly one work shape."""
    content = " ".join(str(work_item.get(key, "")) for key in ("title", "_task_content", "description")).lower()
    if any(token in content for token in ("architectural", "architecture", "migration", "destructive", "cross-system")):
        shape = WorkShape.ARCHITECTURAL.value
    elif any(token in content for token in ("spike", "investigate", "exploratory")):
        shape = WorkShape.SPIKE.value
    else:
        shape = WorkShape.BOUNDED.value
    return {"work_shape": shape}


def _contract_without_identity(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {key: contract[key] for key in sorted(CONTRACT_KEYS - {"contract_id", "contract_hash"})}


def _normalize_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    data = _strict_object(dict(value), CONTRACT_KEYS, "Design Contract")
    _non_empty_string(data["contract_version"], "contract_version")
    _non_empty_string(data["project_id"], "project_id")
    _non_empty_string(data["repository_path"], "repository_path")
    _non_empty_string(data["canonical_branch"], "canonical_branch")
    try:
        validate_run_id(data["run_id"])
    except (TypeError, ValueError) as exc:
        raise ArtifactValidationError(str(exc)) from exc
    for field in ("work_item_id", "work_item_title", "intent", "exact_authority_boundary"):
        _non_empty_string(data[field], field)
    if data["work_shape"] not in {item.value for item in WorkShape}:
        raise ArtifactValidationError("work_shape must be exactly one of SPIKE, BOUNDED, or ARCHITECTURAL")
    for field in ("scope", "success_criteria"):
        _string_list(data[field], field, allow_empty=False)
    for field in ("non_goals", "assumptions", "risks", "dependencies", "failure_conditions"):
        _string_list(data[field], field, allow_empty=True)
    readiness = _strict_object(data["readiness"], READINESS_KEYS, "Design Contract readiness")
    if readiness["task_packet"] not in {TASK_PACKET_MISSING, TASK_PACKET_PRESENT}:
        raise ArtifactValidationError("Design Contract readiness.task_packet is invalid")
    if readiness["execution"] != EXECUTION_NOT_AUTHORIZED:
        raise ArtifactValidationError("Design Contract readiness.execution must be NOT AUTHORIZED")
    if readiness["runner"] != RUNNER_NOT_INVOKED:
        raise ArtifactValidationError("Design Contract readiness.runner must be NOT INVOKED")
    _validate_object_id(data["baseline_head"], "baseline_head")
    _validate_object_id(data["baseline_tree"], "baseline_tree")
    _path_list(data["owned_paths"], "owned_paths", allow_empty=False)
    _path_list(data["protected_dirty_paths"], "protected_dirty_paths", allow_empty=True)
    _argv_list(data["acceptance_instruments"], "acceptance_instruments")
    _string_list(data["discriminating_acceptance_controls"], "discriminating_acceptance_controls", allow_empty=False)
    if not isinstance(data["contract_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["contract_hash"]):
        raise ArtifactValidationError("contract_hash must be a lowercase SHA-256 digest")
    expected_hash = _sha(_contract_without_identity(data))
    if data["contract_hash"] != expected_hash or data["contract_id"] != "design-" + expected_hash:
        raise ArtifactValidationError("Design Contract identity/hash does not match its content")
    return data


def draft_design_contract(
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    work_item: Mapping[str, Any],
    inspection: Mapping[str, Any],
    *,
    run_id: str,
    owned_paths: Sequence[str],
    success_criteria: Sequence[str] | None = None,
    scope: Sequence[str] | None = None,
    non_goals: Sequence[str] | None = None,
    assumptions: Sequence[str] | None = None,
    risks: Sequence[str] | None = None,
    dependencies: Sequence[str] | None = None,
    acceptance_instruments: Sequence[Sequence[str]] | None = None,
    discriminating_acceptance_controls: Sequence[str] | None = None,
    failure_conditions: Sequence[str] | None = None,
    exact_authority_boundary: str | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Draft a deterministic proposal; this function does not authorize execution."""
    manifest = manifest if isinstance(manifest, ProjectManifest) else (
        ProjectManifest.load(manifest) if isinstance(manifest, (Path, str)) else ProjectManifest.from_mapping(manifest)
    )
    if inspection.get("project_id") != manifest.project_id or inspection.get("canonical_branch") != manifest.canonical_branch:
        raise GovernanceBlockerError("Project inspection does not match the project manifest")
    expected_repository = str(Path(manifest.repository_path).expanduser().resolve())
    if inspection.get("repository_path") != expected_repository:
        raise GovernanceBlockerError("Project inspection repository does not match the project manifest")
    validate_run_id(run_id)
    item_id = _non_empty_string(work_item.get("work_item_id"), "work_item_id")
    title = _non_empty_string(work_item.get("title"), "work_item title")
    classification = classify_work(work_item)["work_shape"]
    owned = _path_list(list(owned_paths), "owned_paths", allow_empty=False)
    protected = _path_list(list(inspection.get("protected_dirty_paths", [])), "protected_dirty_paths")
    criteria = list(success_criteria or [f"{item_id} satisfies its canonical task artifact and deterministic acceptance evidence."])
    controls = list(discriminating_acceptance_controls or [
        "Reject conflicting CURRENT and Engineering Plan frontiers.",
        "Bind baseline, candidate, review, and Gate A identities exactly.",
    ])
    contract: dict[str, Any] = {
        "contract_version": "HARN-002.v1",
        "project_id": manifest.project_id,
        "repository_path": str(Path(manifest.repository_path).expanduser().resolve()),
        "canonical_branch": manifest.canonical_branch,
        "run_id": run_id,
        "work_item_id": item_id,
        "work_item_title": title,
        "work_shape": classification,
        "intent": f"Implement the approved scope for {item_id} — {title}.",
        "success_criteria": criteria,
        "scope": list(scope or owned),
        "non_goals": list(non_goals or ["Canonical integration, push, and work outside owned paths."]),
        "baseline_head": _validate_object_id(inspection.get("head"), "inspection.head"),
        "baseline_tree": _validate_object_id(inspection.get("tree"), "inspection.tree"),
        "owned_paths": owned,
        "protected_dirty_paths": protected,
        "assumptions": list(assumptions or []),
        "risks": list(risks or [f"{classification} work requires exact independent acceptance evidence."]),
        "dependencies": list(dependencies or []),
        "acceptance_instruments": [list(item) for item in (acceptance_instruments or [["git", "diff", "--check", "HEAD^", "HEAD"]])],
        "discriminating_acceptance_controls": controls,
        "failure_conditions": list(failure_conditions or ["Any authority, baseline, candidate, review, or repository drift."]),
        "exact_authority_boundary": exact_authority_boundary or (
            "Human Gate A authorizes only this exact Design Contract and its derived HARN-001 Task Packet; "
            "Human Gate B is required before canonical integration."
        ),
        "readiness": {
            "task_packet": work_item.get("task_packet_status", TASK_PACKET_MISSING),
            "execution": EXECUTION_NOT_AUTHORIZED,
            "runner": RUNNER_NOT_INVOKED,
        },
    }
    digest = _sha(_contract_without_identity(contract))
    contract["contract_hash"] = digest
    contract["contract_id"] = "design-" + digest
    normalized = _normalize_contract(contract)
    if output_path is not None:
        _write_json(output_path, normalized)
    return normalized


def load_design_contract(path: Path | str) -> dict[str, Any]:
    return _normalize_contract(_read_json(path))


def _contract_value(contract: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    return load_design_contract(contract) if isinstance(contract, (Path, str)) else _normalize_contract(contract)


def validate_gate_a(contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], *, inspect: bool = True) -> None:
    """Validate exact human Gate A binding and current project truth."""
    contract_data = _contract_value(contract)
    try:
        auth = _strict_object(dict(authorization), GATE_A_KEYS, "Gate A authorization")
    except (ArtifactValidationError, TypeError) as exc:
        raise GovernanceBlockerError("Gate A authorization is missing or not exact") from exc
    if auth["gate"] != "HUMAN_GATE_A" or auth["decision"] != "APPROVED":
        raise GovernanceBlockerError("Gate A is not an exact APPROVED human authorization")
    if auth["contract_id"] != contract_data["contract_id"] or auth["contract_hash"] != contract_data["contract_hash"]:
        raise GovernanceBlockerError("Gate A is bound to a different Design Contract")
    for field in ("baseline_head", "baseline_tree"):
        if not isinstance(auth[field], str) or not SHA_RE.fullmatch(auth[field]) or auth[field].lower() != contract_data[field]:
            raise GovernanceBlockerError(f"Gate A {field} does not match the Design Contract")
    authorized_dirty = _path_list(auth["authorized_protected_dirty_paths"], "authorized_protected_dirty_paths")
    overlap = sorted(path for path in contract_data["protected_dirty_paths"] if any(_paths_overlap(path, owned) for owned in contract_data["owned_paths"]))
    if sorted(authorized_dirty) != overlap:
        raise GovernanceBlockerError("Protected dirty paths overlap owned scope without exact Gate A authority")
    if inspect:
        repo = Path(contract_data["repository_path"])
        observed_branch = _git(repo, ["branch", "--show-current"])
        observed_head = _git(repo, ["rev-parse", "HEAD"]).lower()
        observed_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
        if observed_branch != contract_data["canonical_branch"]:
            raise GovernanceBlockerError("Canonical branch drift after Design Contract creation")
        if observed_head != contract_data["baseline_head"] or observed_tree != contract_data["baseline_tree"]:
            raise GovernanceBlockerError("STALE_BASELINE: repository changed after Design Contract creation")
        if _dirty_paths(repo) != contract_data["protected_dirty_paths"]:
            raise GovernanceBlockerError("Protected dirty baseline changed after Design Contract creation")


def _packet_prompt(contract: Mapping[str, Any]) -> str:
    return (
        f"{contract['intent']}\n\nApproved scope (exact): {json.dumps(contract['scope'], sort_keys=True)}\n"
        f"Success criteria (exact): {json.dumps(contract['success_criteria'], sort_keys=True)}\n"
        f"Non-goals: {json.dumps(contract['non_goals'], sort_keys=True)}"
    )


def _packet_mapping(contract: Mapping[str, Any], authorization: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_id": contract["run_id"],
        "task_id": contract["work_item_id"],
        "product_repo": contract["repository_path"],
        "canonical_branch": contract["canonical_branch"],
        "baseline_head": contract["baseline_head"],
        "baseline_tree": contract["baseline_tree"],
        "authorized_paths": list(contract["owned_paths"]),
        "builder_prompt": _packet_prompt(contract),
        "acceptance_criteria": list(contract["success_criteria"]),
        "test_commands": [list(item) for item in contract["acceptance_instruments"]],
        "commit_message": f"feat({contract['work_item_id'].lower()}): implement approved task",
    }


def validate_task_packet_derivation(contract: Mapping[str, Any] | Path | str, packet: Mapping[str, Any] | TaskPacket) -> None:
    contract_data = _contract_value(contract)
    packet_data = asdict(packet) if isinstance(packet, TaskPacket) else dict(packet)
    expected = _packet_mapping(contract_data, {})
    if set(packet_data) != set(expected):
        raise ArtifactValidationError("Derived Task Packet has unexpected or missing fields")
    for field in expected:
        if packet_data[field] != expected[field]:
            raise GovernanceBlockerError(f"Derived Task Packet widens or changes approved field: {field}")


def derive_task_packet(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    *,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value(contract)
    validate_gate_a(contract_data, authorization)
    packet = _packet_mapping(contract_data, authorization)
    validate_task_packet_derivation(contract_data, packet)
    if output_path is not None:
        _write_json(output_path, packet)
        parse_task_packet(output_path)
    return packet


def dispatch_runner(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    packet_path: Path | str,
    config_path: Path | str | None = None,
) -> dict[str, Any]:
    """Dispatch exactly once to HARN-001 after exact Gate A validation."""
    contract_data = _contract_value(contract)
    validate_gate_a(contract_data, authorization)
    packet = parse_task_packet(packet_path)
    validate_task_packet_derivation(contract_data, packet)
    return run_packet(packet_path, config_path, authorize=True)


def _sha256_file(path: Path, field: str) -> str:
    snapshot = read_artifact_snapshot(path)
    return snapshot.sha256


def _require_evidence_path(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactValidationError(f"{field} must be a non-empty evidence path")
    path = Path(value)
    if path.is_symlink() or not path.exists():
        raise ArtifactValidationError(f"{field} does not reference existing evidence")
    return path


def _review_file_identity(
    path: Path,
    *,
    expected_head: str,
    expected_tree: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    snapshot = read_validated_artifact_snapshot(
        path,
        expected_head=expected_head,
        expected_tree=expected_tree,
    )
    actual_sha256 = snapshot.sha256
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
            raise ArtifactValidationError("review_artifact_sha256 must be a lowercase SHA-256 digest")
        if actual_sha256 != expected_sha256:
            raise ArtifactValidationError("Review evidence changed after runner validation")
    return {"value": snapshot.value, "sha256": actual_sha256, "raw_bytes": snapshot.raw_bytes}


def _runner_acceptance_evidence_identity(data: Mapping[str, Any]) -> str:
    """Return the deterministic identity of the validated Runner evidence set."""
    identity = {
        "run_id": data.get("run_id"),
        "candidate_head": data.get("candidate_head"),
        "candidate_tree": data.get("candidate_tree"),
        "candidate_ref": data.get("candidate_ref"),
        "deterministic_result": data.get("deterministic_result"),
        "verification_disposition": data.get("verification_disposition"),
        "reviewer_disposition": data.get("reviewer_disposition"),
        "evidence_paths": data.get("evidence_paths"),
        "required_evidence_references": data.get("required_evidence_references"),
        "candidate_worktree_fingerprint": data.get("candidate_worktree_fingerprint"),
        "review_worktree_fingerprint": data.get("review_worktree_fingerprint"),
        "review_artifact_sha256": data.get("review_artifact_sha256"),
        "evidence_file_sha256": data.get("evidence_file_sha256"),
    }
    return _sha(identity)


def _validate_fingerprint_artifact(path: Path, expected_fingerprint: str, field: str) -> dict[str, Any]:
    value, artifact_sha256 = _read_json_snapshot(path, field)
    if not isinstance(value, dict) or set(value) != {"fingerprint", "manifest"}:
        raise ArtifactValidationError(f"{field} is not a closed worktree fingerprint artifact")
    fingerprint = value.get("fingerprint")
    if not isinstance(fingerprint, str) or not SHA256_RE.fullmatch(fingerprint) or fingerprint != expected_fingerprint:
        raise ArtifactValidationError(f"{field} does not match the validated worktree fingerprint")
    if not isinstance(value["manifest"], list):
        raise ArtifactValidationError(f"{field}.manifest must be an array")
    ordered = sorted(value["manifest"], key=lambda item: (str(item.get("path", "")), str(item.get("type", ""))) if isinstance(item, dict) else ("", ""))
    if value["manifest"] != ordered:
        raise ArtifactValidationError(f"{field}.manifest is not path-sorted")
    if fingerprint_manifest(value["manifest"]) != fingerprint:
        raise ArtifactValidationError(f"{field}.manifest does not hash to its fingerprint")
    return {**value, "_artifact_sha256": artifact_sha256}


def _validate_runner_acceptance_evidence(
    contract_data: Mapping[str, Any],
    data: Mapping[str, Any],
    *,
    review_snapshot: Any = None,
) -> dict[str, Any]:
    """Validate the complete immutable evidence bundle emitted by Runner V1."""
    if data.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner acceptance evidence run_id does not match the Design Contract")
    if data.get("result") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner acceptance evidence must have result ACCEPTANCE_READY")
    if data.get("deterministic_result") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner deterministic_result is missing or not ACCEPTANCE_READY")
    if data.get("verification_disposition") != "PASS":
        raise ArtifactValidationError("Runner verification_disposition is missing or not PASS")
    candidate_head = _validate_object_id(data.get("candidate_head"), "candidate_head")
    candidate_tree = _validate_object_id(data.get("candidate_tree"), "candidate_tree")
    candidate_ref = data.get("candidate_ref")
    if not isinstance(candidate_ref, str) or not candidate_ref.strip():
        raise ArtifactValidationError("Runner acceptance evidence is missing candidate_ref")
    disposition = data.get("reviewer_disposition")
    if not isinstance(disposition, dict) or set(disposition) != REVIEWER_DISPOSITION_KEYS:
        raise ArtifactValidationError("Runner reviewer disposition is incomplete")
    if disposition != {"dv_result": "PASS", "sos_result": "ACCEPT", "review_disposition": "PASS"}:
        raise ArtifactValidationError("Runner reviewer disposition is not a complete PASS")

    evidence_paths = data.get("evidence_paths")
    if not isinstance(evidence_paths, dict) or set(evidence_paths) != RUNNER_EVIDENCE_PATH_KEYS:
        raise ArtifactValidationError("Runner evidence_paths are incomplete")
    paths = {key: _require_evidence_path(value, f"evidence_paths.{key}") for key, value in evidence_paths.items()}
    review_artifact_value = data.get("review_artifact")
    review_raw_value = data.get("review_raw_artifact")
    pre_fingerprint_value = data.get("review_fingerprint_pre_artifact")
    post_fingerprint_value = data.get("review_fingerprint_post_artifact")
    for field, value in (
        ("review_artifact", review_artifact_value),
        ("review_raw_artifact", review_raw_value),
        ("review_fingerprint_pre_artifact", pre_fingerprint_value),
        ("review_fingerprint_post_artifact", post_fingerprint_value),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ArtifactValidationError(f"Runner acceptance evidence is missing {field}")
    review_artifact = _require_evidence_path(review_artifact_value, "review_artifact")
    review_raw_artifact = _require_evidence_path(review_raw_value, "review_raw_artifact")
    pre_fingerprint_artifact = _require_evidence_path(pre_fingerprint_value, "review_fingerprint_pre_artifact")
    post_fingerprint_artifact = _require_evidence_path(post_fingerprint_value, "review_fingerprint_post_artifact")
    if not isinstance(data.get("review_artifact_sha256"), str) or not SHA256_RE.fullmatch(data["review_artifact_sha256"]):
        raise ArtifactValidationError("Runner acceptance evidence is missing a valid review_artifact_sha256")
    expected_sos = paths["sos"] / "review.json"
    expected_raw = paths["sos"] / "raw-result.json"
    expected_pre = paths["sos"] / "fingerprint-pre.json"
    expected_post = paths["sos"] / "fingerprint-post.json"
    if review_artifact.resolve() != expected_sos.resolve() or review_raw_artifact.resolve() != expected_raw.resolve():
        raise ArtifactValidationError("Runner review evidence is not bound to the canonical SOS artifacts")
    if pre_fingerprint_artifact.resolve() != expected_pre.resolve() or post_fingerprint_artifact.resolve() != expected_post.resolve():
        raise ArtifactValidationError("Runner fingerprint evidence is not bound to the canonical SOS artifacts")

    required = data.get("required_evidence_references")
    expected_references = {str(path) for path in paths.values()} | {
        str(review_artifact), str(review_raw_artifact), str(pre_fingerprint_artifact), str(post_fingerprint_artifact),
    }
    if not isinstance(required, list) or not required or any(not isinstance(item, str) or not item.strip() for item in required):
        raise ArtifactValidationError("required_evidence_references is missing or invalid")
    if len(required) != len(set(required)) or set(required) != expected_references or required != sorted(required):
        raise ArtifactValidationError("required_evidence_references do not exactly bind the evidence bundle")

    manifest, manifest_sha256 = _read_json_snapshot(paths["manifest"], "Runner manifest")
    if not isinstance(manifest, dict) or manifest.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner manifest does not bind the Design Contract run_id")
    product = manifest.get("product")
    if not isinstance(product, dict) or product.get("repo") != contract_data["repository_path"] or product.get("canonical_branch") != contract_data["canonical_branch"]:
        raise ArtifactValidationError("Runner manifest product binding is incomplete")
    if product.get("baseline_head") != contract_data["baseline_head"] or product.get("baseline_tree") != contract_data["baseline_tree"]:
        raise ArtifactValidationError("Runner manifest baseline binding is stale")

    state, state_sha256 = _read_json_snapshot(paths["state"], "Runner state")
    if not isinstance(state, dict) or state.get("run_id") != contract_data["run_id"] or state.get("state") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner state does not prove ACCEPTANCE_READY")
    events_snapshot = read_artifact_snapshot(paths["events"])
    try:
        event_lines = events_snapshot.raw_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError("Runner event evidence is not valid UTF-8") from exc
    if not event_lines:
        raise ArtifactValidationError("Runner event evidence is empty")
    try:
        events = [json.loads(line) for line in event_lines]
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Runner event evidence is not valid JSON: {exc.msg}") from exc
    if not isinstance(events[-1], dict) or events[-1].get("event") != "acceptance_ready" or events[-1].get("to_state") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner event evidence does not end at ACCEPTANCE_READY")

    builder_invocation, builder_sha256 = _read_json_snapshot(paths["builder"] / "invocation.json", "Builder acceptance evidence")
    if not isinstance(builder_invocation, dict) or builder_invocation.get("exit_code") != 0:
        raise ArtifactValidationError("Builder acceptance evidence is incomplete")
    deterministic_dirs = sorted(paths["deterministic"].glob("test-*"), key=lambda path: path.name)
    if not deterministic_dirs:
        raise ArtifactValidationError("Deterministic acceptance evidence contains no test invocations")
    deterministic_file_hashes: dict[str, str] = {}
    for directory in deterministic_dirs:
        invocation, invocation_sha256 = _read_json_snapshot(directory / "invocation.json", "Deterministic acceptance evidence")
        deterministic_file_hashes[directory.name + "/invocation.json"] = invocation_sha256
        if not isinstance(invocation, dict) or invocation.get("exit_code") != 0 or invocation.get("timed_out"):
            raise ArtifactValidationError("Deterministic acceptance evidence contains a non-PASS test")
    dv, dv_sha256 = _read_json_snapshot(paths["dv"] / "result.json", "DV acceptance evidence")
    if not isinstance(dv, dict) or set(dv) != {"result", "findings"} or dv.get("result") != "PASS" or not isinstance(dv.get("findings"), list):
        raise ArtifactValidationError("DV acceptance evidence is incomplete or not PASS")

    if review_snapshot is None:
        review = _review_file_identity(
            review_artifact,
            expected_head=candidate_head,
            expected_tree=candidate_tree,
            expected_sha256=data.get("review_artifact_sha256"),
        )
    else:
        if review_snapshot.sha256 != data.get("review_artifact_sha256"):
            raise ArtifactValidationError("Review evidence changed after snapshot validation")
        review = {"value": review_snapshot.value, "sha256": review_snapshot.sha256, "raw_bytes": review_snapshot.raw_bytes}
        validate_codex_review(review["value"], expected_head=candidate_head, expected_tree=candidate_tree)
    if review["value"]["disposition"] != "PASS":
        raise ArtifactValidationError("Runner review evidence is not PASS")
    raw_review_snapshot = read_artifact_snapshot(review_raw_artifact)
    stored_fingerprint = data.get("review_worktree_fingerprint")
    candidate_fingerprint = data.get("candidate_worktree_fingerprint")
    for field, value in (("candidate_worktree_fingerprint", candidate_fingerprint), ("review_worktree_fingerprint", stored_fingerprint)):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise ArtifactValidationError(f"Runner {field} is missing or invalid")
    candidate_worktree = paths["worktree"]
    review_worktree = paths["review_worktree"]
    if _git(candidate_worktree, ["rev-parse", "HEAD"]).lower() != candidate_head or _git(candidate_worktree, ["rev-parse", "HEAD^{tree}"]).lower() != candidate_tree:
        raise GovernanceBlockerError("Runner candidate worktree identity is stale")
    if _git(review_worktree, ["rev-parse", "HEAD"]).lower() != candidate_head or _git(review_worktree, ["rev-parse", "HEAD^{tree}"]).lower() != candidate_tree:
        raise GovernanceBlockerError("Runner verifier worktree identity is stale")
    if _git(candidate_worktree, ["status", "--porcelain"]) or _git(review_worktree, ["status", "--porcelain"]):
        raise GovernanceBlockerError("Candidate or verifier worktree is not Git-clean")
    if fingerprint_worktree(candidate_worktree) != candidate_fingerprint or fingerprint_worktree(review_worktree) != stored_fingerprint:
        raise GovernanceBlockerError("Candidate or verifier worktree filesystem fingerprint changed")
    pre = _validate_fingerprint_artifact(pre_fingerprint_artifact, stored_fingerprint, "review fingerprint preflight")
    post = _validate_fingerprint_artifact(post_fingerprint_artifact, stored_fingerprint, "review fingerprint postflight")
    if pre["manifest"] != post["manifest"]:
        raise GovernanceBlockerError("Review pre/post filesystem manifests differ")
    expected_ref = candidate_branch_name(TaskPacket(**_packet_mapping(contract_data, {})))
    if candidate_ref != expected_ref:
        raise ArtifactValidationError("Runner candidate_ref does not match the immutable Task Packet")
    product_repo = Path(contract_data["repository_path"])
    if _git(product_repo, ["rev-parse", candidate_ref]).lower() != candidate_head:
        raise GovernanceBlockerError("Runner candidate reference does not bind candidate HEAD")
    if _git(product_repo, ["rev-parse", candidate_ref + "^{tree}"]).lower() != candidate_tree:
        raise GovernanceBlockerError("Runner candidate reference does not bind candidate TREE")
    evidence_file_sha256 = {
        "manifest.json": manifest_sha256,
        "state.json": state_sha256,
        "events.ndjson": events_snapshot.sha256,
        "builder/invocation.json": builder_sha256,
        **{f"deterministic/{key}": value for key, value in deterministic_file_hashes.items()},
        "dv/result.json": dv_sha256,
        "sos/review.json": review["sha256"],
        "sos/raw-result.json": raw_review_snapshot.sha256,
        "sos/fingerprint-pre.json": pre["_artifact_sha256"],
        "sos/fingerprint-post.json": post["_artifact_sha256"],
    }
    identity_data = dict(data)
    identity_data["evidence_file_sha256"] = evidence_file_sha256
    return {
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "candidate_ref": candidate_ref,
        "review": review["value"],
        "review_snapshot_sha256": review["sha256"],
        "review_artifact_sha256": review["sha256"],
        "runner_acceptance_evidence_sha256": _runner_acceptance_evidence_identity(identity_data),
        "review_fingerprint_pre_artifact_sha256": pre["_artifact_sha256"],
        "review_fingerprint_post_artifact_sha256": post["_artifact_sha256"],
        "evidence_file_sha256": evidence_file_sha256,
        "evidence_paths": {key: str(path) for key, path in paths.items()},
        "required_evidence_references": list(required),
    }


def ingest_runner_result(contract: Mapping[str, Any] | Path | str, result: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    """Accept only a complete, candidate-bound Runner acceptance bundle."""
    contract_data = _contract_value(contract)
    data = _read_json(result) if isinstance(result, (Path, str)) else dict(result)
    if not isinstance(data, dict) or data.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner result run_id does not match the Design Contract")
    outcome = data.get("result")
    if outcome not in {"ACCEPTANCE_READY", "STOPPED"}:
        raise ArtifactValidationError("Runner result has an unsupported deterministic outcome")
    error_class = data.get("error_class")
    if error_class is not None and error_class not in {item.value for item in ErrorClass}:
        raise ArtifactValidationError("Runner result error_class is invalid")
    if outcome == "ACCEPTANCE_READY":
        evidence = _validate_runner_acceptance_evidence(contract_data, data)
        candidate_head, candidate_tree = evidence["candidate_head"], evidence["candidate_tree"]
        reviewer_disposition = {"dv_result": "PASS", "sos_result": "ACCEPT", "review_disposition": "PASS"}
        return {
            "result": "RESULT_INGESTED",
            "controller_phase": ControllerPhase.ACCEPTANCE_READY.value,
            "run_id": data["run_id"],
            "candidate_head": candidate_head,
            "candidate_tree": candidate_tree,
            "candidate_ref": evidence["candidate_ref"],
            "deterministic_result": data["deterministic_result"],
            "verification_disposition": data["verification_disposition"],
            "reviewer_disposition": reviewer_disposition,
            "evidence_references": evidence["required_evidence_references"],
            "evidence_paths": evidence["evidence_paths"],
            "required_evidence_references": evidence["required_evidence_references"],
            "review_artifact": data["review_artifact"],
            "review_raw_artifact": data["review_raw_artifact"],
            "review_fingerprint_pre_artifact": data["review_fingerprint_pre_artifact"],
            "review_fingerprint_post_artifact": data["review_fingerprint_post_artifact"],
            "review_worktree_fingerprint": data["review_worktree_fingerprint"],
            "candidate_worktree_fingerprint": data["candidate_worktree_fingerprint"],
            "review": evidence["review"],
            "review_artifact_sha256": evidence["review_artifact_sha256"],
            "runner_acceptance_evidence_sha256": evidence["runner_acceptance_evidence_sha256"],
            "evidence_file_sha256": evidence["evidence_file_sha256"],
            "error_class": error_class,
        }
    candidate_head = data.get("candidate_head")
    candidate_tree = data.get("candidate_tree")
    if candidate_head is not None:
        candidate_head = _validate_object_id(candidate_head, "candidate_head")
    if candidate_tree is not None:
        candidate_tree = _validate_object_id(candidate_tree, "candidate_tree")
    if (candidate_head is None) != (candidate_tree is None):
        raise ArtifactValidationError("Stopped Runner result must bind both candidate IDs or neither")
    return {
        "result": "RESULT_INGESTED",
        "controller_phase": ControllerPhase.STOPPED.value,
        "run_id": data["run_id"],
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "deterministic_result": "STOPPED",
        "reviewer_disposition": {},
        "evidence_references": [],
        "error_class": error_class,
    }


def validate_review_binding(
    review: Mapping[str, Any],
    candidate_head: str,
    candidate_tree: str,
    *,
    actual_candidate_head: str | None = None,
    actual_candidate_tree: str | None = None,
) -> None:
    expected_head = _validate_object_id(candidate_head, "candidate_head")
    expected_tree = _validate_object_id(candidate_tree, "candidate_tree")
    validate_codex_review(review, expected_head=expected_head, expected_tree=expected_tree)
    if actual_candidate_head is not None and actual_candidate_head.lower() != expected_head:
        raise GovernanceBlockerError("REVIEW_STALE: current candidate HEAD differs from review")
    if actual_candidate_tree is not None and actual_candidate_tree.lower() != expected_tree:
        raise GovernanceBlockerError("REVIEW_STALE: current candidate TREE differs from review")


def prepare_gate_b(
    contract: Mapping[str, Any] | Path | str,
    ingested_result: Mapping[str, Any],
    review: Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Build deterministic evidence for a future, fresh Human Gate-B decision."""
    contract_data = _contract_value(contract)
    if not isinstance(ingested_result, Mapping) or ingested_result.get("result") != "RESULT_INGESTED":
        raise ArtifactValidationError("Gate B requires a validated ingested Runner result")
    if ingested_result.get("controller_phase") != ControllerPhase.ACCEPTANCE_READY.value:
        raise GovernanceBlockerError("Gate B cannot be prepared before ACCEPTANCE_READY")
    source = dict(ingested_result)
    source.update({
        "result": "ACCEPTANCE_READY",
        "run_id": ingested_result.get("run_id"),
        "deterministic_result": ingested_result.get("deterministic_result"),
        "verification_disposition": ingested_result.get("verification_disposition"),
    })
    candidate_head = _validate_object_id(ingested_result.get("candidate_head"), "candidate_head")
    candidate_tree = _validate_object_id(ingested_result.get("candidate_tree"), "candidate_tree")
    review_snapshot = None
    if isinstance(review, (Path, str)):
        if Path(review).resolve() != Path(source["review_artifact"]).resolve():
            raise ArtifactValidationError("Gate B review input is not the ingested review artifact")
        review_snapshot = read_validated_artifact_snapshot(
            review,
            expected_head=candidate_head,
            expected_tree=candidate_tree,
        )
        normalized_review = review_snapshot.value
    else:
        normalized_review = validate_codex_review(review, expected_head=candidate_head, expected_tree=candidate_tree)
    evidence = _validate_runner_acceptance_evidence(contract_data, source, review_snapshot=review_snapshot)
    if evidence["review"] != normalized_review:
        raise ArtifactValidationError("Gate B review evidence differs from the validated immutable review artifact")
    if "review" in ingested_result:
        ingested_review = validate_codex_review(
            ingested_result["review"],
            expected_head=candidate_head,
            expected_tree=candidate_tree,
        )
        if ingested_review != evidence["review"]:
            raise ArtifactValidationError("Ingested review snapshot differs from the current validated artifact")
    repo = Path(contract_data["repository_path"])
    if _git(repo, ["branch", "--show-current"]) != contract_data["canonical_branch"]:
        raise GovernanceBlockerError("Gate B canonical branch drift")
    if _git(repo, ["rev-parse", "HEAD"]).lower() != contract_data["baseline_head"] or _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != contract_data["baseline_tree"]:
        raise GovernanceBlockerError("Gate B canonical baseline drift")
    if _dirty_paths(repo):
        raise GovernanceBlockerError("Gate B requires a clean canonical project worktree")
    packet = TaskPacket(**_packet_mapping(contract_data, {}))
    runner_evidence_keys = {
        "run_id", "result", "candidate_head", "candidate_tree", "candidate_ref",
        "deterministic_result", "verification_disposition", "reviewer_disposition",
        "evidence_paths", "required_evidence_references", "review_artifact",
        "review_raw_artifact", "review_fingerprint_pre_artifact", "review_fingerprint_post_artifact",
        "review_worktree_fingerprint", "candidate_worktree_fingerprint", "review_artifact_sha256", "evidence_file_sha256",
    }
    runner_evidence = {key: source[key] for key in sorted(runner_evidence_keys)}
    package_without_hash = {
        "gate": "HUMAN_GATE_B",
        "decision": "PENDING",
        "package_version": "HARN-002.GATE_B.v1",
        "project_id": contract_data["project_id"],
        "repository_path": contract_data["repository_path"],
        "canonical_branch": contract_data["canonical_branch"],
        "expected_canonical_head": contract_data["baseline_head"],
        "expected_canonical_tree": contract_data["baseline_tree"],
        # Retain these names for the existing HARN-002 evidence vocabulary.
        "contract_id": contract_data["contract_id"],
        "contract_hash": contract_data["contract_hash"],
        "run_id": contract_data["run_id"],
        "baseline_head": contract_data["baseline_head"],
        "baseline_tree": contract_data["baseline_tree"],
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "candidate_ref": ingested_result["candidate_ref"],
        "expected_changed_paths": sorted(
            _git(repo, ["diff", "--name-only", f"{contract_data['baseline_head']}..{candidate_head}"]).splitlines()
        ),
        "review_artifact": ingested_result["review_artifact"],
        "review_artifact_sha256": ingested_result["review_artifact_sha256"],
        "review_disposition": evidence["review"]["disposition"],
        "review_section_pass_states": {
            axis: evidence["review"][axis]["status"]
            for axis in ("security", "operability", "semantics", "architecture")
        },
        "blocking_findings": list(evidence["review"]["blocking_findings"]),
        "design_contract_id": contract_data["contract_id"],
        "design_contract_hash": contract_data["contract_hash"],
        "task_packet_id": "task-" + _sha(packet.__dict__),
        "task_packet_hash": _sha(packet.__dict__),
        "runner_acceptance_evidence_sha256": evidence["runner_acceptance_evidence_sha256"],
        "required_integrity_evidence": {
            "candidate_worktree_fingerprint": source["candidate_worktree_fingerprint"],
            "review_worktree_fingerprint": source["review_worktree_fingerprint"],
            "review_fingerprint_pre_artifact": source["review_fingerprint_pre_artifact"],
            "review_fingerprint_post_artifact": source["review_fingerprint_post_artifact"],
            "review_fingerprint_pre_artifact_sha256": evidence["review_fingerprint_pre_artifact_sha256"],
            "review_fingerprint_post_artifact_sha256": evidence["review_fingerprint_post_artifact_sha256"],
        },
        "evidence_references": list(source["required_evidence_references"]),
        "runner_acceptance_evidence": runner_evidence,
    }
    package = {
        **package_without_hash,
        "gate_b_package_hash": _sha(package_without_hash),
    }
    _validate_gate_b_package(package, contract_data)
    return package


def _validate_gate_b_package(package: Mapping[str, Any], contract_data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate package structure and its canonical deterministic identity."""
    data = _strict_object(dict(package), GATE_B_PACKAGE_KEYS, "Gate B evidence package")
    if data["gate"] != "HUMAN_GATE_B" or data["decision"] != "PENDING":
        raise ArtifactValidationError("Gate B evidence package is not a pending Human Gate-B package")
    if data["package_version"] != "HARN-002.GATE_B.v1":
        raise ArtifactValidationError("Gate B evidence package version is unsupported")
    for field in ("project_id", "repository_path", "canonical_branch", "run_id", "candidate_ref", "review_artifact"):
        _non_empty_string(data[field], field)
    for package_field, contract_field in (
        ("project_id", "project_id"),
        ("repository_path", "repository_path"),
        ("canonical_branch", "canonical_branch"),
        ("run_id", "run_id"),
        ("design_contract_id", "contract_id"),
        ("design_contract_hash", "contract_hash"),
    ):
        if data[package_field] != contract_data[contract_field]:
            raise GovernanceBlockerError(f"Gate B package {package_field} does not match the Design Contract")
    for field in ("expected_canonical_head", "expected_canonical_tree", "baseline_head", "baseline_tree", "candidate_head", "candidate_tree"):
        _validate_object_id(data[field], field)
    if data["expected_canonical_head"] != contract_data["baseline_head"] or data["expected_canonical_tree"] != contract_data["baseline_tree"]:
        raise GovernanceBlockerError("Gate B package expected canonical baseline does not match the Design Contract")
    if data["baseline_head"] != data["expected_canonical_head"] or data["baseline_tree"] != data["expected_canonical_tree"]:
        raise ArtifactValidationError("Gate B package baseline aliases disagree with expected canonical baseline")
    expected_ref = candidate_branch_name(TaskPacket(**_packet_mapping(contract_data, {})))
    if data["candidate_ref"] != expected_ref:
        raise ArtifactValidationError("Gate B package candidate reference does not match the immutable Task Packet")
    changed_paths = _path_list(data["expected_changed_paths"], "expected_changed_paths")
    if any(not any(_paths_overlap(path, owned) for owned in contract_data["owned_paths"]) for path in changed_paths):
        raise GovernanceBlockerError("Gate B package changed-path scope exceeds the approved Design Contract")
    for field in ("contract_hash", "design_contract_hash", "review_artifact_sha256", "runner_acceptance_evidence_sha256", "task_packet_hash", "gate_b_package_hash"):
        if not isinstance(data[field], str) or not SHA256_RE.fullmatch(data[field]):
            raise ArtifactValidationError(f"Gate B package {field} is not a lowercase SHA-256 digest")
    packet = _packet_mapping(contract_data, {})
    task_packet_hash = _sha(packet)
    if data["task_packet_hash"] != task_packet_hash or data["task_packet_id"] != "task-" + task_packet_hash:
        raise GovernanceBlockerError("Gate B package Task Packet identity is not exact")
    if data["design_contract_hash"] != contract_data["contract_hash"]:
        raise GovernanceBlockerError("Gate B package Design Contract hash is not exact")

    sections = data["review_section_pass_states"]
    if not isinstance(sections, dict) or set(sections) != {"security", "operability", "semantics", "architecture"} or any(value != "PASS" for value in sections.values()):
        raise ArtifactValidationError("Gate B package does not contain all S/O/S/A PASS states")
    if data["review_disposition"] != "PASS" or data["blocking_findings"] != []:
        raise GovernanceBlockerError("Gate B package review is not a zero-blocker PASS")
    evidence_references = data["evidence_references"]
    if (
        not isinstance(evidence_references, list)
        or any(not isinstance(reference, str) for reference in evidence_references)
        or len(evidence_references) != len(set(evidence_references))
        or evidence_references != sorted(evidence_references)
    ):
        raise ArtifactValidationError("Gate B package evidence references are not deterministic")

    integrity_keys = {
        "candidate_worktree_fingerprint", "review_worktree_fingerprint",
        "review_fingerprint_pre_artifact", "review_fingerprint_post_artifact",
        "review_fingerprint_pre_artifact_sha256", "review_fingerprint_post_artifact_sha256",
    }
    integrity = data["required_integrity_evidence"]
    if not isinstance(integrity, dict) or set(integrity) != integrity_keys:
        raise ArtifactValidationError("Gate B package integrity evidence is incomplete")
    for field in ("candidate_worktree_fingerprint", "review_worktree_fingerprint", "review_fingerprint_pre_artifact_sha256", "review_fingerprint_post_artifact_sha256"):
        if not isinstance(integrity[field], str) or not SHA256_RE.fullmatch(integrity[field]):
            raise ArtifactValidationError(f"Gate B package integrity evidence {field} is invalid")
    for field in ("review_fingerprint_pre_artifact", "review_fingerprint_post_artifact"):
        _non_empty_string(integrity[field], field)
    runner_for_integrity = data["runner_acceptance_evidence"]
    if not isinstance(runner_for_integrity, dict):
        raise ArtifactValidationError("Gate B package Runner acceptance evidence is incomplete")
    if integrity["candidate_worktree_fingerprint"] != runner_for_integrity.get("candidate_worktree_fingerprint") or integrity["review_worktree_fingerprint"] != runner_for_integrity.get("review_worktree_fingerprint"):
        raise ArtifactValidationError("Gate B package integrity evidence disagrees with Runner evidence")

    runner = data["runner_acceptance_evidence"]
    runner_keys = {
        "run_id", "result", "candidate_head", "candidate_tree", "candidate_ref",
        "deterministic_result", "verification_disposition", "reviewer_disposition",
        "evidence_paths", "required_evidence_references", "review_artifact",
        "review_raw_artifact", "review_fingerprint_pre_artifact", "review_fingerprint_post_artifact",
        "review_worktree_fingerprint", "candidate_worktree_fingerprint", "review_artifact_sha256", "evidence_file_sha256",
    }
    if not isinstance(runner, dict) or set(runner) != runner_keys:
        raise ArtifactValidationError("Gate B package Runner acceptance evidence is incomplete")
    if runner["candidate_head"] != data["candidate_head"] or runner["candidate_tree"] != data["candidate_tree"] or runner["candidate_ref"] != data["candidate_ref"]:
        raise ArtifactValidationError("Gate B package candidate binding is inconsistent")
    if runner["review_artifact"] != data["review_artifact"] or runner["review_artifact_sha256"] != data["review_artifact_sha256"]:
        raise ArtifactValidationError("Gate B package review artifact binding is inconsistent")
    if runner["required_evidence_references"] != data["evidence_references"]:
        raise ArtifactValidationError("Gate B package evidence reference binding is inconsistent")
    file_hashes = runner["evidence_file_sha256"]
    if not isinstance(file_hashes, dict) or not file_hashes or any(
        not isinstance(key, str) or not isinstance(value, str) or not SHA256_RE.fullmatch(value)
        for key, value in file_hashes.items()
    ):
        raise ArtifactValidationError("Gate B package file-level evidence hashes are incomplete")
    if _runner_acceptance_evidence_identity(runner) != data["runner_acceptance_evidence_sha256"]:
        raise ArtifactValidationError("Gate B package Runner acceptance evidence hash is inconsistent")
    package_hash = data["gate_b_package_hash"]
    if _sha({key: data[key] for key in sorted(GATE_B_PACKAGE_KEYS - {"gate_b_package_hash"})}) != package_hash:
        raise ArtifactValidationError("Gate B package hash does not match its canonical contents")
    return data


def load_gate_b_package(path: Path | str, contract: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    """Load a Gate-B package from one byte snapshot and validate its identity."""
    value, _ = _read_json_snapshot(path, "Gate B evidence package")
    contract_data = _contract_value(contract)
    return _validate_gate_b_package(value, contract_data)


def _validate_gate_b_authorization_shape(
    contract_data: Mapping[str, Any],
    authorization: Mapping[str, Any],
    package: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        auth = _strict_object(dict(authorization), GATE_B_AUTHORIZATION_KEYS, "Human Gate-B authorization")
    except (ArtifactValidationError, TypeError) as exc:
        raise GovernanceBlockerError("Human Gate-B authorization is missing or not exact") from exc
    authorization_id = auth["authorization_id"]
    if not isinstance(authorization_id, str) or not authorization_id.strip() or "/" in authorization_id or "\\" in authorization_id or authorization_id in {".", ".."}:
        raise GovernanceBlockerError("Human Gate-B authorization_id is invalid")
    if auth["gate_b_package_hash"] != package["gate_b_package_hash"]:
        raise GovernanceBlockerError("Human Gate-B authorization is bound to a different package")
    for field in ("candidate_head", "candidate_tree", "expected_canonical_head", "expected_canonical_tree"):
        _validate_object_id(auth[field], field)
    if auth["candidate_head"] != package["candidate_head"] or auth["candidate_tree"] != package["candidate_tree"]:
        raise GovernanceBlockerError("Human Gate-B candidate binding does not match the evidence package")
    if auth["expected_canonical_head"] != package["expected_canonical_head"] or auth["expected_canonical_tree"] != package["expected_canonical_tree"]:
        raise GovernanceBlockerError("Human Gate-B expected canonical baseline binding does not match the evidence package")
    if auth["expected_canonical_head"] != contract_data["baseline_head"] or auth["expected_canonical_tree"] != contract_data["baseline_tree"]:
        raise GovernanceBlockerError("Human Gate-B expected canonical baseline does not match the Design Contract")
    return {**auth, "authorization_id": authorization_id}


def validate_gate_b(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    package: Mapping[str, Any] | Path | str | None = None,
) -> None:
    """Validate a fresh Human Gate-B authorization against one exact package."""
    contract_data = _contract_value(contract)
    if package is None:
        raise GovernanceBlockerError("Human Gate-B validation requires the exact evidence package")
    package_data = load_gate_b_package(package, contract_data) if isinstance(package, (Path, str)) else _validate_gate_b_package(package, contract_data)
    _validate_gate_b_authorization_shape(contract_data, authorization, package_data)
    runner = dict(package_data["runner_acceptance_evidence"])
    evidence = _validate_runner_acceptance_evidence(contract_data, runner)
    if evidence["runner_acceptance_evidence_sha256"] != package_data["runner_acceptance_evidence_sha256"]:
        raise GovernanceBlockerError("Gate B Runner acceptance evidence changed after package preparation")
    if evidence["evidence_file_sha256"] != runner["evidence_file_sha256"]:
        raise GovernanceBlockerError("Gate B file-level evidence changed after package preparation")
    if evidence["review_artifact_sha256"] != package_data["review_artifact_sha256"]:
        raise GovernanceBlockerError("Gate B review artifact changed after package preparation")
    integrity = package_data["required_integrity_evidence"]
    if evidence["review_fingerprint_pre_artifact_sha256"] != integrity["review_fingerprint_pre_artifact_sha256"] or evidence["review_fingerprint_post_artifact_sha256"] != integrity["review_fingerprint_post_artifact_sha256"]:
        raise GovernanceBlockerError("Gate B integrity evidence changed after package preparation")
    if evidence["review"]["disposition"] != "PASS":
        raise GovernanceBlockerError("Gate B review is no longer PASS")
    repo = Path(contract_data["repository_path"])
    if _git(repo, ["branch", "--show-current"]) != contract_data["canonical_branch"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: canonical branch drift")
    if _git(repo, ["rev-parse", "HEAD"]).lower() != package_data["expected_canonical_head"] or _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != package_data["expected_canonical_tree"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: canonical baseline drift")
    if _dirty_paths(repo) != contract_data["protected_dirty_paths"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: protected canonical worktree changed")


def _gate_b_evidence_directory(package: Mapping[str, Any]) -> Path:
    review_path = Path(package["review_artifact"])
    try:
        info = os.lstat(review_path)
    except OSError as exc:
        raise GovernanceBlockerError("Gate B review artifact is not available for an attempt claim") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GovernanceBlockerError("Gate B review artifact is not a regular non-symlink file")
    evidence_dir = review_path.parent / "gate-b"
    try:
        existing = os.lstat(evidence_dir)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B evidence directory cannot be inspected") from exc
    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode)):
        raise GovernanceBlockerError("Gate B evidence directory is not a regular directory")
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B evidence directory cannot be created") from exc
    return evidence_dir


def _claim_gate_b_authorization(package: Mapping[str, Any], authorization: Mapping[str, Any]) -> Path:
    """Exclusively consume an authorization before the integration critical section."""
    evidence_dir = _gate_b_evidence_directory(package)
    authorization_id = authorization["authorization_id"]
    claim_path = evidence_dir / f"attempt-{authorization_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    claim = {
        "authorization_id": authorization_id,
        "gate_b_package_hash": package["gate_b_package_hash"],
        "candidate_head": package["candidate_head"],
        "candidate_tree": package["candidate_tree"],
        "expected_canonical_head": package["expected_canonical_head"],
        "expected_canonical_tree": package["expected_canonical_tree"],
        "attempt": "STARTED",
    }
    try:
        descriptor = os.open(os.fspath(claim_path), flags, 0o600)
    except FileExistsError as exc:
        raise GovernanceBlockerError("GATE_B_AUTHORIZATION_REUSED: authorization_id was already consumed") from exc
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B authorization claim cannot be created") from exc
    try:
        payload = (json.dumps(claim, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(descriptor, payload)
    except OSError as exc:
        # Leave the exclusive claim in place. A started attempt is consumed even
        # if durable failure evidence cannot be completed.
        raise RunnerEnvironmentError("Gate B authorization claim cannot be recorded") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return claim_path


@contextmanager
def _gate_b_control_lock(package: Mapping[str, Any]):
    """Serialize canonical integration attempts using the evidence-local lock."""
    evidence_dir = _gate_b_evidence_directory(package)
    lock_path = evidence_dir / "integration.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(lock_path), flags, 0o600)
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B integration lock cannot be acquired") from exc
    try:
        if fcntl is None:  # pragma: no cover - supported platform is POSIX
            raise RunnerEnvironmentError("Gate B integration requires a supported repository lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B integration lock operation failed") from exc
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(descriptor)
        except OSError:
            pass


def _record_gate_b_attempt(package: Mapping[str, Any], authorization: Mapping[str, Any], outcome: Mapping[str, Any]) -> None:
    """Persist one immutable terminal outcome without enabling a retry."""
    evidence_dir = _gate_b_evidence_directory(package)
    result_path = evidence_dir / f"attempt-{authorization['authorization_id']}.result.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(result_path), flags, 0o600)
    except OSError:
        return
    try:
        payload = (json.dumps(dict(outcome), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(descriptor, payload)
    except OSError:
        pass
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _fast_forward_exact_baseline(repo: Path, expected_head: str, candidate_head: str, branch: str) -> None:
    """Fast-forward the canonical worktree with Git's compare-and-swap ref check."""
    branch_ref = _git(repo, ["symbolic-ref", "-q", "HEAD"])
    if branch_ref != "refs/heads/" + branch:
        raise GovernanceBlockerError("Canonical integration branch reference drift")
    # The old object ID is a compare-and-swap guard. A concurrent ref change
    # therefore fails the operation instead of being accepted as another base.
    _git(repo, ["merge-base", "--is-ancestor", expected_head, candidate_head])
    _git(repo, ["update-ref", branch_ref, candidate_head, expected_head])
    # Update the already-verified clean index/worktree to the exact new tree;
    # this is not reset/clean/stash/rebase and has no rollback path.
    _git(repo, ["read-tree", "-u", "-m", expected_head, candidate_head])


def integrate_after_gate_b(
    contract: Mapping[str, Any] | Path | str,
    gate_b_authorization: Mapping[str, Any],
    *,
    package: Mapping[str, Any] | Path | str | None = None,
    perform: bool = False,
) -> dict[str, Any]:
    """Perform one explicitly authorized fast-forward integration after Gate B.

    The default is deliberately non-mutating.  HARN-002 development stops at
    Gate B; this function exists solely as the explicit, human-authorized next
    transition and never retries, repairs, resets, or pushes.
    """
    contract_data = _contract_value(contract)
    if package is None:
        raise GovernanceBlockerError("Canonical integration requires the exact Gate B evidence package")
    package_data = load_gate_b_package(package, contract_data) if isinstance(package, (Path, str)) else _validate_gate_b_package(package, contract_data)
    auth = _validate_gate_b_authorization_shape(contract_data, gate_b_authorization, package_data)
    if not perform:
        raise GovernanceBlockerError("Canonical integration requires an explicit perform=True invocation after Gate B")

    # Structural checks happen before consumption. Once the exclusive claim is
    # created, every outcome is terminal and the authorization cannot be reused.
    claim_path = _claim_gate_b_authorization(package_data, auth)
    outcome: dict[str, Any] = {
        "authorization_id": auth["authorization_id"],
        "gate_b_package_hash": package_data["gate_b_package_hash"],
        "attempt": "FAILED",
    }
    try:
        with _gate_b_control_lock(package_data):
            # All evidence and live Git checks are deliberately repeated inside
            # the lock at the start of the consumed attempt.
            validate_gate_b(contract_data, auth, package_data)
            repo = Path(contract_data["repository_path"])
            candidate_head = package_data["candidate_head"]
            candidate_tree = package_data["candidate_tree"]
            candidate_ref = package_data["candidate_ref"]
            actual_changed_paths = sorted(
                _git(repo, ["diff", "--name-only", f"{package_data['expected_canonical_head']}..{candidate_head}"]).splitlines()
            )
            if actual_changed_paths != package_data["expected_changed_paths"]:
                raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: candidate changed-path scope drift")
            _fast_forward_exact_baseline(
                repo,
                package_data["expected_canonical_head"],
                candidate_head,
                contract_data["canonical_branch"],
            )
            post_branch = _git(repo, ["branch", "--show-current"])
            post_head = _git(repo, ["rev-parse", "HEAD"]).lower()
            post_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
            post_candidate_head = _git(repo, ["rev-parse", candidate_ref]).lower()
            post_candidate_tree = _git(repo, ["rev-parse", candidate_ref + "^{tree}"]).lower()
            post_changed_paths = sorted(
                _git(repo, ["diff", "--name-only", f"{package_data['expected_canonical_head']}..{post_head}"]).splitlines()
            )
            if (
                post_branch != contract_data["canonical_branch"]
                or post_head != candidate_head
                or post_tree != candidate_tree
                or post_candidate_head != candidate_head
                or post_candidate_tree != candidate_tree
                or post_changed_paths != package_data["expected_changed_paths"]
                or _dirty_paths(repo) != contract_data["protected_dirty_paths"]
            ):
                raise GovernanceBlockerError("Post-integration verification disagrees with the authorized candidate")
            outcome.update({"attempt": "PASS", "canonical_head": post_head, "canonical_tree": post_tree})
            return {
                "result": "CANONICAL_INTEGRATED",
                "controller_phase": ControllerPhase.POST_INTEGRATION_VERIFY.value,
                "run_id": contract_data["run_id"],
                "candidate_head": candidate_head,
                "candidate_tree": candidate_tree,
                "authorization_id": auth["authorization_id"],
                "gate_b_package_hash": package_data["gate_b_package_hash"],
                "claim": str(claim_path),
            }
    except Exception as exc:
        outcome.update({"error": str(exc), "error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR")})
        raise
    finally:
        _record_gate_b_attempt(package_data, auth, outcome)


def _empty_state() -> dict[str, Any]:
    return {
        "project_id": None,
        "repository": None,
        "canonical_branch": None,
        "baseline_head": None,
        "baseline_tree": None,
        "protected_dirty_paths": [],
        "work_item_id": None,
        "work_shape": None,
        "contract_id": None,
        "task_packet_ref": None,
        "run_id": None,
        "candidate_head": None,
        "candidate_tree": None,
        "candidate_ref": None,
        "phase": ControllerPhase.PROJECT_DISCOVERY.value,
        "pending_gate": None,
    }


def load_controller_state(path: Path | str) -> dict[str, Any]:
    data = _state_validation(_read_json(path))
    for field in ("project_id", "repository", "canonical_branch", "work_item_id", "contract_id", "task_packet_ref", "run_id", "candidate_head", "candidate_tree", "candidate_ref", "pending_gate"):
        if data[field] is not None and not isinstance(data[field], str):
            raise ArtifactValidationError(f"Controller state {field} must be a string or null")
    for field in ("baseline_head", "baseline_tree"):
        if data[field] is not None:
            _validate_object_id(data[field], field)
    if data["candidate_head"] is not None:
        _validate_object_id(data["candidate_head"], "candidate_head")
    if data["candidate_tree"] is not None:
        _validate_object_id(data["candidate_tree"], "candidate_tree")
    _path_list(data["protected_dirty_paths"], "protected_dirty_paths")
    if data["work_shape"] is not None and data["work_shape"] not in {item.value for item in WorkShape}:
        raise ArtifactValidationError("Controller state work_shape is invalid")
    if data["phase"] not in {item.value for item in ControllerPhase}:
        raise ArtifactValidationError("Controller state phase is invalid")
    return data


def resume_controller(
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    state: Mapping[str, Any] | Path | str,
    *,
    current_candidate: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Re-read Git truth and stop on any cursor/Git disagreement."""
    state_data = load_controller_state(state) if isinstance(state, (Path, str)) else load_controller_state_from_mapping(state)
    manifest_data = manifest if isinstance(manifest, ProjectManifest) else (
        ProjectManifest.load(manifest) if isinstance(manifest, (Path, str)) else ProjectManifest.from_mapping(manifest)
    )
    inspection = inspect_project(manifest_data)
    expected = {
        "project_id": manifest_data.project_id,
        "repository": str(Path(manifest_data.repository_path).expanduser().resolve()),
        "canonical_branch": manifest_data.canonical_branch,
    }
    for field, value in expected.items():
        if state_data[field] is not None and state_data[field] != value:
            raise GovernanceBlockerError(f"STATE_GIT_DRIFT: controller {field} disagrees with manifest/Git")
    for field in ("baseline_head", "baseline_tree"):
        if state_data[field] is not None and state_data[field] != inspection["head" if field.endswith("head") else "tree"]:
            raise GovernanceBlockerError(f"STATE_GIT_DRIFT: controller {field} disagrees with current Git")
    if state_data["protected_dirty_paths"] != inspection["protected_dirty_paths"]:
        raise GovernanceBlockerError("STATE_GIT_DRIFT: protected dirty baseline changed")
    if current_candidate is not None:
        head, tree = current_candidate[0].lower(), current_candidate[1].lower()
        if state_data["candidate_head"] != head or state_data["candidate_tree"] != tree:
            raise GovernanceBlockerError("STATE_GIT_DRIFT: controller candidate disagrees with current candidate")
    elif state_data["candidate_ref"] is not None:
        candidate_head = _git(Path(state_data["repository"]), ["rev-parse", state_data["candidate_ref"]]).lower()
        candidate_tree = _git(Path(state_data["repository"]), ["rev-parse", state_data["candidate_ref"] + "^{tree}"]).lower()
        if candidate_head != state_data["candidate_head"] or candidate_tree != state_data["candidate_tree"]:
            raise GovernanceBlockerError("STATE_GIT_DRIFT: controller candidate reference disagrees with Git")
    return {"result": "RESUME_VERIFIED", "phase": state_data["phase"], "inspection": {key: value for key, value in inspection.items() if not key.startswith("_")}}


def load_controller_state_from_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return _state_validation(dict(value))


def _state_validation(data: dict[str, Any]) -> dict[str, Any]:
    required = {
        "project_id", "repository", "canonical_branch", "baseline_head", "baseline_tree", "protected_dirty_paths",
        "work_item_id", "work_shape", "contract_id", "task_packet_ref", "run_id", "candidate_head", "candidate_tree", "candidate_ref",
        "phase", "pending_gate",
    }
    _strict_object(data, required, "Controller state")
    for field in ("project_id", "repository", "canonical_branch", "work_item_id", "contract_id", "task_packet_ref", "run_id", "candidate_head", "candidate_tree", "candidate_ref", "pending_gate"):
        if data[field] is not None and not isinstance(data[field], str):
            raise ArtifactValidationError(f"Controller state {field} must be a string or null")
    for field in ("baseline_head", "baseline_tree", "candidate_head", "candidate_tree"):
        if data[field] is not None:
            _validate_object_id(data[field], field)
    if data["candidate_ref"] is not None and (data["candidate_head"] is None or data["candidate_tree"] is None):
        raise ArtifactValidationError("Controller state candidate_ref requires candidate HEAD and TREE")
    _path_list(data["protected_dirty_paths"], "protected_dirty_paths")
    if data["work_shape"] is not None and data["work_shape"] not in {item.value for item in WorkShape}:
        raise ArtifactValidationError("Controller state work_shape is invalid")
    if data["phase"] not in {item.value for item in ControllerPhase}:
        raise ArtifactValidationError("Controller state phase is invalid")
    return data


def write_controller_state(path: Path | str, state: Mapping[str, Any]) -> None:
    _write_json(path, _state_validation(dict(state)))


@dataclass
class Controller:
    """Convenience facade that persists only the orchestration cursor."""

    manifest: ProjectManifest
    state_path: Path | None = None

    @classmethod
    def from_manifest(cls, path: Path | str, state_path: Path | str | None = None) -> "Controller":
        return cls(ProjectManifest.load(path), Path(state_path) if state_path else None)

    def _save(self, state: dict[str, Any]) -> dict[str, Any]:
        if self.state_path is not None:
            write_controller_state(self.state_path, state)
        return state

    def inspect(self) -> dict[str, Any]:
        return inspect_project(self.manifest)

    def discover(self) -> dict[str, Any]:
        return discover_next_work(self.manifest)

    def draft(self, **kwargs: Any) -> dict[str, Any]:
        inspection = kwargs.pop("inspection", None) or self.inspect()
        item = kwargs.pop("work_item", None) or self.discover()
        contract = draft_design_contract(self.manifest, item, inspection, **kwargs)
        self._save({
            **_empty_state(), "project_id": self.manifest.project_id, "repository": str(Path(self.manifest.repository_path).resolve()),
            "canonical_branch": self.manifest.canonical_branch, "baseline_head": contract["baseline_head"],
            "baseline_tree": contract["baseline_tree"], "protected_dirty_paths": contract["protected_dirty_paths"],
            "work_item_id": contract["work_item_id"], "work_shape": contract["work_shape"],
            "contract_id": contract["contract_id"], "run_id": contract["run_id"],
            "phase": ControllerPhase.WAITING_HUMAN_GATE_A.value, "pending_gate": "HUMAN_GATE_A",
        })
        return contract

    def derive(self, contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], packet_path: Path | str) -> dict[str, Any]:
        packet = derive_task_packet(contract, authorization, output_path=packet_path)
        if self.state_path is not None:
            state = load_controller_state(self.state_path)
            state.update({"task_packet_ref": str(Path(packet_path).resolve()), "phase": ControllerPhase.EXECUTION_PREP.value, "pending_gate": None})
            self._save(state)
        return packet

    def dispatch(self, contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], packet_path: Path | str, config_path: Path | str | None = None) -> dict[str, Any]:
        result = dispatch_runner(contract, authorization, packet_path, config_path)
        ingested = ingest_runner_result(contract, result)
        if self.state_path is not None:
            state = load_controller_state(self.state_path)
            candidate_ref = ingested.get("candidate_ref") if ingested["candidate_head"] and ingested["candidate_tree"] else None
            state.update({"phase": ingested["controller_phase"], "candidate_head": ingested["candidate_head"], "candidate_tree": ingested["candidate_tree"], "candidate_ref": candidate_ref, "run_id": ingested["run_id"]})
            self._save(state)
        return result

    def resume(self, *, current_candidate: tuple[str, str] | None = None) -> dict[str, Any]:
        if self.state_path is None:
            raise GovernanceBlockerError("resume requires a persisted controller state path")
        return resume_controller(self.manifest, self.state_path, current_candidate=current_candidate)
