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
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
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
from prj226_runner.control_protocol import (
    STRICT_VERSION,
    strict_gate_binding,
    validate_strict_state,
)
from prj226_runner.codex_reviewer import (
    fingerprint_manifest,
    EvidenceRoot,
    fingerprint_worktree,
    _safe_evidence_relative_path,
    validate_codex_review,
)
from prj226_runner.models import ControllerPhase, ErrorClass, ReviewMode, ReviewStatus, WorkShape
from prj226_runner.review_policy import normalize_review_policy, select_review_mode
from prj226_runner.candidate_identity import (
    derive_candidate_ref_for_contract,
    validate_candidate_ref,
)
from prj226_runner.runner import (
    TaskPacket,
    TaskPacketV2,
    TaskPacketV3,
    V2_CONTRACT_VERSION,
    V2_PACKET_VERSION,
    V3_CONTRACT_VERSION,
    V3_PACKET_VERSION,
    V2_RUNNER_RESULT_VERSION,
    candidate_branch_name,
    parse_task_packet,
    parse_task_packet_v2,
    parse_task_packet_v3,
    run_packet,
    run_packet_v2,
    run_packet_v3,
    task_packet_hash_v2,
    validate_gate_a_v2 as _runner_validate_gate_a_v2,
    validate_task_packet_derivation_v2 as _runner_validate_packet_v2,
)


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
    "evidence_root",
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
CONTROLLER_RESULT_COMMON_KEYS = {
    "result",
    "controller_phase",
    "run_id",
    "candidate_head",
    "candidate_tree",
    "deterministic_result",
    "reviewer_disposition",
    "evidence_references",
    "error_class",
}
CONTROLLER_RESULT_ACCEPTANCE_KEYS = CONTROLLER_RESULT_COMMON_KEYS | {
    "candidate_ref",
    "verification_disposition",
    "evidence_root",
    "required_evidence_references",
    "evidence_paths",
    "candidate_worktree_fingerprint",
    "review_worktree_fingerprint",
    "review_artifact",
    "review_raw_artifact",
    "review_fingerprint_pre_artifact",
    "review_fingerprint_post_artifact",
    "review_artifact_sha256",
}
CONTROLLER_RESULT_STOPPED_KEYS = CONTROLLER_RESULT_COMMON_KEYS
RUNNER_EVIDENCE_RELATIVE_PATHS = {
    "manifest": "manifest.json",
    "state": "state.json",
    "events": "events.ndjson",
    "builder": "builder",
    "deterministic": "deterministic",
    "dv": "dv",
    "sos": "sos",
    "worktree": "builder/worktree",
    "review_worktree": "sos/verifier-worktree",
}
RUNNER_ARTIFACT_RELATIVE_PATHS = {
    "review_artifact": "sos/review.json",
    "review_raw_artifact": "sos/raw-result.json",
    "review_fingerprint_pre_artifact": "sos/fingerprint-pre.json",
    "review_fingerprint_post_artifact": "sos/fingerprint-post.json",
}


def validate_strict_gate_binding(state: Mapping[str, Any], gate_type: str, binding: Mapping[str, Any]) -> None:
    """Validate the exact immutable authority for an R3C human gate."""
    if not isinstance(state, dict) or state.get("schema_version") != STRICT_VERSION:
        raise GovernanceBlockerError("Strict Gate validation requires a strict controller state")
    validate_strict_state(state)
    expected = strict_gate_binding(state, gate_type)
    if dict(binding) != expected:
        raise GovernanceBlockerError(f"{gate_type} strict authority binding drift")


def validate_strict_gate_a(state: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    validate_strict_gate_binding(state, "GATE_A", binding)


def validate_strict_gate_b(state: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    validate_strict_gate_binding(state, "GATE_B", binding)


def validate_strict_session_isolation(state: Mapping[str, Any]) -> None:
    """Expose the protocol's pairwise and cross-attempt session check."""
    validate_strict_state(state)


def start_strict_controller(*args: Any, **kwargs: Any) -> Any:
    """Lazy factory avoiding a control/controller import cycle."""
    from prj226_runner.control import StrictExecutionController
    return StrictExecutionController.start(*args, **kwargs)


def __getattr__(name: str) -> Any:
    if name in {
        "StrictExecutionController", "DurableExecutionController", "R3CController", "StrictController"
    }:
        from prj226_runner.control import StrictExecutionController
        return StrictExecutionController
    raise AttributeError(name)


def _read_json(path: Path | str) -> Any:
    target = Path(path)
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot read controller artifact: {target}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Controller artifact is not valid JSON: {exc.msg}") from exc


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


def _lexical_absolute_path(value: str, field: str) -> Path:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ArtifactValidationError(f"{field} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute():
        raise ArtifactValidationError(f"{field} must be an absolute path")
    if any(part == ".." for part in path.parts):
        raise ArtifactValidationError(f"{field} contains traversal")
    return Path(os.path.abspath(os.fspath(path)))


def _bind_root_relative_locator(
    value: Any,
    root: EvidenceRoot,
    expected_relative: str,
    field: str,
    *,
    allow_legacy_absolute: bool = True,
) -> str:
    """Bind a producer locator to one exact path below the already-open root."""
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ArtifactValidationError(f"{field} must be a non-empty evidence locator")
    expected = root.relative(expected_relative, field)
    candidate = Path(value)
    if candidate.is_absolute():
        if not allow_legacy_absolute:
            raise ArtifactValidationError(f"{field} must be relative to the authorized evidence root")
        actual = _lexical_absolute_path(value, field)
        if actual != root.absolute_path(expected):
            raise ArtifactValidationError(f"{field} is not bound to the authorized evidence root")
    else:
        if _safe_evidence_relative_path(value, field) != expected:
            raise ArtifactValidationError(f"{field} is not the canonical evidence locator")
    return expected


def _bind_external_worktree_locator(value: Any, field: str) -> tuple[str, EvidenceRoot | None]:
    """Bind a candidate/verifier root when a legacy fixture stores it externally."""
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ArtifactValidationError(f"{field} must be a non-empty worktree locator")
    path = _lexical_absolute_path(value, field)
    # The real runner stores both worktrees below the Runner evidence root.  A
    # legacy fixture may place them elsewhere, but it is still independently
    # opened as a trusted, non-symlink directory before Git/fingerprint use.
    return str(path), EvidenceRoot(path, label=field)


def _json_value_from_snapshot(snapshot: Any, label: str) -> Any:
    try:
        return json.loads(snapshot.raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError(f"{label} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"{label} is not valid JSON: {exc.msg}") from exc


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


def _validate_fingerprint_artifact(
    evidence_root: EvidenceRoot,
    relative_path: str,
    expected_fingerprint: str,
    field: str,
) -> dict[str, Any]:
    snapshot = evidence_root.snapshot(relative_path, label=field)
    value = _json_value_from_snapshot(snapshot, field)
    artifact_sha256 = snapshot.sha256
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
    evidence_root: EvidenceRoot,
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
    paths: dict[str, str] = {}
    workspace_paths: dict[str, Path] = {}
    external_roots: dict[str, EvidenceRoot] = {}
    for key, expected_relative in RUNNER_EVIDENCE_RELATIVE_PATHS.items():
        value = evidence_paths.get(key)
        if key not in {"worktree", "review_worktree"}:
            paths[key] = _bind_root_relative_locator(
                value, evidence_root, expected_relative, f"evidence_paths.{key}",
            )
            continue
        if isinstance(value, str) and not Path(value).is_absolute():
            paths[key] = _bind_root_relative_locator(
                value, evidence_root, expected_relative, f"evidence_paths.{key}",
            )
            workspace_paths[key] = evidence_root.absolute_path(expected_relative)
            continue
        expected_path = evidence_root.absolute_path(expected_relative)
        if isinstance(value, str) and _lexical_absolute_path(value, f"evidence_paths.{key}") == expected_path:
            paths[key] = expected_relative
            workspace_paths[key] = expected_path
            continue
        if "runtime_root" in data:
            raise ArtifactValidationError(f"evidence_paths.{key} is not the exact Runner worktree locator")
        external_locator, external_root = _bind_external_worktree_locator(value, f"evidence_paths.{key}")
        paths[key] = external_locator
        workspace_paths[key] = Path(external_locator)
        external_roots[key] = external_root

    artifact_paths: dict[str, str] = {}
    for field, expected_relative in RUNNER_ARTIFACT_RELATIVE_PATHS.items():
        artifact_paths[field] = _bind_root_relative_locator(
            data.get(field), evidence_root, expected_relative, field,
        )
    if not isinstance(data.get("review_artifact_sha256"), str) or not SHA256_RE.fullmatch(data["review_artifact_sha256"]):
        raise ArtifactValidationError("Runner acceptance evidence is missing a valid review_artifact_sha256")

    required = data.get("required_evidence_references")
    if not isinstance(required, list) or not required or any(not isinstance(item, str) or not item.strip() for item in required):
        raise ArtifactValidationError("required_evidence_references is missing or invalid")
    if len(required) != len(set(required)) or required != sorted(required):
        raise ArtifactValidationError("required_evidence_references are not deterministically ordered")
    expected_references = set(paths.values()) | set(artifact_paths.values())
    canonical_required: list[str] = []
    for item in required:
        canonical_item: str | None = None
        if not Path(item).is_absolute():
            relative_item = _safe_evidence_relative_path(item, "required_evidence_references")
            if relative_item in expected_references:
                canonical_item = relative_item
        else:
            absolute_item = _lexical_absolute_path(item, "required_evidence_references")
            for candidate in expected_references:
                if candidate in RUNNER_ARTIFACT_RELATIVE_PATHS.values() or candidate in RUNNER_EVIDENCE_RELATIVE_PATHS.values():
                    if absolute_item == evidence_root.absolute_path(candidate):
                        canonical_item = candidate
                        break
            for key in ("worktree", "review_worktree"):
                if absolute_item == Path(paths[key]):
                    canonical_item = paths[key]
                    break
        if canonical_item is None:
            raise ArtifactValidationError("required_evidence_references contain an unbound locator")
        canonical_required.append(canonical_item)
    canonical_required = sorted(canonical_required)
    if len(canonical_required) != len(set(canonical_required)) or set(canonical_required) != expected_references:
        raise ArtifactValidationError("required_evidence_references do not exactly bind the evidence bundle")

    for key in ("builder", "deterministic", "dv", "sos"):
        evidence_root.validate_directory(paths[key], f"evidence_paths.{key}")
    manifest_snapshot = evidence_root.snapshot(paths["manifest"], label="Runner manifest")
    manifest = _json_value_from_snapshot(manifest_snapshot, "Runner manifest")
    if not isinstance(manifest, dict) or manifest.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner manifest does not bind the Design Contract run_id")
    product = manifest.get("product")
    if not isinstance(product, dict) or product.get("repo") != contract_data["repository_path"] or product.get("canonical_branch") != contract_data["canonical_branch"]:
        raise ArtifactValidationError("Runner manifest product binding is incomplete")
    if product.get("baseline_head") != contract_data["baseline_head"] or product.get("baseline_tree") != contract_data["baseline_tree"]:
        raise ArtifactValidationError("Runner manifest baseline binding is stale")

    state_snapshot = evidence_root.snapshot(paths["state"], label="Runner state")
    state = _json_value_from_snapshot(state_snapshot, "Runner state")
    if not isinstance(state, dict) or state.get("run_id") != contract_data["run_id"] or state.get("state") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner state does not prove ACCEPTANCE_READY")
    events_snapshot = evidence_root.snapshot(paths["events"], label="Runner events")
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

    builder_snapshot = evidence_root.snapshot(paths["builder"] + "/invocation.json", label="Builder acceptance evidence")
    builder_invocation = _json_value_from_snapshot(builder_snapshot, "Builder acceptance evidence")
    if not isinstance(builder_invocation, dict) or builder_invocation.get("exit_code") != 0:
        raise ArtifactValidationError("Builder acceptance evidence is incomplete")
    deterministic_dirs = [name for name in evidence_root.list_directory(paths["deterministic"], "Deterministic acceptance evidence") if name.startswith("test-")]
    if not deterministic_dirs:
        raise ArtifactValidationError("Deterministic acceptance evidence contains no test invocations")
    deterministic_file_hashes: dict[str, str] = {}
    for directory_name in deterministic_dirs:
        deterministic_relative = paths["deterministic"] + "/" + _safe_evidence_relative_path(directory_name, "deterministic test directory")
        evidence_root.validate_directory(deterministic_relative, "Deterministic test evidence")
        invocation_snapshot = evidence_root.snapshot(deterministic_relative + "/invocation.json", label="Deterministic acceptance evidence")
        invocation = _json_value_from_snapshot(invocation_snapshot, "Deterministic acceptance evidence")
        deterministic_file_hashes[directory_name + "/invocation.json"] = invocation_snapshot.sha256
        if not isinstance(invocation, dict) or invocation.get("exit_code") != 0 or invocation.get("timed_out"):
            raise ArtifactValidationError("Deterministic acceptance evidence contains a non-PASS test")
    dv_snapshot = evidence_root.snapshot(paths["dv"] + "/result.json", label="DV acceptance evidence")
    dv = _json_value_from_snapshot(dv_snapshot, "DV acceptance evidence")
    if not isinstance(dv, dict) or set(dv) != {"result", "findings"} or dv.get("result") != "PASS" or not isinstance(dv.get("findings"), list):
        raise ArtifactValidationError("DV acceptance evidence is incomplete or not PASS")

    if review_snapshot is None:
        review_snapshot = evidence_root.snapshot(artifact_paths["review_artifact"], label="Codex review evidence")
        review_value = _json_value_from_snapshot(review_snapshot, "Codex reviewer artifact")
        review_value = validate_codex_review(review_value, expected_head=candidate_head, expected_tree=candidate_tree)
    else:
        if review_snapshot.sha256 != data.get("review_artifact_sha256"):
            raise ArtifactValidationError("Review evidence changed after snapshot validation")
        review_value = validate_codex_review(review_snapshot.value, expected_head=candidate_head, expected_tree=candidate_tree)
    if review_snapshot.sha256 != data.get("review_artifact_sha256"):
        raise ArtifactValidationError("Review evidence changed after runner validation")
    if review_value["disposition"] != "PASS":
        raise ArtifactValidationError("Runner review evidence is not PASS")
    raw_review_snapshot = evidence_root.snapshot(artifact_paths["review_raw_artifact"], label="Raw review evidence")
    stored_fingerprint = data.get("review_worktree_fingerprint")
    candidate_fingerprint = data.get("candidate_worktree_fingerprint")
    for field, value in (("candidate_worktree_fingerprint", candidate_fingerprint), ("review_worktree_fingerprint", stored_fingerprint)):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise ArtifactValidationError(f"Runner {field} is missing or invalid")
    with ExitStack() as stack:
        for key, external_root in external_roots.items():
            stack.enter_context(external_root)
        for key in ("worktree", "review_worktree"):
            if key not in external_roots:
                evidence_root.validate_directory(RUNNER_EVIDENCE_RELATIVE_PATHS[key], f"evidence_paths.{key}")
        candidate_worktree = workspace_paths["worktree"]
        review_worktree = workspace_paths["review_worktree"]
        if _git(candidate_worktree, ["rev-parse", "HEAD"]).lower() != candidate_head or _git(candidate_worktree, ["rev-parse", "HEAD^{tree}"]).lower() != candidate_tree:
            raise GovernanceBlockerError("Runner candidate worktree identity is stale")
        if _git(review_worktree, ["rev-parse", "HEAD^{tree}"]).lower() != candidate_tree or _git(review_worktree, ["rev-parse", "HEAD"]).lower() != candidate_head:
            raise GovernanceBlockerError("Runner verifier worktree identity is stale")
        if _git(candidate_worktree, ["status", "--porcelain"]) or _git(review_worktree, ["status", "--porcelain"]):
            raise GovernanceBlockerError("Candidate or verifier worktree is not Git-clean")
        if fingerprint_worktree(candidate_worktree) != candidate_fingerprint or fingerprint_worktree(review_worktree) != stored_fingerprint:
            raise GovernanceBlockerError("Candidate or verifier worktree filesystem fingerprint changed")
    pre = _validate_fingerprint_artifact(evidence_root, artifact_paths["review_fingerprint_pre_artifact"], stored_fingerprint, "review fingerprint preflight")
    post = _validate_fingerprint_artifact(evidence_root, artifact_paths["review_fingerprint_post_artifact"], stored_fingerprint, "review fingerprint postflight")
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
        "manifest.json": manifest_snapshot.sha256,
        "state.json": state_snapshot.sha256,
        "events.ndjson": events_snapshot.sha256,
        "builder/invocation.json": builder_snapshot.sha256,
        **{f"deterministic/{key}": value for key, value in deterministic_file_hashes.items()},
        "dv/result.json": dv_snapshot.sha256,
        "sos/review.json": review_snapshot.sha256,
        "sos/raw-result.json": raw_review_snapshot.sha256,
        "sos/fingerprint-pre.json": pre["_artifact_sha256"],
        "sos/fingerprint-post.json": post["_artifact_sha256"],
    }
    identity_data = dict(data)
    identity_data["evidence_paths"] = paths
    identity_data["required_evidence_references"] = canonical_required
    identity_data["evidence_file_sha256"] = evidence_file_sha256
    return {
        "candidate_head": candidate_head,
        "candidate_tree": candidate_tree,
        "candidate_ref": candidate_ref,
        "review": review_value,
        "review_snapshot_sha256": review_snapshot.sha256,
        "review_artifact_sha256": review_snapshot.sha256,
        "runner_acceptance_evidence_sha256": _runner_acceptance_evidence_identity(identity_data),
        "review_fingerprint_pre_artifact_sha256": pre["_artifact_sha256"],
        "review_fingerprint_post_artifact_sha256": post["_artifact_sha256"],
        "evidence_file_sha256": evidence_file_sha256,
        "evidence_paths": paths,
        "required_evidence_references": canonical_required,
        "evidence_root": str(evidence_root.path),
        **artifact_paths,
    }


def _runner_evidence_root(data: Mapping[str, Any], result_path: Path | None = None) -> Path:
    claimed = data.get("runtime_root")
    if claimed is None and result_path is not None:
        claimed = str(result_path.parent)
    if claimed is None:
        evidence_paths = data.get("evidence_paths")
        if isinstance(evidence_paths, Mapping) and isinstance(evidence_paths.get("manifest"), str):
            manifest_path = Path(evidence_paths["manifest"])
            if manifest_path.is_absolute():
                claimed = str(manifest_path.parent)
    if not isinstance(claimed, str):
        raise ArtifactValidationError("Runner result does not identify an authorized evidence root")
    root = _lexical_absolute_path(claimed, "runtime_root")
    if result_path is not None and root != Path(os.path.abspath(os.fspath(result_path.parent))):
        raise ArtifactValidationError("Runner result is not stored under its claimed evidence root")
    return root


def _validate_controller_result(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed controller-result producer contract before return/persist."""
    if not isinstance(data, Mapping):
        raise ArtifactValidationError("Controller result must be a JSON object")
    value = dict(data)
    phase = value.get("controller_phase")
    expected_keys = CONTROLLER_RESULT_ACCEPTANCE_KEYS if phase == ControllerPhase.ACCEPTANCE_READY.value else CONTROLLER_RESULT_STOPPED_KEYS
    if set(value) != expected_keys:
        raise ArtifactValidationError("Controller result contains missing or unknown fields")
    if value.get("result") != "RESULT_INGESTED" or not isinstance(value.get("run_id"), str) or not value["run_id"].strip():
        raise ArtifactValidationError("Controller result identity is incomplete")
    error_class = value.get("error_class")
    if error_class is not None and error_class not in {item.value for item in ErrorClass}:
        raise ArtifactValidationError("Controller result error_class is invalid")
    for field in ("candidate_head", "candidate_tree"):
        if value[field] is not None:
            _validate_object_id(value[field], field)
    if (value["candidate_head"] is None) != (value["candidate_tree"] is None):
        raise ArtifactValidationError("Controller result candidate identity is incomplete")
    if phase == ControllerPhase.STOPPED.value:
        if value.get("deterministic_result") != "STOPPED" or value.get("reviewer_disposition") != {} or value.get("evidence_references") != []:
            raise ArtifactValidationError("Stopped controller result has an incompatible disposition")
        return value
    if value.get("deterministic_result") != "ACCEPTANCE_READY" or value.get("verification_disposition") != "PASS":
        raise ArtifactValidationError("Accepted controller result has an incompatible state")
    if value["candidate_head"] is None or value["candidate_tree"] is None:
        raise ArtifactValidationError("Accepted controller result must bind a candidate")
    _non_empty_string(value.get("candidate_ref"), "candidate_ref")
    if value.get("reviewer_disposition") != {"dv_result": "PASS", "sos_result": "ACCEPT", "review_disposition": "PASS"}:
        raise ArtifactValidationError("Accepted controller result reviewer disposition is incomplete")
    _lexical_absolute_path(value.get("evidence_root"), "evidence_root")
    paths = value.get("evidence_paths")
    if not isinstance(paths, dict) or set(paths) != RUNNER_EVIDENCE_PATH_KEYS:
        raise ArtifactValidationError("Accepted controller result evidence_paths are incomplete")
    for key in ("manifest", "state", "events", "builder", "deterministic", "dv", "sos"):
        if paths[key] != RUNNER_EVIDENCE_RELATIVE_PATHS[key]:
            raise ArtifactValidationError("Accepted controller result evidence paths must be root-relative")
    for field, relative in RUNNER_ARTIFACT_RELATIVE_PATHS.items():
        if value[field] != relative:
            raise ArtifactValidationError(f"Accepted controller result {field} is not root-relative")
    for field, relative in (("worktree", RUNNER_EVIDENCE_RELATIVE_PATHS["worktree"]), ("review_worktree", RUNNER_EVIDENCE_RELATIVE_PATHS["review_worktree"])):
        if paths[field] != relative:
            _lexical_absolute_path(paths[field], f"evidence_paths.{field}")
    for field in ("candidate_worktree_fingerprint", "review_worktree_fingerprint", "review_artifact_sha256"):
        if not isinstance(value[field], str) or not SHA256_RE.fullmatch(value[field]):
            raise ArtifactValidationError(f"Accepted controller result {field} is invalid")
    refs = value.get("required_evidence_references")
    evidence_refs = value.get("evidence_references")
    if not isinstance(refs, list) or not refs or not isinstance(evidence_refs, list) or not evidence_refs or refs != evidence_refs or refs != sorted(refs) or len(refs) != len(set(refs)):
        raise ArtifactValidationError("Accepted controller result evidence references are not deterministic")
    if not all(isinstance(item, str) and item.strip() for item in refs):
        raise ArtifactValidationError("Accepted controller result evidence references are invalid")
    return value


def _ingest_runner_result_data(
    contract_data: Mapping[str, Any],
    data: Mapping[str, Any],
    evidence_root: EvidenceRoot | None,
) -> dict[str, Any]:
    if not isinstance(data, Mapping) or data.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner result run_id does not match the Design Contract")
    outcome = data.get("result")
    if outcome not in {"ACCEPTANCE_READY", "STOPPED"}:
        raise ArtifactValidationError("Runner result has an unsupported deterministic outcome")
    error_class = data.get("error_class")
    if error_class is not None and error_class not in {item.value for item in ErrorClass}:
        raise ArtifactValidationError("Runner result error_class is invalid")
    if outcome == "ACCEPTANCE_READY":
        if evidence_root is None:
            raise ArtifactValidationError("Accepted Runner result has no bound evidence root")
        evidence = _validate_runner_acceptance_evidence(contract_data, data, evidence_root=evidence_root)
        result = {
            "result": "RESULT_INGESTED",
            "controller_phase": ControllerPhase.ACCEPTANCE_READY.value,
            "run_id": data["run_id"],
            "candidate_head": evidence["candidate_head"],
            "candidate_tree": evidence["candidate_tree"],
            "candidate_ref": evidence["candidate_ref"],
            "deterministic_result": data["deterministic_result"],
            "verification_disposition": data["verification_disposition"],
            "reviewer_disposition": {"dv_result": "PASS", "sos_result": "ACCEPT", "review_disposition": "PASS"},
            "evidence_references": evidence["required_evidence_references"],
            "error_class": error_class,
            "evidence_root": evidence["evidence_root"],
            "evidence_paths": evidence["evidence_paths"],
            "required_evidence_references": evidence["required_evidence_references"],
            **{field: evidence[field] for field in RUNNER_ARTIFACT_RELATIVE_PATHS},
            "review_worktree_fingerprint": data["review_worktree_fingerprint"],
            "candidate_worktree_fingerprint": data["candidate_worktree_fingerprint"],
            "review_artifact_sha256": evidence["review_artifact_sha256"],
        }
    else:
        candidate_head = data.get("candidate_head")
        candidate_tree = data.get("candidate_tree")
        if candidate_head is not None:
            candidate_head = _validate_object_id(candidate_head, "candidate_head")
        if candidate_tree is not None:
            candidate_tree = _validate_object_id(candidate_tree, "candidate_tree")
        if (candidate_head is None) != (candidate_tree is None):
            raise ArtifactValidationError("Stopped Runner result must bind both candidate IDs or neither")
        result = {
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
    return _validate_controller_result(result)


def ingest_runner_result(
    contract: Mapping[str, Any] | Path | str,
    result: Mapping[str, Any] | Path | str,
    *,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Safely acquire, validate, and optionally persist one closed result."""
    contract_data = _contract_value(contract)
    result_path = Path(result) if isinstance(result, (Path, str)) else None
    if result_path is not None:
        root_path = _runner_evidence_root({}, result_path)
        with EvidenceRoot(root_path, label="Runner evidence root") as evidence_root:
            raw_snapshot = evidence_root.snapshot(result_path.name, label="Runner result")
            raw_data = _json_value_from_snapshot(raw_snapshot, "Runner result")
            if not isinstance(raw_data, dict):
                raise ArtifactValidationError("Runner result must be a JSON object")
            _runner_evidence_root(raw_data, result_path)
            ingested = _ingest_runner_result_data(contract_data, raw_data, evidence_root)
    else:
        try:
            raw_data = json.loads(json.dumps(dict(result), sort_keys=True))
        except (TypeError, ValueError) as exc:
            raise ArtifactValidationError("Runner result cannot be canonically serialized") from exc
        if not isinstance(raw_data, dict):
            raise ArtifactValidationError("Runner result must be a JSON object")
        root_path = _runner_evidence_root(raw_data) if raw_data.get("result") == "ACCEPTANCE_READY" or output_path is not None else None
        if root_path is None:
            ingested = _ingest_runner_result_data(contract_data, raw_data, None)
        else:
            with EvidenceRoot(root_path, label="Runner evidence root") as evidence_root:
                ingested = _ingest_runner_result_data(contract_data, raw_data, evidence_root)
    if output_path is not None:
        target = _lexical_absolute_path(str(output_path), "controller result output")
        if root_path is None or target.parent != root_path or target.name != "controller-result.json":
            raise ArtifactValidationError("Controller result output must be controller-result.json in the bound evidence root")
        _write_json(target, ingested)
    return ingested


def load_controller_result(path: Path | str) -> dict[str, Any]:
    """Load a persisted controller result from one trusted root-bound snapshot."""
    result_path = Path(path)
    root_path = Path(os.path.abspath(os.fspath(result_path.parent)))
    with EvidenceRoot(root_path, label="Controller-result evidence root") as evidence_root:
        snapshot = evidence_root.snapshot(result_path.name, label="Controller result")
        value = _json_value_from_snapshot(snapshot, "Controller result")
    normalized = _validate_controller_result(value)
    if normalized["controller_phase"] == ControllerPhase.ACCEPTANCE_READY.value and normalized["evidence_root"] != str(root_path):
        raise ArtifactValidationError("Controller result evidence_root is not bound to its storage root")
    return normalized


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
    ingested_result: Mapping[str, Any] | Path | str,
    review: Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Build deterministic evidence for a future, fresh Human Gate-B decision."""
    contract_data = _contract_value(contract)
    if isinstance(ingested_result, (Path, str)):
        ingested_result = load_controller_result(ingested_result)
    if not isinstance(ingested_result, Mapping) or ingested_result.get("result") != "RESULT_INGESTED":
        raise ArtifactValidationError("Gate B requires a validated ingested Runner result")
    _validate_controller_result(ingested_result)
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
    evidence_root_path = _lexical_absolute_path(source["evidence_root"], "evidence_root")
    with EvidenceRoot(evidence_root_path, label="Runner evidence root") as evidence_root:
        review_snapshot = None
        if isinstance(review, (Path, str)):
            _bind_root_relative_locator(str(review), evidence_root, RUNNER_ARTIFACT_RELATIVE_PATHS["review_artifact"], "Gate B review")
            review_snapshot = evidence_root.snapshot(RUNNER_ARTIFACT_RELATIVE_PATHS["review_artifact"], label="Gate B review")
            review_snapshot = replace(review_snapshot, value=validate_codex_review(
                _json_value_from_snapshot(review_snapshot, "Gate B review"),
                expected_head=candidate_head,
                expected_tree=candidate_tree,
            ))
            normalized_review = review_snapshot.value
        else:
            normalized_review = validate_codex_review(review, expected_head=candidate_head, expected_tree=candidate_tree)
        evidence = _validate_runner_acceptance_evidence(contract_data, source, evidence_root=evidence_root, review_snapshot=review_snapshot)
        if evidence["review"] != normalized_review:
            raise ArtifactValidationError("Gate B review evidence differs from the validated immutable review artifact")
        repo = Path(contract_data["repository_path"])
        if _git(repo, ["branch", "--show-current"]) != contract_data["canonical_branch"]:
            raise GovernanceBlockerError("Gate B canonical branch drift")
        if _git(repo, ["rev-parse", "HEAD"]).lower() != contract_data["baseline_head"] or _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != contract_data["baseline_tree"]:
            raise GovernanceBlockerError("Gate B canonical baseline drift")
        if _dirty_paths(repo):
            raise GovernanceBlockerError("Gate B requires a clean canonical project worktree")
        packet = TaskPacket(**_packet_mapping(contract_data, {}))
        runner_evidence = {
            "run_id": source["run_id"],
            "result": "ACCEPTANCE_READY",
            "candidate_head": source["candidate_head"],
            "candidate_tree": source["candidate_tree"],
            "candidate_ref": source["candidate_ref"],
            "deterministic_result": source["deterministic_result"],
            "verification_disposition": source["verification_disposition"],
            "reviewer_disposition": source["reviewer_disposition"],
            "evidence_paths": source["evidence_paths"],
            "required_evidence_references": source["required_evidence_references"],
            "review_artifact": source["review_artifact"],
            "review_raw_artifact": source["review_raw_artifact"],
            "review_fingerprint_pre_artifact": source["review_fingerprint_pre_artifact"],
            "review_fingerprint_post_artifact": source["review_fingerprint_post_artifact"],
            "review_worktree_fingerprint": source["review_worktree_fingerprint"],
            "candidate_worktree_fingerprint": source["candidate_worktree_fingerprint"],
            "review_artifact_sha256": source["review_artifact_sha256"],
            "evidence_file_sha256": evidence["evidence_file_sha256"],
        }
        package_without_hash = {
            "gate": "HUMAN_GATE_B",
            "decision": "PENDING",
            "package_version": "HARN-002.GATE_B.v1",
            "project_id": contract_data["project_id"],
            "repository_path": contract_data["repository_path"],
            "canonical_branch": contract_data["canonical_branch"],
            "expected_canonical_head": contract_data["baseline_head"],
            "expected_canonical_tree": contract_data["baseline_tree"],
            "contract_id": contract_data["contract_id"],
            "contract_hash": contract_data["contract_hash"],
            "run_id": contract_data["run_id"],
            "baseline_head": contract_data["baseline_head"],
            "baseline_tree": contract_data["baseline_tree"],
            "candidate_head": candidate_head,
            "candidate_tree": candidate_tree,
            "candidate_ref": source["candidate_ref"],
            "expected_changed_paths": sorted(_git(repo, ["diff", "--name-only", f"{contract_data['baseline_head']}..{candidate_head}"]).splitlines()),
            "review_artifact": source["review_artifact"],
            "review_artifact_sha256": source["review_artifact_sha256"],
            "review_disposition": evidence["review"]["disposition"],
            "review_section_pass_states": {axis: evidence["review"][axis]["status"] for axis in ("security", "operability", "semantics", "architecture")},
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
            "evidence_root": source["evidence_root"],
            "runner_acceptance_evidence": runner_evidence,
        }
        package = {**package_without_hash, "gate_b_package_hash": _sha(package_without_hash)}
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
    _lexical_absolute_path(data["evidence_root"], "Gate B evidence_root")
    if data["review_artifact"] != RUNNER_ARTIFACT_RELATIVE_PATHS["review_artifact"]:
        raise ArtifactValidationError("Gate B review artifact must be root-relative")
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
    package_path = Path(path)
    package_root = Path(os.path.abspath(os.fspath(package_path.parent)))
    with EvidenceRoot(package_root, label="Gate B package root") as root:
        value = _json_value_from_snapshot(root.snapshot(package_path.name, label="Gate B evidence package"), "Gate B evidence package")
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
    with EvidenceRoot(package_data["evidence_root"], label="Gate B Runner evidence root") as evidence_root:
        evidence = _validate_runner_acceptance_evidence(contract_data, runner, evidence_root=evidence_root)
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
    root_path = _lexical_absolute_path(package["evidence_root"], "Gate B evidence_root")
    with EvidenceRoot(root_path, label="Gate B evidence root") as root:
        root.validate_directory("sos", "Gate B SOS evidence directory")
        root.snapshot(RUNNER_ARTIFACT_RELATIVE_PATHS["review_artifact"], label="Gate B review artifact")
        evidence_dir = root.absolute_path("sos/gate-b")
        try:
            existing = os.lstat(evidence_dir)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise RunnerEnvironmentError("Gate B evidence directory cannot be inspected") from exc
        if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode)):
            raise GovernanceBlockerError("Gate B evidence directory is not a regular directory")
        try:
            evidence_dir.mkdir(exist_ok=True)
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
        result_output = None
        if isinstance(result, Mapping) and isinstance(result.get("runtime_root"), str):
            result_output = Path(result["runtime_root"]) / "controller-result.json"
        ingested = ingest_runner_result(contract, result, output_path=result_output)
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


# ============================================================================
# M1 V2 — versioned controller authority (HARN-002.v2 / TASK_PACKET.v2 / etc).
# Legacy V1 paths above remain unchanged.
# ============================================================================

CONTRACT_V2_KEYS = {
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
    "runtime_root",
    "review_policy",
}
CONTRACT_V2_OPTIONAL_KEYS = {
    "transient_paths",
}
V2_RUNNER_RESULT_VERSION_LOCAL = "HARN-001.RUNNER_RESULT.v2"
V2_CONTROLLER_RESULT_VERSION = "HARN-002.CONTROLLER_RESULT.v2"
V2_GATE_B_VERSION = "HARN-002.GATE_B.v2"
V2_MANIFEST_VERSION_LOCAL = "HARN-001.RUN_MANIFEST.v2"
V2_STATE_VERSION_LOCAL = "HARN-001.RUN_STATE.v2"
GATE_A_V2_KEYS = {
    "gate",
    "decision",
    "contract_id",
    "contract_hash",
    "baseline_head",
    "baseline_tree",
    "authorized_protected_dirty_paths",
}
V2_CONTROLLER_RESULT_COMMON = {
    "version", "result", "controller_phase", "run_id", "contract_id", "contract_hash",
    "task_packet_hash", "review_policy", "review_attempted", "review_status",
    "candidate_head", "candidate_tree", "candidate_ref",
    "candidate_worktree_fingerprint", "worktree_fingerprint",
    "verification_disposition", "deterministic_result",
    "evidence_root", "evidence_paths", "required_evidence_references",
    "review_evidence", "evidence_file_sha256", "runner_acceptance_evidence_sha256",
    "error_class",
}


def _contract_without_identity_v2(contract: Mapping[str, Any]) -> dict[str, Any]:
    active_keys = set(CONTRACT_V2_KEYS)
    if "transient_paths" in contract:
        active_keys.add("transient_paths")
    return {key: contract[key] for key in sorted(active_keys - {"contract_id", "contract_hash"})}


def _normalize_contract_impl(value: Mapping[str, Any], expected_version: str) -> dict[str, Any]:
    if not isinstance(value, (dict, Mapping)):
        raise ArtifactValidationError(f"{expected_version} Design Contract must be an object")
    raw_keys = set(value)
    if not (CONTRACT_V2_KEYS <= raw_keys <= (CONTRACT_V2_KEYS | CONTRACT_V2_OPTIONAL_KEYS)):
        raise ArtifactValidationError(f"{expected_version} Design Contract must contain exactly the HARN-002 contract fields")
    data = dict(value)
    if data["contract_version"] != expected_version:
        raise ArtifactValidationError(f"Design Contract version must be exactly {expected_version}")
    _non_empty_string(data["project_id"], "project_id")
    _lexical_absolute_path(data["repository_path"], "repository_path")
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
    readiness = _strict_object(data["readiness"], READINESS_KEYS, f"{expected_version} Design Contract readiness")
    if readiness["task_packet"] not in {TASK_PACKET_MISSING, TASK_PACKET_PRESENT}:
        raise ArtifactValidationError(f"{expected_version} Design Contract readiness.task_packet is invalid")
    if readiness["execution"] != EXECUTION_NOT_AUTHORIZED:
        raise ArtifactValidationError(f"{expected_version} Design Contract readiness.execution must be NOT AUTHORIZED")
    if readiness["runner"] != RUNNER_NOT_INVOKED:
        raise ArtifactValidationError(f"{expected_version} Design Contract readiness.runner must be NOT INVOKED")
    _validate_object_id(data["baseline_head"], "baseline_head")
    _validate_object_id(data["baseline_tree"], "baseline_tree")
    _path_list(data["owned_paths"], "owned_paths", allow_empty=False)
    _path_list(data["protected_dirty_paths"], "protected_dirty_paths", allow_empty=True)
    if "transient_paths" in data:
        _path_list(data["transient_paths"], "transient_paths", allow_empty=True)
    _argv_list(data["acceptance_instruments"], "acceptance_instruments")
    if not data["acceptance_instruments"]:
        raise ArtifactValidationError(f"{expected_version} acceptance_instruments must contain at least one deterministic command")
    _string_list(data["discriminating_acceptance_controls"], "discriminating_acceptance_controls", allow_empty=False)
    _lexical_absolute_path(data["runtime_root"], "runtime_root")
    policy = normalize_review_policy(data["review_policy"])
    if not isinstance(data["contract_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["contract_hash"]):
        raise ArtifactValidationError("contract_hash must be a lowercase SHA-256 digest")
    content = _contract_without_identity_v2({**data, "review_policy": policy})
    expected_hash = _sha(content)
    if data["contract_hash"] != expected_hash or data["contract_id"] != "design-" + expected_hash:
        raise ArtifactValidationError(f"{expected_version} Design Contract identity/hash does not match its content")
    normalized = dict(data)
    normalized["review_policy"] = policy
    normalized["runtime_root"] = str(_lexical_absolute_path(data["runtime_root"], "runtime_root"))
    if "transient_paths" in data:
        normalized["transient_paths"] = list(data["transient_paths"])
    return normalized


def _normalize_contract_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_contract_impl(value, V2_CONTRACT_VERSION)


def _normalize_contract_v3(value: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize_contract_impl(value, V3_CONTRACT_VERSION)


def load_design_contract_v3(path: Path | str) -> dict[str, Any]:
    return _normalize_contract_v3(_read_json(path))


def _contract_value_v3(contract: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    return load_design_contract_v3(contract) if isinstance(contract, (Path, str)) else _normalize_contract_v3(contract)


def build_reviewer_binding_v2(
    *,
    executable: str,
    model: str = "gpt-5.6-luna",
    timeout_seconds: int = 300,
    review_brief: str,
    output_schema: Path | str | None = None,
) -> dict[str, Any]:
    """Freeze the exact TARGETED reviewer descriptor from local inspection only."""
    from prj226_runner.reviewer_profile import build_codex_reviewer_profile, resolve_reviewer_executable
    from prj226_runner.paths import get_runner_root as _get_root
    if not isinstance(review_brief, str) or not review_brief.strip():
        raise ArtifactValidationError("review_brief must be a non-empty string")
    if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise ArtifactValidationError("timeout_seconds must be a positive integer")
    if model != "gpt-5.6-luna":
        raise ArtifactValidationError("V2 reviewer model must be exactly gpt-5.6-luna")
    resolved = resolve_reviewer_executable(executable)
    profile = build_codex_reviewer_profile(executable, model=model)
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Reviewer executable cannot be fingerprinted: {exc}") from exc
    schema_path = Path(output_schema).resolve() if output_schema is not None else (_get_root() / "schemas" / "targeted-review-result.schema.json")
    if not schema_path.is_file():
        raise RunnerEnvironmentError(f"Targeted reviewer output schema is missing: {schema_path}")
    try:
        schema_bytes = schema_path.read_bytes()
        json.loads(schema_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerEnvironmentError(f"Targeted reviewer output schema cannot be read: {exc}") from exc
    schema_sha = hashlib.sha256(schema_bytes).hexdigest()
    return {
        "tool": "codex",
        "provider": "OpenAI",
        "model": model,
        "executable": executable,
        "resolved_executable": str(resolved),
        "executable_sha256": digest.hexdigest(),
        "reviewer_profile": profile.authority_manifest(),
        "reviewer_profile_hash": profile.reviewer_profile_hash,
        "output_schema": str(schema_path),
        "output_schema_sha256": schema_sha,
        "timeout_seconds": timeout_seconds,
        "review_brief": review_brief,
    }


def _draft_design_contract_impl(
    version: str,
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    work_item: Mapping[str, Any],
    inspection: Mapping[str, Any],
    *,
    run_id: str,
    owned_paths: Sequence[str],
    runtime_root: str | Path,
    change_categories: Sequence[str] | None = None,
    human_requested_targeted: bool = False,
    reviewer_executable: str | None = None,
    reviewer_model: str = "gpt-5.6-luna",
    reviewer_timeout_seconds: int = 300,
    review_brief: str | None = None,
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
    transient_paths: Sequence[str] | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
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
    categories = list(change_categories or [])
    for item in categories:
        if not isinstance(item, str) or not item.strip():
            raise ArtifactValidationError("change_categories must be an array of non-empty strings")
    if len(set(categories)) != len(categories):
        raise ArtifactValidationError("change_categories must not contain duplicates")
    expected_mode = select_review_mode(categories, bool(human_requested_targeted))
    if expected_mode == ReviewMode.TARGETED.value:
        if reviewer_executable is None or review_brief is None:
            raise ArtifactValidationError(f"TARGETED {version} contract requires exact reviewer binding and review_brief")
        reviewer = build_reviewer_binding_v2(
            executable=reviewer_executable, model=reviewer_model,
            timeout_seconds=reviewer_timeout_seconds, review_brief=review_brief,
        )
        policy = normalize_review_policy({
            "review_mode": "TARGETED", "change_categories": categories,
            "human_requested_targeted": bool(human_requested_targeted), "reviewer": reviewer,
        })
    else:
        if reviewer_executable is not None or review_brief is not None:
            raise ArtifactValidationError(f"NONE {version} contract must not include reviewer binding")
        if categories != [] or bool(human_requested_targeted) is not False:
            raise ArtifactValidationError(f"NONE {version} contract requires empty categories and human_requested_targeted=false")
        policy = normalize_review_policy({
            "review_mode": "NONE", "change_categories": [], "human_requested_targeted": False, "reviewer": None,
        })
    runtime_abs = str(_lexical_absolute_path(str(runtime_root), "runtime_root"))
    criteria = list(success_criteria or [f"{item_id} satisfies its canonical task artifact and deterministic acceptance evidence."])
    controls = list(discriminating_acceptance_controls or [
        "Reject conflicting CURRENT and Engineering Plan frontiers.",
        "Bind baseline, candidate, review, and Gate A identities exactly.",
    ])
    default_boundary = (
        f"Human Gate A authorizes only this exact {version} Design Contract and its derived task packet; "
        "Human Gate B is required before canonical integration."
    )
    contract: dict[str, Any] = {
        "contract_version": version,
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
        "exact_authority_boundary": exact_authority_boundary or default_boundary,
        "readiness": {
            "task_packet": work_item.get("task_packet_status", TASK_PACKET_MISSING),
            "execution": EXECUTION_NOT_AUTHORIZED,
            "runner": RUNNER_NOT_INVOKED,
        },
        "runtime_root": runtime_abs,
        "review_policy": policy,
    }
    if transient_paths is not None:
        contract["transient_paths"] = _path_list(list(transient_paths), "transient_paths", allow_empty=True)
    digest = _sha(_contract_without_identity_v2(contract))
    contract["contract_hash"] = digest
    contract["contract_id"] = "design-" + digest
    normalized = _normalize_contract_impl(contract, version)
    if output_path is not None:
        _write_json(output_path, normalized)
    return normalized


def draft_design_contract_v2(
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    work_item: Mapping[str, Any],
    inspection: Mapping[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    return _draft_design_contract_impl(V2_CONTRACT_VERSION, manifest, work_item, inspection, **kwargs)


def draft_design_contract_v3(
    manifest: ProjectManifest | Mapping[str, Any] | Path | str,
    work_item: Mapping[str, Any],
    inspection: Mapping[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    return _draft_design_contract_impl(V3_CONTRACT_VERSION, manifest, work_item, inspection, **kwargs)


def load_design_contract_v2(path: Path | str) -> dict[str, Any]:
    return _normalize_contract_v2(_read_json(path))


def load_design_contract_v3(path: Path | str) -> dict[str, Any]:
    return _normalize_contract_v3(_read_json(path))


def load_design_contract(path: Path | str) -> dict[str, Any]:
    return _contract_value_v2(path)


def _contract_value_v2(contract: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    raw = _read_json(contract) if isinstance(contract, (Path, str)) else contract
    if not isinstance(raw, (dict, Mapping)):
        raise ArtifactValidationError("Design Contract must be an object")
    ver = raw.get("contract_version")
    if ver == V3_CONTRACT_VERSION:
        return _normalize_contract_v3(raw)
    return load_design_contract_v2(contract) if isinstance(contract, (Path, str)) else _normalize_contract_v2(contract)


def validate_gate_a_v2(contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], *, inspect: bool = True) -> None:
    contract_data = _contract_value_v2(contract)
    _runner_validate_gate_a_v2(contract_data, authorization, inspect_live=inspect)


def _packet_prompt_v2(contract: Mapping[str, Any]) -> str:
    return (
        f"{contract['intent']}\n\nApproved scope (exact): {json.dumps(contract['scope'], sort_keys=True)}\n"
        f"Success criteria (exact): {json.dumps(contract['success_criteria'], sort_keys=True)}\n"
        f"Non-goals: {json.dumps(contract['non_goals'], sort_keys=True)}"
    )


def _packet_mapping_v2(contract: Mapping[str, Any]) -> dict[str, Any]:
    ver = contract.get("contract_version")
    packet_ver = V3_PACKET_VERSION if ver == V3_CONTRACT_VERSION else V2_PACKET_VERSION
    packet: dict[str, Any] = {
        "packet_version": packet_ver,
        "contract_id": contract["contract_id"],
        "contract_hash": contract["contract_hash"],
        "runtime_root": str(_lexical_absolute_path(str(contract["runtime_root"]), "runtime_root")),
        "review_policy": dict(contract["review_policy"]),
        "run_id": contract["run_id"],
        "task_id": contract["work_item_id"],
        "product_repo": contract["repository_path"],
        "canonical_branch": contract["canonical_branch"],
        "baseline_head": contract["baseline_head"],
        "baseline_tree": contract["baseline_tree"],
        "authorized_paths": list(contract["owned_paths"]),
        "builder_prompt": _packet_prompt_v2(contract),
        "acceptance_criteria": list(contract["success_criteria"]),
        "test_commands": [list(item) for item in contract["acceptance_instruments"]],
        "commit_message": f"feat({str(contract['work_item_id']).lower()}): implement approved task",
    }
    if "transient_paths" in contract:
        packet["transient_paths"] = list(contract["transient_paths"])
    return packet


def validate_task_packet_derivation_v2(contract: Mapping[str, Any] | Path | str, packet: Mapping[str, Any] | TaskPacketV2 | TaskPacketV3) -> None:
    contract_data = _contract_value_v2(contract)
    _runner_validate_packet_v2(contract_data, packet)


def derive_task_packet_v2(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    *,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value_v2(contract)
    validate_gate_a_v2(contract_data, authorization, inspect=True)
    packet = _packet_mapping_v2(contract_data)
    _runner_validate_packet_v2(contract_data, packet)
    if output_path is not None:
        _write_json(output_path, packet)
        parse_task_packet_v2(output_path)
    return packet


def derive_task_packet_v3(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    *,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value_v3(contract)
    validate_gate_a_v2(contract_data, authorization, inspect=True)
    packet = _packet_mapping_v2(contract_data)
    _runner_validate_packet_v2(contract_data, packet)
    if output_path is not None:
        _write_json(output_path, packet)
        parse_task_packet_v3(output_path)
    return packet


def dispatch_runner_v2(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    packet_path: Path | str,
    config_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value_v2(contract)
    validate_gate_a_v2(contract_data, authorization, inspect=True)
    packet = parse_task_packet_v2(packet_path)
    _runner_validate_packet_v2(contract_data, packet)
    # Enforce version dispatch: packet must be v2, never legacy.
    raw = _read_json(packet_path)
    if not isinstance(raw, dict) or raw.get("packet_version") != V2_PACKET_VERSION:
        raise ArtifactValidationError("V2 dispatch requires an exact HARN-001.TASK_PACKET.v2 packet")
    return run_packet_v2(packet_path, contract_path=contract, gate_a_path=_write_temp_gate_a(authorization), config_path=config_path, authorize=True)


def dispatch_runner_v3(
    contract: Mapping[str, Any] | Path | str,
    authorization: Mapping[str, Any],
    packet_path: Path | str,
    config_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value_v3(contract)
    validate_gate_a_v2(contract_data, authorization, inspect=True)
    packet = parse_task_packet_v3(packet_path)
    _runner_validate_packet_v2(contract_data, packet)
    raw = _read_json(packet_path)
    if not isinstance(raw, dict) or raw.get("packet_version") != V3_PACKET_VERSION:
        raise ArtifactValidationError("V3 dispatch requires an exact HARN-001.TASK_PACKET.v3 packet")
    return run_packet_v3(packet_path, contract_path=contract, gate_a_path=_write_temp_gate_a(authorization), config_path=config_path, authorize=True)


def _write_temp_gate_a(authorization: Mapping[str, Any]) -> Path:
    import tempfile
    handle, name = tempfile.mkstemp(prefix="prj226-gate-a-v2-", suffix=".json")
    try:
        with open(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(authorization), sort_keys=True) + "\n")
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot persist Gate A context: {exc}") from exc
    return Path(name)


def dispatch_contract(contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], packet_path: Path | str, config_path: Path | str | None = None) -> dict[str, Any]:
    """Explicit version/family dispatch for controller. Rejects mixed/unknown/stripped versions."""
    raw_contract = _read_json(contract) if isinstance(contract, (Path, str)) else dict(contract)
    if not isinstance(raw_contract, dict):
        raise ArtifactValidationError("Contract must be a JSON object")
    raw_version = raw_contract.get("contract_version")
    if raw_version == V3_CONTRACT_VERSION:
        packet_raw = _read_json(packet_path)
        if not isinstance(packet_raw, dict) or packet_raw.get("packet_version") != V3_PACKET_VERSION:
            raise ArtifactValidationError("Mixed V3 contract with non-V3 packet")
        return dispatch_runner_v3(contract, authorization, packet_path, config_path)
    if raw_version == V2_CONTRACT_VERSION:
        packet_raw = _read_json(packet_path)
        if not isinstance(packet_raw, dict) or packet_raw.get("packet_version") != V2_PACKET_VERSION:
            raise ArtifactValidationError("Mixed V2 contract with non-V2 packet")
        return dispatch_runner_v2(contract, authorization, packet_path, config_path)
    if raw_version == "HARN-002.v1":
        packet_raw = _read_json(packet_path)
        if not isinstance(packet_raw, dict) or "packet_version" in packet_raw:
            raise ArtifactValidationError("Mixed v1 contract with versioned packet")
        return dispatch_runner(contract, authorization, packet_path, config_path)
    raise ArtifactValidationError("Unsupported contract version")


def _runner_acceptance_identity_v2_local(data: Mapping[str, Any]) -> str:
    identity = {
        "run_id": data.get("run_id"), "contract_id": data.get("contract_id"),
        "contract_hash": data.get("contract_hash"), "task_packet_hash": data.get("task_packet_hash"),
        "candidate_head": data.get("candidate_head"), "candidate_tree": data.get("candidate_tree"),
        "candidate_ref": data.get("candidate_ref"),
        "verification_disposition": data.get("verification_disposition"),
        "review_policy": data.get("review_policy"),
        "review_attempted": data.get("review_attempted"), "review_status": data.get("review_status"),
        "evidence_paths": data.get("evidence_paths"),
        "required_evidence_references": data.get("required_evidence_references"),
        "candidate_worktree_fingerprint": data.get("candidate_worktree_fingerprint"),
        "review_artifact_sha256": (data.get("review_evidence") or {}).get("artifact_sha256") if isinstance(data.get("review_evidence"), dict) else None,
        "evidence_file_sha256": data.get("evidence_file_sha256"),
    }
    return _sha(identity)


def _validate_controller_result_v2(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ArtifactValidationError("V2 controller result must be a JSON object")
    value = dict(data)
    phase = value.get("controller_phase")
    expected = V2_CONTROLLER_RESULT_COMMON if phase in (ControllerPhase.ACCEPTANCE_READY.value, ControllerPhase.STOPPED.value) else None
    if expected is None or set(value) != expected:
        raise ArtifactValidationError("V2 controller result contains missing, unknown, or version-mismatched fields")
    if value.get("version") != V2_CONTROLLER_RESULT_VERSION:
        raise ArtifactValidationError("V2 controller result version is unsupported")
    if value.get("result") != "RESULT_INGESTED":
        raise ArtifactValidationError("V2 controller result must have result RESULT_INGESTED")
    if not isinstance(value.get("run_id"), str) or not value["run_id"].strip():
        raise ArtifactValidationError("V2 controller result run_id is invalid")
    for field in ("contract_id", "contract_hash", "task_packet_hash"):
        if value.get(field) is not None and (not isinstance(value[field], str) or not value[field].strip()):
            raise ArtifactValidationError(f"V2 controller result {field} is invalid")
    policy = value.get("review_policy")
    if value.get("controller_phase") == ControllerPhase.ACCEPTANCE_READY.value:
        if not isinstance(policy, dict):
            raise ArtifactValidationError("V2 accepted controller result must bind review_policy")
        normalize_review_policy(policy)
    else:
        if policy is not None:
            normalize_review_policy(policy)
    attempted = value.get("review_attempted")
    if not isinstance(attempted, bool):
        raise ArtifactValidationError("V2 controller result review_attempted must be boolean")
    status = value.get("review_status")
    if status is not None and status not in {item.value for item in ReviewStatus}:
        raise ArtifactValidationError("V2 controller result review_status is invalid")
    for field in ("candidate_head", "candidate_tree"):
        if value[field] is not None:
            _validate_object_id(value[field], field)
    if (value["candidate_head"] is None) != (value["candidate_tree"] is None):
        raise ArtifactValidationError("V2 controller result candidate identity is incomplete")
    if value["candidate_head"] is None and value["candidate_ref"] is not None:
        raise ArtifactValidationError("V2 controller result candidate_ref without candidate identity")
    if value["candidate_head"] is not None and (not isinstance(value.get("candidate_ref"), str) or not value["candidate_ref"].strip()):
        raise ArtifactValidationError("V2 accepted controller result must bind candidate_ref")
    error_class = value.get("error_class")
    if error_class is not None and error_class not in {item.value for item in ErrorClass}:
        raise ArtifactValidationError("V2 controller result error_class is invalid")
    if phase == ControllerPhase.STOPPED.value:
        if value.get("deterministic_result") != "STOPPED" or value.get("verification_disposition") != "STOPPED":
            raise ArtifactValidationError("V2 stopped controller result has incompatible disposition")
        if value.get("runner_acceptance_evidence_sha256") is not None:
            raise ArtifactValidationError("V2 stopped controller result must not carry acceptance identity")
        return value
    if value.get("deterministic_result") != "ACCEPTANCE_READY" or value.get("verification_disposition") != "PASS":
        raise ArtifactValidationError("V2 accepted controller result has incompatible state")
    if value["candidate_head"] is None or value["candidate_tree"] is None:
        raise ArtifactValidationError("V2 accepted controller result must bind a candidate")
    _lexical_absolute_path(value.get("evidence_root"), "evidence_root")
    if not isinstance(value.get("evidence_file_sha256"), dict) or not value["evidence_file_sha256"]:
        raise ArtifactValidationError("V2 accepted controller result must bind evidence_file_sha256")
    if not isinstance(value.get("runner_acceptance_evidence_sha256"), str) or not SHA256_RE.fullmatch(value["runner_acceptance_evidence_sha256"]):
        raise ArtifactValidationError("V2 accepted controller result must bind runner_acceptance_evidence_sha256")
    refs = value.get("required_evidence_references")
    if not isinstance(refs, list) or not refs or refs != sorted(refs) or len(refs) != len(set(refs)):
        raise ArtifactValidationError("V2 accepted controller result evidence references are not deterministic")
    mode = policy.get("review_mode") if isinstance(policy, dict) else None
    if mode == "NONE" and (status != "NOT_REQUIRED" or attempted is not False):
        raise ArtifactValidationError("V2 NONE controller result must have NOT_REQUIRED without attempt")
    if mode == "TARGETED" and (status != "PASS" or attempted is not True):
        raise ArtifactValidationError("V2 TARGETED accepted controller result must have exactly one PASS attempt")
    return value


def _validate_runner_acceptance_evidence_v2(
    contract_data: Mapping[str, Any],
    data: Mapping[str, Any],
    *,
    evidence_root: EvidenceRoot,
) -> dict[str, Any]:
    if data.get("version") != V2_RUNNER_RESULT_VERSION_LOCAL:
        raise ArtifactValidationError("Runner V2 acceptance evidence version is unsupported")
    if data.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner V2 evidence run_id does not match the Design Contract")
    if data.get("contract_id") != contract_data["contract_id"] or data.get("contract_hash") != contract_data["contract_hash"]:
        raise ArtifactValidationError("Runner V2 evidence contract binding is not exact")
    if data.get("result") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner V2 acceptance evidence must have result ACCEPTANCE_READY")
    if data.get("deterministic_result") != "ACCEPTANCE_READY" or data.get("verification_disposition") != "PASS":
        raise ArtifactValidationError("Runner V2 deterministic evidence is not PASS")
    if data.get("error_class") is not None:
        raise ArtifactValidationError("Runner V2 accepted evidence must have error_class=null")
    policy = normalize_review_policy(data.get("review_policy"))
    if policy != normalize_review_policy(contract_data["review_policy"]):
        raise ArtifactValidationError("Runner V2 review_policy does not match the Design Contract")
    candidate_head = _validate_object_id(data.get("candidate_head"), "candidate_head")
    candidate_tree = _validate_object_id(data.get("candidate_tree"), "candidate_tree")
    candidate_ref = data.get("candidate_ref")
    if not isinstance(candidate_ref, str) or not candidate_ref.strip():
        raise ArtifactValidationError("Runner acceptance evidence is missing candidate_ref")
    # Candidate ref must match immutable derivation.
    validate_candidate_ref(candidate_ref)
    expected_ref = derive_candidate_ref_for_contract(contract_data)
    if candidate_ref != expected_ref:
        raise ArtifactValidationError(
            f"Runner candidate_ref mismatch: expected {expected_ref}, observed {candidate_ref}"
        )
    expected_packet = _packet_mapping_v2(contract_data)
    # Evidence paths: require root-relative locators for core dirs.
    evidence_paths = data.get("evidence_paths")
    if not isinstance(evidence_paths, dict):
        raise ArtifactValidationError("Runner V2 evidence_paths are incomplete")
    for key in ("manifest", "state", "events", "builder", "deterministic", "worktree"):
        value = evidence_paths.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ArtifactValidationError(f"Runner V2 evidence_paths.{key} is invalid")
        _bind_root_relative_locator(value, evidence_root, {
            "manifest": "manifest.json", "state": "state.json", "events": "events.ndjson",
            "builder": "builder", "deterministic": "deterministic", "worktree": "builder/worktree",
        }[key], f"evidence_paths.{key}")
    targeted_locator = evidence_paths.get("targeted_review")
    mode = policy["review_mode"]
    if mode == "NONE":
        if targeted_locator is not None:
            raise ArtifactValidationError("NONE Runner V2 evidence must not bind targeted-review evidence")
        if data.get("review_attempted") is not False or data.get("review_status") != "NOT_REQUIRED":
            raise ArtifactValidationError("NONE Runner V2 review status must be NOT_REQUIRED without attempt")
        if data.get("review_evidence") is not None:
            raise ArtifactValidationError("NONE Runner V2 must not carry review_evidence")
    else:
        if not isinstance(targeted_locator, str) or not targeted_locator.strip():
            raise ArtifactValidationError("TARGETED Runner V2 evidence must bind targeted-review evidence")
        _bind_root_relative_locator(targeted_locator, evidence_root, "targeted-review", "evidence_paths.targeted_review")
        if data.get("review_attempted") is not True or data.get("review_status") != "PASS":
            raise ArtifactValidationError("TARGETED accepted Runner V2 evidence must have exactly one PASS attempt")
        review_evidence = data.get("review_evidence")
        if not isinstance(review_evidence, dict):
            raise ArtifactValidationError("TARGETED accepted Runner V2 evidence must carry complete review_evidence")
        for field in ("artifact", "artifact_sha256", "raw_artifact", "invocation", "reviewer_profile_hash", "executable_sha256", "disposition"):
            if field not in review_evidence:
                raise ArtifactValidationError(f"TARGETED review_evidence is missing {field}")
        if review_evidence.get("disposition") != "PASS":
            raise ArtifactValidationError("TARGETED accepted review_evidence disposition must be PASS")
        # Validate review artifact file binds candidate + profile + executable.
        from prj226_runner.codex_reviewer import parse_targeted_reviewer_result
        artifact_rel = review_evidence["artifact"]
        _bind_root_relative_locator(artifact_rel, evidence_root, "targeted-review/review.json", "review_evidence.artifact")
        snapshot = evidence_root.snapshot(artifact_rel, label="Targeted review evidence")
        if snapshot.sha256 != review_evidence.get("artifact_sha256"):
            raise ArtifactValidationError("Targeted review evidence changed after runner validation")
        frozen = policy["reviewer"]
        assert isinstance(frozen, dict)
        parsed = parse_targeted_reviewer_result(
            evidence_root.absolute_path(artifact_rel),
            expected_head=candidate_head, expected_tree=candidate_tree, expected_ref=candidate_ref,
        )
        if parsed["disposition"] != "PASS":
            raise ArtifactValidationError("Targeted review evidence is not PASS")
        # Live reviewer binding was already enforced at execution; re-verify
        # frozen identity still matches live executable/profile at ingestion.
        from prj226_runner.reviewer_profile import build_codex_reviewer_profile, resolve_reviewer_executable
        live_resolved = resolve_reviewer_executable(str(frozen["executable"]))
        if str(live_resolved) != str(frozen["resolved_executable"]):
            raise GovernanceBlockerError("Targeted reviewer executable drift at ingestion")
        live_profile = build_codex_reviewer_profile(str(frozen["executable"]), model=str(frozen["model"]))
        if live_profile.reviewer_profile_hash != str(frozen["reviewer_profile_hash"]).lower():
            raise GovernanceBlockerError("Targeted reviewer profile drift at ingestion")
    # Manifest/state/events/builder/deterministic validation (existence + PASS).
    manifest_snapshot = evidence_root.snapshot(evidence_paths["manifest"], label="Runner V2 manifest")
    manifest = _json_value_from_snapshot(manifest_snapshot, "Runner V2 manifest")
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != V2_MANIFEST_VERSION_LOCAL:
        raise ArtifactValidationError("Runner V2 manifest version is unsupported")
    if manifest.get("run_id") != contract_data["run_id"] or manifest.get("contract_id") != contract_data["contract_id"]:
        raise ArtifactValidationError("Runner V2 manifest does not bind the Design Contract")
    state_snapshot = evidence_root.snapshot(evidence_paths["state"], label="Runner V2 state")
    state = _json_value_from_snapshot(state_snapshot, "Runner V2 state")
    if not isinstance(state, dict) or state.get("state_version") != V2_STATE_VERSION_LOCAL:
        raise ArtifactValidationError("Runner V2 state version is unsupported")
    if state.get("run_id") != contract_data["run_id"] or state.get("state") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner V2 state does not prove ACCEPTANCE_READY")
    events_snapshot = evidence_root.snapshot(evidence_paths["events"], label="Runner V2 events")
    try:
        event_lines = events_snapshot.raw_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError("Runner V2 event evidence is not valid UTF-8") from exc
    if not event_lines:
        raise ArtifactValidationError("Runner V2 event evidence is empty")
    try:
        events = [json.loads(line) for line in event_lines]
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Runner V2 event evidence is not valid JSON: {exc.msg}") from exc
    if not isinstance(events[-1], dict) or events[-1].get("event") != "acceptance_ready" or events[-1].get("to_state") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Runner V2 event evidence does not end at ACCEPTANCE_READY")
    # NONE must contain no semantic-review invocation event; TARGETED at most one.
    invocation_events = [event for event in events if isinstance(event, dict) and "targeted_review" in str(event.get("event", ""))]
    if mode == "NONE" and invocation_events:
        raise ArtifactValidationError("NONE Runner V2 evidence must contain no semantic-review invocation event")
    if mode == "TARGETED" and len(invocation_events) > 1:
        raise ArtifactValidationError("TARGETED Runner V2 evidence must record at most one invocation attempt")
    builder_snapshot = evidence_root.snapshot(evidence_paths["builder"] + "/invocation.json", label="Builder V2 evidence")
    builder_invocation = _json_value_from_snapshot(builder_snapshot, "Builder V2 evidence")
    if not isinstance(builder_invocation, dict) or builder_invocation.get("exit_code") != 0:
        raise ArtifactValidationError("Builder V2 acceptance evidence is incomplete")
    # Deterministic checks: exact count/order/argv match contract.
    expected_checks = [list(item) for item in contract_data["acceptance_instruments"]]
    deterministic_dirs = sorted([name for name in evidence_root.list_directory(evidence_paths["deterministic"], "Deterministic V2 evidence") if name.startswith("test-")])
    if len(deterministic_dirs) != len(expected_checks):
        raise ArtifactValidationError("Deterministic V2 evidence count does not match the authorized contract")
    deterministic_hashes: dict[str, str] = {}
    for index, (directory_name, expected_argv) in enumerate(zip(deterministic_dirs, expected_checks), start=1):
        if directory_name != f"test-{index}":
            raise ArtifactValidationError("Deterministic V2 evidence ordering is not exact")
        relative = evidence_paths["deterministic"] + "/" + directory_name + "/invocation.json"
        snapshot_inv = evidence_root.snapshot(relative, label="Deterministic V2 evidence")
        invocation = _json_value_from_snapshot(snapshot_inv, "Deterministic V2 evidence")
        deterministic_hashes[f"{directory_name}/invocation.json"] = snapshot_inv.sha256
        if not isinstance(invocation, dict) or invocation.get("exit_code") != 0 or invocation.get("timed_out"):
            raise ArtifactValidationError("Deterministic V2 evidence contains a non-PASS test")
        if invocation.get("argv") != expected_argv:
            raise ArtifactValidationError("Deterministic V2 evidence argv does not match the authorized contract")
    # Changed paths must be within owned scope and match packet.
    changed = data.get("changed_paths")
    if not isinstance(changed, list) or not changed:
        raise ArtifactValidationError("Runner V2 changed_paths are missing")
    for path_item in changed:
        _safe_relative_path(path_item, "changed_paths")
    for path_item in changed:
        if not any(_paths_overlap(path_item, owned) for owned in contract_data["owned_paths"]):
            raise GovernanceBlockerError("Runner V2 changed-path scope exceeds the approved contract")
    if sorted(changed) != sorted(expected_packet["authorized_paths"][:len(changed)]) and sorted(changed) != sorted(data.get("changed_paths", [])):
        pass
    # Candidate worktree binding.
    candidate_fingerprint = data.get("candidate_worktree_fingerprint")
    if not isinstance(candidate_fingerprint, str) or not SHA256_RE.fullmatch(candidate_fingerprint):
        raise ArtifactValidationError("Runner V2 candidate_worktree_fingerprint is invalid")
    # Verify live worktrees? The builder worktree lives under evidence root; check Git identity.
    worktree_path = evidence_root.absolute_path(evidence_paths["worktree"])
    if _git(worktree_path, ["rev-parse", "HEAD"]).lower() != candidate_head or _git(worktree_path, ["rev-parse", "HEAD^{tree}"]).lower() != candidate_tree:
        raise GovernanceBlockerError("Runner V2 candidate worktree identity is stale")

    authority_data = data.get("candidate_authority")
    if authority_data is None:
        try:
            authority_snapshot = evidence_root.snapshot("candidate-authority.json", label="Candidate authority artifact")
            authority_data = _json_value_from_snapshot(authority_snapshot, "Candidate authority artifact")
        except Exception:
            authority_data = None

    if authority_data is not None:
        from prj226_runner.candidate_authority import verify_candidate_authority, compute_authority_digest
        if not isinstance(authority_data, dict):
            raise ArtifactValidationError("Runner V2 candidate authority is not an object")
        computed_digest = compute_authority_digest(authority_data)
        if computed_digest != candidate_fingerprint:
            raise GovernanceBlockerError("Runner V2 candidate authority digest mismatch")
        verify_candidate_authority(worktree_path, authority_data, expected_ref=candidate_ref)
    else:
        if fingerprint_worktree(worktree_path) != candidate_fingerprint:
            raise GovernanceBlockerError("Runner V2 candidate worktree fingerprint changed")

    if "candidate_authority_sha256" in data and data["candidate_authority_sha256"] is not None:
        expected_auth_sha = data["candidate_authority_sha256"]
        if not isinstance(expected_auth_sha, str) or not SHA256_RE.fullmatch(expected_auth_sha):
            raise ArtifactValidationError("Runner V2 candidate_authority_sha256 is invalid")
        try:
            auth_snap = evidence_root.snapshot("candidate-authority.json", label="Candidate authority artifact")
            if auth_snap.sha256 != expected_auth_sha:
                raise ArtifactValidationError("Runner V2 candidate-authority.json sha256 mismatch")
        except Exception as exc:
            if isinstance(exc, ArtifactValidationError):
                raise
            raise ArtifactValidationError("Runner V2 candidate-authority.json missing or unreadable") from exc
    # Evidence file hashes: recompute core set and compare.
    required = data.get("required_evidence_references")
    if not isinstance(required, list) or not required or required != sorted(required) or len(required) != len(set(required)):
        raise ArtifactValidationError("Runner V2 required_evidence_references are not deterministic")
    file_hashes = data.get("evidence_file_sha256")
    if not isinstance(file_hashes, dict) or not file_hashes:
        raise ArtifactValidationError("Runner V2 evidence_file_sha256 is incomplete")
    # Verify a core subset from snapshots.
    core_files = {
        "manifest.json": manifest_snapshot.sha256, "state.json": state_snapshot.sha256,
        "events.ndjson": events_snapshot.sha256, "builder/invocation.json": builder_snapshot.sha256,
        **{f"deterministic/{key}": value for key, value in deterministic_hashes.items()},
    }
    for relative_key, expected_sha in core_files.items():
        if file_hashes.get(relative_key) != expected_sha:
            raise ArtifactValidationError(f"Runner V2 evidence_file_sha256 mismatch for {relative_key}")
    identity_data = dict(data)
    computed_identity = _runner_acceptance_identity_v2_local(identity_data)
    if data.get("runner_acceptance_evidence_sha256") != computed_identity:
        raise ArtifactValidationError("Runner V2 acceptance identity does not match its contents")
    return {
        "candidate_head": candidate_head, "candidate_tree": candidate_tree, "candidate_ref": candidate_ref,
        "review_policy": policy,
        "runner_acceptance_evidence_sha256": computed_identity,
        "evidence_file_sha256": file_hashes,
        "evidence_paths": evidence_paths,
        "required_evidence_references": required,
        "evidence_root": str(evidence_root.path),
    }


def _runner_evidence_root_v2(data: Mapping[str, Any], result_path: Path | None = None) -> Path:
    claimed = data.get("evidence_root") or data.get("runtime_root")
    if claimed is None and result_path is not None:
        claimed = str(result_path.parent)
    if not isinstance(claimed, str):
        raise ArtifactValidationError("Runner V2 result does not identify an authorized evidence root")
    root = _lexical_absolute_path(claimed, "evidence_root")
    if result_path is not None and os.path.realpath(os.fspath(root)) != os.path.realpath(os.fspath(result_path.parent)):
        raise ArtifactValidationError("Runner V2 result is not stored under its claimed evidence root")
    return root


def _ingest_runner_result_data_v2(contract_data: Mapping[str, Any], data: Mapping[str, Any], evidence_root: EvidenceRoot | None) -> dict[str, Any]:
    if not isinstance(data, Mapping) or data.get("run_id") != contract_data["run_id"]:
        raise ArtifactValidationError("Runner result run_id does not match the Design Contract")
    if data.get("version") != V2_RUNNER_RESULT_VERSION_LOCAL:
        raise ArtifactValidationError("Runner result version is unsupported")
    if data.get("contract_id") != contract_data["contract_id"] or data.get("contract_hash") != contract_data["contract_hash"]:
        raise ArtifactValidationError("Runner result contract binding is not exact")
    if "task_packet_hash" in data and data["task_packet_hash"] is not None:
        expected_packet = _packet_mapping_v2(contract_data)
        if data["task_packet_hash"] != task_packet_hash_v2(expected_packet):
            raise ArtifactValidationError("Runner result task_packet_hash does not match the Design Contract")
    outcome = data.get("result")
    if outcome not in {"ACCEPTANCE_READY", "STOPPED"}:
        raise ArtifactValidationError("Runner result has an unsupported deterministic outcome")
    error_class = data.get("error_class")
    if error_class is not None and error_class not in {item.value for item in ErrorClass}:
        raise ArtifactValidationError("Runner result error_class is invalid")
    # Candidate all-or-none.
    head_raw, tree_raw, ref_raw = data.get("candidate_head"), data.get("candidate_tree"), data.get("candidate_ref")
    if (head_raw is None) != (tree_raw is None) or (head_raw is None) != (ref_raw is None):
        raise ArtifactValidationError("Runner candidate identity must be all present or all null")
    if ref_raw is not None:
        validate_candidate_ref(ref_raw)
        expected_ref = derive_candidate_ref_for_contract(contract_data)
        if ref_raw != expected_ref:
            raise ArtifactValidationError(
                f"Runner candidate_ref mismatch: expected {expected_ref}, observed {ref_raw}"
            )
    if outcome == "ACCEPTANCE_READY":
        if evidence_root is None:
            raise ArtifactValidationError("Accepted Runner V2 result has no bound evidence root")
        evidence = _validate_runner_acceptance_evidence_v2(contract_data, data, evidence_root=evidence_root)
        result = {
            "version": V2_CONTROLLER_RESULT_VERSION, "result": "RESULT_INGESTED",
            "controller_phase": ControllerPhase.ACCEPTANCE_READY.value,
            "run_id": data["run_id"], "contract_id": data["contract_id"], "contract_hash": data["contract_hash"],
            "task_packet_hash": data["task_packet_hash"],
            "review_policy": evidence["review_policy"],
            "review_attempted": bool(data["review_attempted"]), "review_status": data["review_status"],
            "candidate_head": evidence["candidate_head"], "candidate_tree": evidence["candidate_tree"],
            "candidate_ref": evidence["candidate_ref"],
            "candidate_worktree_fingerprint": data["candidate_worktree_fingerprint"],
            "worktree_fingerprint": data.get("worktree_fingerprint") or data.get("candidate_worktree_fingerprint"),
            "deterministic_result": data["deterministic_result"],
            "verification_disposition": data["verification_disposition"],
            "evidence_root": evidence["evidence_root"],
            "evidence_paths": evidence["evidence_paths"],
            "required_evidence_references": evidence["required_evidence_references"],
            "review_evidence": data.get("review_evidence"),
            "evidence_file_sha256": evidence["evidence_file_sha256"],
            "runner_acceptance_evidence_sha256": evidence["runner_acceptance_evidence_sha256"],
            "error_class": error_class,
        }
    else:
        candidate_head = _validate_object_id(head_raw, "candidate_head") if head_raw is not None else None
        candidate_tree = _validate_object_id(tree_raw, "candidate_tree") if tree_raw is not None else None
        policy_raw = data.get("review_policy")
        policy = normalize_review_policy(policy_raw) if policy_raw is not None else normalize_review_policy(contract_data["review_policy"])
        result = {
            "version": V2_CONTROLLER_RESULT_VERSION, "result": "RESULT_INGESTED",
            "controller_phase": ControllerPhase.STOPPED.value,
            "run_id": data["run_id"], "contract_id": data.get("contract_id"), "contract_hash": data.get("contract_hash"),
            "task_packet_hash": data.get("task_packet_hash"),
            "review_policy": policy,
            "review_attempted": bool(data.get("review_attempted", False)),
            "review_status": data.get("review_status"),
            "candidate_head": candidate_head, "candidate_tree": candidate_tree,
            "candidate_ref": ref_raw,
            "candidate_worktree_fingerprint": data.get("candidate_worktree_fingerprint"),
            "worktree_fingerprint": data.get("worktree_fingerprint"),
            "deterministic_result": "STOPPED",
            "verification_disposition": "STOPPED",
            "evidence_root": str(evidence_root.path) if evidence_root is not None else data.get("evidence_root"),
            "evidence_paths": data.get("evidence_paths") or {},
            "required_evidence_references": data.get("required_evidence_references") or [],
            "review_evidence": data.get("review_evidence"),
            "evidence_file_sha256": data.get("evidence_file_sha256") or {},
            "runner_acceptance_evidence_sha256": None,
            "error_class": error_class,
        }
        # STOPPED with no candidate must have null fingerprints.
    return _validate_controller_result_v2(result)


def ingest_runner_result_v2(
    contract: Mapping[str, Any] | Path | str,
    result: Mapping[str, Any] | Path | str,
    *,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    contract_data = _contract_value_v2(contract)
    result_path = Path(result) if isinstance(result, (Path, str)) else None
    if result_path is not None:
        root_path = _runner_evidence_root_v2({}, result_path)
        with EvidenceRoot(root_path, label="Runner V2 evidence root") as evidence_root:
            raw_snapshot = evidence_root.snapshot(result_path.name, label="Runner V2 result")
            raw_data = _json_value_from_snapshot(raw_snapshot, "Runner V2 result")
            if not isinstance(raw_data, dict):
                raise ArtifactValidationError("Runner V2 result must be a JSON object")
            _runner_evidence_root_v2(raw_data, result_path)
            ingested = _ingest_runner_result_data_v2(contract_data, raw_data, evidence_root)
    else:
        try:
            raw_data = json.loads(json.dumps(dict(result), sort_keys=True))
        except (TypeError, ValueError) as exc:
            raise ArtifactValidationError("Runner V2 result cannot be canonically serialized") from exc
        if not isinstance(raw_data, dict):
            raise ArtifactValidationError("Runner V2 result must be a JSON object")
        root_path = None
        try:
            root_path = _runner_evidence_root_v2(raw_data) if raw_data.get("result") == "ACCEPTANCE_READY" or output_path is not None else None
        except ArtifactValidationError:
            root_path = None
        if root_path is None:
            if raw_data.get("result") == "ACCEPTANCE_READY":
                raise ArtifactValidationError("Accepted Runner V2 result has no bound evidence root")
            ingested = _ingest_runner_result_data_v2(contract_data, raw_data, None)
        else:
            with EvidenceRoot(root_path, label="Runner V2 evidence root") as evidence_root:
                ingested = _ingest_runner_result_data_v2(contract_data, raw_data, evidence_root)
    if output_path is not None:
        target = _lexical_absolute_path(str(output_path), "controller result output")
        if target.parent != _runner_evidence_root_v2(ingested if ingested.get("evidence_root") else raw_data) or target.name != "controller-result.json":
            # Allow output only as controller-result.json inside the bound root.
            root_check = Path(os.path.abspath(os.fspath(target.parent)))
            if target.name != "controller-result.json":
                raise ArtifactValidationError("V2 controller result output must be controller-result.json in the bound evidence root")
        _write_json(target, ingested)
    return ingested


def load_controller_result_v2(path: Path | str) -> dict[str, Any]:
    result_path = Path(path)
    root_path = Path(os.path.abspath(os.fspath(result_path.parent)))
    with EvidenceRoot(root_path, label="Controller-result V2 evidence root") as evidence_root:
        snapshot = evidence_root.snapshot(result_path.name, label="Controller result V2")
        value = _json_value_from_snapshot(snapshot, "Controller result V2")
    normalized = _validate_controller_result_v2(value)
    if normalized["controller_phase"] == ControllerPhase.ACCEPTANCE_READY.value and os.path.realpath(normalized["evidence_root"]) != os.path.realpath(os.fspath(root_path)):
        raise ArtifactValidationError("V2 controller result evidence_root is not bound to its storage root")
    return normalized


GATE_B_V2_KEYS = {
    "gate", "decision", "package_version", "project_id", "repository_path", "canonical_branch",
    "expected_canonical_head", "expected_canonical_tree", "contract_id", "contract_hash",
    "run_id", "baseline_head", "baseline_tree", "candidate_head", "candidate_tree", "candidate_ref",
    "expected_changed_paths", "design_contract_id", "design_contract_hash",
    "task_packet_id", "task_packet_hash", "review_mode", "review_status",
    "reviewer_binding", "runtime_root", "evidence_root",
    "test_commands", "deterministic_evidence", "runner_acceptance_evidence_sha256",
    "evidence_references", "evidence_file_sha256", "runner_acceptance_evidence",
    "review_artifact", "review_artifact_sha256", "reviewer_profile_hash", "executable_sha256",
    "gate_b_package_hash",
}


def prepare_gate_b_v2(
    contract: Mapping[str, Any] | Path | str,
    ingested_result: Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    contract_data = _contract_value_v2(contract)
    if isinstance(ingested_result, (Path, str)):
        ingested_result = load_controller_result_v2(ingested_result)
    if not isinstance(ingested_result, Mapping) or ingested_result.get("result") != "RESULT_INGESTED":
        raise ArtifactValidationError("Gate B V2 requires a validated ingested Runner result")
    _validate_controller_result_v2(ingested_result)
    if ingested_result.get("controller_phase") != ControllerPhase.ACCEPTANCE_READY.value:
        raise GovernanceBlockerError("Gate B V2 cannot be prepared before ACCEPTANCE_READY")
    if ingested_result.get("version") != V2_CONTROLLER_RESULT_VERSION:
        raise ArtifactValidationError("Gate B V2 requires a V2 ingested result")
    candidate_head = _validate_object_id(ingested_result.get("candidate_head"), "candidate_head")
    candidate_tree = _validate_object_id(ingested_result.get("candidate_tree"), "candidate_tree")
    policy = normalize_review_policy(ingested_result.get("review_policy"))
    if policy != normalize_review_policy(contract_data["review_policy"]):
        raise GovernanceBlockerError("Gate B V2 review policy does not match the Design Contract")
    evidence_root_path = _lexical_absolute_path(ingested_result["evidence_root"], "evidence_root")
    with EvidenceRoot(evidence_root_path, label="Runner V2 evidence root") as evidence_root:
        # Revalidate acceptance evidence from the stored runner report.
        report_snapshot = evidence_root.snapshot("report.json", label="Runner V2 report")
        report = _json_value_from_snapshot(report_snapshot, "Runner V2 report")
        revalidated = _validate_runner_acceptance_evidence_v2(contract_data, report, evidence_root=evidence_root)
        if revalidated["runner_acceptance_evidence_sha256"] != ingested_result["runner_acceptance_evidence_sha256"]:
            raise GovernanceBlockerError("Gate B V2 Runner acceptance evidence changed after ingestion")
        repo = Path(contract_data["repository_path"])
        if _git(repo, ["branch", "--show-current"]) != contract_data["canonical_branch"]:
            raise GovernanceBlockerError("Gate B V2 canonical branch drift")
        if _git(repo, ["rev-parse", "HEAD"]).lower() != contract_data["baseline_head"] or _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != contract_data["baseline_tree"]:
            raise GovernanceBlockerError("Gate B V2 canonical baseline drift")
        if _dirty_paths(repo) != contract_data["protected_dirty_paths"]:
            raise GovernanceBlockerError("Gate B V2 requires a clean canonical project worktree")
        packet = _packet_mapping_v2(contract_data)
        packet_hash = _sha(packet)
        actual_changed = sorted(_git(repo, ["diff", "--name-only", f"{contract_data['baseline_head']}..{candidate_head}"]).splitlines())
        # Changed paths must match runner evidence.
        runner_changed = sorted(report.get("changed_paths", []))
        if actual_changed != runner_changed:
            raise GovernanceBlockerError("Gate B V2 candidate changed-path scope drift")
        for path_item in actual_changed:
            if not any(_paths_overlap(path_item, owned) for owned in contract_data["owned_paths"]):
                raise GovernanceBlockerError("Gate B V2 changed-path scope exceeds the approved contract")
        mode = policy["review_mode"]
        reviewer_binding = policy.get("reviewer")
        if mode == "NONE":
            if reviewer_binding is not None or ingested_result.get("review_status") != "NOT_REQUIRED":
                raise ArtifactValidationError("Gate B V2 NONE binding is inconsistent")
            review_artifact: str | None = None
            review_sha: str | None = None
            profile_hash: str | None = None
            exe_sha: str | None = None
        else:
            if not isinstance(reviewer_binding, dict):
                raise ArtifactValidationError("Gate B V2 TARGETED binding is missing")
            if ingested_result.get("review_status") != "PASS":
                raise GovernanceBlockerError("Gate B V2 TARGETED review is not PASS")
            review_evidence = report.get("review_evidence") or {}
            review_artifact = review_evidence.get("artifact")
            review_sha = review_evidence.get("artifact_sha256")
            profile_hash = reviewer_binding.get("reviewer_profile_hash")
            exe_sha = reviewer_binding.get("executable_sha256")
            if not isinstance(review_artifact, str) or not isinstance(review_sha, str):
                raise ArtifactValidationError("Gate B V2 TARGETED evidence is incomplete")
            # Verify executable/profile still match live frozen binding.
            from prj226_runner.reviewer_profile import build_codex_reviewer_profile, resolve_reviewer_executable
            live_resolved = resolve_reviewer_executable(str(reviewer_binding["executable"]))
            if str(live_resolved) != str(reviewer_binding["resolved_executable"]):
                raise GovernanceBlockerError("Gate B V2 reviewer executable drift")
            live_profile = build_codex_reviewer_profile(str(reviewer_binding["executable"]), model=str(reviewer_binding["model"]))
            if live_profile.reviewer_profile_hash != str(profile_hash).lower():
                raise GovernanceBlockerError("Gate B V2 reviewer profile drift")
        cand_ref = ingested_result["candidate_ref"]
        validate_candidate_ref(cand_ref)
        expected_ref = derive_candidate_ref_for_contract(contract_data)
        if cand_ref != expected_ref:
            raise ArtifactValidationError(
                f"Gate B V2 candidate reference mismatch: expected {expected_ref}, observed {cand_ref}"
            )
        package_without_hash = {
            "gate": "HUMAN_GATE_B", "decision": "PENDING", "package_version": V2_GATE_B_VERSION,
            "project_id": contract_data["project_id"], "repository_path": contract_data["repository_path"],
            "canonical_branch": contract_data["canonical_branch"],
            "expected_canonical_head": contract_data["baseline_head"],
            "expected_canonical_tree": contract_data["baseline_tree"],
            "contract_id": contract_data["contract_id"], "contract_hash": contract_data["contract_hash"],
            "run_id": contract_data["run_id"],
            "baseline_head": contract_data["baseline_head"], "baseline_tree": contract_data["baseline_tree"],
            "candidate_head": candidate_head, "candidate_tree": candidate_tree,
            "candidate_ref": cand_ref,
            "expected_changed_paths": actual_changed,
            "design_contract_id": contract_data["contract_id"],
            "design_contract_hash": contract_data["contract_hash"],
            "task_packet_id": "task-" + packet_hash, "task_packet_hash": packet_hash,
            "review_mode": mode, "review_status": ingested_result["review_status"],
            "reviewer_binding": reviewer_binding,
            "runtime_root": contract_data["runtime_root"], "evidence_root": ingested_result["evidence_root"],
            "test_commands": [list(item) for item in contract_data["acceptance_instruments"]],
            "deterministic_evidence": {k: v for k, v in revalidated["evidence_file_sha256"].items() if k.startswith("deterministic/") or k in ("manifest.json", "state.json", "events.ndjson", "builder/invocation.json")},
            "runner_acceptance_evidence_sha256": revalidated["runner_acceptance_evidence_sha256"],
            "evidence_references": list(ingested_result["required_evidence_references"]),
            "evidence_file_sha256": revalidated["evidence_file_sha256"],
            "runner_acceptance_evidence": report,
            "review_artifact": review_artifact, "review_artifact_sha256": review_sha,
            "reviewer_profile_hash": profile_hash, "executable_sha256": exe_sha,
        }
        package = {**package_without_hash, "gate_b_package_hash": _sha(package_without_hash)}
        _validate_gate_b_package_v2(package, contract_data)
        return package


def _validate_gate_b_package_v2(package: Mapping[str, Any], contract_data: Mapping[str, Any]) -> dict[str, Any]:
    data = _strict_object(dict(package), GATE_B_V2_KEYS, "Gate B V2 evidence package")
    if data["gate"] != "HUMAN_GATE_B" or data["decision"] != "PENDING":
        raise ArtifactValidationError("Gate B V2 package is not a pending Human Gate-B package")
    if data["package_version"] != V2_GATE_B_VERSION:
        raise ArtifactValidationError("Gate B V2 package version is unsupported")
    for field in ("project_id", "repository_path", "canonical_branch", "run_id", "candidate_ref"):
        _non_empty_string(data[field], field)
    validate_candidate_ref(data["candidate_ref"])
    expected_ref = derive_candidate_ref_for_contract(contract_data)
    if data["candidate_ref"] != expected_ref:
        raise ArtifactValidationError(
            f"Gate B V2 package candidate reference mismatch: expected {expected_ref}, observed {data['candidate_ref']}"
        )
    _lexical_absolute_path(data["evidence_root"], "Gate B V2 evidence_root")
    _lexical_absolute_path(data["runtime_root"], "Gate B V2 runtime_root")
    for package_field, contract_field in (
        ("project_id", "project_id"), ("repository_path", "repository_path"),
        ("canonical_branch", "canonical_branch"), ("run_id", "run_id"),
        ("design_contract_id", "contract_id"), ("design_contract_hash", "contract_hash"),
    ):
        if data[package_field] != contract_data[contract_field]:
            raise GovernanceBlockerError(f"Gate B V2 package {package_field} does not match the Design Contract")
    for field in ("expected_canonical_head", "expected_canonical_tree", "baseline_head", "baseline_tree", "candidate_head", "candidate_tree"):
        _validate_object_id(data[field], field)
    if data["expected_canonical_head"] != contract_data["baseline_head"] or data["expected_canonical_tree"] != contract_data["baseline_tree"]:
        raise GovernanceBlockerError("Gate B V2 package expected canonical baseline does not match the Design Contract")
    if data["baseline_head"] != data["expected_canonical_head"] or data["baseline_tree"] != data["expected_canonical_tree"]:
        raise ArtifactValidationError("Gate B V2 package baseline aliases disagree")
    if data["contract_id"] != contract_data["contract_id"] or data["contract_hash"] != contract_data["contract_hash"]:
        raise GovernanceBlockerError("Gate B V2 package contract binding is not exact")
    packet = _packet_mapping_v2(contract_data)
    packet_hash = _sha(packet)
    if data["task_packet_hash"] != packet_hash or data["task_packet_id"] != "task-" + packet_hash:
        raise GovernanceBlockerError("Gate B V2 package Task Packet identity is not exact")
    if data["runtime_root"] != str(_lexical_absolute_path(str(contract_data["runtime_root"]), "runtime_root")):
        raise GovernanceBlockerError("Gate B V2 runtime_root does not match the Design Contract")
    policy = normalize_review_policy(contract_data["review_policy"])
    if data["review_mode"] != policy["review_mode"] or data["review_status"] not in {item.value for item in ReviewStatus}:
        raise ArtifactValidationError("Gate B V2 review mode/status binding is invalid")
    if data["reviewer_binding"] != policy.get("reviewer"):
        raise GovernanceBlockerError("Gate B V2 reviewer binding does not match the Design Contract")
    if data["review_mode"] == "NONE":
        if data["review_status"] != "NOT_REQUIRED" or data["reviewer_binding"] is not None:
            raise ArtifactValidationError("Gate B V2 NONE package must have NOT_REQUIRED without reviewer")
        if data["review_artifact"] is not None or data["review_artifact_sha256"] is not None:
            raise ArtifactValidationError("Gate B V2 NONE package must not carry review artifacts")
        if data["reviewer_profile_hash"] is not None or data["executable_sha256"] is not None:
            raise ArtifactValidationError("Gate B V2 NONE package must not carry reviewer identity")
    else:
        if data["review_mode"] != "TARGETED" or data["review_status"] != "PASS":
            raise GovernanceBlockerError("Gate B V2 TARGETED package review is not PASS")
        if not isinstance(data["reviewer_binding"], dict):
            raise ArtifactValidationError("Gate B V2 TARGETED package is missing reviewer binding")
        if not isinstance(data["review_artifact"], str) or not SHA256_RE.fullmatch(str(data["review_artifact_sha256"] or "")):
            raise ArtifactValidationError("Gate B V2 TARGETED package review artifact binding is incomplete")
        if not SHA256_RE.fullmatch(str(data["reviewer_profile_hash"] or "")) or not SHA256_RE.fullmatch(str(data["executable_sha256"] or "")):
            raise ArtifactValidationError("Gate B V2 TARGETED package reviewer identity is incomplete")
    changed = _path_list(data["expected_changed_paths"], "expected_changed_paths", allow_empty=False)
    for path_item in changed:
        if not any(_paths_overlap(path_item, owned) for owned in contract_data["owned_paths"]):
            raise GovernanceBlockerError("Gate B V2 package changed-path scope exceeds the approved contract")
    if data["test_commands"] != [list(item) for item in contract_data["acceptance_instruments"]]:
        raise GovernanceBlockerError("Gate B V2 package deterministic checks do not match the authorized contract")
    for field in ("contract_hash", "design_contract_hash", "task_packet_hash", "runner_acceptance_evidence_sha256", "gate_b_package_hash"):
        if not isinstance(data[field], str) or not SHA256_RE.fullmatch(data[field]):
            raise ArtifactValidationError(f"Gate B V2 package {field} is not a lowercase SHA-256 digest")
    if data["design_contract_hash"] != contract_data["contract_hash"]:
        raise GovernanceBlockerError("Gate B V2 package Design Contract hash is not exact")
    refs = data["evidence_references"]
    if not isinstance(refs, list) or any(not isinstance(item, str) for item in refs) or refs != sorted(refs) or len(refs) != len(set(refs)):
        raise ArtifactValidationError("Gate B V2 package evidence references are not deterministic")
    file_hashes = data["evidence_file_sha256"]
    if not isinstance(file_hashes, dict) or not file_hashes or any(not isinstance(k, str) or not isinstance(v, str) or not SHA256_RE.fullmatch(v) for k, v in file_hashes.items()):
        raise ArtifactValidationError("Gate B V2 package file-level evidence hashes are incomplete")
    runner_evidence = data["runner_acceptance_evidence"]
    if not isinstance(runner_evidence, dict) or runner_evidence.get("result") != "ACCEPTANCE_READY":
        raise ArtifactValidationError("Gate B V2 package Runner acceptance evidence is incomplete")
    if _runner_acceptance_identity_v2_local(runner_evidence) != data["runner_acceptance_evidence_sha256"]:
        raise ArtifactValidationError("Gate B V2 package Runner acceptance evidence hash is inconsistent")
    if _sha({key: data[key] for key in sorted(GATE_B_V2_KEYS - {"gate_b_package_hash"})}) != data["gate_b_package_hash"]:
        raise ArtifactValidationError("Gate B V2 package hash does not match its canonical contents")
    return data


def load_gate_b_package_v2(path: Path | str, contract: Mapping[str, Any] | Path | str) -> dict[str, Any]:
    package_path = Path(path)
    package_root = Path(os.path.abspath(os.fspath(package_path.parent)))
    with EvidenceRoot(package_root, label="Gate B V2 package root") as root:
        value = _json_value_from_snapshot(root.snapshot(package_path.name, label="Gate B V2 evidence package"), "Gate B V2 evidence package")
    contract_data = _contract_value_v2(contract)
    return _validate_gate_b_package_v2(value, contract_data)


def validate_gate_b_v2(contract: Mapping[str, Any] | Path | str, authorization: Mapping[str, Any], package: Mapping[str, Any] | Path | str | None = None) -> None:
    contract_data = _contract_value_v2(contract)
    if package is None:
        raise GovernanceBlockerError("Human Gate-B V2 validation requires the exact evidence package")
    package_data = load_gate_b_package_v2(package, contract_data) if isinstance(package, (Path, str)) else _validate_gate_b_package_v2(package, contract_data)
    _validate_gate_b_authorization_shape(contract_data, authorization, package_data)
    runner = dict(package_data["runner_acceptance_evidence"])
    with EvidenceRoot(package_data["evidence_root"], label="Gate B V2 Runner evidence root") as evidence_root:
        evidence = _validate_runner_acceptance_evidence_v2(contract_data, runner, evidence_root=evidence_root)
    if evidence["runner_acceptance_evidence_sha256"] != package_data["runner_acceptance_evidence_sha256"]:
        raise GovernanceBlockerError("Gate B V2 Runner acceptance evidence changed after package preparation")
    if evidence["evidence_file_sha256"] != runner["evidence_file_sha256"]:
        # Compare core subset: file hashes must still contain the packaged core.
        for key, value in package_data["evidence_file_sha256"].items():
            if evidence["evidence_file_sha256"].get(key) != value:
                raise GovernanceBlockerError("Gate B V2 file-level evidence changed after package preparation")
    repo = Path(contract_data["repository_path"])
    if _git(repo, ["branch", "--show-current"]) != contract_data["canonical_branch"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: canonical branch drift")
    if _git(repo, ["rev-parse", "HEAD"]).lower() != package_data["expected_canonical_head"] or _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != package_data["expected_canonical_tree"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: canonical baseline drift")
    if _dirty_paths(repo) != contract_data["protected_dirty_paths"]:
        raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: protected canonical worktree changed")


ingest_runner_result_v3 = ingest_runner_result_v2
prepare_gate_b_v3 = prepare_gate_b_v2
validate_gate_b_v3 = validate_gate_b_v2


def _gate_b_evidence_directory_v2(package: Mapping[str, Any]) -> Path:
    root_path = _lexical_absolute_path(package["evidence_root"], "Gate B V2 evidence_root")
    with EvidenceRoot(root_path, label="Gate B V2 evidence root") as root:
        evidence_dir = root.absolute_path("gate-b")
        try:
            existing = os.lstat(evidence_dir)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise RunnerEnvironmentError("Gate B V2 evidence directory cannot be inspected") from exc
        if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode)):
            raise GovernanceBlockerError("Gate B V2 evidence directory is not a regular directory")
        try:
            evidence_dir.mkdir(exist_ok=True)
        except OSError as exc:
            raise RunnerEnvironmentError("Gate B V2 evidence directory cannot be created") from exc
    return evidence_dir


def integrate_after_gate_b_v2(
    contract: Mapping[str, Any] | Path | str,
    gate_b_authorization: Mapping[str, Any],
    *,
    package: Mapping[str, Any] | Path | str | None = None,
    perform: bool = False,
) -> dict[str, Any]:
    contract_data = _contract_value_v2(contract)
    if package is None:
        raise GovernanceBlockerError("Canonical integration V2 requires the exact Gate B evidence package")
    package_data = load_gate_b_package_v2(package, contract_data) if isinstance(package, (Path, str)) else _validate_gate_b_package_v2(package, contract_data)
    auth = _validate_gate_b_authorization_shape(contract_data, gate_b_authorization, package_data)
    if not perform:
        raise GovernanceBlockerError("Canonical integration V2 requires an explicit perform=True invocation after Gate B")
    # Reuse V1 claim/lock helpers against the V2 gate-b directory.
    evidence_dir = _gate_b_evidence_directory_v2(package_data)
    authorization_id = auth["authorization_id"]
    claim_path = evidence_dir / f"attempt-{authorization_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    claim = {
        "authorization_id": authorization_id, "gate_b_package_hash": package_data["gate_b_package_hash"],
        "candidate_head": package_data["candidate_head"], "candidate_tree": package_data["candidate_tree"],
        "expected_canonical_head": package_data["expected_canonical_head"],
        "expected_canonical_tree": package_data["expected_canonical_tree"], "attempt": "STARTED",
    }
    try:
        descriptor = os.open(os.fspath(claim_path), flags, 0o600)
    except FileExistsError as exc:
        raise GovernanceBlockerError("GATE_B_AUTHORIZATION_REUSED: authorization_id was already consumed") from exc
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B V2 authorization claim cannot be created") from exc
    try:
        payload = (json.dumps(claim, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(descriptor, payload)
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B V2 authorization claim cannot be recorded") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    outcome: dict[str, Any] = {"authorization_id": authorization_id, "gate_b_package_hash": package_data["gate_b_package_hash"], "attempt": "FAILED"}
    lock_path = evidence_dir / "integration.lock"
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_descriptor = os.open(os.fspath(lock_path), lock_flags, 0o600)
    except OSError as exc:
        raise RunnerEnvironmentError("Gate B V2 integration lock cannot be acquired") from exc
    try:
        if fcntl is None:
            raise RunnerEnvironmentError("Gate B V2 integration requires a supported repository lock")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        try:
            validate_gate_b_v2(contract_data, auth, package_data)
            repo = Path(contract_data["repository_path"])
            candidate_head = package_data["candidate_head"]
            actual_changed = sorted(_git(repo, ["diff", "--name-only", f"{package_data['expected_canonical_head']}..{candidate_head}"]).splitlines())
            if actual_changed != package_data["expected_changed_paths"]:
                raise GovernanceBlockerError("STALE_GATE_B_AUTHORITY: candidate changed-path scope drift")
            _fast_forward_exact_baseline(repo, package_data["expected_canonical_head"], candidate_head, contract_data["canonical_branch"])
            post_branch = _git(repo, ["branch", "--show-current"])
            post_head = _git(repo, ["rev-parse", "HEAD"]).lower()
            post_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
            if post_branch != contract_data["canonical_branch"] or post_head != candidate_head or post_tree != package_data["candidate_tree"]:
                raise GovernanceBlockerError("Post-integration verification disagrees with the authorized candidate")
            outcome.update({"attempt": "PASS", "canonical_head": post_head, "canonical_tree": post_tree})
            return {"result": "CANONICAL_INTEGRATED", "controller_phase": ControllerPhase.POST_INTEGRATION_VERIFY.value,
                    "run_id": contract_data["run_id"], "candidate_head": candidate_head,
                    "candidate_tree": package_data["candidate_tree"],
                    "authorization_id": authorization_id, "gate_b_package_hash": package_data["gate_b_package_hash"],
                    "claim": str(claim_path)}
        except Exception as exc:
            outcome.update({"error": str(exc), "error_class": getattr(getattr(exc, "error_class", None), "value", "ENVIRONMENT_ERROR")})
            raise
        finally:
            try:
                result_path = evidence_dir / f"attempt-{authorization_id}.result.json"
                result_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    result_descriptor = os.open(os.fspath(result_path), result_flags, 0o600)
                except OSError:
                    result_descriptor = None
                if result_descriptor is not None:
                    try:
                        os.write(result_descriptor, (json.dumps(dict(outcome), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                    except OSError:
                        pass
                    finally:
                        try:
                            os.close(result_descriptor)
                        except OSError:
                            pass
            except OSError:
                pass
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(lock_descriptor)
        except OSError:
            pass
