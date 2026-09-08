"""Deterministic HARN-001 lifecycle orchestration.

This module deliberately keeps provider argv construction separate from the
Git/state-machine logic.  It contains no retry, repair, merge, or push path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from prj226_runner.calibration import (
    build_opencode_config_dict,
    build_subprocess_env,
    parse_opencode_output,
    run_calibration_subprocess,
    validate_run_id,
)
from prj226_runner.codex_reviewer import (
    TARGETED_REVIEW_VERSION,
    build_codex_reviewer_invocation,
    fingerprint_worktree,
    check_codex_reviewer_binding,
    parse_targeted_reviewer_result,
    read_artifact_snapshot,
    run_codex_review,
    run_targeted_review,
    validate_targeted_review,
)
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    GovernanceBlockerError,
    ImplementationFailureError,
    ReviewStaleError,
    RunnerEnvironmentError,
    RunnerError,
)
from prj226_runner.models import ReviewMode, ReviewStatus, RunState
from prj226_runner.paths import get_runner_root, get_runtime_root
from prj226_runner.review_policy import normalize_review_policy


SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ROLES = ("builder", "dv", "sos_reviewer")


@dataclass(frozen=True)
class TaskPacket:
    run_id: str
    task_id: str
    product_repo: str
    canonical_branch: str
    baseline_head: str
    baseline_tree: str
    authorized_paths: list[str]
    builder_prompt: str
    acceptance_criteria: list[str]
    test_commands: list[list[str]]
    commit_message: str


@dataclass(frozen=True)
class RoleConfig:
    tool: str
    executable: str
    model: str
    timeout_seconds: int


@dataclass(frozen=True)
class RunnerConfig:
    runtime_root: Path
    agents: dict[str, RoleConfig]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot read task packet: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"Task packet is not valid JSON: {exc.msg}") from exc


def _safe_repo_path(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactValidationError("product_repo must be a non-empty string")


def _safe_relative_path(value: object, field: str = "authorized_paths") -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ArtifactValidationError(f"{field} contains an invalid path")
    path = Path(value)
    if path.is_absolute() or "\\" in value or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise ArtifactValidationError(f"{field} contains an unsafe path: {value!r}")
    return value


def parse_task_packet(path: Path | str) -> TaskPacket:
    """Parse and strictly validate the small Task Packet contract without a dependency."""
    data = _read_json(Path(path))
    required = {
        "run_id", "task_id", "product_repo", "canonical_branch", "baseline_head",
        "baseline_tree", "authorized_paths", "builder_prompt", "acceptance_criteria",
        "test_commands", "commit_message",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ArtifactValidationError("Task packet must contain exactly the HARN-001 contract fields")
    try:
        validate_run_id(data["run_id"])
    except ValueError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    for key in ("task_id", "canonical_branch", "builder_prompt", "commit_message"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise ArtifactValidationError(f"{key} must be a non-empty string")
    _safe_repo_path(data["product_repo"])
    for key in ("baseline_head", "baseline_tree"):
        if not isinstance(data[key], str) or not SHA_RE.fullmatch(data[key]):
            raise ArtifactValidationError(f"{key} must be a 40-character Git object ID")
    paths = data["authorized_paths"]
    if not isinstance(paths, list) or not paths:
        raise ArtifactValidationError("authorized_paths must be a non-empty array")
    safe_paths = [_safe_relative_path(item) for item in paths]
    if len(set(safe_paths)) != len(safe_paths):
        raise ArtifactValidationError("authorized_paths must not contain duplicates")
    criteria = data["acceptance_criteria"]
    if not isinstance(criteria, list) or not criteria or not all(isinstance(x, str) and x.strip() for x in criteria):
        raise ArtifactValidationError("acceptance_criteria must be a non-empty array of strings")
    commands = data["test_commands"]
    if not isinstance(commands, list) or not all(
        isinstance(command, list) and command and all(isinstance(arg, str) and arg for arg in command)
        for command in commands
    ):
        raise ArtifactValidationError("test_commands must be an array of non-empty argv arrays")
    return TaskPacket(
        run_id=data["run_id"], task_id=data["task_id"], product_repo=data["product_repo"],
        canonical_branch=data["canonical_branch"], baseline_head=data["baseline_head"].lower(),
        baseline_tree=data["baseline_tree"].lower(), authorized_paths=safe_paths,
        builder_prompt=data["builder_prompt"], acceptance_criteria=list(criteria),
        test_commands=[list(command) for command in commands], commit_message=data["commit_message"],
    )


def load_config(path: Path | str | None = None) -> RunnerConfig:
    """Load role bindings.  Packet data never selects a provider or model."""
    config_path = Path(path) if path else Path(os.environ.get("PRJ226_RUNNER_CONFIG", get_runner_root() / "config" / "runner.example.toml"))
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RunnerEnvironmentError(f"Cannot load runner config: {config_path}") from exc
    runner = raw.get("runner")
    agents_raw = raw.get("agents")
    if not isinstance(runner, dict) or not isinstance(runner.get("runtime_root"), str) or not isinstance(agents_raw, dict):
        raise ArtifactValidationError("Runner config must define runner.runtime_root and agents")
    agents: dict[str, RoleConfig] = {}
    for role in _ROLES:
        entry = agents_raw.get(role)
        if not isinstance(entry, dict):
            raise ArtifactValidationError(f"Runner config is missing agents.{role}")
        try:
            tool, executable, model = entry["tool"], entry["executable"], entry["model"]
            timeout = entry.get("timeout_seconds", 300)
        except KeyError as exc:
            raise ArtifactValidationError(f"Runner config agents.{role} is incomplete") from exc
        if not all(isinstance(value, str) and value.strip() for value in (tool, executable, model)):
            raise ArtifactValidationError(f"Runner config agents.{role} has invalid identity")
        if not isinstance(timeout, int) or timeout <= 0:
            raise ArtifactValidationError(f"Runner config agents.{role}.timeout_seconds must be positive")
        agents[role] = RoleConfig(tool, executable, model, timeout)
    return RunnerConfig(get_runtime_root(runner["runtime_root"]), agents)


def _git(repo: Path, args: list[str], *, check: bool = True) -> str:
    command = ["git", "-C", str(repo), *args]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, check=False)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Unable to execute Git: {exc}") from exc
    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown Git failure"
        raise GovernanceBlockerError(f"Git verification failed: {message}")
    return result.stdout.strip()


def _canonical_baseline(packet: TaskPacket) -> Path:
    repo = Path(packet.product_repo).resolve()
    if not repo.is_dir() or not (repo / ".git").exists():
        raise RunnerEnvironmentError("product_repo is not an existing Git worktree")
    branch = _git(repo, ["branch", "--show-current"])
    if branch != packet.canonical_branch:
        raise GovernanceBlockerError(f"Canonical branch drift: expected {packet.canonical_branch}, observed {branch}")
    head = _git(repo, ["rev-parse", "HEAD"]).lower()
    if head != packet.baseline_head:
        raise GovernanceBlockerError(f"Baseline HEAD drift: expected {packet.baseline_head}, observed {head}")
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    if tree != packet.baseline_tree:
        raise GovernanceBlockerError(f"Baseline TREE drift: expected {packet.baseline_tree}, observed {tree}")
    if _git(repo, ["status", "--porcelain"]):
        raise GovernanceBlockerError("Canonical product worktree is dirty")
    return repo


def candidate_branch_name(packet: TaskPacket) -> str:
    safe_task = re.sub(r"[^A-Za-z0-9._-]+", "-", packet.task_id).strip(".-")
    safe_run = re.sub(r"[^A-Za-z0-9._-]+", "-", packet.run_id).strip(".-")
    return f"harn-candidate/{safe_task}-{safe_run}"


def _paths_for(config: RunnerConfig, packet: TaskPacket) -> dict[str, Path]:
    root = config.runtime_root / packet.run_id
    return {
        "root": root, "manifest": root / "manifest.json", "state": root / "state.json",
        "events": root / "events.ndjson", "builder": root / "builder", "deterministic": root / "deterministic",
        "dv": root / "dv", "sos": root / "sos", "worktree": root / "builder" / "worktree",
        "review_worktree": root / "sos" / "verifier-worktree",
    }


def _inspect(packet: TaskPacket, config: RunnerConfig) -> dict[str, Any]:
    repo = _canonical_baseline(packet)
    reviewer = config.agents["sos_reviewer"]
    if reviewer.tool == "codex":
        # This is local binding/schema/executable inspection only.  It must
        # never be replaced by a provider startup or availability call.
        check_codex_reviewer_binding(reviewer.executable, model=reviewer.model)
    paths = _paths_for(config, packet)
    if paths["root"].exists():
        raise GovernanceBlockerError(f"Run ID collision: immutable runtime evidence already exists at {paths['root']}")
    return {
        "result": "READY_FOR_HUMAN_AUTHORIZATION", "run_id": packet.run_id, "task_id": packet.task_id,
        "product_repo": str(repo), "baseline_head": packet.baseline_head, "baseline_tree": packet.baseline_tree,
        "candidate_branch": candidate_branch_name(packet), "candidate_worktree": str(paths["worktree"]),
        "roles": {role: {"tool": item.tool, "model": item.model} for role, item in config.agents.items()},
    }


def inspect_packet(packet_path: Path | str, config_path: Path | str | None = None) -> dict[str, Any]:
    """Read-only preflight.  It creates no run directory or Git worktree."""
    return _inspect(parse_task_packet(packet_path), load_config(config_path))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class _RunEvidence:
    def __init__(self, paths: dict[str, Path], packet: TaskPacket, config: RunnerConfig) -> None:
        self.paths, self.packet, self.config = paths, packet, config
        self.state = RunState.CREATED

    def start(self) -> None:
        self.paths["root"].mkdir(parents=True)
        manifest = {
            "run_id": self.packet.run_id, "task_id": self.packet.task_id, "created_at": _utc_now(),
            "product": {"repo": self.packet.product_repo, "canonical_branch": self.packet.canonical_branch,
                        "baseline_head": self.packet.baseline_head, "baseline_tree": self.packet.baseline_tree},
            "authorized_paths": self.packet.authorized_paths, "acceptance_criteria": self.packet.acceptance_criteria,
            "test_commands": self.packet.test_commands,
            "roles": {role: {"tool": item.tool, "executable": item.executable, "model": item.model,
                              "timeout_seconds": item.timeout_seconds} for role, item in self.config.agents.items()},
        }
        _write_json(self.paths["manifest"], manifest)
        self.transition(RunState.CREATED, "run_created")

    def transition(self, state: RunState, event: str, payload: dict[str, Any] | None = None) -> None:
        prior = self.state
        self.state = state
        record = {"timestamp": _utc_now(), "event": event, "from_state": prior.value if prior != state else None,
                  "to_state": state.value, "payload": payload or {}}
        with self.paths["events"].open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        _write_json(self.paths["state"], {"run_id": self.packet.run_id, "state": state.value,
                                            "updated_at": record["timestamp"], "last_event": event,
                                            "stop_reason": None})

    def stop(self, reason: str, error_class: str) -> None:
        prior = self.state
        self.state = RunState.STOPPED
        record = {"timestamp": _utc_now(), "event": "run_stopped", "from_state": prior.value,
                  "to_state": "STOPPED", "payload": {"reason": reason, "error_class": error_class}}
        with self.paths["events"].open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        _write_json(self.paths["state"], {"run_id": self.packet.run_id, "state": "STOPPED",
                                            "updated_at": record["timestamp"], "last_event": "run_stopped",
                                            "stop_reason": reason})


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_builder_invocation(role: RoleConfig, workspace: Path, packet: TaskPacket) -> list[str]:
    """Build, but do not execute, the configured Builder provider command."""
    prompt = (
        f"{packet.builder_prompt}\n\nAuthorized paths (exact lock): {json.dumps(packet.authorized_paths)}\n"
        f"Acceptance criteria: {json.dumps(packet.acceptance_criteria)}\n\n"
        "Work only in the current isolated worktree. Do not modify any other path. "
        "Do not commit. Do not push. Return a concise result."
    )
    if role.tool == "codex":
        return [role.executable, "--ask-for-approval", "never", "exec", "-C", str(workspace),
                "--sandbox", "workspace-write", "--model", role.model, prompt]
    return [role.executable, "--model", role.model, prompt]


def build_reviewer_invocation(role: RoleConfig, prompt: str) -> list[str]:
    """Build a provider invocation kept separate from lifecycle semantics."""
    if role.tool == "codex":
        return build_codex_reviewer_invocation(
            role.executable,
            Path.cwd(),
            prompt,
            output_path=Path.cwd() / "reviewer-result.json",
            model=role.model,
        )
    if role.tool == "opencode2":
        return [role.executable, "run", "--standalone", "--format", "json", "--agent", "harn-readonly",
                "--model", role.model, prompt]
    return [role.executable, "--model", role.model, prompt]


def _run_process(argv: list[str], cwd: Path, directory: Path, timeout: int, env: dict[str, str] | None = None) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    stdout, stderr = directory / "stdout.log", directory / "stderr.log"
    try:
        exit_code, timed_out, duration_ms = run_calibration_subprocess(argv, cwd, stdout, stderr, timeout, env)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Provider command could not start: {exc}") from exc
    result = {"argv": argv, "exit_code": exit_code, "timed_out": timed_out, "duration_ms": duration_ms,
              "stdout": str(stdout), "stderr": str(stderr)}
    _write_json(directory / "invocation.json", result)
    if timed_out:
        raise AgentExecutionError(f"Provider command timed out after {timeout} seconds")
    if exit_code != 0:
        raise AgentExecutionError(f"Provider command exited with {exit_code}")
    return result


def _changed_paths(repo: Path, baseline: str) -> list[str]:
    tracked = _git(repo, ["diff", "--name-only", baseline]).splitlines()
    untracked = _git(repo, ["ls-files", "--others", "--exclude-standard"]).splitlines()
    return sorted(set(path for path in [*tracked, *untracked] if path))


def _verify_candidate_identity(
    repo: Path,
    baseline: str,
    candidate: str,
    tree: str,
    expected_paths: Iterable[str],
    candidate_ref: str | None = None,
    expected_fingerprint: str | None = None,
) -> None:
    if _git(repo, ["rev-parse", "HEAD"]).lower() != candidate:
        raise GovernanceBlockerError("Candidate HEAD changed after freeze")
    if _git(repo, ["rev-parse", "HEAD^{tree}"]).lower() != tree:
        raise GovernanceBlockerError("Candidate TREE changed after freeze")
    if candidate_ref is not None and _git(repo, ["rev-parse", candidate_ref]).lower() != candidate:
        raise GovernanceBlockerError("Candidate reference changed after freeze")
    if _git(repo, ["status", "--porcelain"]):
        raise GovernanceBlockerError("Candidate worktree is not clean")
    if expected_fingerprint is not None and fingerprint_worktree(repo) != expected_fingerprint:
        raise GovernanceBlockerError("Candidate worktree filesystem fingerprint changed")
    parents = _git(repo, ["rev-list", "--parents", "-n", "1", "HEAD"]).split()
    if len(parents) != 2 or parents[1].lower() != baseline:
        raise GovernanceBlockerError("Candidate topology no longer has the baseline as its sole parent")
    changed = _git(repo, ["diff", "--name-only", f"{baseline}..{candidate}"]).splitlines()
    if sorted(changed) != sorted(expected_paths):
        raise GovernanceBlockerError("Effective changed paths differ from frozen candidate")


def _freeze_candidate(repo: Path, packet: TaskPacket, expected_paths: list[str]) -> tuple[str, str]:
    if not expected_paths:
        raise ImplementationFailureError("Builder produced no changes")
    check = subprocess.run(["git", "-C", str(repo), "diff", "--check"], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, shell=False, check=False)
    if check.returncode != 0:
        raise ImplementationFailureError(f"git diff --check failed: {check.stdout or check.stderr}")
    for path in expected_paths:
        _git(repo, ["add", "--", path])
    staged = _git(repo, ["diff", "--cached", "--name-only", packet.baseline_head]).splitlines()
    if sorted(staged) != sorted(expected_paths):
        raise GovernanceBlockerError("Explicit staging did not exactly match changed paths")
    _git(repo, ["commit", "-m", packet.commit_message])
    candidate = _git(repo, ["rev-parse", "HEAD"]).lower()
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    _verify_candidate_identity(repo, packet.baseline_head, candidate, tree, expected_paths)
    return candidate, tree


def _review_context(packet: TaskPacket, candidate: str, tree: str, changes: list[str], tests: list[dict[str, Any]]) -> str:
    compact_tests = [{"argv": item["argv"], "exit_code": item["exit_code"]} for item in tests]
    return json.dumps({"task_id": packet.task_id, "run_id": packet.run_id, "baseline_head": packet.baseline_head,
                       "baseline_tree": packet.baseline_tree, "candidate_head": candidate, "candidate_tree": tree,
                       "authorized_paths": packet.authorized_paths, "actual_changed_paths": changes,
                       "acceptance_criteria": packet.acceptance_criteria, "deterministic_tests": compact_tests})


def _fresh_reviewer_env(directory: Path) -> dict[str, str]:
    config_dir, data_dir, state_dir = directory / "xdg-config", directory / "xdg-data", directory / "xdg-state"
    for item in (config_dir, data_dir, state_dir):
        item.mkdir(parents=True, exist_ok=True)
    policy = build_opencode_config_dict()
    policy["default_agent"] = "harn-readonly"
    policy["agents"]["harn-readonly"] = policy["agents"].pop("calibration-readonly")
    policy_json = json.dumps(policy, sort_keys=True)
    _write_text(config_dir / "opencode" / "opencode.json", policy_json)
    return build_subprocess_env({
        "OPENCODE_CONFIG_CONTENT": policy_json,
        "XDG_CONFIG_HOME": str(config_dir),
        "XDG_DATA_HOME": str(data_dir),
        "XDG_STATE_HOME": str(state_dir),
    })


def _parse_reviewer_result(path: Path, kind: str) -> tuple[str, list[Any]]:
    try:
        raw = read_artifact_snapshot(path).raw_bytes.decode("utf-8")
    except (ArtifactValidationError, UnicodeDecodeError) as exc:
        raise ArtifactValidationError(f"{kind} reviewer output is not a safe UTF-8 artifact") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        try:
            value = parse_opencode_output(raw)
        except ValueError as exc:
            raise ArtifactValidationError(f"{kind} reviewer did not produce a normalized JSON result") from exc
    if not isinstance(value, dict):
        raise ArtifactValidationError(f"{kind} reviewer result must be a JSON object")
    verdict = value.get("result", value.get("recommendation"))
    findings = value.get("findings", [])
    allowed = {"PASS", "FAIL"} if kind == "dv" else {"ACCEPT", "REJECT"}
    if verdict not in allowed or not isinstance(findings, list):
        raise ArtifactValidationError(f"{kind} reviewer result is invalid")
    return verdict, findings


def _run_tests(
    repo: Path,
    packet: TaskPacket,
    evidence: _RunEvidence,
    candidate: str,
    tree: str,
    changes: list[str],
    expected_fingerprint: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, argv in enumerate(packet.test_commands, start=1):
        result = _run_process(argv, repo, evidence.paths["deterministic"] / f"test-{index}", 300)
        results.append(result)
        if result["exit_code"] != 0:
            raise ImplementationFailureError(f"Deterministic test {index} failed")
        _verify_candidate_identity(repo, packet.baseline_head, candidate, tree, changes, expected_fingerprint=expected_fingerprint)
    check = subprocess.run(["git", "-C", str(repo), "diff", "--check", f"{packet.baseline_head}..{candidate}"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, check=False)
    if check.returncode != 0:
        raise ImplementationFailureError("Frozen candidate fails git diff --check")
    _verify_candidate_identity(repo, packet.baseline_head, candidate, tree, changes, expected_fingerprint=expected_fingerprint)
    return results


def _create_builder_worktree(repo: Path, packet: TaskPacket, worktree: Path) -> str:
    branch = candidate_branch_name(packet)
    if worktree.exists():
        raise GovernanceBlockerError("Planned Builder worktree already exists")
    result = subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", branch, str(worktree), packet.baseline_head],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, check=False)
    if result.returncode != 0:
        raise GovernanceBlockerError(f"Cannot create isolated Builder worktree: {result.stderr.strip() or result.stdout.strip()}")
    return branch


def _create_candidate_verifier_worktree(repo: Path, candidate: str, worktree: Path) -> Path:
    """Create a detached, clean verifier worktree pinned to the frozen candidate."""
    if worktree.exists():
        raise GovernanceBlockerError("Planned candidate verifier worktree already exists")
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(worktree), candidate],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot create candidate verifier worktree: {exc}") from exc
    if result.returncode != 0:
        raise GovernanceBlockerError(
            f"Cannot create candidate verifier worktree: {result.stderr.strip() or result.stdout.strip()}"
        )
    return worktree


def _codex_review_prompt(packet: TaskPacket, candidate: str, tree: str, changes: list[str], tests: list[dict[str, Any]]) -> str:
    """Build the exact Repair-2 review brief, including the semantic frontier distinction."""
    context = _review_context(packet, candidate, tree, changes, tests)
    return (
        "You are the independent Security / Operability / Semantics / Architecture reviewer for HARN-002 Repair-2. "
        "Review the current immutable candidate in the current working directory read-only. Do not edit, create, "
        "delete, commit, reset, checkout, merge, push, or repair anything. Return only JSON conforming to the "
        "provided closed schema. Set reviewed_head and reviewed_tree to the exact Git HEAD and HEAD^{tree} you inspected. "
        "Review SECURITY: Gate A exact authority, human dirty baseline protection, write envelope enforcement, and "
        "mutation bypass. Review OPERABILITY: repository truth precedence, baseline drift, exact candidate/result "
        "binding, resume semantics, and actionable failure taxonomy. Review SEMANTICS critically: frontier discovery "
        "is not execution readiness; CURRENT plus ENGINEERING_PLAN can identify a canonical frontier; a missing Task "
        "Packet does not make discovery undiscoverable but does prevent execution; the controller may classify and "
        "draft a Design Contract and must stop at WAITING_HUMAN_GATE_A; exact Gate A remains mandatory; a derived "
        "Task Packet cannot widen the approved contract; contradictory Task Packet evidence fails closed; and Gate B "
        "cannot be bypassed. Review ARCHITECTURE: HARN-001 reuse, no retry/repair/provider router/fallback/multi-project "
        "subsystem, Git authority, orchestration-only controller state, and no automatic merge/push. Confirm PRJ226 "
        "dry-run remains read-only and ENG-012 is not implemented. Use PASS only when all four axes pass and there "
        "are no blocking findings; otherwise use NEEDS_FIX. Findings must be non-empty strings.\n\n"
        + context
    )


def run_packet(packet_path: Path | str, config_path: Path | str | None = None, *, authorize: bool = False) -> dict[str, Any]:
    """Execute one authorized run. Failures remain as immutable runtime evidence."""
    if not authorize:
        raise GovernanceBlockerError("run requires explicit --authorize; no provider or worktree was created")
    packet, config = parse_task_packet(packet_path), load_config(config_path)
    preflight = _inspect(packet, config)
    repo, paths = Path(preflight["product_repo"]), _paths_for(config, packet)
    evidence = _RunEvidence(paths, packet, config)
    evidence.start()
    summary: dict[str, Any] = {"result": "STOPPED", "run_id": packet.run_id, "task_id": packet.task_id,
                               "runtime_root": str(paths["root"]), "candidate_branch": preflight["candidate_branch"]}
    try:
        evidence.transition(RunState.PREFLIGHT, "preflight_passed", {"baseline": packet.baseline_head})
        evidence.transition(RunState.HUMAN_AUTHORIZED, "human_authorized")
        branch = _create_builder_worktree(repo, packet, paths["worktree"])
        evidence.transition(RunState.BUILDER_RUNNING, "builder_started", {"worktree": str(paths["worktree"]), "branch": branch})
        _run_process(build_builder_invocation(config.agents["builder"], paths["worktree"], packet), paths["worktree"],
                     paths["builder"], config.agents["builder"].timeout_seconds)
        if _git(paths["worktree"], ["rev-parse", "HEAD"]).lower() != packet.baseline_head:
            raise GovernanceBlockerError("Builder created an unexpected commit")
        changes = _changed_paths(paths["worktree"], packet.baseline_head)
        unauthorized = sorted(set(changes) - set(packet.authorized_paths))
        if unauthorized:
            raise GovernanceBlockerError(f"Builder changed unauthorized paths: {unauthorized}")
        candidate, tree = _freeze_candidate(paths["worktree"], packet, changes)
        candidate_fingerprint = fingerprint_worktree(paths["worktree"])
        summary.update({
            "candidate_head": candidate,
            "candidate_tree": tree,
            "candidate_ref": branch,
            "candidate_worktree_fingerprint": candidate_fingerprint,
            "changed_paths": changes,
        })
        evidence.transition(RunState.CANDIDATE_FROZEN, "candidate_frozen", {"head": candidate, "tree": tree, "changed_paths": changes})
        evidence.transition(RunState.DETERMINISTIC_GATES, "deterministic_gates_started")
        tests = _run_tests(paths["worktree"], packet, evidence, candidate, tree, changes, candidate_fingerprint)
        context = _review_context(packet, candidate, tree, changes, tests)
        evidence.transition(RunState.DV_RUNNING, "dv_started")
        dv_prompt = "Review this candidate read-only. Return only JSON: {\"result\":\"PASS|FAIL\",\"findings\":[]}.\n" + context
        _run_process(build_reviewer_invocation(config.agents["dv"], dv_prompt), paths["worktree"], paths["dv"],
                     config.agents["dv"].timeout_seconds, _fresh_reviewer_env(paths["dv"]))
        _verify_candidate_identity(
            paths["worktree"], packet.baseline_head, candidate, tree, changes,
            expected_fingerprint=candidate_fingerprint,
        )
        dv_result, dv_findings = _parse_reviewer_result(paths["dv"] / "stdout.log", "dv")
        _write_json(paths["dv"] / "result.json", {"result": dv_result, "findings": dv_findings})
        if dv_result != "PASS":
            raise ImplementationFailureError("DV reviewer returned FAIL")
        evidence.transition(RunState.SOS_RUNNING, "sos_started")
        sos_role = config.agents["sos_reviewer"]
        if sos_role.tool == "codex":
            review_workspace = _create_candidate_verifier_worktree(repo, candidate, paths["review_worktree"])
            codex_review = run_codex_review(
                sos_role.executable,
                review_workspace,
                paths["sos"],
                candidate_head=candidate,
                candidate_tree=tree,
                candidate_ref=branch,
                prompt=_codex_review_prompt(packet, candidate, tree, changes, tests),
                timeout_seconds=sos_role.timeout_seconds,
            )
            review_value = codex_review["result"]
            _write_json(paths["sos"] / "result.json", review_value)
            _verify_candidate_identity(
                paths["worktree"], packet.baseline_head, candidate, tree, changes, branch,
                expected_fingerprint=candidate_fingerprint,
            )
            _verify_candidate_identity(review_workspace, packet.baseline_head, candidate, tree, changes, branch)
            sos_result = "ACCEPT" if review_value["disposition"] == "PASS" else "REJECT"
            sos_findings = review_value["blocking_findings"] + review_value["non_blocking_findings"]
            summary.update({
                "review_disposition": review_value["disposition"],
                "review_artifact": codex_review["artifact"],
                "review_artifact_sha256": codex_review["artifact_sha256"],
                "review_raw_artifact": codex_review["raw_artifact"],
                "review_worktree_fingerprint": codex_review["fingerprint"],
                "review_fingerprint_pre_artifact": codex_review["fingerprint_pre_artifact"],
                "review_fingerprint_post_artifact": codex_review["fingerprint_post_artifact"],
            })
        else:
            context = _review_context(packet, candidate, tree, changes, tests)
            sos_prompt = "Review SECURITY, OPERABILITY, and SEMANTICS read-only. Return only JSON: {\"recommendation\":\"ACCEPT|REJECT\",\"findings\":[]}.\n" + context
            _run_process(build_reviewer_invocation(sos_role, sos_prompt), paths["worktree"], paths["sos"],
                         sos_role.timeout_seconds, _fresh_reviewer_env(paths["sos"]))
            _verify_candidate_identity(
                paths["worktree"], packet.baseline_head, candidate, tree, changes,
                expected_fingerprint=candidate_fingerprint,
            )
            sos_result, sos_findings = _parse_reviewer_result(paths["sos"] / "stdout.log", "sos")
            _write_json(paths["sos"] / "result.json", {"recommendation": sos_result, "findings": sos_findings})
        if sos_result != "ACCEPT":
            raise ImplementationFailureError("S/O/S reviewer returned REJECT")
        _canonical_baseline(packet)
        evidence.transition(RunState.ACCEPTANCE_READY, "acceptance_ready")
        evidence_paths = {key: str(value) for key, value in paths.items() if key != "root"}
        summary.update({
            "result": "ACCEPTANCE_READY",
            "deterministic_result": "ACCEPTANCE_READY",
            "verification_disposition": "PASS",
            "candidate_head": candidate,
            "candidate_tree": tree,
            "candidate_ref": branch,
            "candidate_worktree_fingerprint": candidate_fingerprint,
            "changed_paths": changes,
            "tests": tests,
            "dv_result": dv_result,
            "sos_result": sos_result,
            "reviewer_disposition": {
                "dv_result": dv_result,
                "sos_result": sos_result,
                **({"review_disposition": summary["review_disposition"]} if "review_disposition" in summary else {}),
            },
            "evidence_paths": evidence_paths,
        })
        required_references = set(evidence_paths.values())
        for key in ("review_artifact", "review_raw_artifact", "review_fingerprint_pre_artifact", "review_fingerprint_post_artifact"):
            if key in summary:
                required_references.add(str(summary[key]))
        summary["required_evidence_references"] = sorted(required_references)
        if "review_artifact" in summary:
            if not isinstance(summary.get("review_artifact_sha256"), str):
                raise ArtifactValidationError("Codex review evidence is missing its same-snapshot SHA-256")
        _write_json(paths["root"] / "report.json", summary)
        return summary
    except RunnerError as exc:
        evidence.stop(exc.message, exc.error_class.value)
        summary.update({"error_class": exc.error_class.value, "error": exc.message})
        _write_json(paths["root"] / "report.json", summary)
        return summary
    except Exception as exc:  # preserve unexpected failure as durable evidence, never retry it
        wrapped = RunnerEnvironmentError(f"Unexpected runner failure: {type(exc).__name__}: {exc}")
        evidence.stop(wrapped.message, wrapped.error_class.value)
        summary.update({"error_class": wrapped.error_class.value, "error": wrapped.message})
        _write_json(paths["root"] / "report.json", summary)
        return summary


# ============================================================================
# M1 V2 — versioned NONE / TARGETED execution primitive.
# Legacy V1 paths above remain byte/semantic compatible and unchanged.
# ============================================================================

V2_PACKET_VERSION = "HARN-001.TASK_PACKET.v2"
V2_CONTRACT_VERSION = "HARN-002.v2"
V2_RUNNER_RESULT_VERSION = "HARN-001.RUNNER_RESULT.v2"
V2_MANIFEST_VERSION = "HARN-001.RUN_MANIFEST.v2"
V2_STATE_VERSION = "HARN-001.RUN_STATE.v2"
V2_GATE_A_KEYS = {
    "gate",
    "decision",
    "contract_id",
    "contract_hash",
    "baseline_head",
    "baseline_tree",
    "authorized_protected_dirty_paths",
}
SHA256_RE_V2 = re.compile(r"^[0-9a-f]{64}$")


def _sha_canonical_v2(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _sha256_file_v2(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class TaskPacketV2:
    packet_version: str
    contract_id: str
    contract_hash: str
    runtime_root: str
    review_policy: dict[str, Any]
    run_id: str
    task_id: str
    product_repo: str
    canonical_branch: str
    baseline_head: str
    baseline_tree: str
    authorized_paths: list[str]
    builder_prompt: str
    acceptance_criteria: list[str]
    test_commands: list[list[str]]
    commit_message: str


def _v2_lexical_absolute(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise ArtifactValidationError(f"{field} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute():
        raise ArtifactValidationError(f"{field} must be an absolute path")
    if any(part == ".." for part in path.parts):
        raise ArtifactValidationError(f"{field} contains traversal")
    return os.path.abspath(os.fspath(path))


def parse_task_packet_v2(path: Path | str) -> TaskPacketV2:
    data = _read_json(Path(path))
    required = {
        "packet_version", "contract_id", "contract_hash", "runtime_root", "review_policy",
        "run_id", "task_id", "product_repo", "canonical_branch", "baseline_head",
        "baseline_tree", "authorized_paths", "builder_prompt", "acceptance_criteria",
        "test_commands", "commit_message",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ArtifactValidationError("Task packet V2 must contain exactly the HARN-001.TASK_PACKET.v2 fields")
    if data["packet_version"] != V2_PACKET_VERSION:
        raise ArtifactValidationError("Task packet V2 version is unsupported")
    if not isinstance(data["contract_id"], str) or not data["contract_id"].startswith("design-"):
        raise ArtifactValidationError("Task packet V2 contract_id is invalid")
    if not isinstance(data["contract_hash"], str) or not SHA256_RE_V2.fullmatch(data["contract_hash"]):
        raise ArtifactValidationError("Task packet V2 contract_hash must be lowercase SHA-256")
    _v2_lexical_absolute(data["runtime_root"], "runtime_root")
    policy = normalize_review_policy(data["review_policy"])
    try:
        validate_run_id(data["run_id"])
    except ValueError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    for key in ("task_id", "canonical_branch", "builder_prompt", "commit_message"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise ArtifactValidationError(f"{key} must be a non-empty string")
    _safe_repo_path(data["product_repo"])
    for key in ("baseline_head", "baseline_tree"):
        if not isinstance(data[key], str) or not SHA_RE.fullmatch(data[key]):
            raise ArtifactValidationError(f"{key} must be a 40-character Git object ID")
    paths = data["authorized_paths"]
    if not isinstance(paths, list) or not paths:
        raise ArtifactValidationError("authorized_paths must be a non-empty array")
    safe_paths = [_safe_relative_path(item) for item in paths]
    if len(set(safe_paths)) != len(safe_paths):
        raise ArtifactValidationError("authorized_paths must not contain duplicates")
    criteria = data["acceptance_criteria"]
    if not isinstance(criteria, list) or not criteria or not all(isinstance(x, str) and x.strip() for x in criteria):
        raise ArtifactValidationError("acceptance_criteria must be a non-empty array of strings")
    commands = data["test_commands"]
    if not isinstance(commands, list) or not commands or not all(
        isinstance(command, list) and command and all(isinstance(arg, str) and arg for arg in command)
        for command in commands
    ):
        raise ArtifactValidationError("V2 test_commands must be a non-empty array of non-empty argv arrays")
    return TaskPacketV2(
        packet_version=V2_PACKET_VERSION,
        contract_id=data["contract_id"], contract_hash=data["contract_hash"].lower(),
        runtime_root=_v2_lexical_absolute(data["runtime_root"], "runtime_root"),
        review_policy=policy,
        run_id=data["run_id"], task_id=data["task_id"], product_repo=data["product_repo"],
        canonical_branch=data["canonical_branch"],
        baseline_head=data["baseline_head"].lower(), baseline_tree=data["baseline_tree"].lower(),
        authorized_paths=safe_paths, builder_prompt=data["builder_prompt"],
        acceptance_criteria=list(criteria),
        test_commands=[list(command) for command in commands],
        commit_message=data["commit_message"],
    )


def task_packet_hash_v2(packet: TaskPacketV2 | Mapping[str, Any]) -> str:
    if isinstance(packet, TaskPacketV2):
        value = {
            "packet_version": packet.packet_version, "contract_id": packet.contract_id,
            "contract_hash": packet.contract_hash, "runtime_root": packet.runtime_root,
            "review_policy": packet.review_policy, "run_id": packet.run_id, "task_id": packet.task_id,
            "product_repo": packet.product_repo, "canonical_branch": packet.canonical_branch,
            "baseline_head": packet.baseline_head, "baseline_tree": packet.baseline_tree,
            "authorized_paths": packet.authorized_paths, "builder_prompt": packet.builder_prompt,
            "acceptance_criteria": packet.acceptance_criteria, "test_commands": packet.test_commands,
            "commit_message": packet.commit_message,
        }
    else:
        value = dict(packet)
    return _sha_canonical_v2(value)


def _load_contract_v2(path: Path | str) -> dict[str, Any]:
    data = _read_json(Path(path))
    if not isinstance(data, dict):
        raise ArtifactValidationError("V2 Design Contract must be a JSON object")
    if data.get("contract_version") != V2_CONTRACT_VERSION:
        raise ArtifactValidationError("V2 Design Contract version is unsupported")
    # Minimal structural check; full normalization lives in controller but the
    # runner must independently reject malformed/mixed versions fail-closed.
    required_min = {
        "contract_id", "contract_hash", "contract_version", "project_id", "repository_path",
        "canonical_branch", "run_id", "work_item_id", "work_item_title", "work_shape",
        "intent", "success_criteria", "scope", "non_goals", "baseline_head", "baseline_tree",
        "owned_paths", "protected_dirty_paths", "assumptions", "risks", "dependencies",
        "acceptance_instruments", "discriminating_acceptance_controls", "failure_conditions",
        "exact_authority_boundary", "readiness", "runtime_root", "review_policy",
    }
    if set(data) != required_min:
        raise ArtifactValidationError("V2 Design Contract must contain exactly the HARN-002.v2 fields")
    policy = normalize_review_policy(data["review_policy"])
    # Recompute identity over all content except id/hash.
    content = {k: data[k] for k in sorted(required_min - {"contract_id", "contract_hash"})}
    # Normalize policy inside content for hashing stability.
    content["review_policy"] = policy
    expected_hash = _sha_canonical_v2(content)
    if data["contract_hash"] != expected_hash or data["contract_id"] != "design-" + expected_hash:
        raise ArtifactValidationError("V2 Design Contract identity/hash does not match its content")
    normalized = dict(data)
    normalized["review_policy"] = policy
    return normalized


def _v2_packet_prompt(contract: Mapping[str, Any]) -> str:
    return (
        f"{contract['intent']}\n\nApproved scope (exact): {json.dumps(contract['scope'], sort_keys=True)}\n"
        f"Success criteria (exact): {json.dumps(contract['success_criteria'], sort_keys=True)}\n"
        f"Non-goals: {json.dumps(contract['non_goals'], sort_keys=True)}"
    )


def _v2_expected_packet_mapping(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "packet_version": V2_PACKET_VERSION,
        "contract_id": contract["contract_id"],
        "contract_hash": contract["contract_hash"],
        "runtime_root": os.path.abspath(os.fspath(contract["runtime_root"])),
        "review_policy": dict(contract["review_policy"]),
        "run_id": contract["run_id"],
        "task_id": contract["work_item_id"],
        "product_repo": contract["repository_path"],
        "canonical_branch": contract["canonical_branch"],
        "baseline_head": contract["baseline_head"],
        "baseline_tree": contract["baseline_tree"],
        "authorized_paths": list(contract["owned_paths"]),
        "builder_prompt": _v2_packet_prompt(contract),
        "acceptance_criteria": list(contract["success_criteria"]),
        "test_commands": [list(item) for item in contract["acceptance_instruments"]],
        "commit_message": f"feat({str(contract['work_item_id']).lower()}): implement approved task",
    }


def validate_task_packet_derivation_v2(contract: Mapping[str, Any], packet: TaskPacketV2 | Mapping[str, Any]) -> None:
    expected = _v2_expected_packet_mapping(contract)
    actual = {
        "packet_version": packet.packet_version if isinstance(packet, TaskPacketV2) else packet.get("packet_version"),
        "contract_id": packet.contract_id if isinstance(packet, TaskPacketV2) else packet.get("contract_id"),
        "contract_hash": packet.contract_hash if isinstance(packet, TaskPacketV2) else packet.get("contract_hash"),
        "runtime_root": packet.runtime_root if isinstance(packet, TaskPacketV2) else packet.get("runtime_root"),
        "review_policy": packet.review_policy if isinstance(packet, TaskPacketV2) else packet.get("review_policy"),
        "run_id": packet.run_id if isinstance(packet, TaskPacketV2) else packet.get("run_id"),
        "task_id": packet.task_id if isinstance(packet, TaskPacketV2) else packet.get("task_id"),
        "product_repo": packet.product_repo if isinstance(packet, TaskPacketV2) else packet.get("product_repo"),
        "canonical_branch": packet.canonical_branch if isinstance(packet, TaskPacketV2) else packet.get("canonical_branch"),
        "baseline_head": packet.baseline_head if isinstance(packet, TaskPacketV2) else packet.get("baseline_head"),
        "baseline_tree": packet.baseline_tree if isinstance(packet, TaskPacketV2) else packet.get("baseline_tree"),
        "authorized_paths": packet.authorized_paths if isinstance(packet, TaskPacketV2) else packet.get("authorized_paths"),
        "builder_prompt": packet.builder_prompt if isinstance(packet, TaskPacketV2) else packet.get("builder_prompt"),
        "acceptance_criteria": packet.acceptance_criteria if isinstance(packet, TaskPacketV2) else packet.get("acceptance_criteria"),
        "test_commands": packet.test_commands if isinstance(packet, TaskPacketV2) else packet.get("test_commands"),
        "commit_message": packet.commit_message if isinstance(packet, TaskPacketV2) else packet.get("commit_message"),
    }
    # Normalize runtime_root lexically before comparison.
    try:
        if isinstance(actual.get("runtime_root"), str):
            actual["runtime_root"] = os.path.abspath(os.fspath(actual["runtime_root"]))
    except Exception as exc:
        raise ArtifactValidationError("V2 packet runtime_root is invalid") from exc
    # Normalize review_policy for comparison.
    try:
        if actual.get("review_policy") is not None:
            actual["review_policy"] = normalize_review_policy(actual["review_policy"])
    except ArtifactValidationError as exc:
        raise ArtifactValidationError(f"V2 packet review_policy is invalid: {exc.message}") from exc
    for field in expected:
        if actual.get(field) != expected[field]:
            raise GovernanceBlockerError(f"Derived V2 Task Packet widens or changes approved field: {field}")


def validate_gate_a_v2(contract: Mapping[str, Any], authorization: Mapping[str, Any], *, inspect_live: bool = True) -> None:
    if not isinstance(authorization, dict) or set(authorization) != V2_GATE_A_KEYS:
        raise GovernanceBlockerError("V2 Gate A authorization is missing or not exact")
    if authorization.get("gate") != "HUMAN_GATE_A" or authorization.get("decision") != "APPROVED":
        raise GovernanceBlockerError("V2 Gate A is not an exact APPROVED human authorization")
    if authorization.get("contract_id") != contract.get("contract_id") or authorization.get("contract_hash") != contract.get("contract_hash"):
        raise GovernanceBlockerError("V2 Gate A is bound to a different Design Contract")
    for field in ("baseline_head", "baseline_tree"):
        value = authorization.get(field)
        if not isinstance(value, str) or not SHA_RE.fullmatch(value) or value.lower() != str(contract.get(field)).lower():
            raise GovernanceBlockerError(f"V2 Gate A {field} does not match the Design Contract")
    auth_dirty = authorization.get("authorized_protected_dirty_paths")
    if not isinstance(auth_dirty, list):
        raise GovernanceBlockerError("V2 Gate A protected dirty paths are malformed")
    for item in auth_dirty:
        _safe_relative_path(item, field="authorized_protected_dirty_paths")
    if len(set(auth_dirty)) != len(auth_dirty):
        raise GovernanceBlockerError("V2 Gate A protected dirty paths contain duplicates")
    overlap = sorted(path for path in contract.get("protected_dirty_paths", []) if any(_paths_overlap_v2(path, owned) for owned in contract.get("owned_paths", [])))
    if sorted(auth_dirty) != overlap:
        raise GovernanceBlockerError("Protected dirty paths overlap owned scope without exact V2 Gate A authority")
    if inspect_live:
        repo = Path(str(contract["repository_path"]))
        observed_branch = _git(repo, ["branch", "--show-current"])
        observed_head = _git(repo, ["rev-parse", "HEAD"]).lower()
        observed_tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
        if observed_branch != contract["canonical_branch"]:
            raise GovernanceBlockerError("Canonical branch drift after V2 Design Contract creation")
        if observed_head != str(contract["baseline_head"]).lower() or observed_tree != str(contract["baseline_tree"]).lower():
            raise GovernanceBlockerError("STALE_BASELINE: repository changed after V2 Design Contract creation")
        # Protected dirty baseline check: compare live dirty paths to contract.
        raw = subprocess.run(["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, check=False)
        if raw.returncode != 0:
            raise GovernanceBlockerError("Cannot inspect protected dirty baseline for V2 Gate A")
        # Reuse controller-style parsing minimal: split NUL records.
        dirty: list[str] = []
        records = raw.stdout.split("\0")
        index = 0
        while index < len(records):
            record = records[index]
            index += 1
            if len(record) < 4:
                continue
            status, path = record[:2], record[3:]
            if status.strip():
                dirty.append(path)
            if status and status[0] in {"R", "C"} and index < len(records) and records[index]:
                dirty.append(records[index])
                index += 1
        if sorted(set(dirty)) != sorted(contract.get("protected_dirty_paths", [])):
            raise GovernanceBlockerError("Protected dirty baseline changed after V2 Design Contract creation")


def _paths_overlap_v2(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _paths_for_v2(config: RunnerConfig, packet: TaskPacketV2) -> dict[str, Path]:
    root = config.runtime_root / packet.run_id
    return {
        "root": root, "manifest": root / "manifest.json", "state": root / "state.json",
        "events": root / "events.ndjson", "builder": root / "builder",
        "deterministic": root / "deterministic",
        "targeted_review": root / "targeted-review",
        "worktree": root / "builder" / "worktree",
    }


def _targeted_schema_path() -> Path:
    return get_runner_root() / "schemas" / "targeted-review-result.schema.json"


def _targeted_review_prompt(packet: TaskPacketV2, contract: Mapping[str, Any], candidate: str, tree: str, changes: list[str], tests: list[dict[str, Any]]) -> str:
    brief = str(packet.review_policy["reviewer"]["review_brief"])
    context = json.dumps({"task_id": packet.task_id, "run_id": packet.run_id,
                          "baseline_head": packet.baseline_head, "baseline_tree": packet.baseline_tree,
                          "candidate_head": candidate, "candidate_tree": tree,
                          "authorized_paths": packet.authorized_paths, "actual_changed_paths": changes,
                          "acceptance_criteria": packet.acceptance_criteria,
                          "deterministic_tests": [{"argv": item["argv"], "exit_code": item["exit_code"]} for item in tests]})
    return brief + "\n\nTargeted semantic review. Inspect the current immutable candidate read-only. Do not edit, commit, or repair. Return only JSON conforming to HARN-002.TARGETED_REVIEW.v1.\n\n" + context


class _RunEvidenceV2:
    def __init__(self, paths: dict[str, Path], packet: TaskPacketV2, config: RunnerConfig, contract: Mapping[str, Any]) -> None:
        self.paths, self.packet, self.config, self.contract = paths, packet, config, contract
        self.state = RunState.CREATED
        self.packet_hash = task_packet_hash_v2(packet)

    def start(self) -> None:
        self.paths["root"].mkdir(parents=True)
        manifest = {
            "manifest_version": V2_MANIFEST_VERSION,
            "run_id": self.packet.run_id,
            "contract_id": self.packet.contract_id,
            "contract_hash": self.packet.contract_hash,
            "task_packet_hash": self.packet_hash,
            "created_at": _utc_now(),
            "product": {"repo": self.packet.product_repo, "canonical_branch": self.packet.canonical_branch,
                        "baseline_head": self.packet.baseline_head, "baseline_tree": self.packet.baseline_tree},
            "runtime_root": self.packet.runtime_root,
            "authorized_paths": self.packet.authorized_paths,
            "acceptance_criteria": self.packet.acceptance_criteria,
            "test_commands": self.packet.test_commands,
            "review_policy": self.packet.review_policy,
            "reviewer_binding": self.packet.review_policy.get("reviewer"),
            "roles": {"builder": {"tool": self.config.agents["builder"].tool,
                                  "executable": self.config.agents["builder"].executable,
                                  "model": self.config.agents["builder"].model,
                                  "timeout_seconds": self.config.agents["builder"].timeout_seconds}},
        }
        _write_json(self.paths["manifest"], manifest)
        self.transition(RunState.CREATED, "run_created", {"contract_id": self.packet.contract_id})

    def _state_payload(self, state: RunState, event: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"run_id": self.packet.run_id, "state": state.value,
                   "updated_at": _utc_now(), "last_event": event, "stop_reason": None,
                   "contract_id": self.packet.contract_id,
                   "review_policy": self.packet.review_policy,
                   "review_attempted": bool((extra or {}).get("review_attempted", False)),
                   "review_status": (extra or {}).get("review_status"),
                   "candidate_head": (extra or {}).get("candidate_head"),
                   "candidate_tree": (extra or {}).get("candidate_tree"),
                   "candidate_ref": (extra or {}).get("candidate_ref")}
        return payload

    def transition(self, state: RunState, event: str, payload: dict[str, Any] | None = None) -> None:
        prior = self.state
        self.state = state
        record = {"timestamp": _utc_now(), "event": event, "from_state": prior.value if prior != state else None,
                  "to_state": state.value, "payload": payload or {}}
        with self.paths["events"].open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        state_doc = self._state_payload(state, event, payload)
        _write_json(self.paths["state"], {"state_version": V2_STATE_VERSION, **state_doc})

    def stop(self, reason: str, error_class: str, extra: dict[str, Any] | None = None) -> None:
        prior = self.state
        self.state = RunState.STOPPED
        record = {"timestamp": _utc_now(), "event": "run_stopped", "from_state": prior.value,
                  "to_state": "STOPPED", "payload": {"reason": reason, "error_class": error_class, **(extra or {})}}
        with self.paths["events"].open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        state_doc = self._state_payload(RunState.STOPPED, "run_stopped", {"stop_reason": reason, **(extra or {})})
        state_doc["stop_reason"] = reason
        _write_json(self.paths["state"], {"state_version": V2_STATE_VERSION, **state_doc})


def _inspect_v2(packet: TaskPacketV2, config: RunnerConfig, contract: Mapping[str, Any]) -> dict[str, Any]:
    repo = _canonical_baseline_v2(packet)
    paths = _paths_for_v2(config, packet)
    if paths["root"].exists():
        raise GovernanceBlockerError(f"Run ID collision: immutable runtime evidence already exists at {paths['root']}")
    # NOTE: V2 NONE must not resolve/inspect any reviewer executable here.
    # TARGETED reviewer binding is validated only after deterministic PASS.
    return {
        "result": "READY_FOR_HUMAN_AUTHORIZATION", "run_id": packet.run_id, "task_id": packet.task_id,
        "product_repo": str(repo), "baseline_head": packet.baseline_head, "baseline_tree": packet.baseline_tree,
        "candidate_branch": candidate_branch_name_v2(packet), "candidate_worktree": str(paths["worktree"]),
        "review_mode": packet.review_policy["review_mode"],
    }


def _canonical_baseline_v2(packet: TaskPacketV2) -> Path:
    repo = Path(packet.product_repo).resolve()
    if not repo.is_dir() or not (repo / ".git").exists():
        raise RunnerEnvironmentError("product_repo is not an existing Git worktree")
    branch = _git(repo, ["branch", "--show-current"])
    if branch != packet.canonical_branch:
        raise GovernanceBlockerError(f"Canonical branch drift: expected {packet.canonical_branch}, observed {branch}")
    head = _git(repo, ["rev-parse", "HEAD"]).lower()
    if head != packet.baseline_head:
        raise GovernanceBlockerError(f"Baseline HEAD drift: expected {packet.baseline_head}, observed {head}")
    tree = _git(repo, ["rev-parse", "HEAD^{tree}"]).lower()
    if tree != packet.baseline_tree:
        raise GovernanceBlockerError(f"Baseline TREE drift: expected {packet.baseline_tree}, observed {tree}")
    if _git(repo, ["status", "--porcelain"]):
        raise GovernanceBlockerError("Canonical product worktree is dirty")
    return repo


def candidate_branch_name_v2(packet: TaskPacketV2) -> str:
    safe_task = re.sub(r"[^A-Za-z0-9._-]+", "-", packet.task_id).strip(".-")
    safe_run = re.sub(r"[^A-Za-z0-9._-]+", "-", packet.run_id).strip(".-")
    return f"harn-candidate/{safe_task}-{safe_run}"


def inspect_packet_v2(packet_path: Path | str, contract_path: Path | str, gate_a_path: Path | str, config_path: Path | str | None = None) -> dict[str, Any]:
    packet = parse_task_packet_v2(packet_path)
    contract = _load_contract_v2(contract_path)
    gate_a = _read_json(Path(gate_a_path))
    if not isinstance(gate_a, dict):
        raise GovernanceBlockerError("V2 Gate A authorization is missing or not exact")
    validate_gate_a_v2(contract, gate_a, inspect_live=True)
    validate_task_packet_derivation_v2(contract, packet)
    config = load_config(config_path)
    # runtime_root authority: packet/contract/config must agree exactly.
    # Use realpath to tolerate /tmp -> /private/tmp symlinks on macOS.
    config_root = os.path.realpath(os.fspath(config.runtime_root))
    contract_root = os.path.realpath(os.fspath(contract["runtime_root"]))
    packet_root = os.path.realpath(os.fspath(packet.runtime_root))
    if packet_root != contract_root:
        raise GovernanceBlockerError("V2 packet runtime_root widens the approved contract")
    if config_root != packet_root:
        raise GovernanceBlockerError("V2 runtime_root mismatch between approved contract and runner config")
    return _inspect_v2(packet, config, contract)


def _run_tests_v2(repo: Path, packet: TaskPacketV2, evidence: _RunEvidenceV2, candidate: str, tree: str, changes: list[str], expected_fingerprint: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, argv in enumerate(packet.test_commands, start=1):
        try:
            result = _run_process(argv, repo, evidence.paths["deterministic"] / f"test-{index}", 300)
        except AgentExecutionError as exc:
            # Deterministic check failure is an implementation failure, not a
            # provider execution error. Preserve invocation evidence already
            # written by _run_process, then fail closed without review.
            raise ImplementationFailureError(f"Deterministic test {index} failed: {exc.message}") from exc
        results.append(result)
        if result["exit_code"] != 0:
            raise ImplementationFailureError(f"Deterministic test {index} failed")
        _verify_candidate_identity(repo, packet.baseline_head, candidate, tree, changes, expected_fingerprint=expected_fingerprint)
    check = subprocess.run(["git", "-C", str(repo), "diff", "--check", f"{packet.baseline_head}..{candidate}"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, check=False)
    if check.returncode != 0:
        raise ImplementationFailureError("Frozen candidate fails git diff --check")
    _verify_candidate_identity(repo, packet.baseline_head, candidate, tree, changes, expected_fingerprint=expected_fingerprint)
    return results


def _evidence_file_hashes_v2(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            try:
                relative = str(path.relative_to(root))
            except ValueError:
                continue
            if relative.startswith("builder/worktree/"):
                continue
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
            except OSError:
                continue
            hashes[relative] = digest.hexdigest()
    return hashes


def _runner_acceptance_identity_v2(data: Mapping[str, Any]) -> str:
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
    return _sha_canonical_v2(identity)


def run_packet_v2(packet_path: Path | str, contract_path: Path | str, gate_a_path: Path | str, config_path: Path | str | None = None, *, authorize: bool = False) -> dict[str, Any]:
    """Execute one V2 run. --authorize alone is insufficient; exact Gate A context is required."""
    if not authorize:
        raise GovernanceBlockerError("run requires explicit --authorize; no provider or worktree was created")
    packet = parse_task_packet_v2(packet_path)
    contract = _load_contract_v2(contract_path)
    gate_a_raw = _read_json(Path(gate_a_path))
    if not isinstance(gate_a_raw, dict):
        raise GovernanceBlockerError("V2 Gate A authorization is missing or not exact")
    validate_gate_a_v2(contract, gate_a_raw, inspect_live=True)
    validate_task_packet_derivation_v2(contract, packet)
    config = load_config(config_path)
    config_root = os.path.realpath(os.fspath(config.runtime_root))
    contract_root = os.path.realpath(os.fspath(contract["runtime_root"]))
    packet_root = os.path.realpath(os.fspath(packet.runtime_root))
    if packet_root != contract_root:
        raise GovernanceBlockerError("V2 packet runtime_root widens the approved contract")
    if config_root != packet_root:
        raise GovernanceBlockerError("V2 runtime_root mismatch between approved contract and runner config")
    preflight = _inspect_v2(packet, config, contract)
    repo, paths = Path(preflight["product_repo"]), _paths_for_v2(config, packet)
    evidence = _RunEvidenceV2(paths, packet, config, contract)
    evidence.start()
    mode = packet.review_policy["review_mode"]
    summary: dict[str, Any] = {
        "version": V2_RUNNER_RESULT_VERSION, "result": "STOPPED",
        "run_id": packet.run_id, "contract_id": packet.contract_id, "contract_hash": packet.contract_hash,
        "task_packet_hash": evidence.packet_hash, "review_policy": packet.review_policy,
        "review_attempted": False, "review_status": ("NOT_REQUIRED" if mode == "NONE" else None),
        "candidate_head": None, "candidate_tree": None, "candidate_ref": None,
        "candidate_worktree_fingerprint": None, "worktree_fingerprint": None,
        "verification_disposition": "STOPPED", "deterministic_result": "STOPPED",
        "changed_paths": [], "test_commands": packet.test_commands,
        "evidence_root": str(paths["root"]), "runtime_root": str(paths["root"]),
        "candidate_branch": preflight["candidate_branch"],
    }

    def _finalize_stopped(error_class: str, error: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        evidence_paths = {key: str(value.relative_to(paths["root"])) if isinstance(value, Path) and value != paths["root"] else str(value) for key, value in paths.items() if key != "root"}
        # Normalize worktree/targeted locators to root-relative form.
        evidence_paths = {k: v for k, v in evidence_paths.items() if k in {"manifest", "state", "events", "builder", "deterministic", "worktree", "targeted_review"}}
        if mode == ReviewMode.NONE.value:
            evidence_paths["targeted_review"] = None
        elif not paths["targeted_review"].exists():
            # TARGETED stopped before review artifacts exist: keep locator string
            # for auditability; ingestion tolerates missing dir only for STOPPED.
            pass
        summary.update({
            "evidence_paths": evidence_paths,
            "required_evidence_references": sorted(_evidence_file_hashes_v2(paths["root"]).keys()),
            "evidence_file_sha256": _evidence_file_hashes_v2(paths["root"]),
            "runner_acceptance_evidence_sha256": None,
            "review_evidence": None,
            "error_class": error_class, "error": error,
        })
        if extra:
            summary.update(extra)
        # Enforce candidate all-or-none.
        heads = (summary.get("candidate_head"), summary.get("candidate_tree"), summary.get("candidate_ref"))
        if any(v is not None for v in heads) and not all(v is not None for v in heads):
            summary.update({"candidate_head": None, "candidate_tree": None, "candidate_ref": None,
                            "candidate_worktree_fingerprint": None, "worktree_fingerprint": None})
        _write_json(paths["root"] / "report.json", summary)
        return summary

    try:
        evidence.transition(RunState.PREFLIGHT, "preflight_passed", {"baseline": packet.baseline_head, "review_mode": mode})
        evidence.transition(RunState.HUMAN_AUTHORIZED, "human_authorized", {"contract_id": packet.contract_id})
        branch = _create_builder_worktree(repo, _adapt_packet_v1(packet), paths["worktree"])
        evidence.transition(RunState.BUILDER_RUNNING, "builder_started", {"worktree": str(paths["worktree"]), "branch": branch})
        _run_process(build_builder_invocation(config.agents["builder"], paths["worktree"], _adapt_packet_v1(packet)),
                     paths["worktree"], paths["builder"], config.agents["builder"].timeout_seconds)
        if _git(paths["worktree"], ["rev-parse", "HEAD"]).lower() != packet.baseline_head:
            raise GovernanceBlockerError("Builder created an unexpected commit")
        changes = _changed_paths(paths["worktree"], packet.baseline_head)
        unauthorized = sorted(set(changes) - set(packet.authorized_paths))
        if unauthorized:
            raise GovernanceBlockerError(f"Builder changed unauthorized paths: {unauthorized}")
        candidate, tree = _freeze_candidate(paths["worktree"], _adapt_packet_v1(packet), changes)
        candidate_fingerprint = fingerprint_worktree(paths["worktree"])
        summary.update({"candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch,
                        "candidate_worktree_fingerprint": candidate_fingerprint, "worktree_fingerprint": candidate_fingerprint,
                        "changed_paths": changes})
        evidence.transition(RunState.CANDIDATE_FROZEN, "candidate_frozen",
                            {"head": candidate, "tree": tree, "changed_paths": changes,
                             "review_attempted": False, "review_status": summary["review_status"],
                             "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
        evidence.transition(RunState.DETERMINISTIC_GATES, "deterministic_gates_started",
                            {"review_attempted": False, "review_status": summary["review_status"],
                             "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
        try:
            tests = _run_tests_v2(paths["worktree"], packet, evidence, candidate, tree, changes, candidate_fingerprint)
        except ImplementationFailureError as exc:
            # Deterministic failure blocks any semantic-review setup/invocation.
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": False, "review_status": summary["review_status"],
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED",
                            "tests": []})
            return _finalize_stopped(exc.error_class.value, exc.message)
        # Deterministic PASS.
        summary.update({"tests": tests})
        if mode == ReviewMode.NONE.value:
            # NONE: zero semantic-review setup, invocation, artifacts.
            if paths["targeted_review"].exists():
                raise GovernanceBlockerError("NONE run must not create targeted-review evidence")
            _canonical_baseline_v2(packet)
            evidence.transition(RunState.ACCEPTANCE_READY, "acceptance_ready",
                                {"review_attempted": False, "review_status": "NOT_REQUIRED",
                                 "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"result": "ACCEPTANCE_READY", "review_attempted": False, "review_status": "NOT_REQUIRED",
                            "verification_disposition": "PASS", "deterministic_result": "ACCEPTANCE_READY",
                            "error_class": None, "error": None, "review_evidence": None})
            evidence_paths = {key: str(value.relative_to(paths["root"])) for key, value in paths.items() if key != "root"}
            evidence_paths["targeted_review"] = None
            file_hashes = _evidence_file_hashes_v2(paths["root"])
            # Ensure no reviewer artifacts leaked into evidence hashes for NONE.
            summary.update({"evidence_paths": evidence_paths,
                            "required_evidence_references": sorted(file_hashes.keys()),
                            "evidence_file_sha256": file_hashes})
            summary["runner_acceptance_evidence_sha256"] = _runner_acceptance_identity_v2(summary)
            _write_json(paths["root"] / "report.json", summary)
            return summary
        # TARGETED: exactly one attempt after deterministic PASS.
        frozen = packet.review_policy["reviewer"]
        assert isinstance(frozen, dict)
        evidence.transition(RunState.DV_RUNNING, "targeted_review_started",
                            {"review_attempted": True, "review_status": None,
                             "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
        summary.update({"review_attempted": True, "review_status": None})
        # Live drift checks before invocation (consumes the single attempt on failure).
        try:
            _validate_targeted_live_binding(frozen)
        except RunnerError as exc:
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": True, "review_status": None,
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
            extra = {"review_attempted": True, "review_status": None,
                     "review_evidence": {"invocation": None, "stdout": None, "stderr": None, "exit_code": None, "timed_out": None}}
            _write_json(paths["targeted_review"] / "preflight-failure.json", {"error": exc.message, "error_class": exc.error_class.value})
            finalized = _finalize_stopped(exc.error_class.value, exc.message, extra)
            return finalized
        # Single invocation; process failure wins over any PASS file.
        prompt = _targeted_review_prompt(packet, contract, candidate, tree, changes, tests)
        schema_path = _targeted_schema_path()
        # Verify frozen schema sha still matches live schema file.
        try:
            live_schema_sha = _sha256_file_v2(schema_path)
        except OSError as exc:
            raise RunnerEnvironmentError(f"Targeted output schema cannot be read: {exc}") from exc
        if live_schema_sha != str(frozen["output_schema_sha256"]).lower():
            exc = ArtifactValidationError("Targeted output schema drift from frozen Gate A binding")
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": True, "review_status": None,
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            return _finalize_stopped(exc.error_class.value, exc.message,
                                     {"review_attempted": True, "review_status": None,
                                      "review_evidence": {"invocation": None, "stdout": None, "stderr": None, "exit_code": None, "timed_out": None}})
        try:
            targeted = run_targeted_review(
                str(frozen["executable"]), paths["worktree"], paths["targeted_review"],
                candidate_head=candidate, candidate_tree=tree, candidate_ref=branch,
                prompt=prompt, timeout_seconds=int(frozen["timeout_seconds"]),
                output_schema=schema_path,
            )
            # Enforce frozen Gate A reviewer binding against live evidence.
            if targeted.get("reviewer_profile_hash") != str(frozen["reviewer_profile_hash"]).lower():
                raise ArtifactValidationError("Targeted reviewer live profile hash differs from frozen Gate A binding")
            if targeted.get("executable_sha256") != str(frozen["executable_sha256"]).lower():
                raise ArtifactValidationError("Targeted reviewer live executable fingerprint differs from frozen Gate A binding")
        except AgentExecutionError as exc:
            # Preserve partial evidence; process failure wins.
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": True, "review_status": ReviewStatus.EXECUTION_FAILURE.value,
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
            partial = _collect_targeted_partial_v2(paths["targeted_review"])
            return _finalize_stopped(exc.error_class.value, exc.message,
                                     {"review_attempted": True, "review_status": ReviewStatus.EXECUTION_FAILURE.value,
                                      "review_evidence": partial})
        except ArtifactValidationError as exc:
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": True, "review_status": None,
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
            partial = _collect_targeted_partial_v2(paths["targeted_review"])
            # For malformed/missing, preserve what exists but never accept.
            if not isinstance(partial, dict):
                partial = {"invocation": None, "stdout": None, "stderr": None, "exit_code": None, "timed_out": None}
            return _finalize_stopped(exc.error_class.value, exc.message,
                                     {"review_attempted": True, "review_status": None, "review_evidence": partial})
        except ReviewStaleError as exc:
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": True, "review_status": None,
                           "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
            partial = _collect_targeted_partial_v2(paths["targeted_review"])
            if not isinstance(partial, dict):
                partial = {"invocation": None, "stdout": None, "stderr": None, "exit_code": None, "timed_out": None}
            return _finalize_stopped(exc.error_class.value, exc.message,
                                     {"review_attempted": True, "review_status": None, "review_evidence": partial})
        # Validate exact targeted result binding already done inside run_targeted_review;
        # re-verify candidate identity after review and check disposition.
        _verify_candidate_identity(paths["worktree"], packet.baseline_head, candidate, tree, changes, branch,
                                   expected_fingerprint=candidate_fingerprint)
        result_value = targeted["result"]
        disposition = result_value["disposition"]
        # Evidence hashes already bound via snapshots; verify artifact sha matches.
        review_evidence = {
            "artifact": str(Path(targeted["artifact"]).relative_to(paths["root"])),
            "artifact_sha256": targeted["artifact_sha256"],
            "raw_artifact": str(Path(targeted["raw_artifact"]).relative_to(paths["root"])),
            "raw_artifact_sha256": targeted["raw_artifact_sha256"],
            "invocation": str(Path(targeted["invocation"]).relative_to(paths["root"])),
            "reviewer_profile": str(Path(targeted["reviewer_profile"]).relative_to(paths["root"])),
            "reviewer_profile_hash": targeted["reviewer_profile_hash"],
            "executable_sha256": targeted["executable_sha256"],
            "fingerprint_pre": str(Path(targeted["fingerprint_pre_artifact"]).relative_to(paths["root"])),
            "fingerprint_post": str(Path(targeted["fingerprint_post_artifact"]).relative_to(paths["root"])),
            "disposition": disposition,
            "blocking_findings": list(result_value["blocking_findings"]),
            "non_blocking_findings": list(result_value["non_blocking_findings"]),
        }
        if disposition == "PASS":
            _canonical_baseline_v2(packet)
            evidence.transition(RunState.ACCEPTANCE_READY, "acceptance_ready",
                                {"review_attempted": True, "review_status": ReviewStatus.PASS.value,
                                 "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
            summary.update({"result": "ACCEPTANCE_READY", "review_attempted": True,
                            "review_status": ReviewStatus.PASS.value,
                            "verification_disposition": "PASS", "deterministic_result": "ACCEPTANCE_READY",
                            "error_class": None, "error": None, "review_evidence": review_evidence})
            evidence_paths = {key: str(value.relative_to(paths["root"])) for key, value in paths.items() if key != "root"}
            file_hashes = _evidence_file_hashes_v2(paths["root"])
            summary.update({"evidence_paths": evidence_paths,
                            "required_evidence_references": sorted(file_hashes.keys()),
                            "evidence_file_sha256": file_hashes})
            summary["runner_acceptance_evidence_sha256"] = _runner_acceptance_identity_v2(summary)
            _write_json(paths["root"] / "report.json", summary)
            return summary
        # NEEDS_FIX blocks acceptance with implementation failure classification.
        exc = ImplementationFailureError("Targeted reviewer returned NEEDS_FIX")
        evidence.stop(exc.message, exc.error_class.value,
                      {"review_attempted": True, "review_status": ReviewStatus.NEEDS_FIX.value,
                       "candidate_head": candidate, "candidate_tree": tree, "candidate_ref": branch})
        summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
        return _finalize_stopped(exc.error_class.value, exc.message,
                                 {"review_attempted": True, "review_status": ReviewStatus.NEEDS_FIX.value,
                                  "review_evidence": review_evidence})
    except RunnerError as exc:
        try:
            evidence.stop(exc.message, exc.error_class.value,
                          {"review_attempted": bool(summary.get("review_attempted")),
                           "review_status": summary.get("review_status"),
                           "candidate_head": summary.get("candidate_head"),
                           "candidate_tree": summary.get("candidate_tree"),
                           "candidate_ref": summary.get("candidate_ref")})
        except Exception:
            pass
        summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
        return _finalize_stopped(exc.error_class.value, exc.message)
    except Exception as exc:
        wrapped = RunnerEnvironmentError(f"Unexpected runner failure: {type(exc).__name__}: {exc}")
        try:
            evidence.stop(wrapped.message, wrapped.error_class.value,
                          {"review_attempted": bool(summary.get("review_attempted")),
                           "review_status": summary.get("review_status"),
                           "candidate_head": summary.get("candidate_head"),
                           "candidate_tree": summary.get("candidate_tree"),
                           "candidate_ref": summary.get("candidate_ref")})
        except Exception:
            pass
        summary.update({"verification_disposition": "STOPPED", "deterministic_result": "STOPPED"})
        return _finalize_stopped(wrapped.error_class.value, wrapped.message)


def _adapt_packet_v1(packet: TaskPacketV2) -> TaskPacket:
    return TaskPacket(run_id=packet.run_id, task_id=packet.task_id, product_repo=packet.product_repo,
                      canonical_branch=packet.canonical_branch, baseline_head=packet.baseline_head,
                      baseline_tree=packet.baseline_tree, authorized_paths=list(packet.authorized_paths),
                      builder_prompt=packet.builder_prompt, acceptance_criteria=list(packet.acceptance_criteria),
                      test_commands=[list(c) for c in packet.test_commands], commit_message=packet.commit_message)


def _validate_targeted_live_binding(frozen: Mapping[str, Any]) -> None:
    from prj226_runner.reviewer_profile import build_codex_reviewer_profile, resolve_reviewer_executable
    executable = str(frozen["executable"])
    resolved = resolve_reviewer_executable(executable)
    if str(resolved) != str(frozen["resolved_executable"]):
        raise ArtifactValidationError("Targeted reviewer resolved executable differs from frozen Gate A binding")
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RunnerEnvironmentError(f"Targeted reviewer executable cannot be fingerprinted: {exc}") from exc
    if digest.hexdigest() != str(frozen["executable_sha256"]).lower():
        raise ArtifactValidationError("Targeted reviewer executable fingerprint drift from frozen Gate A binding")
    profile = build_codex_reviewer_profile(executable, model=str(frozen["model"]))
    if profile.reviewer_profile_hash != str(frozen["reviewer_profile_hash"]).lower():
        raise ArtifactValidationError("Targeted reviewer profile drift from frozen Gate A binding")
    if profile.model != str(frozen["model"]):
        raise ArtifactValidationError("Targeted reviewer model drift from frozen Gate A binding")


def _collect_targeted_partial_v2(evidence_dir: Path) -> dict[str, Any]:
    partial: dict[str, Any] = {}
    for name in ("invocation.json", "stdout.log", "stderr.log"):
        candidate = evidence_dir / name
        key = {"invocation.json": "invocation", "stdout.log": "stdout", "stderr.log": "stderr"}[name]
        if candidate.is_file():
            try:
                if name.endswith(".json"):
                    partial[key] = json.loads(candidate.read_text(encoding="utf-8"))
                else:
                    partial[key] = candidate.read_text(encoding="utf-8")[:4000]
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                partial[key] = None
        else:
            partial[key] = None
    invocation = partial.get("invocation") if isinstance(partial.get("invocation"), dict) else None
    partial["exit_code"] = invocation.get("exit_code") if invocation else None
    partial["timed_out"] = invocation.get("timed_out") if invocation else None
    return partial


def dispatch_packet(path: Path | str) -> str:
    """Explicit version/family dispatch. Never infer, strip, or fall back."""
    data = _read_json(Path(path))
    if not isinstance(data, dict):
        raise ArtifactValidationError("Packet must be a JSON object")
    if "packet_version" in data:
        if data["packet_version"] == V2_PACKET_VERSION:
            return "v2"
        raise ArtifactValidationError("Unsupported packet version")
    # Legacy V1 has exactly the HARN-001 contract fields with no version.
    legacy_required = {"run_id", "task_id", "product_repo", "canonical_branch", "baseline_head",
                       "baseline_tree", "authorized_paths", "builder_prompt", "acceptance_criteria",
                       "test_commands", "commit_message"}
    if set(data) == legacy_required:
        return "v1"
    raise ArtifactValidationError("Unsupported or mixed packet version")
