"""Deterministic HARN-001 lifecycle orchestration.

This module deliberately keeps provider argv construction separate from the
Git/state-machine logic.  It contains no retry, repair, merge, or push path.
"""

from __future__ import annotations

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
    build_codex_reviewer_invocation,
    fingerprint_worktree,
    check_codex_reviewer_binding,
    run_codex_review,
)
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    GovernanceBlockerError,
    ImplementationFailureError,
    RunnerEnvironmentError,
    RunnerError,
)
from prj226_runner.models import RunState
from prj226_runner.paths import get_runner_root, get_runtime_root


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
    raw = path.read_text(encoding="utf-8")
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
