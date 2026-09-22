"""Durable, offline controller kernel. No provider adapters or promotion path.

Reasoning occurs only at PLANNING and PLANNER_ASSESSMENT. Execution adapters
return a receipt for Runner evidence, never authorization or acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from prj226_runner import controller as C, runner as R
from prj226_runner.control_protocol import (
    ATTACHMENT_LIMIT, CONTEXT_LIMIT, COUNTERS, DECISIONS, VERSION,
    STRICT_COUNTERS, STRICT_VERSION, BuilderExecutorPort, BuilderRequest, ControllerPlannerPort,
    PlannerContext, StrictExecutionRequest, closed, decode, digest, encode, gate_binding,
    parse_decision, reference, strict_gate_binding, strict_reference,
    validate_state, validate_strict_state, validate_strict_planner_proposal,
    validate_task_packet_v3,
)
from prj226_runner.control_store import ControlStore, fsync_directory, read_file
from prj226_runner.codex_reviewer import EvidenceRoot
from prj226_runner.candidate_authority import build_candidate_authority, verify_candidate_authority
from prj226_runner.control_runtime import validate_runtime
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError, RunnerError


def build_context(state: dict[str, Any], *, attachment: str | None = None,
                  required_attachment: bool = False, limit: int = CONTEXT_LIMIT) -> PlannerContext:
    validate_state(state)
    if type(limit) is not int or not 0 < limit <= CONTEXT_LIMIT:
        raise ArtifactValidationError("Invalid normal context limit")
    if required_attachment and attachment is None:
        raise GovernanceBlockerError("Required semantic evidence is missing")
    source = attachment.encode("utf-8") if attachment is not None else None
    if source is not None and len(source) > ATTACHMENT_LIMIT:
        raise GovernanceBlockerError("Semantic attachment exceeds byte budget; no truncation allowed")
    if state.get("schema_version") == STRICT_VERSION:
        keys = (
            "controller_id", "task_id", "goal", "revision", "phase", "baseline", "scope",
            "approved_scope", "contract_ref", "runtime_ref", "planner_profile_ref",
            "builder_profile_ref", "reviewer_profile_ref", "repair_policy", "attempt_index",
            "repair_cycles", "candidate", "verification", "review", "repair_history",
        )
        document = {
            "schema_version": STRICT_VERSION,
            "state": {key: state[key] for key in keys},
            "included_sections": list(keys),
            "omitted_sections": ["raw_logs", "unrelated_history", "repository_files"],
            "attachment": None,
            "byte_count": 0,
        }
        if source is not None:
            document["attachment"] = {"byte_count": len(source), "sha256": hashlib.sha256(source).hexdigest()}
            document["included_sections"].append("semantic_attachment")
        else:
            document["omitted_sections"].append("semantic_attachment")
        while document["byte_count"] != len(encode(document)):
            document["byte_count"] = len(encode(document))
        raw = encode(document)
        if len(raw) > limit:
            raise GovernanceBlockerError("Required controller context exceeds byte budget")
        return PlannerContext(raw, hashlib.sha256(raw).hexdigest(), source)
    keys = ("controller_id", "task_id", "goal", "revision", "phase", "baseline", "scope",
            "planner_profile_ref", "builder_profile_ref", "contract_ref", "packet_ref",
            "candidate", "verification_summary", "latest_decision_ref", *COUNTERS)
    document = {"schema_version": VERSION, "state": {key:state[key] for key in keys},
                "included_sections": list(keys),
                "omitted_sections": ["raw_logs", "unrelated_history", "repository_files"],
                "attachment": None, "byte_count": 0}
    if source is not None:
        document["attachment"] = {"byte_count": len(source), "sha256": hashlib.sha256(source).hexdigest()}
        document["included_sections"].append("semantic_attachment")
    else:
        document["omitted_sections"].append("semantic_attachment")
    while document["byte_count"] != len(encode(document)):
        document["byte_count"] = len(encode(document))
    raw = encode(document)
    if len(raw) > limit:
        raise GovernanceBlockerError("Required controller context exceeds byte budget")
    return PlannerContext(raw, hashlib.sha256(raw).hexdigest(), source)


def compact_report(state: dict[str, Any]) -> dict[str, Any]:
    if state.get("schema_version") == STRICT_VERSION:
        validate_strict_state(state)
        gate = state["pending_gate"]
        report = {
            "schema_version": STRICT_VERSION,
            "status": state["terminal_state"] or ("HUMAN_GATE_REQUIRED" if gate else "RUNNING"),
            "controller_id": state["controller_id"],
            "task": state["task_id"],
            "revision": state["revision"],
            "phase": state["phase"],
            "question": gate["question"] if gate else None,
            "gate": {key: gate[key] for key in ("gate_id", "revision", "binding_digest")} if gate else None,
            "candidate": state["candidate"],
            "verification": state["verification"],
            "review": state["review"],
            "planner_invocations": state["planner_invocations"],
            "builder_invocations": state["builder_invocations"],
            "freeze_invocations": state["freeze_invocations"],
            "verifier_invocations": state["verifier_invocations"],
            "reviewer_invocations": state["reviewer_invocations"],
            "repair_cycles": state["repair_cycles"],
            "attempt_index": state["attempt_index"],
            "blocker_count": 1 if state["phase"] == "BLOCKED" else 0,
            "reason": state["terminal_reason"],
            "canonical_integration_performed": False,
            "token_usage": None,
        }
        report["disposition"] = report["status"]
        return report
    validate_state(state)
    status = state["terminal_state"] or ("HUMAN_GATE_REQUIRED" if state["pending_gate"] else "RUNNING")
    gate = state["pending_gate"]
    return {"schema_version": VERSION, "status": status, "controller_id": state["controller_id"],
            "task": state["task_id"], "revision": state["revision"], "phase": state["phase"],
            "question": gate["question"] if gate else None,
            "gate": {k:gate[k] for k in ("gate_id", "revision", "binding_digest")} if gate else None,
            "verification": state["verification_summary"], "candidate": state["candidate"],
            "planner_invocations": state["planner_invocations"], "builder_invocations": state["builder_invocations"],
            "retry_count": state["retry_count"], "fallback_count": state["fallback_count"],
            "human_responses": len(state["gate_a_history"]) + len(state["gate_b_history"]),
            "blocker_count": state["blocker_count"], "reason": state["terminal_reason"],
            "canonical_integration_performed": False, "token_usage": None}


def format_report(report: dict[str, Any]) -> str:
    lines = [f"STATUS: {report['status']}", f"TASK: {report['task']}", f"CURRENT: {report['phase']}",
             f"INVOCATIONS: planner {report['planner_invocations']}, builder {report['builder_invocations']}"]
    if report["question"]:
        lines.append(report["question"])
    if report["reason"]:
        lines.append(f"REASON: {report['reason']}")
    if report["status"] == "COMPLETE":
        lines.append("Canonical integration: prepared only; not performed.")
    return "\n".join(lines)


def _read_first_journal_line(
    path: Path,
    *,
    max_file_size: int = 16 * 1024 * 1024,
    max_line_length: int = 2 * 1024 * 1024,
) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_file_size:
            raise ArtifactValidationError("Evidence must be a bounded single-link regular file")
        first_event = bytearray()
        while True:
            read_size = min(64 * 1024, max_line_length - len(first_event) + 1)
            chunk = os.read(fd, read_size)
            if not chunk:
                if not first_event:
                    return b""
                raise ArtifactValidationError("Incomplete controller journal")
            newline_idx = chunk.find(b"\n")
            if newline_idx != -1:
                if len(first_event) + newline_idx > max_line_length:
                    raise ArtifactValidationError("Controller journal first event exceeds 2 MiB")
                return bytes(first_event) + chunk[:newline_idx]
            first_event.extend(chunk)
            if len(first_event) > max_line_length:
                raise ArtifactValidationError("Controller journal first event exceeds 2 MiB")
    finally:
        os.close(fd)


class DurableController:
    def __init__(self, root: Path | str, *, planner: ControllerPlannerPort | None = None,
                 builder: BuilderExecutorPort | None = None, reviewer: Any = None,
                 verifier: Any = None) -> None:
        self.store = ControlStore(root)
        self.planner, self.builder = planner, builder
        self.reviewer, self.verifier = reviewer, verifier

    @classmethod
    def start(cls, root: Path | str, *, controller_id: str, goal: str, contract_path: Path | str | None = None,
              planner_profile_ref: str, builder_profile_ref: str, planner_budget: int = 2,
              planner: ControllerPlannerPort | None = None, builder: BuilderExecutorPort | None = None,
              strict: bool = False, **strict_options: Any) -> "DurableController":
        if not strict and set(strict_options) & {
            "runtime", "runtime_path", "reviewer", "verifier", "max_repair_cycles",
            "baseline", "repository", "scope", "approved_scope", "packet", "packet_path",
            "reviewer_profile_ref", "contract",
        }:
            strict = True
        if strict:
            # The explicit flag is the only bridge from the legacy facade to
            # the R3C schema; a legacy store is never reinterpreted in place.
            strict_contract = strict_options.pop("contract", None)
            return StrictExecutionController.start(
                root,
                controller_id=controller_id,
                goal=goal,
                **({"contract_path": contract_path} if contract_path is not None else {"contract": strict_contract}),
                planner_profile_ref=planner_profile_ref,
                builder_profile_ref=builder_profile_ref,
                planner=planner,
                builder=builder,
                **strict_options,
            )  # type: ignore[return-value]
        if contract_path is None:
            raise ArtifactValidationError("Legacy controller start requires contract_path")
        contract = C._contract_value_v3(decode(read_file(Path(contract_path))))
        instance = cls(root, planner=planner, builder=builder)
        repo = Path(contract["repository_path"]).resolve()
        if instance.store.root == repo or repo in instance.store.root.parents:
            raise GovernanceBlockerError("Controller evidence must be outside the canonical repository")
        if contract["protected_dirty_paths"]:
            raise GovernanceBlockerError("CTRL-R001 requires a clean canonical baseline")
        baseline = {"repository": str(repo), "branch": contract["canonical_branch"],
                    "head": contract["baseline_head"], "tree": contract["baseline_tree"]}
        state = {"schema_version": VERSION, "controller_id": controller_id, "goal": goal,
                 "task_id": contract["work_item_id"], "revision": 1, "baseline": baseline,
                 "phase": "START", "planner_profile_ref": planner_profile_ref, "builder_profile_ref": builder_profile_ref,
                 "contract_ref": {"path":"contract.json", "sha256":digest(contract)}, "packet_ref":None,
                 "scope": list(contract["owned_paths"]), "candidate":None, "gate_a_history":[], "gate_b_history":[],
                 "pending_gate":None, **{key:0 for key in COUNTERS}, "planner_budget":planner_budget,
                 "latest_decision_ref":None, "pending_action":None, "verification_summary":None,
                 "terminal_state":None, "terminal_reason":None, "evidence_refs":[]}
        validate_state(state)
        instance._baseline(state)
        instance.store.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        fsync_directory(instance.store.root.parent)
        with instance.store.writer():
            instance.store.artifact("contract.json", contract)
            instance.store.commit(state, "controller_created")
        return instance

    @classmethod
    def start_strict(cls, *args: Any, **kwargs: Any) -> "StrictExecutionController":
        return StrictExecutionController.start(*args, **kwargs)

    def _strict_delegate(self) -> Any | None:
        """Open a strict store through the R3C implementation when requested."""
        try:
            journal = self.store.root / "events.ndjson"
            first_line = _read_first_journal_line(journal, max_file_size=16 * 1024 * 1024)
            if not first_line:
                raise ArtifactValidationError("Controller journal is empty")
            first_event = decode(first_line)
            if isinstance(first_event, dict) and first_event.get("schema_version") == STRICT_VERSION:
                return StrictExecutionController(
                    self.store.root,
                    planner=self.planner,
                    builder=self.builder,
                    reviewer=self.reviewer,
                    verifier=self.verifier,
                )
        except FileNotFoundError:
            return None
        return None

    def _baseline(self, state: dict[str, Any]) -> None:
        baseline = state["baseline"]
        repo = Path(baseline["repository"])
        for args, expected in ((["branch", "--show-current"], baseline["branch"]),
                               (["rev-parse", "HEAD"], baseline["head"]),
                               (["rev-parse", "HEAD^{tree}"], baseline["tree"]),
                               (["status", "--porcelain=v1", "--untracked-files=all"], "")):
            if C._git(repo, args) != expected:
                raise GovernanceBlockerError("Canonical baseline drift")

    def _contract(self, state: dict[str, Any]) -> dict[str, Any]:
        contract = C._contract_value_v3(self.store.read_artifact(state["contract_ref"]))
        expected = {"repository":contract["repository_path"], "branch":contract["canonical_branch"],
                    "head":contract["baseline_head"], "tree":contract["baseline_tree"]}
        if state["baseline"] != expected or state["scope"] != contract["owned_paths"] or state["task_id"] != contract["work_item_id"]:
            raise GovernanceBlockerError("State disagrees with frozen contract")
        return contract

    def _save(self, state: dict[str, Any], kind: str, **changes: Any) -> dict[str, Any]:
        return self.store.commit({**state, **changes, "revision":state["revision"] + 1}, kind)

    def _block(self, state: dict[str, Any], reason: str) -> dict[str, Any]:
        return self._save(state, "controller_blocked", phase="BLOCKED", terminal_state="BLOCKED",
                          terminal_reason=reason[:2048], pending_gate=None, pending_action=None,
                          blocker_count=state["blocker_count"] + 1)

    def _claim(self, state: dict[str, Any], kind: str) -> dict[str, Any]:
        action = {"id":f"action-{state['revision'] + 1}", "kind":kind,
                  "status":"PREPARED", "revision":state["revision"] + 1}
        return self._save(state, "action_prepared", pending_action=action)

    def _gate_a(self, state: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
        if not state["gate_a_history"] or state["gate_a_history"][-1]["human_response"] != "approve":
            raise GovernanceBlockerError("Missing explicit Gate A approval")
        gate = state["gate_a_history"][-1]["gate"]
        # Gate A predates candidate creation, so compare its original candidate binding.
        bound = gate_binding({**state, "candidate":None}, None)
        if gate["binding"] != bound:
            raise GovernanceBlockerError("Gate A authority drift")
        return {"gate":"HUMAN_GATE_A", "decision":"APPROVED", "contract_id":contract["contract_id"],
                "contract_hash":contract["contract_hash"], "baseline_head":contract["baseline_head"],
                "baseline_tree":contract["baseline_tree"], "authorized_protected_dirty_paths":[]}

    def _request_gate(self, state: dict[str, Any], kind: str, *, package: dict[str, str] | None = None,
                      latest_decision_ref: dict[str, str]) -> dict[str, Any]:
        revision = state["revision"] + 1
        binding = gate_binding(state, package)
        question = (f"{kind}: {state['task_id']}\nScope: {', '.join(state['scope'])}\n"
                    f"Planner: {state['planner_profile_ref']}; builder: {state['builder_profile_ref']}\n"
                    + ("Authorize one implementation attempt?" if kind == "GATE_A" else "Authorize integration preparation only (no Git integration)?")
                    + "\nReply: approve / deny")
        gate = {"gate_id":f"{state['controller_id']}-{kind}-{revision}", "gate_type":kind,
                "revision":revision, "binding":binding, "binding_digest":digest(binding), "question":question}
        return self._save(state, "human_gate_requested", phase="WAITING_HUMAN_" + kind,
                          pending_gate=gate, pending_action=None, latest_decision_ref=latest_decision_ref)

    def _dispatch(self, state: dict[str, Any]) -> dict[str, Any]:
        action = state["pending_action"]
        kind = action["kind"]
        adapter = self.planner if kind == "PLANNER" else self.builder
        if adapter is None:
            return state
        profile = state["planner_profile_ref" if kind == "PLANNER" else "builder_profile_ref"]
        if adapter.profile_ref != profile:
            raise GovernanceBlockerError("Adapter profile substitution forbidden")
        counter = "planner_invocations" if kind == "PLANNER" else "builder_invocations"
        budget = state["planner_budget"] if kind == "PLANNER" else 1
        if state[counter] >= budget:
            raise GovernanceBlockerError("Invocation budget exhausted; retry forbidden")
        state = self._save(state, "action_started", pending_action={**action, "status":"STARTED", "revision":state["revision"] + 1}, **{counter:state[counter]+1})
        action = state["pending_action"]
        if kind == "PLANNER":
            context = build_context(state)
            self.store.artifact(action["id"] + ".context.json", {"document":decode(context.document), "digest":context.digest})
            output = adapter.decide(context)
            # Validate before persisting model content, with no prose fallback.
            value = parse_decision(output, state, context.digest)
        else:
            contract = self._contract(state)
            packet = self.store.read_artifact(state["packet_ref"])
            R.validate_task_packet_derivation_v3(contract, packet)
            request = BuilderRequest(action["id"], state["task_id"], profile, encode(contract), encode(packet), encode(self._gate_a(state, contract)))
            value = self._receipt(adapter.execute(request), state)
        # An adapter never receives state. Detect unauthorized on-disk changes too.
        if self.store.load() != state:
            raise GovernanceBlockerError("Adapter changed controller state")
        self.store.artifact(action["id"] + ".result.json", {"schema_version":VERSION, "action_id":action["id"], "kind":kind, "output":value})
        return self._complete(state)

    def _receipt(self, raw: str | bytes, state: dict[str, Any]) -> dict[str, Any]:
        value = closed(decode(raw, limit=8192), {"schema_version", "action_id", "report_ref"}, "builder receipt")
        if value["schema_version"] != VERSION or value["action_id"] != state["pending_action"]["id"]:
            raise ArtifactValidationError("Builder receipt identity mismatch")
        ref = reference(value["report_ref"])
        contract = self._contract(state)
        expected = Path(contract["runtime_root"]) / contract["run_id"] / "report.json"
        if ref["path"] != str(expected):
            raise GovernanceBlockerError("Builder receipt is outside the bound Runner evidence root")
        if hashlib.sha256(read_file(expected)).hexdigest() != ref["sha256"]:
            raise ArtifactValidationError("Runner report digest mismatch")
        return value

    def _complete(self, state: dict[str, Any]) -> dict[str, Any]:
        action = state["pending_action"]
        path = self.store.root / (action["id"] + ".result.json")
        raw = read_file(path)
        result = closed(decode(raw), {"schema_version", "action_id", "kind", "output"}, "action completion")
        if result["schema_version"] != VERSION or result["action_id"] != action["id"] or result["kind"] != action["kind"]:
            raise ArtifactValidationError("Action completion identity mismatch")
        ref = {"path":path.name, "sha256":hashlib.sha256(raw).hexdigest()}
        if action["kind"] == "BUILDER":
            receipt = self._receipt(encode(result["output"]), state)
            return self._save(state, "builder_completed", pending_action=None, phase="RESULT_INGESTION",
                              evidence_refs=state["evidence_refs"] + [ref, receipt["report_ref"]])
        ctx = decode(read_file(self.store.root / (action["id"] + ".context.json")))
        closed(ctx, {"document", "digest"}, "saved planner context")
        expected = build_context(state)
        if ctx != {"document":decode(expected.document), "digest":expected.digest}:
            raise GovernanceBlockerError("Saved planner context is stale or changed")
        decision = parse_decision(encode(result["output"]), state, expected.digest)
        if decision["action"] == "BLOCK":
            return self._save(state, "planner_blocked", latest_decision_ref=ref, pending_action=None,
                              phase="BLOCKED", terminal_state="BLOCKED", terminal_reason="PLANNER_BLOCK: " + decision["reason"], blocker_count=state["blocker_count"]+1)
        if decision["action"] == "PROPOSE_TASK":
            return self._request_gate(state, "GATE_A", latest_decision_ref=ref)
        contract = self._contract(state)
        ingested = self._ingest(state)
        package = C.prepare_gate_b_v3(contract, ingested)
        package_ref = self.store.artifact("gate-b-package.json", package)
        return self._request_gate(state, "GATE_B", package=package_ref, latest_decision_ref=ref)

    def _ingest(self, state: dict[str, Any]) -> dict[str, Any]:
        contract = self._contract(state)
        path = Path(contract["runtime_root"]) / contract["run_id"] / "report.json"
        refs = [ref for ref in state["evidence_refs"] if ref["path"] == str(path)]
        with EvidenceRoot(path.parent, label="Controller bound Runner evidence") as root:
            snapshot = root.snapshot(path.name, label="Completed Runner report")
            if len(refs) != 1 or snapshot.sha256 != refs[0]["sha256"]:
                raise ArtifactValidationError("Missing or changed completed Runner evidence")
            # Hash and ingest the same snapshot under the existing root authority.
            raw = C._json_value_from_snapshot(snapshot, "Completed Runner report")
            result = C._ingest_runner_result_data_v2(contract, raw, root)
        if result["controller_phase"] != "ACCEPTANCE_READY":
            raise GovernanceBlockerError("Runner result is not ACCEPTANCE_READY")
        return result

    def _step(self, state: dict[str, Any]) -> dict[str, Any]:
        self._baseline(state)
        self._contract(state)
        if state["retry_count"] or state["fallback_count"]:
            raise GovernanceBlockerError("Retry/fallback budget is zero")
        if state["pending_action"]:
            action = state["pending_action"]
            if action["status"] == "PREPARED":
                return self._dispatch(state)
            if (self.store.root / (action["id"] + ".result.json")).exists():
                return self._complete(state)
            raise GovernanceBlockerError("AMBIGUOUS_INTERRUPTED_ACTION: automatic replay forbidden")
        phase = state["phase"]
        if phase == "START":
            return self._save(state, "discovery_started", phase="DISCOVERY")
        if phase == "DISCOVERY":
            return self._save(state, "bound_task_discovered", phase="PLANNING")
        if phase in DECISIONS:
            if self.planner is None:
                return state
            return self._claim(state, "PLANNER")
        if phase == "EXECUTION_PREP":
            contract = self._contract(state)
            packet = C.derive_task_packet_v3(contract, self._gate_a(state, contract))
            packet_ref = self.store.artifact("packet.json", packet)
            return self._save(state, "execution_prepared", packet_ref=packet_ref, phase="RUNNER_ACTIVE")
        if phase == "RUNNER_ACTIVE":
            if self.builder is None:
                return state
            return self._claim(state, "BUILDER")
        if phase == "RESULT_INGESTION":
            result = self._ingest(state)
            contract = self._contract(state)
            path = str(Path(contract["runtime_root"]) / contract["run_id"] / "report.json")
            ref = next(ref for ref in state["evidence_refs"] if ref["path"] == path)
            return self._save(state, "result_verified", phase="PLANNER_ASSESSMENT",
                              candidate={"head":result["candidate_head"], "tree":result["candidate_tree"], "ref":result["candidate_ref"]},
                              verification_summary={"deterministic":"PASS", "review":result["review_status"], "report_ref":ref})
        if phase == "CANONICAL_INTEGRATION_PREP":
            self._ingest(state)
            entry = state["gate_b_history"][-1]
            package = self.store.read_artifact(entry["gate"]["binding"]["package"])
            auth = {"authorization_id":entry["gate"]["gate_id"], "gate_b_package_hash":package["gate_b_package_hash"],
                    **{key:package[key] for key in ("candidate_head", "candidate_tree", "expected_canonical_head", "expected_canonical_tree")}}
            C.validate_gate_b_v3(self._contract(state), auth, package)
            return self._save(state, "integration_prepared_only", phase="COMPLETE", terminal_state="COMPLETE",
                              terminal_reason="INTEGRATION_PREPARED_ONLY; canonical repository unchanged")
        return state

    def resume(self, *, max_steps: int = 32) -> dict[str, Any]:
        strict = self._strict_delegate()
        if strict is not None:
            return strict.resume(max_steps=max_steps)
        if type(max_steps) is not int or not 1 <= max_steps <= 64:
            raise ArtifactValidationError("Invalid deterministic step budget")
        with self.store.writer():
            state = self.store.load(recover=True)
            for _ in range(max_steps):
                if state["terminal_state"]:
                    break
                if state["pending_gate"]:
                    try:
                        self._baseline(state)
                    except Exception as exc:
                        state = self._block(self.store.load(), f"{type(exc).__name__}: {str(exc)[:512]}")
                    break
                try:
                    next_state = self._step(state)
                except RunnerError as exc:
                    # Reload because a dispatch claim may have advanced before failure.
                    state = self._block(self.store.load(), f"{exc.error_class.value}: {exc.message}")
                    break
                except Exception as exc:
                    state = self._block(self.store.load(), f"ENVIRONMENT_ERROR: {type(exc).__name__}")
                    break
                if next_state == state:
                    break
                state = next_state
            return compact_report(state)

    def reply(self, *, gate_id: str, revision: int, binding_digest: str, response: str) -> dict[str, Any]:
        strict = self._strict_delegate()
        if strict is not None:
            return strict.reply(gate_id=gate_id, revision=revision, binding_digest=binding_digest, response=response)
        with self.store.writer():
            state = self.store.load(recover=True)
            gate = state["pending_gate"]
            if gate is None or type(revision) is not int or (gate_id, revision, binding_digest) != (gate["gate_id"], state["revision"], gate["binding_digest"]):
                raise GovernanceBlockerError("Stale or replayed human gate reply")
            if response not in {"approve", "deny"}:
                raise GovernanceBlockerError("Human response must be literal approve or deny")
            self._baseline(state)
            self._contract(state)
            history = "gate_a_history" if gate["gate_type"] == "GATE_A" else "gate_b_history"
            authorization = {"gate_id":gate_id, "binding_digest":binding_digest, "decision":"APPROVED"} if response == "approve" else None
            entry = {"gate":gate, "human_response":response, "source":"local-cli", "authorization":authorization}
            changes = {history:state[history] + [entry], "pending_gate":None}
            if response == "deny":
                changes.update(phase="BLOCKED", terminal_state="BLOCKED", terminal_reason="HUMAN_DECLINED", blocker_count=state["blocker_count"]+1)
            else:
                changes["phase"] = "EXECUTION_PREP" if gate["gate_type"] == "GATE_A" else "CANONICAL_INTEGRATION_PREP"
            state = self._save(state, "human_response_recorded", **changes)
            return compact_report(state)

    def status(self) -> dict[str, Any]:
        strict = self._strict_delegate()
        if strict is not None:
            return strict.status()
        state = self.store.load()
        self._contract(state)
        return compact_report(state)

    def wait(self, *, timeout: float = 30.0, interval: float = 0.1) -> dict[str, Any]:
        strict = self._strict_delegate()
        if strict is not None:
            return strict.wait(timeout=timeout, interval=interval)
        if not 0 <= timeout <= 60 or not 0 < interval <= 1:
            raise ArtifactValidationError("Wait requires timeout 0..60 seconds and interval 0..1")
        deadline = time.monotonic() + timeout
        while True:
            report = self.status()
            if report["status"] != "RUNNING" or time.monotonic() >= deadline:
                return report
            time.sleep(min(interval, max(0, deadline-time.monotonic())))


def add_cli(subparsers: Any) -> None:
    parser = subparsers.add_parser("control", help="Durable controller core (real adapters deferred)")
    commands = parser.add_subparsers(dest="control_command", required=True)
    for command in ("start", "status", "wait", "reply", "resume"):
        item = commands.add_parser(command)
        item.add_argument("--session", type=Path, required=True)
        item.add_argument("--json", action="store_true", dest="control_json")
        if command == "start":
            item.add_argument("--id", required=True)
            item.add_argument("--goal", required=True)
            item.add_argument("--contract", type=Path, required=True)
            item.add_argument("--planner-profile", required=True)
            item.add_argument("--builder-profile", required=True)
        elif command == "wait":
            item.add_argument("--timeout", type=float, default=30.0)
        elif command == "reply":
            item.add_argument("--gate-id", required=True)
            item.add_argument("--revision", type=int, required=True)
            item.add_argument("--binding-digest", required=True)
            item.add_argument("--response", choices=("approve", "deny"), required=True)


def run_cli(args: Any) -> int:
    try:
        controller = DurableController(args.session)
        if args.control_command == "start":
            controller = DurableController.start(args.session, controller_id=args.id, goal=args.goal,
                contract_path=args.contract, planner_profile_ref=args.planner_profile, builder_profile_ref=args.builder_profile)
            report = controller.status()
        elif args.control_command == "reply":
            report = controller.reply(gate_id=args.gate_id, revision=args.revision, binding_digest=args.binding_digest, response=args.response)
        elif args.control_command == "resume":
            report = controller.resume()
        elif args.control_command == "wait":
            report = controller.wait(timeout=args.timeout)
        else:
            report = controller.status()
        if report["status"] == "RUNNING" and args.control_command == "resume":
            report["note"] = "Real adapters are deferred to CTRL-R002; no execution was launched."
        print(json.dumps(report, indent=2, sort_keys=True) if args.control_json else format_report(report))
        if not args.control_json and "note" in report:
            print(report["note"])
        return 20 if report["status"] == "BLOCKED" else 10 if report["status"] == "HUMAN_GATE_REQUIRED" else 0
    except (RunnerError, OSError) as exc:
        error_class = exc.error_class.value if isinstance(exc, RunnerError) else "ENVIRONMENT_ERROR"
        print(json.dumps({"status":"BLOCKED", "error_class":error_class, "reason":str(exc)}))
        return 20


# ---------------------------------------------------------------------------
# R3C strict execution lifecycle
# ---------------------------------------------------------------------------


def _strict_jsonable(value: Any) -> Any:
    """Convert provider-facing values to bounded JSON without trusting repr()."""
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _strict_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strict_jsonable(item) for item in value]
    if hasattr(value, "__dict__"):
        return _strict_jsonable(vars(value))
    raise ArtifactValidationError("Strict action result is not JSON serializable")


def _strict_read_json(path: Path) -> Any:
    return decode(read_file(path))


def _strict_git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except OSError as exc:
        raise GovernanceBlockerError(f"Git unavailable: {exc}") from exc
    if result.returncode != 0:
        raise GovernanceBlockerError(
            f"Git command failed: {' '.join(args)}: {(result.stderr or result.stdout).strip()}"
        )
    return result.stdout.strip()


def _strict_changed_paths(worktree: Path, baseline_head: str) -> list[str]:
    tracked = _strict_git(worktree, "diff", "--name-only", baseline_head).splitlines()
    untracked = _strict_git(worktree, "ls-files", "--others", "--exclude-standard").splitlines()
    return sorted(set(path for path in (*tracked, *untracked) if path))


def _strict_load_value(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, (str, Path)):
        loaded = decode(read_file(Path(value)))
    else:
        loaded = value
    if not isinstance(loaded, dict):
        raise ArtifactValidationError(f"{label} must be a JSON object")
    return _strict_jsonable(loaded)


def _strict_ref(value: Mapping[str, Any], label: str = "strict artifact reference") -> dict[str, str]:
    """Convert the store's legacy locator return into the strict ``ref`` shape."""
    if not isinstance(value, Mapping):
        raise ArtifactValidationError(f"{label} is not a reference object")
    name = value.get("ref", value.get("path"))
    result = {"ref": name, "sha256": value.get("sha256")}
    strict_reference(result, label)
    return result


class StrictExecutionController:
    """Durable R3C controller with explicit at-most-once action claims.

    The class is intentionally independent of the legacy ``DurableController``.
    A strict run is selected by this class (or one of its compatibility aliases)
    and therefore cannot silently reinterpret an existing CTRL-R001 store.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        planner: Any = None,
        builder: Any = None,
        verifier: Any = None,
        reviewer: Any = None,
    ) -> None:
        self.store = ControlStore(root)
        self.planner = planner
        self.builder = builder
        self.verifier = verifier
        self.reviewer = reviewer
        self._contract_data: dict[str, Any] | None = None
        self._runtime_data: dict[str, Any] | None = None
        self._packet_data: dict[str, Any] | None = None

    @classmethod
    def start(
        cls,
        root: Path | str,
        *,
        controller_id: str,
        goal: str,
        contract: Mapping[str, Any] | Path | str | None = None,
        contract_path: Path | str | None = None,
        runtime: Mapping[str, Any] | Path | str | None = None,
        runtime_path: Path | str | None = None,
        packet: Mapping[str, Any] | Path | str | None = None,
        packet_path: Path | str | None = None,
        baseline: Mapping[str, Any] | None = None,
        repository: Path | str | None = None,
        task_id: str | None = None,
        scope: Sequence[str] | None = None,
        approved_scope: Sequence[str] | None = None,
        planner_profile_ref: str | None = None,
        builder_profile_ref: str | None = None,
        reviewer_profile_ref: str | None = None,
        max_repair_cycles: int = 2,
        planner: Any = None,
        builder: Any = None,
        verifier: Any = None,
        reviewer: Any = None,
    ) -> "StrictExecutionController":
        instance = cls(root, planner=planner, builder=builder, verifier=verifier, reviewer=reviewer)
        if contract is not None and contract_path is not None:
            raise ArtifactValidationError("Provide either contract or contract_path, not both")
        if runtime is not None and runtime_path is not None:
            raise ArtifactValidationError("Provide either runtime or runtime_path, not both")
        if packet is not None and packet_path is not None:
            raise ArtifactValidationError("Provide either packet or packet_path, not both")
        contract_data = _strict_load_value(contract_path or contract, "strict contract") if (contract_path or contract) is not None else {}
        runtime_data = _strict_load_value(runtime_path or runtime, "strict runtime") if (runtime_path or runtime) is not None else {}
        packet_data = _strict_load_value(packet_path or packet, "strict packet") if (packet_path or packet) is not None else None

        # A qualified runtime bundle is validated structurally without probing
        # provider executables during state creation.  R3B performs the live
        # executable and session checks at invocation time.
        if runtime_data.get("schema_version") == "PRJ226.CONTROL_RUNTIME.v1":
            runtime_data = validate_runtime(runtime_data, verify_executables=False)
        roles = runtime_data.get("roles") if isinstance(runtime_data.get("roles"), dict) else {}

        def role_ref(role: str, explicit: str | None) -> str:
            if explicit is not None:
                if not isinstance(explicit, str) or not explicit.strip():
                    raise ArtifactValidationError(f"Invalid {role} profile reference")
                configured = roles.get(role, {}) if isinstance(roles, dict) else {}
                configured_ref = configured.get("profile_ref") if isinstance(configured, dict) else None
                if configured_ref is not None and configured_ref != explicit:
                    raise GovernanceBlockerError(f"{role} profile substitution forbidden")
                return explicit
            value = roles.get(role, {}) if isinstance(roles, dict) else {}
            candidate = value.get("profile_ref") if isinstance(value, dict) else None
            return candidate if isinstance(candidate, str) and candidate else f"strict-{role}-profile"

        planner_profile_ref = role_ref("planner", planner_profile_ref)
        builder_profile_ref = role_ref("builder", builder_profile_ref)
        reviewer_profile_ref = role_ref("reviewer", reviewer_profile_ref)
        if type(max_repair_cycles) is not int or not 0 <= max_repair_cycles <= 2:
            raise ArtifactValidationError("max_repair_cycles must be an integer from 0 through 2")

        repository_value = repository
        if repository_value is None:
            repository_value = contract_data.get("repository_path") or contract_data.get("repository")
        baseline_data = dict(baseline or {})
        if repository_value is not None:
            baseline_data.setdefault("repository", str(Path(repository_value).resolve()))
        for target, source in (("branch", "canonical_branch"), ("head", "baseline_head"), ("tree", "baseline_tree")):
            if target not in baseline_data and source in contract_data:
                baseline_data[target] = contract_data[source]
        required_baseline = {"repository", "branch", "head", "tree"}
        if set(baseline_data) != required_baseline:
            raise ArtifactValidationError("Strict controller requires an exact canonical baseline")
        baseline_data["repository"] = str(Path(baseline_data["repository"]).resolve())
        baseline_data["head"] = str(baseline_data["head"]).lower()
        baseline_data["tree"] = str(baseline_data["tree"]).lower()
        repository_path = Path(baseline_data["repository"])
        scope_values = list(approved_scope if approved_scope is not None else (scope if scope is not None else contract_data.get("owned_paths", contract_data.get("scope", []))))
        if not scope_values:
            raise ArtifactValidationError("Strict controller requires a non-empty approved scope")
        if task_id is None:
            task_id = contract_data.get("work_item_id") or contract_data.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            raise ArtifactValidationError("Strict controller requires task_id")
        if instance.store.root == repository_path or repository_path in instance.store.root.parents:
            raise GovernanceBlockerError("Strict controller evidence must be outside the canonical repository")
        instance._assert_baseline_values(baseline_data)

        if not contract_data:
            contract_data = {
                "contract_version": "PRJ226.R3C.CONTRACT.v1",
                "controller_id": controller_id,
                "task_id": task_id,
                "goal": goal,
                "repository_path": baseline_data["repository"],
                "canonical_branch": baseline_data["branch"],
                "baseline_head": baseline_data["head"],
                "baseline_tree": baseline_data["tree"],
                "owned_paths": scope_values,
            }
        if packet_data is not None:
            validate_task_packet_v3(packet_data, approved_scope=scope_values)
            if contract_data.get("contract_version") == R.V3_CONTRACT_VERSION:
                R.validate_task_packet_derivation_v3(contract_data, packet_data)
            packet_scope = packet_data.get("authorized_paths")
            if packet_scope is not None and list(packet_scope) != scope_values:
                raise GovernanceBlockerError("Strict packet widens or changes Gate A scope")

        root_path = instance.store.root
        root_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        root_path.mkdir(mode=0o700, exist_ok=False)
        fsync_directory(root_path.parent)
        with instance.store.writer():
            contract_ref = _strict_ref(instance.store.artifact("contract.json", contract_data), "contract reference")
            runtime_ref = _strict_ref(instance.store.artifact("runtime.json", runtime_data or {"schema_version": "PRJ226.CONTROL_RUNTIME.v1", "roles": {}}), "runtime reference")
            packet_ref = _strict_ref(instance.store.artifact("packet.json", packet_data), "packet reference") if packet_data is not None else None
            state: dict[str, Any] = {
                "schema_version": STRICT_VERSION,
                "controller_id": controller_id,
                "task_id": task_id,
                "goal": goal,
                "revision": 1,
                "baseline": baseline_data,
                "scope": list(scope_values),
                "approved_scope": list(scope_values),
                "contract_ref": contract_ref,
                "runtime_ref": runtime_ref,
                "packet_ref": packet_ref,
                "planner_profile_ref": planner_profile_ref,
                "builder_profile_ref": builder_profile_ref,
                "reviewer_profile_ref": reviewer_profile_ref,
                "repair_policy": {"max_repair_cycles": max_repair_cycles},
                "phase": "START",
                "attempt_index": 0,
                "repair_cycles": 0,
                "planner_session": None,
                "builder_session": None,
                "reviewer_session": None,
                "planner_sessions": [],
                "builder_sessions": [],
                "reviewer_sessions": [],
                "gate_a": None,
                "gate_b": None,
                "gate_a_history": [],
                "gate_b_history": [],
                "pending_gate": None,
                "pending_action": None,
                "action_history": [],
                "candidate": None,
                "verification": None,
                "review": None,
                "repair_history": [],
                "evidence_refs": [],
                "latest_result_ref": None,
                **{key: 0 for key in STRICT_COUNTERS},
                "terminal_state": None,
                "terminal_reason": None,
            }
            validate_strict_state(state)
            instance.store.commit(state, "strict_controller_created")
        instance._contract_data = contract_data
        instance._runtime_data = runtime_data
        instance._packet_data = packet_data
        return instance

    def _inputs(self, state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
        contract = self.store.read_artifact(state["contract_ref"])
        runtime = self.store.read_artifact(state["runtime_ref"])
        packet = self.store.read_artifact(state["packet_ref"]) if state["packet_ref"] is not None else None
        if not isinstance(contract, dict) or not isinstance(runtime, dict) or (packet is not None and not isinstance(packet, dict)):
            raise ArtifactValidationError("Strict controller inputs are not JSON objects")
        if packet is not None:
            validate_task_packet_v3(packet, approved_scope=state["scope"])
            if contract.get("contract_version") == R.V3_CONTRACT_VERSION:
                R.validate_task_packet_derivation_v3(contract, packet)
            if packet.get("task_id") != state["task_id"]:
                raise GovernanceBlockerError("Strict Task Packet task_id is not bound to controller authority")
        self._contract_data, self._runtime_data, self._packet_data = contract, runtime, packet
        return contract, runtime, packet

    @staticmethod
    def _assert_baseline_values(baseline: Mapping[str, Any]) -> None:
        repository = Path(str(baseline["repository"]))
        observed = (
            _strict_git(repository, "branch", "--show-current"),
            _strict_git(repository, "rev-parse", "HEAD").lower(),
            _strict_git(repository, "rev-parse", "HEAD^{tree}").lower(),
            _strict_git(repository, "status", "--porcelain=v1", "--untracked-files=all"),
        )
        expected = (baseline["branch"], str(baseline["head"]).lower(), str(baseline["tree"]).lower(), "")
        if observed != expected:
            raise GovernanceBlockerError("Canonical baseline drift")

    def _baseline(self, state: dict[str, Any]) -> None:
        self._assert_baseline_values(state["baseline"])

    def _save(self, state: dict[str, Any], kind: str, **changes: Any) -> dict[str, Any]:
        return self.store.commit({**state, **changes, "revision": state["revision"] + 1}, kind)

    def _block(self, state: dict[str, Any], reason: str) -> dict[str, Any]:
        if state["phase"] == "BLOCKED":
            return state
        return self._save(
            state,
            "strict_controller_blocked",
            phase="BLOCKED",
            terminal_state="BLOCKED",
            terminal_reason=reason[:2048],
            pending_gate=None,
            pending_action=None,
        )

    def _action_claim(self, state: dict[str, Any], kind: str) -> dict[str, Any]:
        if kind not in {"PLANNER", "BUILDER", "FREEZE", "VERIFIER", "REVIEWER"}:
            raise ArtifactValidationError("Invalid strict action kind")
        action = {
            "id": f"action-{state['revision'] + 1}",
            "kind": kind,
            "status": "PREPARED",
            "attempt_index": state["attempt_index"],
            "revision": state["revision"] + 1,
        }
        return self._save(state, "strict_action_prepared", pending_action=action)

    def _mark_started(self, state: dict[str, Any]) -> dict[str, Any]:
        action = state["pending_action"]
        if action is None or action["status"] != "PREPARED":
            raise GovernanceBlockerError("Strict action is not PREPARED")
        counter_key = {
            "PLANNER": "planner_invocations",
            "BUILDER": "builder_invocations",
            "FREEZE": "freeze_invocations",
            "VERIFIER": "verifier_invocations",
            "REVIEWER": "reviewer_invocations",
        }[action["kind"]]
        started = {**action, "status": "STARTED", "revision": state["revision"] + 1}
        return self._save(
            state,
            "strict_action_started",
            pending_action=started,
            **{counter_key: state[counter_key] + 1},
        )

    def _result_path(self, action_id: str) -> Path:
        return self.store.root / f"{action_id}.result.json"

    def _persist_result(self, action: dict[str, Any], outcome: Mapping[str, Any]) -> dict[str, str]:
        value = {
            "schema_version": STRICT_VERSION,
            "action_id": action["id"],
            "kind": action["kind"],
            "attempt_index": action["attempt_index"],
            "status": "COMPLETED",
            "outcome": _strict_jsonable(dict(outcome)),
        }
        return _strict_ref(self.store.artifact(f"{action['id']}.result.json", value), "strict action result reference")

    def _load_result(self, state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        action = state["pending_action"]
        if action is None:
            raise GovernanceBlockerError("No strict action is pending")
        path = self._result_path(action["id"])
        raw = read_file(path)
        value = decode(raw)
        if not isinstance(value, dict) or set(value) != {"schema_version", "action_id", "kind", "attempt_index", "status", "outcome"}:
            raise ArtifactValidationError("Strict action result has an invalid closed envelope")
        if value["schema_version"] != STRICT_VERSION or value["action_id"] != action["id"] or value["kind"] != action["kind"] or value["attempt_index"] != action["attempt_index"] or value["status"] != "COMPLETED":
            raise ArtifactValidationError("Strict action result identity mismatch")
        if not isinstance(value["outcome"], dict):
            raise ArtifactValidationError("Strict action result outcome is not an object")
        return value["outcome"], {"ref": path.name, "sha256": hashlib.sha256(raw).hexdigest()}

    def _record_session(self, state: dict[str, Any], kind: str, session_id: str | None) -> dict[str, Any]:
        if kind not in {"PLANNER", "BUILDER", "REVIEWER"}:
            raise GovernanceBlockerError("GOVERNANCE BLOCK: invalid role session kind")
        if not isinstance(session_id, str) or not session_id.strip():
            raise GovernanceBlockerError("GOVERNANCE BLOCK: missing role session ID")
        session_id = session_id.strip()
        all_sessions = state["planner_sessions"] + state["builder_sessions"] + state["reviewer_sessions"]
        if session_id in all_sessions:
            raise GovernanceBlockerError("GOVERNANCE BLOCK: reused or duplicate session ID")
        mapping = {
            "PLANNER": ("planner_sessions", "planner_session"),
            "BUILDER": ("builder_sessions", "builder_session"),
            "REVIEWER": ("reviewer_sessions", "reviewer_session"),
        }
        list_key, current_key = mapping[kind]
        return {list_key: state[list_key] + [session_id], current_key: session_id}

    def _profile(self, runtime: Mapping[str, Any], role: str) -> dict[str, Any]:
        roles = runtime.get("roles")
        profile = roles.get(role) if isinstance(roles, Mapping) else None
        if isinstance(profile, Mapping):
            return dict(profile)
        return {"profile_ref": "", "model": "gpt-6-astra" if role == "reviewer" else ""}

    def _context_bytes(self, state: dict[str, Any], action: dict[str, Any], *, candidate: dict[str, Any] | None = None) -> bytes:
        contract, runtime, packet = self._inputs(state)
        context = {
            "schema_version": STRICT_VERSION,
            "controller_id": state["controller_id"],
            "task_id": state["task_id"],
            "goal": state["goal"],
            "phase": state["phase"],
            "attempt_index": state["attempt_index"],
            "approved_scope": state["approved_scope"],
            "baseline": state["baseline"],
            "repair_history": state["repair_history"],
            "contract": contract,
            "packet": packet,
            "candidate": candidate,
            "action_id": action["id"],
        }
        return encode(context)

    def _call_role(self, role: str, adapter: Any, request: StrictExecutionRequest, context: bytes, cwd: Path) -> Any:
        if adapter is None:
            raise GovernanceBlockerError(f"No {role} adapter is configured")
        runtime = self._runtime_data or {}
        profile = self._profile(runtime, role)
        adapter_profile = getattr(adapter, "profile_ref", None)
        configured_profile = profile.get("profile_ref")
        if adapter_profile is not None and configured_profile and adapter_profile != configured_profile:
            raise GovernanceBlockerError(f"{role} adapter profile substitution forbidden")
        evidence_dir = self.store.root / "invocations" / request.action_id / role
        evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        execute_role = getattr(adapter, "execute_role", None)
        if callable(execute_role):
            return execute_role(
                role_name=role,
                profile=profile,
                task_id=request.task_id,
                context_bytes=context,
                cwd=cwd,
                evidence_dir=evidence_dir,
            )
        if role == "planner" and callable(getattr(adapter, "decide", None)):
            return adapter.decide(PlannerContext(context, hashlib.sha256(context).hexdigest()))
        if callable(getattr(adapter, "execute", None)):
            return adapter.execute(request)
        if callable(getattr(adapter, "invoke", None)):
            return adapter.invoke(request)
        if callable(adapter):
            return adapter(request)
        raise GovernanceBlockerError(f"Configured {role} adapter is not callable")

    @staticmethod
    def _supervision_value(receipt: Any, record: Mapping[str, Any]) -> dict[str, Any] | None:
        evidence = getattr(receipt, "supervision_evidence", None)
        if evidence is None and isinstance(record.get("supervision"), Mapping):
            return dict(record["supervision"])
        if evidence is None:
            return None
        return {
            "exit_code": getattr(evidence, "returncode", getattr(evidence, "exit_code", None)),
            "quiescent": getattr(evidence, "final_group_quiescent", getattr(evidence, "quiescent", False)),
            "timeout_event": getattr(evidence, "timeout_event", False),
            "term_event": getattr(evidence, "term_event", False),
            "kill_event": getattr(evidence, "kill_event", False),
            "output_flood": False,
        }

    def _normalize_receipt(self, raw: Any, role: str) -> dict[str, Any]:
        if isinstance(raw, (str, bytes)):
            raise ArtifactValidationError(f"{role} result must be a validated InvocationReceipt")
        if isinstance(raw, Mapping):
            value = dict(raw)
            nested = value.get("receipt")
            if nested is not None and isinstance(nested, Mapping):
                value = {**value, **dict(nested)}
        else:
            value = {}
        session_id = getattr(raw, "session_id", value.get("session_id"))
        observed_role = getattr(raw, "role", value.get("role"))
        if observed_role is not None and str(observed_role).upper() != role.upper():
            raise GovernanceBlockerError("Invocation receipt role identity mismatch")
        disposition = getattr(raw, "disposition", value.get("disposition", "SUCCESS"))
        exit_code = getattr(raw, "exit_code", value.get("exit_code", 0))
        record = getattr(raw, "record", value.get("record", {}))
        if not isinstance(record, Mapping):
            record = {}
        record = _strict_jsonable(dict(record))
        supervision = self._supervision_value(raw, record)
        if supervision is None and isinstance(value.get("supervision"), Mapping):
            supervision = dict(value["supervision"])
        attestation = getattr(raw, "attestation_result", None)
        attested = getattr(
            attestation,
            "attestation_passed",
            value.get("attestation_passed", record.get("attestation", {}).get("attestation_passed") if isinstance(record.get("attestation"), Mapping) else None),
        )
        attested_session_id = getattr(attestation, "session_id", None)
        if attested_session_id is None:
            attested_session_id = getattr(raw, "attested_session_id", value.get("attested_session_id"))
        if attested_session_id is None and isinstance(record.get("attestation"), Mapping):
            attested_session_id = record["attestation"].get("attested_session_id", record["attestation"].get("session_id"))
        explicit_receipt = (
            hasattr(raw, "invocation_id")
            or "invocation_id" in value
            or "attested_session_id" in value
            or "attestation" in value
            or isinstance(raw, Mapping) and isinstance(raw.get("receipt"), Mapping)
        )
        semantic = getattr(raw, "semantic_result", value.get("semantic_result", record.get("semantic_result")))
        semantic = _strict_jsonable(semantic) if semantic is not None else None
        provider_receipt = True
        try:
            normalized_exit_code = int(exit_code)
        except (TypeError, ValueError) as exc:
            raise ArtifactValidationError("Invocation receipt exit_code is invalid") from exc
        ok = str(disposition).upper() in {"SUCCESS", "COMPLETED"} and normalized_exit_code == 0
        failure_reason: str | None = None
        if not isinstance(session_id, str) or not session_id.strip() or not isinstance(attested_session_id, str) or not attested_session_id.strip():
            ok = False
            failure_reason = "SESSION_ATTESTATION_MISMATCH"
        elif attested_session_id != session_id:
            ok = False
            failure_reason = "ATTESTATION_MISMATCH"
        quiescent = supervision.get("quiescent") if isinstance(supervision, Mapping) else None
        if quiescent is None and isinstance(supervision, Mapping):
            quiescent = supervision.get("final_group_quiescent")
        if supervision is None or quiescent is not True:
            ok = False
            failure_reason = "NON_QUIESCENT_PROCESS_GROUP"
        if isinstance(supervision, Mapping) and any(
            supervision.get(key) is True for key in ("timeout_event", "kill_event", "output_flood")
        ):
            ok = False
            if supervision.get("output_flood") is True:
                failure_reason = "OUTPUT_FLOOD"
            elif supervision.get("timeout_event") is True:
                failure_reason = "TIMEOUT"
            elif supervision.get("kill_event") is True:
                failure_reason = "KILL"
        if attested is not True:
            ok = False
            failure_reason = "ATTESTATION_MISMATCH"
        if normalized_exit_code != 0:
            failure_reason = failure_reason or "PROVIDER_EXIT_NONZERO"
        return {
            "ok": ok,
            "session_id": session_id,
            "attested_session_id": attested_session_id,
            "exit_code": normalized_exit_code,
            "disposition": disposition,
            "supervision": _strict_jsonable(supervision),
            "attestation_passed": bool(attested) if attested is not None else None,
            "semantic_result": semantic,
            "proposal": value.get("proposal"),
            "explicit_receipt": explicit_receipt,
            "record": record,
            "provider_receipt": provider_receipt,
            "evidence_digest": getattr(raw, "evidence_digest", value.get("evidence_digest")),
            "failure_reason": failure_reason,
        }

    def _builder_operation(self, state: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        repository = Path(state["baseline"]["repository"])
        attempt_dir = self.store.root / f"attempt-{action['attempt_index']}"
        worktree = attempt_dir / "builder-worktree"
        run_suffix = hashlib.sha256(str(self.store.root).encode("utf-8")).hexdigest()[:10]
        branch = f"prj226-{state['controller_id'].lower()}-{run_suffix}-attempt-{action['attempt_index']}"
        if worktree.exists():
            raise GovernanceBlockerError("Planned builder worktree already exists")
        attempt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _strict_git(repository, "worktree", "add", "-b", branch, str(worktree), state["baseline"]["head"])
        context = self._context_bytes(state, action)
        request = StrictExecutionRequest(
            action_id=action["id"], task_id=state["task_id"], attempt_index=action["attempt_index"],
            worktree=str(worktree), scope=tuple(state["scope"]), context_json=context,
            contract_json=encode(self._contract_data or {}), runtime_json=encode(self._runtime_data or {}),
        )
        receipt = self._normalize_receipt(self._call_role("builder", self.builder, request, context, worktree), "builder")
        # A builder is confined to its candidate worktree; re-check the
        # canonical repository before accepting any builder evidence.
        self._baseline(state)
        if not receipt["ok"]:
            raise GovernanceBlockerError(receipt.get("failure_reason") or "BUILDER_INVOCATION_FAILED")
        if _strict_git(worktree, "rev-parse", "HEAD").lower() != state["baseline"]["head"].lower():
            raise GovernanceBlockerError("BUILDER_COMMIT_DETECTED")
        changed = _strict_changed_paths(worktree, state["baseline"]["head"])
        unauthorized = sorted(set(changed) - set(state["scope"]))
        if unauthorized:
            raise GovernanceBlockerError(f"SCOPE_BREACH: builder changed unauthorized paths {unauthorized}")
        if not changed:
            raise GovernanceBlockerError("BUILDER_PRODUCED_NO_CHANGES")
        diff_check = subprocess.run(
            ["git", "-C", str(worktree), "diff", "--check"], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, shell=False, check=False,
        )
        if diff_check.returncode != 0:
            raise GovernanceBlockerError("BUILDER_DIFF_CHECK_FAILED")
        return {
            "ok": True,
            "session_id": receipt["session_id"],
            "receipt": receipt,
            "worktree": str(worktree),
            "branch": branch,
            "changed_paths": changed,
        }

    def _last_outcome(self, state: dict[str, Any], kind: str, attempt: int | None = None) -> dict[str, Any]:
        for item in reversed(state["action_history"]):
            if item["kind"] == kind and (attempt is None or item["attempt_index"] == attempt):
                value = self.store.read_artifact(item["result_ref"])
                if not isinstance(value, dict) or not isinstance(value.get("outcome"), dict):
                    raise ArtifactValidationError("Strict action history result is malformed")
                return value["outcome"]
        raise GovernanceBlockerError(f"Missing completed strict {kind} action")

    def _freeze_operation(self, state: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        builder = self._last_outcome(state, "BUILDER", action["attempt_index"])
        if builder.get("ok") is not True:
            raise GovernanceBlockerError("Cannot freeze an unsuccessful builder action")
        worktree = Path(str(builder["worktree"]))
        branch = str(builder["branch"])
        changed = list(builder["changed_paths"])
        self._baseline(state)
        if _strict_git(worktree, "rev-parse", "HEAD").lower() != state["baseline"]["head"].lower():
            raise GovernanceBlockerError("BUILDER_COMMIT_DETECTED")
        if sorted(set(_strict_changed_paths(worktree, state["baseline"]["head"]))) != sorted(changed):
            raise GovernanceBlockerError("SCOPE_BREACH: changed paths changed before freeze")
        if set(changed) - set(state["scope"]):
            raise GovernanceBlockerError("SCOPE_BREACH: freeze path set is outside approved scope")
        check = subprocess.run(
            ["git", "-C", str(worktree), "diff", "--check"], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, shell=False, check=False,
        )
        if check.returncode != 0:
            raise GovernanceBlockerError("git diff --check failed before freeze")
        for path in changed:
            _strict_git(worktree, "add", "--", path)
        staged = _strict_git(worktree, "diff", "--cached", "--name-only", state["baseline"]["head"]).splitlines()
        if sorted(staged) != sorted(changed):
            raise GovernanceBlockerError("Freeze staging did not exactly match approved scope")
        contract = self._contract_data or {}
        message = contract.get("commit_message") or f"candidate: {state['task_id']} attempt {action['attempt_index']}"
        if not isinstance(message, str) or not message.strip():
            raise ArtifactValidationError("Strict candidate commit message is invalid")
        _strict_git(worktree, "commit", "-m", message)
        head = _strict_git(worktree, "rev-parse", "HEAD").lower()
        tree = _strict_git(worktree, "rev-parse", "HEAD^{tree}").lower()
        parents = _strict_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()
        if len(parents) != 2 or parents[1].lower() != state["baseline"]["head"].lower():
            raise GovernanceBlockerError("Candidate topology does not have the canonical baseline as its sole parent")
        authority = build_candidate_authority(
            worktree,
            head,
            branch,
            state["baseline"]["head"],
            changed,
            transient_paths=(contract.get("transient_paths") or []),
        )
        authority_ref = _strict_ref(
            self.store.artifact(f"candidate-authority-{action['attempt_index']}.json", authority),
            "candidate authority reference",
        )
        verify_candidate_authority(worktree, authority, expected_ref=branch)
        return {
            "ok": True,
            "candidate": {
                "head": head,
                "tree": tree,
                "ref": branch,
                "authority_ref": authority_ref,
                "worktree": str(worktree),
                "attempt_index": action["attempt_index"],
                "changed_paths": changed,
            },
        }

    def _candidate_authority(self, state: dict[str, Any]) -> tuple[dict[str, Any], Path]:
        candidate = state["candidate"]
        if candidate is None:
            raise GovernanceBlockerError("No frozen candidate is available")
        worktree = Path(candidate["worktree"]).resolve()
        try:
            worktree.relative_to(self.store.root)
        except ValueError as exc:
            raise GovernanceBlockerError("Candidate worktree is outside the controller runtime boundary") from exc
        authority = self.store.read_artifact(candidate["authority_ref"])
        if not isinstance(authority, dict):
            raise ArtifactValidationError("Candidate authority is not an object")
        verify_candidate_authority(worktree, authority, expected_ref=candidate["ref"])
        return authority, worktree

    def _test_commands(self) -> list[list[str]]:
        packet = self._packet_data or {}
        contract = self._contract_data or {}
        commands = packet.get("test_commands", contract.get("acceptance_instruments", []))
        if not isinstance(commands, list):
            raise ArtifactValidationError("Approved verifier commands are malformed")
        result: list[list[str]] = []
        for command in commands:
            if not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg for arg in command):
                raise ArtifactValidationError("Approved verifier commands must be argv arrays")
            result.append(list(command))
        return result

    def _verifier_operation(self, state: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        authority, worktree = self._candidate_authority(state)
        self._baseline(state)
        candidate = state["candidate"]
        context = self._context_bytes(state, action, candidate=candidate)
        request = StrictExecutionRequest(
            action_id=action["id"], task_id=state["task_id"], attempt_index=action["attempt_index"],
            worktree=str(worktree), scope=tuple(state["scope"]), context_json=context,
            contract_json=encode(self._contract_data or {}), runtime_json=encode(self._runtime_data or {}),
            candidate_json=encode(candidate),
        )
        if self.verifier is not None:
            raw = self.verifier.execute(request) if callable(getattr(self.verifier, "execute", None)) else self.verifier(request) if callable(self.verifier) else None
            if not isinstance(raw, Mapping):
                raise ArtifactValidationError("Verifier result must be a JSON object")
            result = _strict_jsonable(dict(raw))
            status = result.get("status", result.get("verdict"))
            if status not in {"PASS", "FAIL", "BLOCKED"}:
                raise ArtifactValidationError("Verifier result must be PASS, FAIL, or BLOCKED")
            result["status"] = status
            if status == "FAIL":
                result.setdefault("eligible_repair", True)
            result["ok"] = status != "BLOCKED"
            verify_candidate_authority(worktree, authority, expected_ref=candidate["ref"])
            return result
        tests = self._test_commands()
        results: list[dict[str, Any]] = []
        canonical = Path(state["baseline"]["repository"]).resolve()
        scratch_temp = self.store.root / "verifier-scratch"
        scratch_home = scratch_temp / "home"
        scratch_temp.mkdir(mode=0o700, parents=True, exist_ok=True)
        scratch_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        writable_roots = [scratch_temp, scratch_home]
        repository_roots = [worktree, canonical]
        verifier_env = os.environ.copy()
        verifier_env.update({
            "TMPDIR": str(scratch_temp),
            "TMP": str(scratch_temp),
            "TEMP": str(scratch_temp),
            "HOME": str(scratch_home),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        for index, argv in enumerate(tests, 1):
            try:
                completed = R.execute_confined_command(
                    argv,
                    cwd=worktree,
                    timeout=300,
                    env=verifier_env,
                    repository_roots=repository_roots,
                    writable_roots=writable_roots,
                )
            except GovernanceBlockerError:
                raise
            except Exception as exc:
                message = str(exc).lower()
                if "log limit" in message or "output flood" in message:
                    return {"ok": False, "status": "BLOCKED", "reason": "OUTPUT_FLOOD", "eligible_repair": False, "tests": results}
                if "timeout" in message or "timed out" in message:
                    return {"ok": False, "status": "BLOCKED", "reason": "TIMEOUT", "eligible_repair": False, "tests": results}
                if "survivor" in message or "quiescen" in message:
                    return {"ok": False, "status": "BLOCKED", "reason": "NON_QUIESCENT_PROCESS_GROUP", "eligible_repair": False, "tests": results}
                return {"ok": False, "status": "BLOCKED", "reason": "VERIFIER_ENVIRONMENT_ERROR", "eligible_repair": False, "tests": results}
            if completed.supervision.timeout_event:
                return {"ok": False, "status": "BLOCKED", "reason": "TIMEOUT", "eligible_repair": False, "tests": results}
            item = {"index": index, "argv": argv, "exit_code": completed.returncode}
            results.append(item)
            verify_candidate_authority(worktree, authority, expected_ref=candidate["ref"])
            self._baseline(state)
            if completed.returncode != 0:
                return {
                    "ok": False, "status": "FAIL", "reason": "DETERMINISTIC_TEST_FAILURE",
                    "eligible_repair": True, "tests": results,
                }
        check = R.execute_confined_command(
            ["git", "-C", str(worktree), "diff", "--check", f"{state['baseline']['head']}..{candidate['head']}"],
            cwd=worktree,
            timeout=30,
            env=verifier_env,
            repository_roots=repository_roots,
            writable_roots=writable_roots,
        )
        if check.supervision.timeout_event:
            return {"ok": False, "status": "BLOCKED", "reason": "TIMEOUT", "eligible_repair": False, "tests": results}
        if check.returncode != 0:
            return {"ok": False, "status": "FAIL", "reason": "DETERMINISTIC_DIFF_CHECK_FAILURE", "eligible_repair": True, "tests": results}
        self._baseline(state)
        verify_candidate_authority(worktree, authority, expected_ref=candidate["ref"])
        return {"ok": True, "status": "PASS", "reason": "ALL_DETERMINISTIC_CHECKS_PASSED", "eligible_repair": False, "tests": results}

    def _review_operation(self, state: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        authority, worktree = self._candidate_authority(state)
        self._baseline(state)
        profile = self._profile(self._runtime_data or {}, "reviewer")
        if profile.get("model") and profile.get("model") != "gpt-6-astra":
            raise GovernanceBlockerError("Reviewer must use the fresh gpt-6-astra profile")
        context = self._context_bytes(state, action, candidate=state["candidate"])
        request = StrictExecutionRequest(
            action_id=action["id"], task_id=state["task_id"], attempt_index=action["attempt_index"],
            worktree=str(worktree), scope=tuple(state["scope"]), context_json=context,
            contract_json=encode(self._contract_data or {}), runtime_json=encode(self._runtime_data or {}),
            candidate_json=encode(state["candidate"]),
        )
        raw = self._call_role("reviewer", self.reviewer, request, context, worktree)
        receipt = self._normalize_receipt(raw, "reviewer")
        if not receipt["ok"]:
            raise GovernanceBlockerError(receipt.get("failure_reason") or "REVIEWER_INVOCATION_FAILED")
        semantic = receipt.get("semantic_result")
        if not isinstance(semantic, Mapping) or semantic.get("kind") != "TEXT" or not isinstance(semantic.get("text"), str):
            raise ArtifactValidationError("Reviewer semantic result is missing or not InvocationReceipt-owned")
        text_value = semantic["text"]
        if len(text_value.encode("utf-8")) > 64 * 1024:
            raise ArtifactValidationError("Reviewer semantic result exceeds 64 KiB")
        if semantic.get("sha256") != hashlib.sha256(text_value.encode("utf-8")).hexdigest():
            raise ArtifactValidationError("Reviewer semantic result digest mismatch")
        parsed = decode(text_value, limit=64 * 1024)
        if not isinstance(parsed, dict):
            raise ArtifactValidationError("Reviewer semantic result must be a JSON object")
        verdict = parsed.get("verdict", parsed.get("result", parsed.get("disposition")))
        if verdict not in {"PASS", "NEEDS_FIX"}:
            raise ArtifactValidationError("Reviewer must return PASS or NEEDS_FIX")
        verify_candidate_authority(worktree, authority, expected_ref=state["candidate"]["ref"])
        self._baseline(state)
        return {
            "ok": True,
            "status": verdict,
            "verdict": verdict,
            "findings": parsed.get("findings", []),
            "session_id": receipt["session_id"],
            "receipt": receipt,
            "semantic_result": semantic,
        }

    @staticmethod
    def _planner_proposal(receipt: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
        proposal = receipt.get("proposal")
        semantic = receipt.get("semantic_result")
        if proposal is None and isinstance(semantic, Mapping):
            if semantic.get("kind") == "TEXT" and isinstance(semantic.get("text"), str):
                parsed = decode(semantic["text"], limit=64 * 1024)
                if isinstance(parsed, Mapping):
                    proposal = parsed.get("proposal", parsed if "summary" in parsed else None)
            elif isinstance(semantic, Mapping):
                proposal = semantic.get("proposal", semantic if "summary" in semantic else None)
        if proposal is None:
            raise ArtifactValidationError("Planner invocation did not produce an affirmative proposal")
        return validate_strict_planner_proposal(dict(proposal), approved_scope=list(state["scope"]))

    def _planner_operation(self, state: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        context = self._context_bytes(state, action)
        request = StrictExecutionRequest(
            action_id=action["id"], task_id=state["task_id"], attempt_index=action["attempt_index"],
            worktree=state["baseline"]["repository"], scope=tuple(state["scope"]), context_json=context,
            contract_json=encode(self._contract_data or {}), runtime_json=encode(self._runtime_data or {}),
        )
        raw = self._call_role("planner", self.planner, request, context, Path(state["baseline"]["repository"]))
        receipt = self._normalize_receipt(raw, "planner")
        if not receipt["ok"]:
            raise GovernanceBlockerError("PLANNER_INVOCATION_FAILED")
        proposal = self._planner_proposal(receipt, state)
        return {"ok": True, "session_id": receipt["session_id"], "receipt": receipt, "proposal": proposal}

    def _dispatch(self, state: dict[str, Any]) -> dict[str, Any]:
        action = state["pending_action"]
        if action is None:
            raise GovernanceBlockerError("No strict action is pending")
        if action["status"] == "PREPARED":
            state = self._mark_started(state)
            action = state["pending_action"]
        if action["status"] != "STARTED":
            raise GovernanceBlockerError("Strict action is not STARTED")
        kind = action["kind"]
        try:
            if kind == "PLANNER":
                outcome = self._planner_operation(state, action)
            elif kind == "BUILDER":
                outcome = self._builder_operation(state, action)
            elif kind == "FREEZE":
                outcome = self._freeze_operation(state, action)
            elif kind == "VERIFIER":
                outcome = self._verifier_operation(state, action)
            elif kind == "REVIEWER":
                outcome = self._review_operation(state, action)
            else:  # pragma: no cover - state validation closes this branch
                raise GovernanceBlockerError("Unknown strict action")
        except Exception as exc:
            # Ordinary provider/deterministic failures still receive a durable
            # result.  A real interruption (KeyboardInterrupt/SystemExit) is
            # deliberately not caught, leaving STARTED for fail-closed resume.
            message = str(exc).lower()
            classified = (
                "TIMEOUT" if "timeout" in message or "timed out" in message else
                "OUTPUT_FLOOD" if "log limit" in message or "output flood" in message else
                "NON_QUIESCENT_PROCESS_GROUP" if "survivor" in message or "quiescen" in message else
                "ATTESTATION_MISMATCH" if "attest" in message else
                "HASH_MISMATCH" if "digest" in message or "authority" in message else
                None
            )
            outcome = {
                "ok": False,
                "status": "BLOCKED",
                "reason": classified or f"{type(exc).__name__}: {str(exc)[:512]}",
                "eligible_repair": False,
            }
        self._persist_result(action, outcome)
        return self._complete_action(state)

    def _complete_action(self, state: dict[str, Any]) -> dict[str, Any]:
        action = state["pending_action"]
        if action is None or action["status"] != "STARTED":
            raise GovernanceBlockerError("Strict action completion requires a STARTED action")
        outcome, result_ref = self._load_result(state)
        if not isinstance(outcome, dict):
            raise ArtifactValidationError("Strict action outcome is malformed")
        history_entry = {
            "id": action["id"], "kind": action["kind"], "status": "COMPLETED",
            "attempt_index": action["attempt_index"], "result_ref": result_ref,
            "session_id": outcome.get("session_id"), "revision": state["revision"] + 1,
        }
        changes: dict[str, Any] = {
            "pending_action": None,
            "action_history": state["action_history"] + [history_entry],
            "evidence_refs": state["evidence_refs"] + [result_ref],
            "latest_result_ref": result_ref,
        }
        if action["kind"] in {"PLANNER", "BUILDER", "REVIEWER"} and outcome.get("ok") is True:
            changes.update(self._record_session(state, action["kind"], outcome.get("session_id")))
        if action["kind"] == "PLANNER":
            if outcome.get("ok") is not True:
                return self._block({**state, **changes, "revision": state["revision"]}, "PLANNER_INVOCATION_FAILED")
            return self._save(state, "strict_planner_completed", **changes)
        if action["kind"] == "BUILDER":
            if outcome.get("ok") is not True:
                return self._block({**state, **changes, "revision": state["revision"]}, str(outcome.get("reason", "BUILDER_BLOCKED")))
            return self._save(state, "strict_builder_completed", phase="FREEZING", **changes)
        if action["kind"] == "FREEZE":
            if outcome.get("ok") is not True:
                return self._block({**state, **changes, "revision": state["revision"]}, str(outcome.get("reason", "FREEZE_BLOCKED")))
            return self._save(state, "strict_freeze_completed", phase="VERIFYING", candidate=outcome["candidate"], **changes)
        if action["kind"] == "VERIFIER":
            status = outcome.get("status")
            report = {key: value for key, value in outcome.items() if key != "ok"}
            report["report_ref"] = result_ref
            changes["verification"] = report
            if status == "PASS":
                changes["phase"] = "REVIEWING"
                return self._save(state, "strict_verifier_completed", **changes)
            if status == "FAIL" and outcome.get("eligible_repair") is True:
                # The verifier always hands off to the independent reviewer;
                # assessment is reached only after REVIEWING.
                changes["phase"] = "REVIEWING"
                return self._save(state, "strict_verifier_failed", **changes)
            return self._block({**state, **changes, "revision": state["revision"]}, str(outcome.get("reason", "VERIFIER_BLOCKED")))
        if action["kind"] == "REVIEWER":
            status = outcome.get("status")
            report = {key: value for key, value in outcome.items() if key != "ok"}
            report["receipt_ref"] = result_ref
            changes["review"] = report
            if status in {"PASS", "NEEDS_FIX"}:
                changes["phase"] = "ASSESSING"
                return self._save(state, "strict_reviewer_completed", **changes)
            return self._block({**state, **changes, "revision": state["revision"]}, str(outcome.get("reason", "REVIEWER_BLOCKED")))
        raise GovernanceBlockerError("Unknown strict action completion")

    def _request_gate(self, state: dict[str, Any], gate_type: str) -> dict[str, Any]:
        binding = strict_gate_binding(state, gate_type)
        revision = state["revision"] + 1
        question = (
            f"{gate_type}: {state['task_id']}\n"
            f"Scope: {', '.join(state['scope'])}\n"
            + ("Authorize attempt 0?" if gate_type == "GATE_A" else "Authorize integration preparation only (no canonical Git mutation)?")
            + "\nReply: approve / deny"
        )
        gate = {
            "gate_id": f"{state['controller_id']}-{gate_type}-{revision}",
            "gate_type": gate_type,
            "revision": revision,
            "binding": binding,
            "binding_digest": digest(binding),
            "question": question,
        }
        changes = {"pending_gate": gate}
        if gate_type == "GATE_A":
            changes["gate_a"] = gate
            changes["phase"] = "WAITING_HUMAN_GATE_A"
        else:
            changes["gate_b"] = gate
            changes["phase"] = "WAITING_HUMAN_GATE_B"
        return self._save(state, "strict_human_gate_requested", **changes)

    @staticmethod
    def _repair_feedback(state: Mapping[str, Any]) -> dict[str, Any]:
        candidate = state.get("candidate")
        if not isinstance(candidate, Mapping):
            raise GovernanceBlockerError("Cannot derive repair feedback without a failed candidate")
        return {
            "failed_candidate_identity": decode(encode(dict(candidate))),
            "verification_summary": decode(encode(state.get("verification"))) if state.get("verification") is not None else None,
            "review_findings": decode(encode(state.get("review"))) if state.get("review") is not None else None,
            "previous_attempt_index": state["attempt_index"],
        }

    def _assess(self, state: dict[str, Any]) -> dict[str, Any]:
        verification = state["verification"] or {}
        review = state["review"] or {}
        if verification.get("status") == "FAIL":
            if verification.get("eligible_repair") is not True:
                return self._block(state, str(verification.get("reason", "INELIGIBLE_VERIFICATION_FAILURE")))
            if state["repair_cycles"] >= state["repair_policy"]["max_repair_cycles"]:
                return self._block(state, "REPAIR_BUDGET_EXHAUSTED")
            return self._save(
                state,
                "strict_repair_started",
                phase="BUILDING",
                attempt_index=state["attempt_index"] + 1,
                repair_cycles=state["repair_cycles"] + 1,
                repair_history=state["repair_history"] + [self._repair_feedback(state)],
                candidate=None,
                verification=None,
                review=None,
                gate_b=None,
            )
        if verification.get("status") != "PASS":
            return self._block(state, "VERIFICATION_DID_NOT_PASS")
        if review.get("status") == "NEEDS_FIX":
            if state["repair_cycles"] >= state["repair_policy"]["max_repair_cycles"]:
                return self._block(state, "REPAIR_BUDGET_EXHAUSTED")
            return self._save(
                state,
                "strict_repair_started",
                phase="BUILDING",
                attempt_index=state["attempt_index"] + 1,
                repair_cycles=state["repair_cycles"] + 1,
                repair_history=state["repair_history"] + [self._repair_feedback(state)],
                candidate=None,
                verification=None,
                review=None,
                gate_b=None,
            )
        if review.get("status") == "PASS":
            return self._request_gate(state, "GATE_B")
        return self._block(state, "REVIEW_DID_NOT_PASS")

    def _step(self, state: dict[str, Any]) -> dict[str, Any]:
        self._inputs(state)
        self._baseline(state)
        if state["pending_action"] is not None:
            action = state["pending_action"]
            if action["status"] == "PREPARED":
                if self._result_path(action["id"]).exists():
                    raise GovernanceBlockerError("AMBIGUOUS_INTERRUPTED_ACTION")
                return self._dispatch(state)
            result_path = self._result_path(action["id"])
            if result_path.exists():
                try:
                    self._load_result(state)
                except Exception as exc:
                    raise GovernanceBlockerError("AMBIGUOUS_INTERRUPTED_ACTION") from exc
                return self._complete_action(state)
            raise GovernanceBlockerError("AMBIGUOUS_INTERRUPTED_ACTION")
        phase = state["phase"]
        if phase == "START":
            return self._save(state, "strict_planning_started", phase="PLANNING")
        if phase == "PLANNING":
            if self.planner is None:
                return self._block(state, "PLANNER_REQUIRED_BEFORE_GATE_A")
            if not any(item["kind"] == "PLANNER" and item["attempt_index"] == state["attempt_index"] for item in state["action_history"]):
                return self._action_claim(state, "PLANNER")
            planner_outcome = self._last_outcome(state, "PLANNER", state["attempt_index"])
            proposal = planner_outcome.get("proposal")
            validate_strict_planner_proposal(proposal, approved_scope=state["scope"])
            return self._request_gate(state, "GATE_A")
        if phase == "BUILDING":
            return self._action_claim(state, "BUILDER")
        if phase == "FREEZING":
            return self._action_claim(state, "FREEZE")
        if phase == "VERIFYING":
            return self._action_claim(state, "VERIFIER")
        if phase == "REVIEWING":
            return self._action_claim(state, "REVIEWER")
        if phase == "ASSESSING":
            return self._assess(state)
        return state

    def state(self) -> dict[str, Any]:
        value = self.store.load()
        validate_strict_state(value)
        return value

    def _report(self, state: dict[str, Any]) -> dict[str, Any]:
        result = dict(state)
        result["status"] = state["terminal_state"] or ("HUMAN_GATE_REQUIRED" if state["pending_gate"] else "RUNNING")
        result["disposition"] = result["status"]
        result["task"] = state["task_id"]
        result["question"] = state["pending_gate"]["question"] if state["pending_gate"] else None
        result["gate"] = state["pending_gate"]
        result["reason"] = state["terminal_reason"]
        result["canonical_integration_performed"] = False
        return result

    def status(self) -> dict[str, Any]:
        return self._report(self.state())

    def _gate_b_evidence(self, state: dict[str, Any]) -> None:
        """Revalidate the immutable evidence bound by Gate B before approval."""
        verification = state.get("verification")
        review = state.get("review")
        if not isinstance(verification, Mapping) or verification.get("status") != "PASS":
            raise GovernanceBlockerError("Gate B requires a verifier PASS")
        if not isinstance(review, Mapping) or review.get("status") != "PASS":
            raise GovernanceBlockerError("Gate B requires a reviewer PASS")
        report_ref = verification.get("report_ref")
        receipt_ref = review.get("receipt_ref")
        if not isinstance(report_ref, Mapping) or not isinstance(receipt_ref, Mapping):
            raise GovernanceBlockerError("Gate B evidence references are incomplete")
        report = self.store.read_artifact(dict(report_ref))
        receipt = self.store.read_artifact(dict(receipt_ref))
        if not isinstance(report, Mapping) or not isinstance(receipt, Mapping):
            raise GovernanceBlockerError("Gate B evidence artifacts are malformed")
        if report.get("kind") != "VERIFIER" or report.get("status") != "COMPLETED":
            raise GovernanceBlockerError("Gate B verifier report is not a completed result")
        if receipt.get("kind") != "REVIEWER" or receipt.get("status") != "COMPLETED":
            raise GovernanceBlockerError("Gate B reviewer receipt is not a completed result")
        report_outcome = report.get("outcome")
        receipt_outcome = receipt.get("outcome")
        if not isinstance(report_outcome, Mapping) or report_outcome.get("status") != "PASS":
            raise GovernanceBlockerError("Gate B verifier report does not prove PASS")
        if not isinstance(receipt_outcome, Mapping) or receipt_outcome.get("status") != "PASS":
            raise GovernanceBlockerError("Gate B reviewer receipt does not prove PASS")

    def resume(self, *, max_steps: int = 64) -> dict[str, Any]:
        if type(max_steps) is not int or not 1 <= max_steps <= 128:
            raise ArtifactValidationError("Invalid strict deterministic step budget")
        with self.store.writer():
            state = self.store.load(recover=True)
            for _ in range(max_steps):
                if state["terminal_state"] or state["pending_gate"]:
                    if state["pending_gate"] and state["pending_gate"]["gate_type"] == "GATE_B":
                        self._baseline(state)
                        self._candidate_authority(state)
                        self._gate_b_evidence(state)
                    break
                try:
                    next_state = self._step(state)
                except (RunnerError, OSError) as exc:
                    error_class = getattr(exc, "error_class", "GOVERNANCE_BLOCKER")
                    error_class = getattr(error_class, "value", error_class)
                    message = str(exc)[:512]
                    exact_reasons = {
                        "AMBIGUOUS_INTERRUPTED_ACTION", "REPAIR_BUDGET_EXHAUSTED", "TIMEOUT", "KILL",
                        "OUTPUT_FLOOD", "NON_QUIESCENT_PROCESS_GROUP", "ATTESTATION_MISMATCH", "HASH_MISMATCH",
                    }
                    reason = message if message.split(":", 1)[0] in exact_reasons else f"{error_class}: {message}"
                    state = self._block(self.store.load(), reason)
                    break
                except Exception as exc:
                    state = self._block(self.store.load(), f"{type(exc).__name__}: {str(exc)[:512]}")
                    break
                if next_state == state:
                    break
                state = next_state
            return self._report(state)

    def reply(self, *, gate_id: str, revision: int, binding_digest: str, response: str) -> dict[str, Any]:
        with self.store.writer():
            state = self.store.load(recover=True)
            gate = state["pending_gate"]
            if gate is None or (gate_id, revision, binding_digest) != (gate["gate_id"], state["revision"], gate["binding_digest"]):
                raise GovernanceBlockerError("Stale or replayed strict human gate reply")
            if response not in {"approve", "deny"}:
                raise GovernanceBlockerError("Human response must be literal approve or deny")
            self._baseline(state)
            if gate["gate_type"] == "GATE_B":
                self._candidate_authority(state)
                self._gate_b_evidence(state)
            if gate["binding"] != strict_gate_binding(state, gate["gate_type"]):
                raise GovernanceBlockerError("Strict human gate authority drift")
            authorization = {"gate_id": gate_id, "binding_digest": binding_digest, "decision": "APPROVED"} if response == "approve" else None
            entry = {"gate": gate, "human_response": response, "source": "local-cli", "authorization": authorization}
            history_key = "gate_a_history" if gate["gate_type"] == "GATE_A" else "gate_b_history"
            changes: dict[str, Any] = {history_key: state[history_key] + [entry], "pending_gate": None}
            if response == "deny":
                changes.update(phase="BLOCKED", terminal_state="BLOCKED", terminal_reason="HUMAN_DECLINED")
            elif gate["gate_type"] == "GATE_A":
                changes["phase"] = "BUILDING"
            else:
                changes.update(phase="COMPLETE", terminal_state="COMPLETE", terminal_reason="INTEGRATION_PREPARED_ONLY")
            state = self._save(state, "strict_human_response_recorded", **changes)
            return self._report(state)

    def human_reply(self, **kwargs: Any) -> dict[str, Any]:
        return self.reply(**kwargs)

    def reply_to_gate(self, **kwargs: Any) -> dict[str, Any]:
        return self.reply(**kwargs)

    def wait(self, *, timeout: float = 30.0, interval: float = 0.1) -> dict[str, Any]:
        if not 0 <= timeout <= 60 or not 0 < interval <= 1:
            raise ArtifactValidationError("Wait requires timeout 0..60 seconds and interval 0..1")
        deadline = time.monotonic() + timeout
        while True:
            report = self.status()
            if report["status"] != "RUNNING" or time.monotonic() >= deadline:
                return report
            time.sleep(min(interval, max(0, deadline - time.monotonic())))


# Names used by early R3C callers are retained as aliases; all aliases select
# the strict schema and never open a legacy store as a strict run.
DurableExecutionController = StrictExecutionController
R3CController = StrictExecutionController
StrictController = StrictExecutionController
ExecutionController = StrictExecutionController
AutonomousExecutionController = StrictExecutionController


def start_strict_controller(*args: Any, **kwargs: Any) -> StrictExecutionController:
    return StrictExecutionController.start(*args, **kwargs)
