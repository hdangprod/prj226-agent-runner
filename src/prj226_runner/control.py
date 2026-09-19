"""Durable, offline controller kernel. No provider adapters or promotion path.

Reasoning occurs only at PLANNING and PLANNER_ASSESSMENT. Execution adapters
return a receipt for Runner evidence, never authorization or acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from prj226_runner import controller as C, runner as R
from prj226_runner.control_protocol import (
    ATTACHMENT_LIMIT, CONTEXT_LIMIT, COUNTERS, DECISIONS, VERSION,
    BuilderExecutorPort, BuilderRequest, ControllerPlannerPort, PlannerContext,
    closed, decode, digest, encode, gate_binding, parse_decision, reference, validate_state,
)
from prj226_runner.control_store import ControlStore, fsync_directory, read_file
from prj226_runner.codex_reviewer import EvidenceRoot
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


class DurableController:
    def __init__(self, root: Path | str, *, planner: ControllerPlannerPort | None = None,
                 builder: BuilderExecutorPort | None = None) -> None:
        self.store = ControlStore(root)
        self.planner, self.builder = planner, builder

    @classmethod
    def start(cls, root: Path | str, *, controller_id: str, goal: str, contract_path: Path | str,
              planner_profile_ref: str, builder_profile_ref: str, planner_budget: int = 2,
              planner: ControllerPlannerPort | None = None, builder: BuilderExecutorPort | None = None) -> "DurableController":
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
        if type(max_steps) is not int or not 1 <= max_steps <= 64:
            raise ArtifactValidationError("Invalid deterministic step budget")
        with self.store.writer():
            state = self.store.load(recover=True)
            for _ in range(max_steps):
                if state["terminal_state"] or state["pending_gate"]:
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
        state = self.store.load()
        self._contract(state)
        return compact_report(state)

    def wait(self, *, timeout: float = 30.0, interval: float = 0.1) -> dict[str, Any]:
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
