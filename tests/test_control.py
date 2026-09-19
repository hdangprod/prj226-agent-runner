"""CTRL-R001: offline kernel controls, real Git fixtures, no provider/model calls."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import multiprocessing
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import jsonschema

from prj226_runner import controller as C, runner as R
from prj226_runner.cli import main
from prj226_runner.control import DurableController, build_context, compact_report, format_report
from prj226_runner.control_protocol import (
    ATTACHMENT_LIMIT, CONTEXT_LIMIT, DECISION_VERSION, VERSION, BuilderRequest,
    PlannerContext, decode, digest, encode, parse_decision, validate_transition,
)
from prj226_runner.control_store import ControlStore
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError
from test_m2 import M2Fixture, _git


class FakePlanner:
    profile_ref = "offline-planner-v1"

    def __init__(self, transform=None):
        self.calls = 0
        self.transform = transform

    def decide(self, context: PlannerContext) -> str:
        self.calls += 1
        state = decode(context.document)["state"]
        decision = {"schema_version":DECISION_VERSION, "controller_id":state["controller_id"],
                    "task_id":state["task_id"], "revision":state["revision"], "context_digest":context.digest,
                    "action":"PROPOSE_TASK" if state["phase"] == "PLANNING" else "PREPARE_GATE_B",
                    "reason":"Offline deterministic proposal"}
        if self.transform:
            return self.transform(decision)
        return json.dumps(decision)


class FakeBuilder:
    """Exercises the unmodified Runner with its existing fake executable fixture."""

    profile_ref = "offline-builder-v1"

    def __init__(self, fixture: M2Fixture):
        self.fixture = fixture
        self.calls = 0
        self.before = None

    def execute(self, request: BuilderRequest) -> str:
        self.calls += 1
        if self.before:
            self.before(request)
        folder = self.fixture.root / "adapter-input"
        folder.mkdir()
        for name, raw in (("contract.json",request.contract_json), ("packet.json",request.packet_json), ("gate-a.json",request.gate_a_json)):
            (folder/name).write_bytes(raw)
        R.run_packet_v3(folder/"packet.json", folder/"contract.json", folder/"gate-a.json", self.fixture.config, authorize=True)
        contract = decode(request.contract_json)
        path = Path(contract["runtime_root"]) / contract["run_id"] / "report.json"
        return json.dumps({"schema_version":VERSION, "action_id":request.action_id,
                           "report_ref":{"path":str(path), "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}})


def resume_worker(root: str, entered, release, results) -> None:
    class PausingPlanner(FakePlanner):
        def decide(self, context):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test coordination timeout")
            return super().decide(context)
    controller = DurableController(root, planner=PausingPlanner())
    results.put(controller.resume())


class TestDurableController(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ctrl-r001-test-", dir="/private/tmp")
        self.root = Path(self.temp.name)
        self.fixture = M2Fixture(self.root)
        self.original_head = _git(self.fixture.repo, "rev-parse", "HEAD")
        self.contract_path = self.root / "contract.json"
        self.contract = C.draft_design_contract_v3(
            self.fixture.manifest_dict,
            {"work_item_id":"CTRL-TEST-001", "title":"Offline bounded kernel fixture"},
            C.inspect_project(self.fixture.manifest_dict), run_id="CTRL-TEST-RUN-001",
            owned_paths=["src/app.txt"], runtime_root=str(self.fixture.runtime),
            acceptance_instruments=[[os.sys.executable,"-B","-c",
                "from pathlib import Path; assert Path('src/app.txt').read_text() == 'builder change\\n'"]],
            output_path=self.contract_path,
        )
        self.planner = FakePlanner()
        self.builder = FakeBuilder(self.fixture)
        self.controller = self.start()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def start(self, *, name="session", budget=2):
        return DurableController.start(self.root/name, controller_id="CTRL-TEST", goal="Prove the offline kernel",
            contract_path=self.contract_path, planner_profile_ref=self.planner.profile_ref,
            builder_profile_ref=self.builder.profile_ref, planner_budget=budget,
            planner=self.planner, builder=self.builder)

    def state(self):
        return self.controller.store.load()

    def approve(self):
        gate = self.state()["pending_gate"]
        return self.controller.reply(gate_id=gate["gate_id"], revision=gate["revision"],
            binding_digest=gate["binding_digest"], response="approve")

    def gate_b(self):
        self.assertEqual(self.controller.resume()["status"], "HUMAN_GATE_REQUIRED")
        self.approve()
        report = self.controller.resume()
        self.assertEqual(report["phase"], "WAITING_HUMAN_GATE_B", report)
        return report

    def context_at_planning(self):
        self.controller.resume(max_steps=2)
        state = self.state()
        return state, build_context(state)

    def test_valid_decision_matches_standalone_schema(self):
        state, context = self.context_at_planning()
        raw = self.planner.decide(context)
        value = parse_decision(raw, state, context.digest)
        schema_path = Path(__file__).resolve().parents[1]/"schemas/control-decision.v1.schema.json"
        jsonschema.validate(value, json.loads(schema_path.read_text()))

    def test_malformed_decision_fails_closed(self):
        self.planner.transform = lambda _: "{broken"
        report = self.controller.resume()
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("ARTIFACT_VALIDATION_ERROR", report["reason"])
        self.assertEqual(self.builder.calls, 0)

    def test_unknown_action_fails_closed(self):
        self.planner.transform = lambda d: json.dumps({**d,"action":"RUN_SHELL"})
        self.assertEqual(self.controller.resume()["status"], "BLOCKED")

    def test_duplicate_json_keys_rejected(self):
        state, context = self.context_at_planning()
        raw = self.planner.decide(context).replace('"reason":', '"action":"BLOCK","reason":')
        with self.assertRaisesRegex(ArtifactValidationError, "Duplicate"):
            parse_decision(raw, state, context.digest)

    def test_stale_decision_revision(self):
        self.planner.transform = lambda d: json.dumps({**d,"revision":d["revision"]-1})
        self.assertIn("revision mismatch", self.controller.resume()["reason"])

    def test_wrong_context_digest(self):
        self.planner.transform = lambda d: json.dumps({**d,"context_digest":digest({"other":"context"})})
        self.assertIn("context digest mismatch", self.controller.resume()["reason"])

    def test_wrong_controller_and_task_identity(self):
        state, context = self.context_at_planning()
        valid = json.loads(self.planner.decide(context))
        for key in ("controller_id", "task_id"):
            with self.subTest(key=key), self.assertRaises(GovernanceBlockerError):
                parse_decision(encode({**valid,key:"different"}), state, context.digest)

    def test_legal_complete_lifecycle_preserves_canonical(self):
        self.gate_b()
        self.approve()
        self.assertEqual(self.controller.resume()["status"], "COMPLETE")
        events = self.controller.store._journal()
        phases = list(dict.fromkeys(event["state"]["phase"] for event in events))
        self.assertEqual(phases, ["START","DISCOVERY","PLANNING","WAITING_HUMAN_GATE_A","EXECUTION_PREP",
            "RUNNER_ACTIVE","RESULT_INGESTION","PLANNER_ASSESSMENT","WAITING_HUMAN_GATE_B","CANONICAL_INTEGRATION_PREP","COMPLETE"])
        self.assertEqual(_git(self.fixture.repo,"rev-parse","HEAD"), self.original_head)
        self.assertEqual(_git(self.fixture.repo,"status","--porcelain"), "")

    def test_illegal_state_transition(self):
        before = self.state()
        with self.assertRaisesRegex(GovernanceBlockerError, "Illegal"):
            validate_transition(before, {**before,"revision":2,"phase":"EXECUTION_PREP"})

    def test_illegal_planner_transition(self):
        self.planner.transform = lambda d: json.dumps({**d,"action":"PREPARE_GATE_B"})
        self.assertIn("Illegal planner action", self.controller.resume()["reason"])

    def test_durable_reload_and_gate_stop(self):
        report = self.controller.resume()
        reloaded = DurableController(self.controller.store.root, planner=self.planner, builder=self.builder)
        self.assertEqual(reloaded.status(), report)
        self.assertEqual(reloaded.resume(), report)
        self.assertEqual(self.planner.calls, 1)

    def test_writer_lock_excludes_second_controller(self):
        peer = DurableController(self.controller.store.root)
        with self.controller.store.writer(), self.assertRaisesRegex(GovernanceBlockerError, "CONTROLLER_BUSY"):
            peer.resume()

    def test_atomic_snapshot_recovers_from_fsynced_event(self):
        store = self.controller.store
        old = (store.root/"state.json").read_bytes()
        state = self.state()
        with store.writer(), patch.object(store,"_atomic",side_effect=OSError("simulated power loss")):
            with self.assertRaises(OSError):
                store.commit({**state,"revision":2,"phase":"DISCOVERY"},"discovery_started")
        self.assertEqual((store.root/"state.json").read_bytes(),old)
        with store.writer():
            recovered = store.load(recover=True)
        self.assertEqual(recovered["phase"],"DISCOVERY")
        self.assertEqual(decode((store.root/"state.json").read_bytes()),recovered)

    def test_torn_journal_blocks_without_truncation(self):
        path = self.controller.store.root/"events.ndjson"
        with path.open("ab") as f:
            f.write(b'{"unfinished":')
        raw = path.read_bytes()
        with self.assertRaises(ArtifactValidationError):
            self.controller.resume()
        self.assertEqual(path.read_bytes(),raw)

    def test_conflicting_snapshot_blocks_without_repair(self):
        path = self.controller.store.root/"state.json"
        state = self.state()
        path.write_bytes(encode({**state,"goal":"Unauthorized replacement"}))
        with self.assertRaisesRegex(ArtifactValidationError,"conflicts"):
            self.controller.resume()

    def test_claim_is_durable_before_builder_dispatch(self):
        self.controller.resume()
        self.approve()
        def inspect(request):
            persisted = ControlStore(self.controller.store.root).load()
            self.assertEqual(persisted["pending_action"]["status"], "STARTED")
            self.assertEqual(persisted["pending_action"]["id"], request.action_id)
            self.assertEqual(persisted["builder_invocations"],1)
        self.builder.before = inspect
        self.assertEqual(self.controller.resume()["status"],"HUMAN_GATE_REQUIRED")

    def test_prepared_not_started_claim_can_continue(self):
        self.controller.resume(max_steps=3)
        self.assertEqual(self.state()["pending_action"]["status"],"PREPARED")
        self.assertEqual(self.planner.calls,0)
        self.assertEqual(self.controller.resume()["status"],"HUMAN_GATE_REQUIRED")
        self.assertEqual(self.planner.calls,1)

    def test_completed_planner_action_reconciles_without_replay(self):
        with patch.object(self.controller,"_complete",side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.controller.resume()
        self.assertEqual(self.state()["pending_action"]["status"],"STARTED")
        self.assertEqual(self.controller.resume()["status"],"HUMAN_GATE_REQUIRED")
        self.assertEqual(self.planner.calls,1)

    def test_completed_builder_action_reconciles_without_replay(self):
        self.controller.resume()
        self.approve()
        with patch.object(self.controller,"_complete",side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.controller.resume()
        self.assertEqual(self.builder.calls,1)
        self.assertEqual(self.controller.resume()["phase"],"WAITING_HUMAN_GATE_B")
        self.assertEqual(self.builder.calls,1)

    def test_ambiguous_planner_interrupt_blocks_without_replay(self):
        with patch.object(self.planner,"decide",side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.controller.resume()
        report = self.controller.resume()
        self.assertEqual(report["status"],"BLOCKED")
        self.assertIn("AMBIGUOUS_INTERRUPTED_ACTION",report["reason"])
        self.assertEqual(report["planner_invocations"],1)
        self.assertEqual(self.planner.calls,0)

    def test_ambiguous_builder_interrupt_blocks_without_replay(self):
        self.controller.resume()
        self.approve()
        with patch.object(self.builder,"execute",side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.controller.resume()
        report = self.controller.resume()
        self.assertIn("AMBIGUOUS_INTERRUPTED_ACTION",report["reason"])
        self.assertEqual(report["builder_invocations"],1)
        self.assertEqual(self.fixture.builder_calls(),0)

    def test_gate_a_response_persists_exact_authority(self):
        self.controller.resume()
        gate = self.state()["pending_gate"]
        self.assertEqual(self.approve()["phase"],"EXECUTION_PREP")
        entry = self.state()["gate_a_history"][0]
        self.assertEqual(entry["gate"],gate)
        self.assertEqual(entry["human_response"],"approve")
        self.assertEqual(entry["authorization"]["binding_digest"],digest(gate["binding"]))
        self.assertEqual(self.builder.calls,0)

    def test_gate_b_response_only_prepares_integration(self):
        self.gate_b()
        self.assertEqual(self.approve()["phase"],"CANONICAL_INTEGRATION_PREP")
        with patch.object(C,"integrate_after_gate_b_v2",side_effect=AssertionError("promotion forbidden")):
            self.assertEqual(self.controller.resume()["status"],"COMPLETE")
        self.assertEqual(len(self.state()["gate_b_history"]),1)
        self.assertEqual(_git(self.fixture.repo,"rev-parse","HEAD"),self.original_head)

    def test_stale_gate_reply_rejected(self):
        self.controller.resume()
        gate = self.state()["pending_gate"]
        for kwargs in ({"revision":gate["revision"]-1}, {"binding_digest":digest({"stale":True})}, {"gate_id":"different"}):
            args = {"gate_id":gate["gate_id"],"revision":gate["revision"],"binding_digest":gate["binding_digest"],"response":"approve"}
            with self.subTest(kwargs=kwargs), self.assertRaises(GovernanceBlockerError):
                self.controller.reply(**(args|kwargs))
        self.assertEqual(self.state()["pending_gate"],gate)

    def test_replayed_gate_reply_rejected(self):
        self.controller.resume()
        gate = self.state()["pending_gate"]
        self.approve()
        with self.assertRaisesRegex(GovernanceBlockerError,"replayed"):
            self.controller.reply(gate_id=gate["gate_id"],revision=gate["revision"],binding_digest=gate["binding_digest"],response="approve")
        self.assertEqual(len(self.state()["gate_a_history"]),1)

    def test_planner_cannot_authorize_or_supply_commands(self):
        state, context = self.context_at_planning()
        value = decode(self.planner.decide(context))
        for extra in ({"authorization":"APPROVED"},{"shell":"touch anything"},{"git":["push"]},{"owned_paths":["outside"]}):
            with self.subTest(extra=extra), self.assertRaises(ArtifactValidationError):
                parse_decision(encode(value|extra),state,context.digest)

    def test_builder_receipt_cannot_supply_authorization(self):
        self.controller.resume()
        self.approve()
        with patch.object(self.builder,"execute",return_value=json.dumps({"authorization":"APPROVED"})):
            report = self.controller.resume()
        self.assertEqual(report["status"],"BLOCKED")
        self.assertEqual(self.state()["gate_b_history"],[])

    def test_builder_input_is_immutable_and_does_not_expose_state(self):
        self.controller.resume()
        self.approve()
        def inspect(request):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                request.profile_ref = "substituted"
            self.assertIsInstance(request.contract_json,bytes)
            self.assertFalse(hasattr(request,"state"))
            self.assertFalse(hasattr(request,"controller_root"))
        self.builder.before = inspect
        self.assertEqual(self.controller.resume()["phase"],"WAITING_HUMAN_GATE_B")

    def test_retry_budget_enforced(self):
        with self.controller.store.writer():
            state = self.state()
            self.controller.store.commit({**state,"revision":2,"retry_count":1},"budget_violation")
        self.assertEqual(self.controller.resume()["status"],"BLOCKED")
        self.assertEqual(self.planner.calls,0)

    def test_fallback_budget_enforced(self):
        with self.controller.store.writer():
            state = self.state()
            self.controller.store.commit({**state,"revision":2,"fallback_count":1},"budget_violation")
        self.assertEqual(self.controller.resume()["status"],"BLOCKED")
        self.assertEqual(self.planner.calls,0)

    def test_planner_budget_and_accounting(self):
        self.controller = self.start(name="budget-session",budget=1)
        self.controller.resume()
        self.approve()
        report = self.controller.resume()
        self.assertEqual(report["status"],"BLOCKED")
        self.assertEqual(report["planner_invocations"],1)
        self.assertIn("budget exhausted",report["reason"])

    def test_builder_and_planner_invocation_accounting(self):
        self.gate_b()
        state = self.state()
        self.assertEqual((state["planner_invocations"],state["builder_invocations"]),(2,1))
        self.assertEqual((self.planner.calls,self.builder.calls,self.fixture.builder_calls()),(2,1,1))
        self.assertEqual((state["retry_count"],state["fallback_count"]),(0,0))
        self.assertEqual(self.fixture.reviewer_calls(),0)

    def test_mechanical_transitions_use_zero_planner_calls(self):
        self.controller.resume(max_steps=2)
        self.assertEqual(self.planner.calls,0)
        self.assertEqual(self.state()["phase"],"PLANNING")
        self.controller.resume()
        self.approve()
        self.controller.resume(max_steps=1)
        self.assertEqual(self.state()["phase"],"RUNNER_ACTIVE")
        self.assertEqual(self.planner.calls,1)
        for _ in range(3):
            self.controller.status()
            self.controller.wait(timeout=0)
        self.assertEqual(self.planner.calls,1)

    def test_context_limit_and_no_silent_semantic_truncation(self):
        state = self.state()
        with self.assertRaises(GovernanceBlockerError):
            build_context(state,limit=256)
        with self.assertRaises(GovernanceBlockerError):
            build_context(state,attachment="x"*(ATTACHMENT_LIMIT+1))
        with self.assertRaises(GovernanceBlockerError):
            build_context(state,required_attachment=True)
        context = build_context(state,attachment="x"*ATTACHMENT_LIMIT)
        self.assertEqual(len(context.attachment),ATTACHMENT_LIMIT)
        self.assertLessEqual(len(context.document),CONTEXT_LIMIT)

    def test_context_coverage_bytes_and_digest(self):
        context = build_context(self.state())
        document = decode(context.document)
        self.assertEqual(document["byte_count"],len(context.document))
        self.assertEqual(context.digest,hashlib.sha256(context.document).hexdigest())
        self.assertIn("baseline",document["included_sections"])
        self.assertIn("raw_logs",document["omitted_sections"])
        self.assertIn("semantic_attachment",document["omitted_sections"])

    def test_block_report(self):
        self.planner.transform = lambda d: json.dumps({**d,"action":"BLOCK","reason":"Need a human decision"})
        report = self.controller.resume()
        self.assertEqual(report["status"],"BLOCKED")
        self.assertIn("PLANNER_BLOCK",format_report(report))
        self.assertEqual(report["blocker_count"],1)

    def test_human_gate_report_is_compact(self):
        report = self.controller.resume()
        text = format_report(report)
        self.assertIn("HUMAN_GATE_REQUIRED",text)
        self.assertIn("approve / deny",text)
        self.assertLess(len(text),1000)

    def test_complete_report_does_not_claim_promotion_or_usage(self):
        self.gate_b()
        self.approve()
        report = self.controller.resume()
        self.assertEqual(report["status"],"COMPLETE")
        self.assertFalse(report["canonical_integration_performed"])
        self.assertIsNone(report["token_usage"])
        self.assertIn("prepared only",format_report(report))

    def test_concurrent_resume_does_not_duplicate_planner(self):
        ctx = multiprocessing.get_context("fork")
        entered, release, results = ctx.Event(), ctx.Event(), ctx.Queue()
        child = ctx.Process(target=resume_worker,args=(str(self.controller.store.root),entered,release,results))
        child.start()
        try:
            self.assertTrue(entered.wait(10))
            with self.assertRaisesRegex(GovernanceBlockerError,"CONTROLLER_BUSY"):
                self.controller.resume()
        finally:
            release.set()
            child.join(10)
        self.assertEqual(child.exitcode,0)
        self.assertEqual(results.get(timeout=1)["planner_invocations"],1)
        self.assertEqual(self.state()["planner_invocations"],1)

    def test_cli_start_status_wait_resume_without_real_adapters(self):
        session = self.root/"cli-session"
        argv = ["control","start","--session",str(session),"--id","CLI-001","--goal","Offline CLI boundary",
                "--contract",str(self.contract_path),"--planner-profile",self.planner.profile_ref,
                "--builder-profile",self.builder.profile_ref,"--json"]
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(argv),0)
        self.assertEqual(json.loads(output.getvalue())["status"],"RUNNING")
        for command in ("resume","status","wait"):
            args = ["control",command,"--session",str(session),"--json"]
            if command == "wait":
                args += ["--timeout","0"]
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(args),0)
            self.assertEqual(json.loads(output.getvalue())["planner_invocations"],0)
        self.assertEqual(DurableController(session).store.load()["phase"],"PLANNING")

    def test_cli_exact_reply_and_read_only_wait(self):
        self.controller.resume()
        root = self.controller.store.root
        before = {p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["control","wait","--session",str(root),"--timeout","0"]),10)
        self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir() if p.is_file()})
        gate = self.state()["pending_gate"]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["control","reply","--session",str(root),"--gate-id",gate["gate_id"],
                "--revision",str(gate["revision"]),"--binding-digest",gate["binding_digest"],"--response","approve"]),0)
        self.assertEqual(self.state()["phase"],"EXECUTION_PREP")

    def test_adapter_substitution_blocks_before_call(self):
        self.planner.profile_ref = "different-profile"
        self.assertEqual(self.controller.resume()["status"],"BLOCKED")
        self.assertEqual(self.planner.calls,0)

    def test_denied_gate_is_terminal(self):
        self.controller.resume()
        gate = self.state()["pending_gate"]
        report = self.controller.reply(gate_id=gate["gate_id"],revision=gate["revision"],binding_digest=gate["binding_digest"],response="deny")
        self.assertEqual(report["status"],"BLOCKED")
        self.assertIsNone(self.state()["gate_a_history"][0]["authorization"])
        self.assertEqual(self.controller.resume(),report)

    def test_changed_baseline_rejects_approval(self):
        self.controller.resume()
        (self.fixture.repo/"README.md").write_text("changed\n")
        with self.assertRaisesRegex(GovernanceBlockerError,"baseline drift"):
            self.approve()
        self.assertEqual(self.builder.calls,0)

    def test_contract_tampering_blocks(self):
        path = self.controller.store.root/"contract.json"
        value = json.loads(path.read_text())
        value["intent"] = "Changed authority"
        path.write_text(json.dumps(value))
        self.assertEqual(self.controller.resume()["status"],"BLOCKED")
        self.assertEqual(self.planner.calls,0)

    def test_failed_deterministic_verification_never_reaches_assessment(self):
        self.controller.resume()
        self.approve()
        with patch.dict(os.environ,{"FAKE_NO_CHANGE":"1"}):
            report = self.controller.resume()
        self.assertEqual(report["status"],"BLOCKED")
        self.assertEqual(self.planner.calls,1)
        self.assertIsNone(self.state()["verification_summary"])

    def test_no_environment_secrets_in_context_or_events(self):
        with patch.dict(os.environ,{"CTRL_TEST_SECRET":"must-not-enter-evidence"}):
            self.controller.resume()
        for path in self.controller.store.root.iterdir():
            if path.is_file():
                self.assertNotIn(b"must-not-enter-evidence",path.read_bytes())


if __name__ == "__main__":
    unittest.main()
