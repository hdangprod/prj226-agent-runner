"""Discriminating HARN-002 controls using disposable Git projects."""

from __future__ import annotations

import json
import jsonschema
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner.controller import (
    Controller,
    ProjectManifest,
    classify_work,
    derive_task_packet,
    discover_next_work,
    draft_design_contract,
    ingest_runner_result,
    load_controller_result,
    inspect_project,
    integrate_after_gate_b,
    load_controller_state,
    prepare_gate_b,
    resume_controller,
    validate_gate_a,
    validate_review_binding,
    validate_task_packet_derivation,
    write_controller_state,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError
from prj226_runner.models import ControllerPhase, WorkShape


class TestHarn002Controller(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "project"
        subprocess.run(["git", "init", str(self.repo)], capture_output=True, text=True, check=True)
        self._git("config", "user.email", "controller@example.test")
        self._git("config", "user.name", "Controller Test")
        (self.repo / "docs/development/tasks").mkdir(parents=True)
        (self.repo / "README.md").write_text("synthetic project\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs/README.md").write_text("project docs\n", encoding="utf-8")
        (self.repo / "docs/development/CURRENT.md").write_text(
            "# Current\n\n**Next executable work:** ENG-012 — Deterministic Integrated Semantic Acceptance\n",
            encoding="utf-8",
        )
        (self.repo / "docs/development/ENGINEERING_PLAN.md").write_text(
            "| Task | Description | State |\n| --- | --- | --- |\n"
            "| `ENG-012` | deterministic acceptance | `PROPOSED` |\n"
            "| `ENG-013` | provider qualification | `PROPOSED` |\n",
            encoding="utf-8",
        )
        (self.repo / "docs/development/tasks/ENG-012-acceptance.md").write_text(
            "# ENG-012 — Deterministic Integrated Semantic Acceptance\n\n"
            "Cross-system semantic acceptance work.\n",
            encoding="utf-8",
        )
        self._git("add", ".")
        self._git("commit", "-m", "base")
        self.branch = self._git("branch", "--show-current")
        self.baseline_head = self._git("rev-parse", "HEAD")
        self.baseline_tree = self._git("rev-parse", "HEAD^{tree}")
        self.manifest = {
            "project_id": "SYNTH-001",
            "repository_path": str(self.repo),
            "canonical_branch": self.branch,
            "canonical_docs": {
                "current": "docs/development/CURRENT.md",
                "engineering_plan": "docs/development/ENGINEERING_PLAN.md",
                "governance": ["AGENTS.md"],
                "project": ["README.md", "docs/README.md"],
            },
            "discovery_rules": {
                "current_next_work_marker": "**Next executable work:**",
                "plan_task_column": "Task",
                "plan_state_column": "State",
                "eligible_plan_states": ["PROPOSED", "READY"],
                "task_id_pattern": "ENG-[0-9]{3}",
                "task_file_glob": "docs/development/tasks/{task_id}-*.md",
            },
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def _inspection(self) -> dict:
        return inspect_project(self.manifest)

    def _work_item(self) -> dict:
        return discover_next_work(self.manifest, self._inspection())

    def _contract(self, *, owned_paths: list[str] | None = None, inspection: dict | None = None) -> dict:
        return draft_design_contract(
            self.manifest,
            self._work_item(),
            inspection or self._inspection(),
            run_id="HARN-002-SYNTH-001",
            owned_paths=owned_paths or ["src/semantic.ts"],
            success_criteria=["semantic acceptance passes"],
            acceptance_instruments=[[sys.executable, "-c", "raise SystemExit(0)"]],
        )

    @staticmethod
    def _gate_a(contract: dict, dirty: list[str] | None = None) -> dict:
        return {
            "gate": "HUMAN_GATE_A",
            "decision": "APPROVED",
            "contract_id": contract["contract_id"],
            "contract_hash": contract["contract_hash"],
            "baseline_head": contract["baseline_head"],
            "baseline_tree": contract["baseline_tree"],
            "authorized_protected_dirty_paths": dirty or [],
        }

    def test_manifest_is_closed_and_inspection_is_read_only(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            ProjectManifest.from_mapping({**self.manifest, "unexpected": True})
        before = (self._git("rev-parse", "HEAD"), self._git("status", "--porcelain"))
        result = self._inspection()
        self.assertEqual(result["result"], "PROJECT_INSPECTED")
        self.assertEqual(result["dirty_paths"], [])
        self.assertEqual(before, (self._git("rev-parse", "HEAD"), self._git("status", "--porcelain")))

    def test_discovery_requires_agreement_between_current_and_plan(self) -> None:
        work = self._work_item()
        self.assertEqual(work["work_item_id"], "ENG-012")
        self.assertEqual(classify_work(work)["work_shape"], WorkShape.ARCHITECTURAL.value)
        (self.repo / "docs/development/ENGINEERING_PLAN.md").write_text(
            "| Task | Description | State |\n| --- | --- | --- |\n| `ENG-099` | wrong frontier | `PROPOSED` |\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(GovernanceBlockerError, "CURRENT says ENG-012"):
            discover_next_work(self.manifest)

    def test_bootstrap_discovery_does_not_require_a_task_packet(self) -> None:
        task_path = self.repo / "docs/development/tasks/ENG-012-acceptance.md"
        task_path.unlink()
        before = (self._git("rev-parse", "HEAD"), self._git("status", "--porcelain"))

        work = discover_next_work(self.manifest)
        self.assertEqual(work["result"], "NEXT_WORK_DISCOVERED")
        self.assertEqual(work["work_item_id"], "ENG-012")
        self.assertIsNone(work["task_path"])
        self.assertEqual(work["task_packet_status"], "MISSING / TO_BE_DERIVED_OR_CANONICALIZED_AFTER_GATE_A")
        self.assertEqual(work["execution_status"], "NOT AUTHORIZED")
        self.assertEqual(work["runner_status"], "NOT INVOKED")

        state_path = self.root / "controller-state.json"
        controller = Controller(ProjectManifest.from_mapping(self.manifest), state_path)
        contract = controller.draft(
            run_id="HARN-002-BOOTSTRAP-001",
            owned_paths=["src/semantic.ts"],
            success_criteria=["semantic acceptance passes"],
            acceptance_instruments=[[sys.executable, "-c", "raise SystemExit(0)"]],
        )
        self.assertEqual(contract["work_item_id"], "ENG-012")
        self.assertEqual(contract["readiness"]["task_packet"], "MISSING / TO_BE_DERIVED_OR_CANONICALIZED_AFTER_GATE_A")
        self.assertEqual(contract["readiness"]["execution"], "NOT AUTHORIZED")
        self.assertEqual(contract["readiness"]["runner"], "NOT INVOKED")
        self.assertEqual(load_controller_state(state_path)["phase"], ControllerPhase.WAITING_HUMAN_GATE_A.value)

        packet_path = self.root / "packet.json"
        with patch("prj226_runner.controller.run_packet") as runner:
            with self.assertRaises(GovernanceBlockerError):
                controller.derive(contract, {}, packet_path)
            runner.assert_not_called()
        self.assertFalse(packet_path.exists())
        self.assertEqual(before, (self._git("rev-parse", "HEAD"), self._git("status", "--porcelain")))

    def test_unknown_frontier_is_a_governance_blocker_even_without_task_packet(self) -> None:
        (self.repo / "docs/development/tasks/ENG-012-acceptance.md").unlink()
        (self.repo / "docs/development/ENGINEERING_PLAN.md").write_text(
            "| Task | Description | State |\n| --- | --- | --- |\n| `ENG-013` | wrong frontier | `PROPOSED` |\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(GovernanceBlockerError, "CURRENT says ENG-012"):
            discover_next_work(self.manifest)

    def test_existing_consistent_task_packet_is_optional_discovery_evidence(self) -> None:
        work = self._work_item()
        self.assertEqual(work["task_packet_status"], "PRESENT / EXECUTION_AUTHORITY_EVIDENCE")
        self.assertEqual(work["task_path"], "docs/development/tasks/ENG-012-acceptance.md")

    def test_existing_contradictory_task_packet_fails_closed(self) -> None:
        (self.repo / "docs/development/tasks/ENG-012-acceptance.md").write_text(
            "# ENG-013 — Provider qualification\n\nContradictory packet.\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(GovernanceBlockerError, "contradicts frontier"):
            discover_next_work(self.manifest)

    def test_contract_stops_at_gate_a_without_project_mutation(self) -> None:
        head, tree = self.baseline_head, self.baseline_tree
        contract = self._contract()
        self.assertEqual(contract["baseline_head"], head)
        self.assertEqual(contract["baseline_tree"], tree)
        self.assertEqual(contract["work_shape"], WorkShape.ARCHITECTURAL.value)
        self.assertEqual(self._git("rev-parse", "HEAD"), head)
        self.assertEqual(self._git("rev-parse", "HEAD^{tree}"), tree)
        self.assertEqual(self._git("status", "--porcelain"), "")

    def test_stale_baseline_refuses_gate_a_execution(self) -> None:
        contract = self._contract()
        (self.repo / "unrelated.txt").write_text("drift\n", encoding="utf-8")
        self._git("add", "unrelated.txt")
        self._git("commit", "-m", "drift")
        with self.assertRaisesRegex(GovernanceBlockerError, "STALE_BASELINE"):
            validate_gate_a(contract, self._gate_a(contract))

    def test_dirty_overlap_is_protected_and_refused_without_exact_authority(self) -> None:
        (self.repo / "src").mkdir()
        (self.repo / "src/semantic.ts").write_text("human\n", encoding="utf-8")
        inspection = self._inspection()
        self.assertEqual(inspection["protected_dirty_paths"], ["src/semantic.ts"])
        contract = self._contract(inspection=inspection)
        with self.assertRaisesRegex(GovernanceBlockerError, "Protected dirty"):
            validate_gate_a(contract, self._gate_a(contract))
        # Exact dirty-path authority is accepted by the binding check, while
        # the existing HARN-001 runner will still refuse a dirty canonical base.
        with patch("prj226_runner.controller._git", side_effect=[self.branch, self.baseline_head, self.baseline_tree]), patch(
            "prj226_runner.controller._dirty_paths", return_value=["src/semantic.ts"]
        ):
            validate_gate_a(contract, self._gate_a(contract, ["src/semantic.ts"]))

    def test_gate_a_bypass_does_not_invoke_harn001_runner(self) -> None:
        contract = self._contract()
        packet_path = self.root / "packet.json"
        with patch("prj226_runner.controller.run_packet") as runner:
            with self.assertRaises(GovernanceBlockerError):
                derive_task_packet(contract, {}, output_path=packet_path)
            runner.assert_not_called()
        self.assertFalse(packet_path.exists())

    def test_packet_widening_is_rejected(self) -> None:
        contract = self._contract()
        packet = derive_task_packet(contract, self._gate_a(contract))
        packet["authorized_paths"].append("outside.txt")
        with self.assertRaises(GovernanceBlockerError):
            validate_task_packet_derivation(contract, packet)
        packet = derive_task_packet(contract, self._gate_a(contract))
        packet["acceptance_criteria"].append("unapproved criterion")
        with self.assertRaises(GovernanceBlockerError):
            validate_task_packet_derivation(contract, packet)

    def test_stale_review_is_rejected(self) -> None:
        review = self._codex_review(self._contract())
        with self.assertRaisesRegex(GovernanceBlockerError, "REVIEW_STALE"):
            validate_review_binding({**review, "reviewed_head": "a" * 40, "reviewed_tree": "b" * 40}, "c" * 40, "d" * 40)
        with self.assertRaisesRegex(GovernanceBlockerError, "REVIEW_STALE"):
            validate_review_binding({**review, "reviewed_head": "a" * 40, "reviewed_tree": "b" * 40}, "a" * 40, "b" * 40, actual_candidate_head="c" * 40, actual_candidate_tree="d" * 40)

    def _codex_review(self, contract: dict, disposition: str = "PASS") -> dict:
        axis_status = "PASS" if disposition == "PASS" else "NEEDS_FIX"
        findings = [] if disposition == "PASS" else ["blocking finding"]
        return {
            "disposition": disposition,
            "reviewed_head": "a" * 40,
            "reviewed_tree": "b" * 40,
            "security": {"status": axis_status, "findings": findings},
            "operability": {"status": axis_status, "findings": findings},
            "semantics": {"status": axis_status, "findings": findings},
            "architecture": {"status": axis_status, "findings": findings},
            "blocking_findings": findings,
            "non_blocking_findings": [],
        }

    def test_identity_only_runner_and_review_evidence_are_rejected(self) -> None:
        contract = self._contract()
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(contract, {
                "run_id": contract["run_id"], "result": "ACCEPTANCE_READY", "candidate_head": "a" * 40,
                "candidate_tree": "b" * 40, "dv_result": "PASS", "sos_result": "ACCEPT",
            })
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(contract, {
                "result": "RESULT_INGESTED", "controller_phase": "ACCEPTANCE_READY",
                "run_id": contract["run_id"], "candidate_head": "a" * 40, "candidate_tree": "b" * 40,
            }, self._codex_review(contract))

    def test_gate_b_bypass_leaves_canonical_branch_unchanged(self) -> None:
        contract = self._contract()
        gate_b = {
            "gate": "HUMAN_GATE_B", "decision": "PENDING", "contract_id": contract["contract_id"],
            "contract_hash": contract["contract_hash"], "run_id": contract["run_id"],
            "baseline_head": contract["baseline_head"], "baseline_tree": contract["baseline_tree"],
            "candidate_head": "a" * 40, "candidate_tree": "b" * 40, "candidate_ref": "candidate",
        }
        before = self._git("rev-parse", "HEAD")
        with self.assertRaises(GovernanceBlockerError):
            integrate_after_gate_b(contract, gate_b, perform=True)
        self.assertEqual(self._git("rev-parse", "HEAD"), before)

    def test_incomplete_result_cannot_prepare_gate_b(self) -> None:
        contract = self._contract()
        candidate_head, candidate_tree = "a" * 40, "b" * 40
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(contract, {
                "run_id": contract["run_id"], "result": "ACCEPTANCE_READY", "candidate_head": candidate_head,
                "candidate_tree": candidate_tree, "dv_result": "PASS", "sos_result": "ACCEPT",
                "evidence_paths": {"worktree": "/tmp/candidate", "report": "/tmp/report.json"},
            })

    def test_state_git_drift_fails_closed(self) -> None:
        contract = self._contract()
        state = {
            "project_id": self.manifest["project_id"], "repository": str(self.repo.resolve()),
            "canonical_branch": self.branch, "baseline_head": contract["baseline_head"],
            "baseline_tree": contract["baseline_tree"], "protected_dirty_paths": [],
            "work_item_id": contract["work_item_id"], "work_shape": contract["work_shape"],
            "contract_id": contract["contract_id"], "task_packet_ref": None, "run_id": contract["run_id"],
            "candidate_head": None, "candidate_tree": None,
            "candidate_ref": None,
            "phase": ControllerPhase.WAITING_HUMAN_GATE_A.value, "pending_gate": "HUMAN_GATE_A",
        }
        state_path = self.root / "state.json"
        write_controller_state(state_path, state)
        self._git("commit", "--allow-empty", "-m", "drift")
        with self.assertRaisesRegex(GovernanceBlockerError, "STATE_GIT_DRIFT|STALE"):
            resume_controller(self.manifest, state_path)
        self.assertEqual(load_controller_state(state_path)["phase"], ControllerPhase.WAITING_HUMAN_GATE_A.value)

    def test_dispatch_reuses_existing_runner_once_after_exact_binding(self) -> None:
        contract = self._contract()
        packet_path = self.root / "packet.json"
        derive_task_packet(contract, self._gate_a(contract), output_path=packet_path)
        fake_result = {"result": "ACCEPTANCE_READY", "run_id": contract["run_id"], "candidate_head": "a" * 40, "candidate_tree": "b" * 40}
        with patch("prj226_runner.controller.run_packet", return_value=fake_result) as runner:
            with self.assertRaises(ArtifactValidationError):
                Controller(self.manifest).dispatch(contract, self._gate_a(contract), packet_path)
        runner.assert_called_once_with(packet_path, None, authorize=True)

    def test_synthetic_end_to_end_reaches_acceptance_ready_through_harn001(self) -> None:
        provider = self.root / "provider.py"
        provider.write_text(
            "#!" + sys.executable + "\n"
            "import json, pathlib, subprocess, sys\n"
            "value = sys.argv[-1]\n"
            "if 'provided closed schema' in value:\n"
            "  output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "  head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()\n"
            "  tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()\n"
            "  axis = {'status': 'PASS', 'findings': []}\n"
            "  output.parent.mkdir(parents=True, exist_ok=True)\n"
            "  output.write_text(json.dumps({'disposition': 'PASS', 'reviewed_head': head, 'reviewed_tree': tree, 'security': axis, 'operability': axis, 'semantics': axis, 'architecture': axis, 'blocking_findings': [], 'non_blocking_findings': []}), encoding='utf-8')\n"
            "elif 'Review this candidate' in value:\n"
            "  print(json.dumps({'result': 'PASS', 'findings': []}))\n"
            "else:\n"
            "  target = pathlib.Path('src/semantic.ts')\n"
            "  target.parent.mkdir(parents=True, exist_ok=True)\n"
            "  target.write_text('candidate\\n')\n",
            encoding="utf-8",
        )
        provider.chmod(0o755)
        runtime = self.root / "runtime"
        config = self.root / "runner.toml"
        executable = json.dumps(str(provider))
        config.write_text(
            "[runner]\n" + f"runtime_root = {json.dumps(str(runtime))}\n\n"
            "[agents.builder]\n" + f"tool = 'codex'\nexecutable = {executable}\nmodel = 'builder'\n" +
            "timeout_seconds = 20\n\n[agents.dv]\n" + f"tool = 'opencode2'\nexecutable = {executable}\nmodel = 'dv'\n" +
            "timeout_seconds = 20\n\n[agents.sos_reviewer]\n" + f"tool = 'codex'\nexecutable = {executable}\nmodel = 'gpt-5.6-luna'\n" +
            "timeout_seconds = 20\n",
            encoding="utf-8",
        )
        contract = self._contract()
        packet_path = self.root / "packet.json"
        derive_task_packet(contract, self._gate_a(contract), output_path=packet_path)
        result = Controller(self.manifest).dispatch(contract, self._gate_a(contract), packet_path, config)
        self.assertEqual(result["result"], "ACCEPTANCE_READY", result)
        ingested = ingest_runner_result(contract, result)
        persisted = load_controller_result(Path(result["runtime_root"]) / "controller-result.json")
        jsonschema.Draft7Validator(json.loads((Path(__file__).parents[1] / "schemas/controller-result.schema.json").read_text(encoding="utf-8"))).validate(persisted)
        self.assertEqual(persisted, ingested)
        gate_b = prepare_gate_b(contract, ingested, json.loads(Path(result["review_artifact"]).read_text(encoding="utf-8")))
        self.assertEqual(gate_b["decision"], "PENDING")
        self.assertEqual(self._git("rev-parse", "HEAD"), self.baseline_head)

    def test_positive_exact_gate_a_lifecycle_binds_fixture_and_reaches_gate_b(self) -> None:
        """A real fixture identity must authorize the complete HARN-002 path."""
        state_path = self.root / "controller-state.json"
        contract_path = self.root / "design-contract.json"
        packet_path = self.root / "task-packet.json"
        controller = Controller(ProjectManifest.from_mapping(self.manifest), state_path)

        # The facade performs discovery and contract drafting from this fixture's
        # live Git identity; no contract or baseline identity is synthetic.
        contract = controller.draft(
            run_id="HARN-002-POSITIVE-001",
            owned_paths=["src/semantic.ts"],
            success_criteria=["semantic acceptance passes"],
            acceptance_instruments=[[sys.executable, "-c", "raise SystemExit(0)"]],
            output_path=contract_path,
        )
        self.assertEqual(load_controller_state(state_path)["phase"], ControllerPhase.WAITING_HUMAN_GATE_A.value)
        self.assertEqual(contract["baseline_head"], self._git("rev-parse", "HEAD"))
        self.assertEqual(contract["baseline_tree"], self._git("rev-parse", "HEAD^{tree}"))

        gate_a = self._gate_a(contract)
        validate_gate_a(contract, gate_a)
        for field, altered in (
            ("contract_id", "design-" + "0" * 64),
            ("contract_hash", "0" * 64),
            ("baseline_head", "0" * 40),
            ("baseline_tree", "0" * 40),
        ):
            with self.subTest(altered_field=field):
                altered_gate = dict(gate_a)
                altered_gate[field] = altered
                with self.assertRaises(GovernanceBlockerError):
                    validate_gate_a(contract, altered_gate, inspect=False)

        packet = controller.derive(contract, gate_a, packet_path)
        validate_task_packet_derivation(contract, packet)
        self.assertEqual(load_controller_state(state_path)["phase"], ControllerPhase.EXECUTION_PREP.value)

        provider = self.root / "provider-positive.py"
        provider.write_text(
            "#!" + sys.executable + "\n"
            "import json, pathlib, subprocess, sys\n"
            "value = sys.argv[-1]\n"
            "if 'provided closed schema' in value:\n"
            "  output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "  head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()\n"
            "  tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()\n"
            "  axis = {'status': 'PASS', 'findings': []}\n"
            "  output.parent.mkdir(parents=True, exist_ok=True)\n"
            "  output.write_text(json.dumps({'disposition': 'PASS', 'reviewed_head': head, 'reviewed_tree': tree, 'security': axis, 'operability': axis, 'semantics': axis, 'architecture': axis, 'blocking_findings': [], 'non_blocking_findings': []}), encoding='utf-8')\n"
            "elif 'Review this candidate' in value:\n"
            "  print(json.dumps({'result': 'PASS', 'findings': []}))\n"
            "else:\n"
            "  target = pathlib.Path('src/semantic.ts')\n"
            "  target.parent.mkdir(parents=True, exist_ok=True)\n"
            "  target.write_text('candidate\\n')\n",
            encoding="utf-8",
        )
        provider.chmod(0o755)
        runtime = self.root / "positive-runtime"
        config = self.root / "positive-runner.toml"
        executable = json.dumps(str(provider))
        config.write_text(
            "[runner]\n" + f"runtime_root = {json.dumps(str(runtime))}\n\n"
            "[agents.builder]\n" + f"tool = 'codex'\nexecutable = {executable}\nmodel = 'builder'\n"
            "timeout_seconds = 20\n\n[agents.dv]\n" + f"tool = 'opencode2'\nexecutable = {executable}\nmodel = 'dv'\n"
            "timeout_seconds = 20\n\n[agents.sos_reviewer]\n" + f"tool = 'codex'\nexecutable = {executable}\nmodel = 'gpt-5.6-luna'\n"
            "timeout_seconds = 20\n",
            encoding="utf-8",
        )

        result = controller.dispatch(contract, gate_a, packet_path, config)
        self.assertEqual(result["result"], "ACCEPTANCE_READY", result)
        ingested = ingest_runner_result(contract, result)
        self.assertEqual(ingested["candidate_head"], result["candidate_head"])
        self.assertEqual(ingested["candidate_tree"], result["candidate_tree"])
        self.assertEqual(load_controller_state(state_path)["phase"], ControllerPhase.ACCEPTANCE_READY.value)
        self.assertEqual(load_controller_state(state_path)["candidate_head"], result["candidate_head"])
        self.assertEqual(load_controller_state(state_path)["candidate_tree"], result["candidate_tree"])

        gate_b = prepare_gate_b(
            contract,
            ingested,
            json.loads(Path(result["review_artifact"]).read_text(encoding="utf-8")),
        )
        self.assertEqual(gate_b["decision"], "PENDING")
        self.assertEqual(gate_b["candidate_head"], result["candidate_head"])
        self.assertEqual(gate_b["candidate_tree"], result["candidate_tree"])
        self.assertEqual(self._git("rev-parse", "HEAD"), self.baseline_head)


if __name__ == "__main__":
    unittest.main()
