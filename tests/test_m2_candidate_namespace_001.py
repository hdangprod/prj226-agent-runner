"""M2-CANDIDATE-NAMESPACE-001: Deterministic Qualification Test Suite.

Proves:
1. Candidate namespace collision resolved for new V3 authority without touching historical refs.
2. Independent campaigns with identical run IDs use distinct cryptographic candidate refs.
3. Exact replay is deterministically blocked closed with GovernanceBlockerError (no retry, no rename).
4. Historical V1/V2 candidate ref derivation remains strictly preserved and unchanged.
5. Exact candidate ref propagation across all 7 lifecycle stages.
6. Legacy adaptation boundary does not fall through to legacy naming for V3.
7. Cross-campaign STOPPED-result provenance contamination is strictly rejected.
8. Negative tests: ref deletion, repointing, foreign ref, tampering, mixed versions, malformed refs.
9. No provider invocation on preflight or governance blockers.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from prj226_runner import candidate_authority as CA
from prj226_runner import candidate_identity as CI
from prj226_runner import controller as C
from prj226_runner import runner as R
from prj226_runner import workflow as W
from prj226_runner.cli import main as cli_main
from prj226_runner.errors import (
    ArtifactValidationError,
    GovernanceBlockerError,
    ReviewStaleError,
    RunnerError,
)

FAKE_BUILDER_SRC = """#!@@EXE@@
import json, os, pathlib, subprocess, sys
counter = pathlib.Path(@@COUNTER@@)
try:
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
except Exception:
    prior = 0
counter.write_text(str(prior + 1), encoding="utf-8")
if os.environ.get("FAKE_BUILDER_FAIL"):
    raise SystemExit(3)
target = pathlib.Path(os.environ.get("FAKE_TARGET", "src/app.txt"))
if os.environ.get("FAKE_NO_CHANGE"):
    raise SystemExit(0)
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("candidate content\\n", encoding="utf-8")
"""

FAKE_REVIEWER_SRC = """#!@@EXE@@
import json, os, pathlib, subprocess, sys
counter = pathlib.Path(@@COUNTER@@)
try:
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
except Exception:
    prior = 0
counter.write_text(str(prior + 1), encoding="utf-8")
args = sys.argv
out = pathlib.Path(args[args.index("-o") + 1]) if "-o" in args else None
prompt = args[-1] if len(args) > 1 else ""

head = "0" * 40
tree = "0" * 40
ref_from_prompt = None

try:
    context_str = prompt.split("\\n\\n")[-1]
    context_data = json.loads(context_str)
    head = context_data.get("candidate_head") or ("0" * 40)
    tree = context_data.get("candidate_tree") or ("0" * 40)
    ref_from_prompt = context_data.get("candidate_ref")
except Exception:
    pass

if out is None:
    raise SystemExit(0)

out.parent.mkdir(parents=True, exist_ok=True)
payload = {
    "review_version": "HARN-002.TARGETED_REVIEW.v1",
    "disposition": "PASS",
    "reviewed_head": head,
    "reviewed_tree": tree,
    "blocking_findings": [],
    "non_blocking_findings": [],
}
if ref_from_prompt is not None:
    payload["reviewed_ref"] = ref_from_prompt

out.write_text(json.dumps(payload), encoding="utf-8")
"""


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class NamespaceTestFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "product"
        self.runtime = root / "runtime"
        self.config = root / "runner.toml"
        self.manifest_path = root / "manifest.json"
        self.builder_count = root / "builder-count.txt"
        self.reviewer_count = root / "reviewer-count.txt"
        self.fake_builder = root / "fake-builder.py"
        self.fake_reviewer = root / "fake-reviewer.py"
        self.manifest_dict: dict[str, Any] = {}

    def init(self) -> None:
        self.repo.mkdir(parents=True, exist_ok=True)
        self.runtime.mkdir(parents=True, exist_ok=True)

        _git(self.repo, "init")
        _git(self.repo, "config", "user.name", "Namespace Tests")
        _git(self.repo, "config", "user.email", "namespace@example.test")
        _git(self.repo, "config", "commit.gpgsign", "false")

        (self.repo / "src").mkdir(parents=True, exist_ok=True)
        (self.repo / "src" / "app.txt").write_text("initial\n", encoding="utf-8")
        (self.repo / "README.md").write_text("repo\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs" / "tasks").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / "CURRENT.md").write_text("**Next executable work:** TASK-001\n", encoding="utf-8")
        (self.repo / "docs" / "PLAN.md").write_text(
            "| Task | Description | State |\n| --- | --- | --- |\n| TASK-001 | acceptance | PROPOSED |\n",
            encoding="utf-8",
        )
        (self.repo / "docs" / "tasks" / "TASK-001.md").write_text("# TASK-001 — Acceptance\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "initial commit")
        self.canonical_branch = _git(self.repo, "branch", "--show-current")

        builder_code = FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace(
            "@@COUNTER@@", json.dumps(str(self.builder_count))
        )
        self.fake_builder.write_text(builder_code, encoding="utf-8")
        self.fake_builder.chmod(self.fake_builder.stat().st_mode | stat.S_IXUSR)

        reviewer_code = FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace(
            "@@COUNTER@@", json.dumps(str(self.reviewer_count))
        )
        self.fake_reviewer.write_text(reviewer_code, encoding="utf-8")
        self.fake_reviewer.chmod(self.fake_reviewer.stat().st_mode | stat.S_IXUSR)

        self.write_config()

        self.manifest_dict = {
            "project_id": "NAMESPACE-TEST",
            "repository_path": str(self.repo),
            "canonical_branch": self.canonical_branch,
            "canonical_docs": {
                "current": "docs/CURRENT.md",
                "engineering_plan": "docs/PLAN.md",
                "governance": ["AGENTS.md"],
                "project": ["README.md"],
            },
            "discovery_rules": {
                "current_next_work_marker": "**Next executable work:**",
                "plan_task_column": "Task",
                "plan_state_column": "State",
                "eligible_plan_states": ["PROPOSED"],
                "task_id_pattern": "TASK-[0-9]+",
                "task_file_glob": "docs/tasks/{task_id}.md",
            },
        }
        self.manifest_path.write_text(json.dumps(self.manifest_dict, indent=2, sort_keys=True), encoding="utf-8")

    def write_config(self) -> None:
        self.config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(self.runtime))}\n\n"
            "[agents.builder]\n"
            "tool = \"codex\"\n"
            f"executable = {json.dumps(str(self.fake_builder))}\n"
            "model = \"gpt-5.6-luna\"\n"
            "timeout_seconds = 20\n\n"
            "[agents.dv]\n"
            "tool = \"opencode2\"\n"
            "executable = \"opencode\"\n"
            "model = \"Muse\"\n"
            "timeout_seconds = 20\n\n"
            "[agents.sos_reviewer]\n"
            "tool = \"codex\"\n"
            f"executable = {json.dumps(str(self.fake_reviewer))}\n"
            "model = \"gpt-5.6-luna\"\n"
            "timeout_seconds = 20\n",
            encoding="utf-8",
        )

    def builder_calls(self) -> int:
        return int(self.builder_count.read_text(encoding="utf-8")) if self.builder_count.exists() else 0

    def reviewer_calls(self) -> int:
        return int(self.reviewer_count.read_text(encoding="utf-8")) if self.reviewer_count.exists() else 0

    def draft_v2(self, run_id: str = "TASK-001-RUN", task_id: str = "TASK-001", targeted: bool = True, **overrides: Any) -> dict[str, Any]:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = {"work_item_id": task_id, "title": f"Work for {task_id}"}
        kwargs: dict[str, Any] = {
            "run_id": run_id,
            "owned_paths": ["src/app.txt"],
            "runtime_root": str(self.runtime),
            "change_categories": ["MODULE_BOUNDARY"] if targeted else [],
            "human_requested_targeted": False,
            "acceptance_instruments": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
        }
        if targeted:
            kwargs.update({
                "reviewer_executable": str(self.fake_reviewer),
                "reviewer_model": "gpt-5.6-luna",
                "reviewer_timeout_seconds": 20,
                "review_brief": "Targeted review brief",
            })
        kwargs.update(overrides)
        return C.draft_design_contract_v2(manifest, work_item, inspection, **kwargs)

    def draft_v3(self, run_id: str = "TASK-001-RUN", task_id: str = "TASK-001", targeted: bool = True, **overrides: Any) -> dict[str, Any]:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = {"work_item_id": task_id, "title": f"Work for {task_id}"}
        kwargs: dict[str, Any] = {
            "run_id": run_id,
            "owned_paths": ["src/app.txt"],
            "runtime_root": str(self.runtime),
            "change_categories": ["MODULE_BOUNDARY"] if targeted else [],
            "human_requested_targeted": False,
            "acceptance_instruments": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
        }
        if targeted:
            kwargs.update({
                "reviewer_executable": str(self.fake_reviewer),
                "reviewer_model": "gpt-5.6-luna",
                "reviewer_timeout_seconds": 20,
                "review_brief": "Targeted review brief",
            })
        kwargs.update(overrides)
        return C.draft_design_contract_v3(manifest, work_item, inspection, **kwargs)

    def gate_a_for(self, contract: dict[str, Any]) -> dict[str, Any]:
        overlap = sorted(
            path for path in contract.get("protected_dirty_paths", [])
            if any(path == owned or path.startswith(owned + "/") or owned.startswith(path + "/") for owned in contract["owned_paths"])
        )
        return {
            "gate": "HUMAN_GATE_A",
            "decision": "APPROVED",
            "contract_id": contract["contract_id"],
            "contract_hash": contract["contract_hash"],
            "baseline_head": contract["baseline_head"],
            "baseline_tree": contract["baseline_tree"],
            "authorized_protected_dirty_paths": overlap,
        }

    def init_workflow(self) -> dict[str, Any]:
        scopes_path = self.root / "scopes.json"
        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "default": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": [],
                },
                "context-authz": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": [],
                },
            },
        }
        scopes_path.write_text(json.dumps(scopes_dict, indent=2, sort_keys=True), encoding="utf-8")
        return W.init_project(self.manifest_path, self.config, scopes_path=scopes_path)


class TestM2CandidateNamespace(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.fixture = NamespaceTestFixture(Path(self.tmp.name))
        self.fixture.init()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # -------------------------------------------------------------------------
    # Test A: Historical branch collision reproduction and clean V3 resolution
    # -------------------------------------------------------------------------
    def test_a_historical_branch_collision_resolved_in_v3(self) -> None:
        """Historical branch collision: V2 collides on harn-candidate/{task}-{run}.

        V3 derives a namespaced candidate ref containing the full contract hash,
        creates the worktree cleanly, and leaves the historical branch untouched.
        """
        repo = self.fixture.repo
        initial_commit = _git(repo, "rev-parse", "HEAD")

        # 1. Simulate an existing historical candidate branch in the product repo
        legacy_branch = "harn-candidate/TASK-002-TASK-002-RUN"
        _git(repo, "branch", legacy_branch, initial_commit)
        self.assertEqual(_git(repo, "rev-parse", legacy_branch), initial_commit)

        # 2. Draft and execute new V3 authority with identical task and run labels
        contract = self.fixture.draft_v3(run_id="TASK-002-RUN", task_id="TASK-002")
        self.assertEqual(contract["contract_version"], "HARN-002.v3")

        contract_path = self.fixture.root / "contract-v3.json"
        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")

        gate_a = self.fixture.gate_a_for(contract)
        gate_path = self.fixture.root / "gate-a-v3.json"
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")

        packet_path = self.fixture.root / "packet-v3.json"
        packet = C.derive_task_packet_v3(contract, gate_a, output_path=packet_path)
        self.assertEqual(packet["packet_version"], "HARN-001.TASK_PACKET.v3")

        expected_v3_ref = f"harn-candidate/v3-TASK-002-TASK-002-RUN-{contract['contract_hash']}"
        derived_ref = CI.derive_candidate_ref_for_packet(packet)
        self.assertEqual(derived_ref, expected_v3_ref)
        self.assertNotEqual(derived_ref, legacy_branch)

        # 3. Execute V3 packet: worktree creation succeeds without collision
        result = R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual(result["candidate_ref"], expected_v3_ref)

        # 4. Verify the historical branch was untouched
        self.assertEqual(_git(repo, "rev-parse", legacy_branch), initial_commit)

        # 5. Verify the V3 candidate branch exists and points to the new candidate head
        self.assertTrue(_git(repo, "rev-parse", f"refs/heads/{expected_v3_ref}"))
        self.assertEqual(_git(repo, "rev-parse", f"refs/heads/{expected_v3_ref}"), result["candidate_head"])

    # -------------------------------------------------------------------------
    # Test B: Two independent campaigns with identical task/run IDs
    # -------------------------------------------------------------------------
    def test_b_two_independent_campaigns_different_refs(self) -> None:
        """Two independent campaigns with identical task/run labels produce distinct V3 refs."""
        runtime_a = self.fixture.root / "runtime-campaign-a"
        runtime_b = self.fixture.root / "runtime-campaign-b"
        runtime_a.mkdir(parents=True, exist_ok=True)
        runtime_b.mkdir(parents=True, exist_ok=True)

        contract_a = self.fixture.draft_v3(run_id="SHARED-RUN", task_id="TASK-SHARED", runtime_root=str(runtime_a))
        contract_b = self.fixture.draft_v3(run_id="SHARED-RUN", task_id="TASK-SHARED", runtime_root=str(runtime_b))

        # Because runtime_root is bound into Design Contract, contract hashes differ
        self.assertNotEqual(contract_a["contract_hash"], contract_b["contract_hash"])

        ref_a = CI.derive_candidate_ref_for_contract(contract_a)
        ref_b = CI.derive_candidate_ref_for_contract(contract_b)
        self.assertNotEqual(ref_a, ref_b)
        self.assertTrue(ref_a.endswith(contract_a["contract_hash"]))
        self.assertTrue(ref_b.endswith(contract_b["contract_hash"]))

        # Execute Campaign A
        config_a = self.fixture.root / "runner-a.toml"
        config_a.write_text(
            self.fixture.config.read_text(encoding="utf-8").replace(str(self.fixture.runtime), str(runtime_a)),
            encoding="utf-8",
        )
        gate_a = self.fixture.gate_a_for(contract_a)
        packet_path_a = self.fixture.root / "packet-a.json"
        contract_path_a = self.fixture.root / "contract-a.json"
        gate_path_a = self.fixture.root / "gate-a.json"
        contract_path_a.write_text(json.dumps(contract_a, indent=2), encoding="utf-8")
        gate_path_a.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")
        C.derive_task_packet_v3(contract_a, gate_a, output_path=packet_path_a)

        result_a = R.run_packet_v3(packet_path_a, contract_path_a, gate_path_a, config_a, authorize=True)
        self.assertEqual(result_a["result"], "ACCEPTANCE_READY")

        # Execute Campaign B in same product repo
        config_b = self.fixture.root / "runner-b.toml"
        config_b.write_text(
            self.fixture.config.read_text(encoding="utf-8").replace(str(self.fixture.runtime), str(runtime_b)),
            encoding="utf-8",
        )
        gate_b = self.fixture.gate_a_for(contract_b)
        packet_path_b = self.fixture.root / "packet-b.json"
        contract_path_b = self.fixture.root / "contract-b.json"
        gate_path_b = self.fixture.root / "gate-b.json"
        contract_path_b.write_text(json.dumps(contract_b, indent=2), encoding="utf-8")
        gate_path_b.write_text(json.dumps(gate_b, indent=2), encoding="utf-8")
        C.derive_task_packet_v3(contract_b, gate_b, output_path=packet_path_b)

        result_b = R.run_packet_v3(packet_path_b, contract_path_b, gate_path_b, config_b, authorize=True)
        self.assertEqual(result_b["result"], "ACCEPTANCE_READY")

        # Both candidate branches exist simultaneously in product repo without collision
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{ref_a}"))
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{ref_b}"))

    # -------------------------------------------------------------------------
    # Test C: Exact replay blocked closed
    # -------------------------------------------------------------------------
    def test_c_exact_replay_blocked(self) -> None:
        """Replaying the exact same frozen V3 authority halts closed with GovernanceBlockerError."""
        contract = self.fixture.draft_v3(run_id="REPLAY-RUN", task_id="TASK-REPLAY")
        gate_a = self.fixture.gate_a_for(contract)
        contract_path = self.fixture.root / "contract-replay.json"
        gate_path = self.fixture.root / "gate-replay.json"
        packet_path = self.fixture.root / "packet-replay.json"

        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")
        C.derive_task_packet_v3(contract, gate_a, output_path=packet_path)

        # 1st run succeeds
        result1 = R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)
        self.assertEqual(result1["result"], "ACCEPTANCE_READY")
        call_count_after_first = self.fixture.builder_calls()
        self.assertGreater(call_count_after_first, 0)

        # 2nd run with the exact same authority must fail closed before builder invocation
        with self.assertRaises(GovernanceBlockerError) as ctx:
            R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)

        self.assertIn("already exists", str(ctx.exception))
        # Ensure builder was not called again (zero retry, zero alternate name)
        self.assertEqual(self.fixture.builder_calls(), call_count_after_first)

    # -------------------------------------------------------------------------
    # Test D: Historical V1/V2 compatibility
    # -------------------------------------------------------------------------
    def test_d_historical_v1_v2_compatibility(self) -> None:
        """V1 and V2 authority derivation remains strictly preserved."""
        # 1. Test derive_candidate_ref directly
        v1_ref = CI.derive_candidate_ref(
            authority_version="v1",
            task_id="TASK-001",
            run_id="RUN-001",
            contract_hash="a" * 64,
        )
        self.assertEqual(v1_ref, "harn-candidate/TASK-001-RUN-001")

        v2_ref = CI.derive_candidate_ref(
            authority_version="v2",
            task_id="TASK-001",
            run_id="RUN-001",
            contract_hash="a" * 64,
        )
        self.assertEqual(v2_ref, "harn-candidate/TASK-001-RUN-001")

        # 2. Test V2 contract and packet derivation
        contract_v2 = self.fixture.draft_v2(run_id="V2-RUN", task_id="TASK-V2")
        gate_v2 = self.fixture.gate_a_for(contract_v2)
        packet_v2 = C.derive_task_packet_v2(contract_v2, gate_v2)

        self.assertEqual(CI.derive_candidate_ref_for_contract(contract_v2), "harn-candidate/TASK-V2-V2-RUN")
        self.assertEqual(CI.derive_candidate_ref_for_packet(packet_v2), "harn-candidate/TASK-V2-V2-RUN")

        # 3. V3 authority explicitly produces versioned name
        contract_v3 = self.fixture.draft_v3(run_id="V3-RUN", task_id="TASK-V3")
        expected_v3 = f"harn-candidate/v3-TASK-V3-V3-RUN-{contract_v3['contract_hash']}"
        self.assertEqual(CI.derive_candidate_ref_for_contract(contract_v3), expected_v3)

    # -------------------------------------------------------------------------
    # Test E: Propagation across all 7 lifecycle stages
    # -------------------------------------------------------------------------
    def test_e_candidate_ref_propagation(self) -> None:
        """Exact ref equality across all 7 lifecycle stages:

        1. Preflight
        2. Git branch
        3. Candidate authority
        4. Reviewer output (reviewed_ref)
        5. Runner result (report.json)
        6. Controller ingested result
        7. Gate B package
        """
        contract = self.fixture.draft_v3(run_id="PROP-RUN", task_id="TASK-PROP", targeted=True)
        gate_a = self.fixture.gate_a_for(contract)
        contract_path = self.fixture.root / "contract-prop.json"
        gate_path = self.fixture.root / "gate-prop.json"
        packet_path = self.fixture.root / "packet-prop.json"

        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")
        packet = C.derive_task_packet_v3(contract, gate_a, output_path=packet_path)

        expected_ref = CI.derive_candidate_ref_for_contract(contract)

        # Stage 1: Preflight inspection
        preflight = R.inspect_packet_v3(packet_path, contract_path, gate_path, self.fixture.config)
        stage_1_ref = preflight["candidate_branch"]
        self.assertEqual(stage_1_ref, expected_ref)

        # Execute
        runner_result = R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)
        self.assertEqual(runner_result["result"], "ACCEPTANCE_READY")

        # Stage 2: Target Git branch in repository
        stage_2_ref = runner_result["candidate_ref"]
        self.assertEqual(stage_2_ref, expected_ref)
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{stage_2_ref}"))

        # Stage 3: Candidate authority manifest in evidence directory
        run_root = self.fixture.runtime / "PROP-RUN"
        authority_file = run_root / "candidate-authority.json"
        self.assertTrue(authority_file.exists())
        authority_data = json.loads(authority_file.read_text(encoding="utf-8"))
        stage_3_ref = authority_data["candidate_ref"]
        self.assertEqual(stage_3_ref, expected_ref)

        # Stage 5: Runner report
        report_file = run_root / "report.json"
        report_data = json.loads(report_file.read_text(encoding="utf-8"))
        stage_5_ref = report_data["candidate_ref"]
        self.assertEqual(stage_5_ref, expected_ref)

        # Stage 4: Reviewer output reviewed_ref
        review_rel = report_data["review_evidence"]["artifact"]
        review_file = run_root / review_rel
        self.assertTrue(review_file.exists())
        review_data = json.loads(review_file.read_text(encoding="utf-8"))
        stage_4_ref = review_data["reviewed_ref"]
        self.assertEqual(stage_4_ref, expected_ref)

        # Stage 6: Controller ingested result
        ingested = C.ingest_runner_result_v3(contract, report_file)
        self.assertEqual(ingested["result"], "RESULT_INGESTED")
        stage_6_ref = ingested["candidate_ref"]
        self.assertEqual(stage_6_ref, expected_ref)

        # Stage 7: Gate B package
        gate_b = C.prepare_gate_b_v3(contract, ingested)
        stage_7_ref = gate_b["candidate_ref"]
        self.assertEqual(stage_7_ref, expected_ref)

        # Assert total equality across all 7 stages
        self.assertEqual(
            {stage_1_ref, stage_2_ref, stage_3_ref, stage_4_ref, stage_5_ref, stage_6_ref, stage_7_ref},
            {expected_ref},
        )

    # -------------------------------------------------------------------------
    # Test F: Legacy adaptation boundary
    # -------------------------------------------------------------------------
    def test_f_legacy_adaptation_boundary_no_fallthrough(self) -> None:
        """V3 execution never falls through to legacy candidate naming during worktree creation."""
        contract = self.fixture.draft_v3(run_id="ADAPT-RUN", task_id="TASK-ADAPT")
        gate_a = self.fixture.gate_a_for(contract)
        contract_path = self.fixture.root / "contract-adapt.json"
        gate_path = self.fixture.root / "gate-adapt.json"
        packet_path = self.fixture.root / "packet-adapt.json"

        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")
        C.derive_task_packet_v3(contract, gate_a, output_path=packet_path)

        result = R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")

        # The legacy candidate branch MUST NOT exist
        legacy_branch = "harn-candidate/TASK-ADAPT-ADAPT-RUN"
        check_legacy = subprocess.run(
            ["git", "-C", str(self.fixture.repo), "rev-parse", "--verify", f"refs/heads/{legacy_branch}"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(check_legacy.returncode, 0, "Legacy branch was created unexpectedly!")

    # -------------------------------------------------------------------------
    # Provenance Tests: Cross-campaign STOPPED report rejection
    # -------------------------------------------------------------------------
    def test_stopped_result_provenance_binding(self) -> None:
        """A STOPPED report from Campaign A must be rejected against Campaign B contract."""
        runtime_a = self.fixture.root / "runtime-camp-a"
        runtime_b = self.fixture.root / "runtime-camp-b"
        runtime_a.mkdir(parents=True, exist_ok=True)
        runtime_b.mkdir(parents=True, exist_ok=True)

        contract_a = self.fixture.draft_v3(run_id="TASK-002-RUN", task_id="TASK-002", runtime_root=str(runtime_a))
        contract_b = self.fixture.draft_v3(run_id="TASK-002-RUN", task_id="TASK-002", runtime_root=str(runtime_b))

        packet_a_map = C._packet_mapping_v2(contract_a)
        packet_b_map = C._packet_mapping_v2(contract_b)

        # Generate a STOPPED report for Campaign A
        report_a = {
            "version": "HARN-001.RUNNER_RESULT.v2",
            "result": "STOPPED",
            "run_id": "TASK-002-RUN",
            "contract_id": contract_a["contract_id"],
            "contract_hash": contract_a["contract_hash"],
            "task_packet_hash": C._sha(packet_a_map),
            "error_class": "ENVIRONMENT_ERROR",
            "error": "Simulated failure in Campaign A",
            "candidate_head": None,
            "candidate_tree": None,
            "candidate_ref": None,
        }
        # Generate a STOPPED report for Campaign B
        report_b = {
            "version": "HARN-001.RUNNER_RESULT.v2",
            "result": "STOPPED",
            "run_id": "TASK-002-RUN",
            "contract_id": contract_b["contract_id"],
            "contract_hash": contract_b["contract_hash"],
            "task_packet_hash": C._sha(packet_b_map),
            "error_class": "ENVIRONMENT_ERROR",
            "error": "Simulated failure in Campaign B",
            "candidate_head": None,
            "candidate_tree": None,
            "candidate_ref": None,
        }

        # 1. Crossing Campaign A report + Campaign B contract must be REJECTED
        with self.assertRaises(ArtifactValidationError) as ctx_cross_1:
            C.ingest_runner_result_v3(contract_b, report_a)
        self.assertIn("contract", str(ctx_cross_1.exception).lower())

        # 2. Crossing Campaign B report + Campaign A contract must be REJECTED
        with self.assertRaises(ArtifactValidationError) as ctx_cross_2:
            C.ingest_runner_result_v3(contract_a, report_b)
        self.assertIn("contract", str(ctx_cross_2.exception).lower())

        # 3. Same-campaign STOPPED ingestion must PASS
        ingested_a = C.ingest_runner_result_v3(contract_a, report_a)
        self.assertEqual(ingested_a["result"], "RESULT_INGESTED")
        self.assertEqual(ingested_a["controller_phase"], "STOPPED")

        ingested_b = C.ingest_runner_result_v3(contract_b, report_b)
        self.assertEqual(ingested_b["result"], "RESULT_INGESTED")
        self.assertEqual(ingested_b["controller_phase"], "STOPPED")

        # 4. Gate B preparation must remain blocked on STOPPED result
        with self.assertRaises(GovernanceBlockerError) as ctx_gate_b:
            C.prepare_gate_b_v3(contract_a, ingested_a)
        self.assertIn("cannot be prepared before ACCEPTANCE_READY", str(ctx_gate_b.exception))

    # -------------------------------------------------------------------------
    # Negative Tests (Section 13)
    # -------------------------------------------------------------------------
    def test_negative_candidate_ref_deleted(self) -> None:
        """If candidate ref is deleted before authority verification, fail closed."""
        contract = self.fixture.draft_v3(run_id="NEG-DEL", task_id="TASK-DEL")
        auth = CA.build_candidate_authority(
            repo=self.fixture.repo,
            candidate_head=_git(self.fixture.repo, "rev-parse", "HEAD"),
            candidate_ref="refs/heads/candidate-to-delete",
            baseline_head=_git(self.fixture.repo, "rev-parse", "HEAD"),
            approved_changed_paths=[],
        )
        # Create branch, then delete it
        _git(self.fixture.repo, "branch", "candidate-to-delete")
        _git(self.fixture.repo, "branch", "-D", "candidate-to-delete")

        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fixture.repo, auth, expected_ref="refs/heads/candidate-to-delete")

    def test_negative_candidate_ref_repointed(self) -> None:
        """If candidate ref is repointed to a different commit, fail closed."""
        head1 = _git(self.fixture.repo, "rev-parse", "HEAD")
        (self.fixture.repo / "src" / "other.txt").write_text("other\n", encoding="utf-8")
        _git(self.fixture.repo, "add", ".")
        _git(self.fixture.repo, "commit", "-m", "second commit")
        head2 = _git(self.fixture.repo, "rev-parse", "HEAD")

        # Authority binds candidate_head = head1, candidate_ref = refs/heads/cand-branch
        _git(self.fixture.repo, "branch", "cand-branch", head2)  # Points to head2 instead of head1
        auth = CA.build_candidate_authority(
            repo=self.fixture.repo,
            candidate_head=head1,
            candidate_ref="refs/heads/cand-branch",
            baseline_head=head1,
            approved_changed_paths=[],
        )
        # Check out head1 so HEAD matches
        _git(self.fixture.repo, "checkout", head1)
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fixture.repo, auth, expected_ref="refs/heads/cand-branch")

    def test_negative_foreign_ref_pointing_to_same_commit(self) -> None:
        """A foreign candidate ref pointing to the same commit is not interchangeable."""
        head = _git(self.fixture.repo, "rev-parse", "HEAD")
        _git(self.fixture.repo, "branch", "foreign-branch", head)
        auth = CA.build_candidate_authority(
            repo=self.fixture.repo,
            candidate_head=head,
            candidate_ref="refs/heads/foreign-branch",
            baseline_head=head,
            approved_changed_paths=[],
        )
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fixture.repo, auth, expected_ref="refs/heads/expected-branch")

    def test_negative_candidate_authority_tampering(self) -> None:
        """Tampering with candidate_ref in authority manifest fails closed with digest mismatch."""
        head = _git(self.fixture.repo, "rev-parse", "HEAD")
        _git(self.fixture.repo, "branch", "cand-auth-branch", head)
        auth = CA.build_candidate_authority(
            repo=self.fixture.repo,
            candidate_head=head,
            candidate_ref="refs/heads/cand-auth-branch",
            baseline_head=head,
            approved_changed_paths=[],
        )
        auth["candidate_ref"] = "refs/heads/tampered-branch"
        with self.assertRaises(GovernanceBlockerError) as ctx:
            CA.verify_candidate_authority(self.fixture.repo, auth)
        self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_negative_contract_hash_mismatch(self) -> None:
        """Contract hash mismatch between contract and packet/result fails closed."""
        contract = self.fixture.draft_v3(run_id="NEG-HASH", task_id="TASK-HASH")
        gate_a = self.fixture.gate_a_for(contract)
        packet = C.derive_task_packet_v3(contract, gate_a)

        # Mutate contract hash in packet
        packet["contract_hash"] = "f" * 64
        packet_path = self.fixture.root / "packet-mismatch.json"
        packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
        contract_path = self.fixture.root / "contract-mismatch.json"
        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
        gate_path = self.fixture.root / "gate-mismatch.json"
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")

        with self.assertRaises(RunnerError):
            R.inspect_packet_v3(packet_path, contract_path, gate_path, self.fixture.config)

    def test_negative_old_gate_a_with_changed_contract(self) -> None:
        """Old Gate A passed with changed contract fails closed with GovernanceBlockerError."""
        contract1 = self.fixture.draft_v3(run_id="NEG-GATEA-1", task_id="TASK-GA1")
        gate_a1 = self.fixture.gate_a_for(contract1)

        contract2 = self.fixture.draft_v3(run_id="NEG-GATEA-2", task_id="TASK-GA2")

        # Passing gate_a1 with contract2
        with self.assertRaises(GovernanceBlockerError):
            C.validate_gate_a_v2(contract2, gate_a1)

    def test_negative_mixed_authority_versions(self) -> None:
        """Mixed authority versions (e.g. V3 packet with V2 contract) fail closed."""
        contract_v2 = self.fixture.draft_v2(run_id="NEG-MIX", task_id="TASK-MIX")
        gate_v2 = self.fixture.gate_a_for(contract_v2)

        # Attempting to derive V3 packet from V2 contract fails
        with self.assertRaises(ArtifactValidationError):
            C.derive_task_packet_v3(contract_v2, gate_v2)

        # Attempting to inspect V2 packet with V3 runner fails
        packet_v2_path = self.fixture.root / "packet-v2-mix.json"
        contract_v2_path = self.fixture.root / "contract-v2-mix.json"
        gate_v2_path = self.fixture.root / "gate-v2-mix.json"
        C.derive_task_packet_v2(contract_v2, gate_v2, output_path=packet_v2_path)
        contract_v2_path.write_text(json.dumps(contract_v2, indent=2), encoding="utf-8")
        gate_v2_path.write_text(json.dumps(gate_v2, indent=2), encoding="utf-8")

        with self.assertRaises(ArtifactValidationError):
            R.inspect_packet_v3(packet_v2_path, contract_v2_path, gate_v2_path, self.fixture.config)

    def test_negative_unknown_authority_version(self) -> None:
        """Unknown authority versions fail closed."""
        raw_contract = copy.deepcopy(self.fixture.draft_v3(run_id="NEG-UNK", task_id="TASK-UNK"))
        raw_contract["contract_version"] = "HARN-002.v999"
        with self.assertRaises(ArtifactValidationError):
            C._normalize_contract_impl(raw_contract, "HARN-002.v999")

    def test_negative_existing_intended_candidate_ref(self) -> None:
        """If intended candidate ref already exists anywhere in repo, fail closed before provider call."""
        contract = self.fixture.draft_v3(run_id="NEG-EXIST", task_id="TASK-EXIST")
        gate_a = self.fixture.gate_a_for(contract)
        contract_path = self.fixture.root / "contract-exist.json"
        gate_path = self.fixture.root / "gate-exist.json"
        packet_path = self.fixture.root / "packet-exist.json"

        contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
        gate_path.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")
        packet = C.derive_task_packet_v3(contract, gate_a, output_path=packet_path)

        intended_ref = CI.derive_candidate_ref_for_packet(packet)
        # Pre-create intended candidate branch in target repository
        _git(self.fixture.repo, "branch", intended_ref)

        initial_builder_calls = self.fixture.builder_calls()
        with self.assertRaises(GovernanceBlockerError) as ctx:
            R.run_packet_v3(packet_path, contract_path, gate_path, self.fixture.config, authorize=True)

        self.assertIn("already exists", str(ctx.exception))
        # Zero provider invocation
        self.assertEqual(self.fixture.builder_calls(), initial_builder_calls)

    def test_negative_malformed_candidate_refs(self) -> None:
        """Validate malformed candidate refs fail closed."""
        malformed_refs = [
            "",
            "not-harn-candidate/branch",
            "harn-candidate/../traversal",
            "harn-candidate/path//double-slash",
            "harn-candidate/trailing-slash/",
            "harn-candidate/has space",
            "harn-candidate/branch.lock",
            "harn-candidate/rev~1",
            "harn-candidate/rev^2",
            "harn-candidate/rev:colon",
            "harn-candidate/v3-task-run-shortdigest",
            "harn-candidate/v3-task-run-" + "A" * 64,  # Uppercase hex rejected
            "harn-candidate/v3-task-run-" + "g" * 64,  # Non-hex rejected
        ]
        for bad_ref in malformed_refs:
            with self.subTest(bad_ref=bad_ref):
                with self.assertRaises(ArtifactValidationError):
                    CI.validate_candidate_ref(bad_ref)

    def test_negative_branch_derivation_tampering(self) -> None:
        """Branch derivation tampering or unknown authority version fails closed."""
        # 1. Unknown authority version in derive_candidate_ref fails closed
        with self.assertRaises(ArtifactValidationError):
            CI.derive_candidate_ref(
                authority_version="v999",
                task_id="TASK-001",
                run_id="RUN-001",
                contract_hash="0" * 64,
            )

        # 2. Tampering with candidate ref during result ingestion fails closed
        contract = self.fixture.draft_v3(run_id="NEG-TAMP", task_id="TASK-TAMP")
        head = _git(self.fixture.repo, "rev-parse", "HEAD")
        tree = _git(self.fixture.repo, "rev-parse", "HEAD^{tree}")
        report = {
            "version": "HARN-001.RUNNER_RESULT.v2",
            "result": "STOPPED",
            "run_id": "NEG-TAMP",
            "contract_id": contract["contract_id"],
            "contract_hash": contract["contract_hash"],
            "task_packet_hash": C._sha(C._packet_mapping_v2(contract)),
            "error_class": "ENVIRONMENT_ERROR",
            "error": "Stopped",
            "candidate_head": head,
            "candidate_tree": tree,
            "candidate_ref": "harn-candidate/foreign-tampered-ref",
        }
        with self.assertRaises(ArtifactValidationError) as ctx:
            C.ingest_runner_result_v3(contract, report)
        self.assertIn("candidate_ref mismatch", str(ctx.exception))

    # -------------------------------------------------------------------------
    # CLI Plumbing Verification
    # -------------------------------------------------------------------------
    def test_cli_v3_lifecycle_subcommands(self) -> None:
        """Verify inspect-v3, run-v3, draft-contract-v3, derive-task-packet-v3 CLI plumbing."""
        contract_out = self.fixture.root / "cli-contract-v3.json"
        gate_a_out = self.fixture.root / "cli-gate-a-v3.json"
        packet_out = self.fixture.root / "cli-packet-v3.json"

        # 1. draft-contract-v3 plumbing (file creation is authoritative)
        cli_main([
            "draft-contract-v3",
            str(self.fixture.manifest_path),
            "--run-id", "CLI-V3-RUN",
            "--owned-path", "src/app.txt",
            "--runtime-root", str(self.fixture.runtime),
            "--output", str(contract_out),
            "--success-criterion", "app.txt updated",
            "--test-command", json.dumps([sys.executable, "-c", "import sys; sys.exit(0)"]),
        ])
        self.assertTrue(contract_out.is_file())
        contract = json.loads(contract_out.read_text(encoding="utf-8"))
        self.assertEqual(contract["contract_version"], "HARN-002.v3")

        # Prepare Gate A
        gate_a = self.fixture.gate_a_for(contract)
        gate_a_out.write_text(json.dumps(gate_a, indent=2), encoding="utf-8")

        # 2. derive-task-packet-v3 plumbing (file creation is authoritative)
        cli_main([
            "derive-task-packet-v3",
            str(contract_out),
            str(gate_a_out),
            str(packet_out),
        ])
        self.assertTrue(packet_out.is_file())
        packet = json.loads(packet_out.read_text(encoding="utf-8"))
        self.assertEqual(packet["packet_version"], "HARN-001.TASK_PACKET.v3")

        # 3. inspect-v3
        rc = cli_main([
            "inspect-v3",
            str(packet_out),
            str(contract_out),
            str(gate_a_out),
            "--config", str(self.fixture.config),
        ])
        self.assertEqual(rc, 0)

        # 4. run-v3
        rc = cli_main([
            "run-v3",
            str(packet_out),
            str(contract_out),
            str(gate_a_out),
            "--config", str(self.fixture.config),
            "--authorize",
        ])
        self.assertEqual(rc, 0)

        # Verify candidate ref was created
        expected_ref = CI.derive_candidate_ref_for_contract(contract)
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{expected_ref}"))

    # -------------------------------------------------------------------------
    # Production Workflow Tests
    # -------------------------------------------------------------------------
    def test_workflow_v3_normal_task_crosses_collision_point(self) -> None:
        """Verify normal operator workflow drafts V3 contract, uses V3 candidate ref,
        and cleanly crosses pre-existing legacy candidate collision point.
        """
        self.fixture.init_workflow()

        # Pre-create the legacy collision branch that would have blocked execution under old naming
        legacy_branch = "harn-candidate/TASK-001-TASK-001-RUN"
        _git(self.fixture.repo, "branch", legacy_branch)
        legacy_head_before = _git(self.fixture.repo, "rev-parse", f"refs/heads/{legacy_branch}")

        # 1. High-level workflow preview
        preview_res = W.create_task("Implement app", scope="context-authz", preview_only=True, runtime_root=self.fixture.runtime)
        self.assertEqual(preview_res["status"], "PREVIEW")
        tid = preview_res["task_id"]
        self.assertEqual(tid, "TASK-001")

        # Verify contract drafted is V3
        wdir = W._workflow_dir(self.fixture.runtime, tid)
        contract = C.load_design_contract(wdir / "contract.json")
        self.assertEqual(contract["contract_version"], "HARN-002.v3")
        contract_hash = contract["contract_hash"]
        self.assertEqual(len(contract_hash), 64)

        # 2. Approve and execute task
        exec_res = W.create_task("Implement app", scope="context-authz", preview_only=False, approval_text="approve", runtime_root=self.fixture.runtime, task_id=tid)
        self.assertEqual(exec_res["status"], "ACCEPTANCE_READY")

        # Verify derived packet is V3
        packet = json.loads((wdir / "packet.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["packet_version"], "HARN-001.TASK_PACKET.v3")

        # Verify candidate ref is namespaced with contract hash
        expected_candidate_ref = f"harn-candidate/v3-TASK-001-TASK-001-RUN-{contract_hash}"
        record = W.load_task_record(self.fixture.runtime, tid)
        self.assertEqual(record["candidate_ref"], expected_candidate_ref)
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{expected_candidate_ref}"))

        # Verify legacy collision branch is completely untouched
        legacy_head_after = _git(self.fixture.repo, "rev-parse", f"refs/heads/{legacy_branch}")
        self.assertEqual(legacy_head_before, legacy_head_after)

        # Verify get_acceptance_data works with V3
        acc_data = W.get_acceptance_data(tid, runtime_root=self.fixture.runtime)
        self.assertEqual(acc_data["candidate_ref"], expected_candidate_ref)
        self.assertEqual(acc_data["contract"]["contract_version"], "HARN-002.v3")

        # 3. Perform Gate B acceptance integration
        accept_res = W.perform_accept(tid, "approve", runtime_root=self.fixture.runtime)
        self.assertEqual(accept_res["task_id"], tid)
        head_after_accept = _git(self.fixture.repo, "rev-parse", "HEAD")
        self.assertEqual(head_after_accept, accept_res["candidate_head"])
        st = W.get_status(tid, runtime_root=self.fixture.runtime)
        self.assertEqual(st["status"], "ACCEPTED")

    def test_workflow_historical_v2_preview_preserved(self) -> None:
        """Verify historical frozen V2 preview awaiting approval remains V2, retains exact
        original contract hash, derives V2 packet, and uses legacy ref.
        """
        self.fixture.init_workflow()
        tid = "TASK-001"
        wdir = W._workflow_dir(self.fixture.runtime, tid)
        wdir.mkdir(parents=True, exist_ok=True)

        # Draft a frozen V2 contract
        contract_v2 = self.fixture.draft_v2(run_id=f"{tid}-RUN", task_id=tid, targeted=False)
        self.assertEqual(contract_v2["contract_version"], "HARN-002.v2")
        contract_hash_v2 = contract_v2["contract_hash"]
        contract_path = wdir / "contract.json"
        contract_path.write_text(json.dumps(contract_v2, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        # Builder binding
        builder_binding = {
            "tool": "codex",
            "model": "gpt-5.6-luna",
            "executable": str(self.fixture.fake_builder),
            "timeout_seconds": 20,
        }

        # Stage a frozen V2 preview and task record
        plan = {
            "project_id": contract_v2["project_id"],
            "description": "Historical V2 preview",
            "scope": "context-authz",
            "behavior": "Historical V2 behavior",
            "authorized_paths": list(contract_v2["owned_paths"]),
            "checks": [list(c) for c in contract_v2["acceptance_instruments"]],
            "review_mode": contract_v2["review_policy"]["review_mode"],
            "builder_binding": builder_binding,
        }
        record = W._new_task_record(plan, tid, "PREVIEW", None, contract_path=str(contract_path), contract_hash=contract_hash_v2)
        W.save_task_record(self.fixture.runtime, record)

        preview = {
            "task_id": tid,
            "contract_hash": contract_hash_v2,
            "contract_path": str(contract_path),
            "request": plan["description"],
            "behavior": plan["behavior"],
            "files": list(contract_v2["owned_paths"]),
            "checks": [list(c) for c in contract_v2["acceptance_instruments"]],
            "builder_binding": dict(builder_binding),
            "execution": dict(builder_binding),
            "review_mode": contract_v2["review_policy"]["review_mode"],
            "review_reason": "",
            "reviewer": None,
            "uncertainties": [],
            "baseline_head": contract_v2["baseline_head"],
            "baseline_tree": contract_v2["baseline_tree"],
            "canonical_branch": contract_v2["canonical_branch"],
            "product_repository": contract_v2["repository_path"],
            "scope": plan["scope"],
        }
        (wdir / "preview.json").write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        # Approve and execute the historical V2 task
        exec_res = W.create_task("Historical V2 preview", scope="context-authz", preview_only=False, approval_text="approve", runtime_root=self.fixture.runtime, task_id=tid)
        self.assertEqual(exec_res["status"], "ACCEPTANCE_READY")

        # Verify packet derived is V2
        packet = json.loads((wdir / "packet.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["packet_version"], "HARN-001.TASK_PACKET.v2")
        self.assertEqual(packet["contract_hash"], contract_hash_v2)

        # Verify candidate ref is the legacy V2 ref, NOT V3
        expected_legacy_ref = f"harn-candidate/{tid}-{tid}-RUN"
        record_after = W.load_task_record(self.fixture.runtime, tid)
        self.assertEqual(record_after["candidate_ref"], expected_legacy_ref)
        self.assertTrue(_git(self.fixture.repo, "rev-parse", f"refs/heads/{expected_legacy_ref}"))

        # Verify acceptance and integration work for historical V2
        acc_data = W.get_acceptance_data(tid, runtime_root=self.fixture.runtime)
        self.assertEqual(acc_data["candidate_ref"], expected_legacy_ref)
        self.assertEqual(acc_data["contract"]["contract_version"], "HARN-002.v2")

        accept_res = W.perform_accept(tid, "approve", runtime_root=self.fixture.runtime)
        self.assertEqual(accept_res["task_id"], tid)
        head_after_accept = _git(self.fixture.repo, "rev-parse", "HEAD")
        self.assertEqual(head_after_accept, accept_res["candidate_head"])
        st = W.get_status(tid, runtime_root=self.fixture.runtime)
        self.assertEqual(st["status"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
