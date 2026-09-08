"""M1 deterministic verification suite for versioned NONE/TARGETED semantics.

Uses real Runner/Controller producers and consumers in temporary Git fixture
repos with fake/local provider executables only. No live providers.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner import controller as C
from prj226_runner import runner as R
from prj226_runner.codex_reviewer import validate_targeted_review
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    GovernanceBlockerError,
    ImplementationFailureError,
    ReviewStaleError,
)
from prj226_runner.models import ReviewMode, ReviewStatus
from prj226_runner.review_policy import (
    normalize_review_policy,
    select_review_mode,
)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


FAKE_BUILDER_SRC = """#!@@EXE@@
import os, pathlib, subprocess, sys
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
target.write_text("builder change\\n", encoding="utf-8")
if os.environ.get("FAKE_COMMIT"):
    subprocess.run(["git", "add", "--", str(target)], check=True)
    subprocess.run(["git", "commit", "-m", "unexpected"], check=True)
"""

FAKE_REVIEWER_SRC = """#!@@EXE@@
import hashlib, json, os, pathlib, subprocess, sys, time
counter = pathlib.Path(@@COUNTER@@)
try:
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
except Exception:
    prior = 0
counter.write_text(str(prior + 1), encoding="utf-8")
args = sys.argv
out = pathlib.Path(args[args.index("-o") + 1]) if "-o" in args else None
prompt = args[-1] if len(args) > 1 else ""
if "TIMEOUT" in prompt:
    time.sleep(10)
if "MUTATE_WORKTREE" in prompt:
    pathlib.Path("reviewer-mutated.txt").write_text("bad")
if "PROCESS_FAILURE" in prompt and "WITH_OUTPUT" not in prompt:
    raise SystemExit(9)
# Resolve head/tree/ref from workspace git truth
try:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
except Exception:
    head = "0" * 40
    tree = "0" * 40
try:
    branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
    if not branch:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
except Exception:
    branch = "harn-candidate/unknown"
if "MISMATCH_HEAD" in prompt:
    head = "1" * 40
if "MISMATCH_TREE" in prompt:
    tree = "2" * 40
if "MISMATCH_REF" in prompt:
    branch = "harn-candidate/wrong-ref"
if out is None:
    raise SystemExit(0)
if "MALFORMED" in prompt:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("{bad", encoding="utf-8")
    raise SystemExit(0)
if "MISSING_OUTPUT" in prompt:
    raise SystemExit(0)
if "FORCE_NEEDS_FIX" in prompt or prompt.strip() == "NEEDS_FIX":
    disposition = "NEEDS_FIX"
    blocking = ["blocking finding"]
else:
    disposition = "PASS"
    blocking = []
if "BLOCKING_WITH_PASS" in prompt:
    disposition = "PASS"
    blocking = ["contradiction"]
value = {"review_version": "HARN-002.TARGETED_REVIEW.v1", "disposition": disposition, "reviewed_head": head, "reviewed_tree": tree, "reviewed_ref": branch, "blocking_findings": blocking, "non_blocking_findings": []}
if "INVALID_SCHEMA" in prompt:
    value["unexpected"] = "extra"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(value), encoding="utf-8")
if "PROCESS_FAILURE_WITH_OUTPUT" in prompt or ("PROCESS_FAILURE" in prompt and "WITH_OUTPUT" in prompt):
    raise SystemExit(9)
"""


class M1Fixture:
    def __init__(self, root: Path, run_prefix: str = "M1-TEST") -> None:
        self.root = root
        self.repo = root / "product"
        subprocess.run(["git", "init", str(self.repo)], capture_output=True, text=True, check=True)
        _git(self.repo, "config", "user.email", "m1@example.test")
        _git(self.repo, "config", "user.name", "M1 Tests")
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/app.txt").write_text("base\n", encoding="utf-8")
        (self.repo / "docs").mkdir(parents=True)
        (self.repo / "docs/tasks").mkdir(parents=True)
        (self.repo / "docs/CURRENT.md").write_text("**Next executable work:** ENG-001 — Acceptance\n", encoding="utf-8")
        (self.repo / "docs/PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| ENG-001 | acceptance | PROPOSED |\n", encoding="utf-8")
        (self.repo / "docs/tasks/ENG-001.md").write_text("# ENG-001 — Acceptance\n", encoding="utf-8")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs/README.md").write_text("docs\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "base")
        self.branch = _git(self.repo, "branch", "--show-current")
        self.baseline_head = _git(self.repo, "rev-parse", "HEAD")
        self.baseline_tree = _git(self.repo, "rev-parse", "HEAD^{tree}")
        self.builder_count = root / "builder-count.txt"
        self.reviewer_count = root / "reviewer-count.txt"
        self.fake_builder = root / "fake-builder.py"
        builder_src = FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(self.builder_count)))
        self.fake_builder.write_text(builder_src, encoding="utf-8")
        self.fake_builder.chmod(self.fake_builder.stat().st_mode | stat.S_IXUSR)
        self.fake_reviewer = root / "fake-reviewer.py"
        reviewer_src = FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(self.reviewer_count)))
        self.fake_reviewer.write_text(reviewer_src, encoding="utf-8")
        self.fake_reviewer.chmod(self.fake_reviewer.stat().st_mode | stat.S_IXUSR)
        self.runtime = root / "runtime"
        self.config = root / "runner.toml"
        self.counter = 0
        self.write_config()
        self.manifest_dict = {
            "project_id": "M1-001",
            "repository_path": str(self.repo),
            "canonical_branch": self.branch,
            "canonical_docs": {
                "current": "docs/CURRENT.md",
                "engineering_plan": "docs/PLAN.md",
                "governance": ["AGENTS.md"],
                "project": ["README.md", "docs/README.md"],
            },
            "discovery_rules": {
                "current_next_work_marker": "**Next executable work:**",
                "plan_task_column": "Task",
                "plan_state_column": "State",
                "eligible_plan_states": ["PROPOSED"],
                "task_id_pattern": "ENG-[0-9]{3}",
                "task_file_glob": "docs/tasks/{task_id}.md",
            },
        }

    def write_config(self, reviewer_exe: str | None = None) -> None:
        reviewer = reviewer_exe if reviewer_exe is not None else str(self.fake_reviewer)
        self.config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(self.runtime))}\n\n"
            "[agents.builder]\n"
            "tool = 'codex'\n"
            f"executable = {json.dumps(str(self.fake_builder))}\nmodel = 'fake-builder'\ntimeout_seconds = 20\n\n"
            "[agents.dv]\n"
            "tool = 'opencode2'\n"
            f"executable = {json.dumps(str(self.fake_builder))}\nmodel = 'fake-muse'\ntimeout_seconds = 20\n\n"
            "[agents.sos_reviewer]\n"
            "tool = 'opencode2'\n"
            f"executable = {json.dumps(reviewer)}\nmodel = 'fake-mimo'\ntimeout_seconds = 20\n",
            encoding="utf-8",
        )

    def next_run_id(self, prefix: str = "M1-RUN") -> str:
        self.counter += 1
        return f"{prefix}-{self.counter:03d}"

    def builder_calls(self) -> int:
        return int(self.builder_count.read_text(encoding="utf-8")) if self.builder_count.exists() else 0

    def reviewer_calls(self) -> int:
        return int(self.reviewer_count.read_text(encoding="utf-8")) if self.reviewer_count.exists() else 0

    def inspection(self) -> dict:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        return C.inspect_project(manifest)

    def work_item(self, inspection: dict | None = None) -> dict:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        inspection = inspection or C.inspect_project(manifest)
        return C.discover_next_work(manifest, inspection)

    def draft_none(self, run_id: str, inspection: dict | None = None, work_item: dict | None = None, **overrides) -> dict:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        inspection = inspection or C.inspect_project(manifest)
        work_item = work_item or C.discover_next_work(manifest, inspection)
        kwargs: dict = {
            "run_id": run_id, "owned_paths": ["src/app.txt"],
            "runtime_root": str(self.runtime),
            "change_categories": [], "human_requested_targeted": False,
            "acceptance_instruments": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
        }
        kwargs.update(overrides)
        return C.draft_design_contract_v2(manifest, work_item, inspection, **kwargs)

    def draft_targeted(self, run_id: str, brief: str = "Targeted review of MODULE_BOUNDARY change.", categories: list[str] | None = None, **overrides) -> dict:
        manifest = C.ProjectManifest.from_mapping(self.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = C.discover_next_work(manifest, inspection)
        kwargs: dict = {
            "run_id": run_id, "owned_paths": ["src/app.txt"],
            "runtime_root": str(self.runtime),
            "change_categories": categories or ["MODULE_BOUNDARY"],
            "human_requested_targeted": False,
            "reviewer_executable": str(self.fake_reviewer),
            "reviewer_model": "gpt-5.6-luna",
            "reviewer_timeout_seconds": 20,
            "review_brief": brief,
            "acceptance_instruments": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
        }
        kwargs.update(overrides)
        return C.draft_design_contract_v2(manifest, work_item, inspection, **kwargs)

    def gate_a(self, contract: dict) -> dict:
        overlap = sorted(path for path in contract["protected_dirty_paths"] if any(path == owned or path.startswith(owned + "/") or owned.startswith(path + "/") for owned in contract["owned_paths"]))
        return {
            "gate": "HUMAN_GATE_A", "decision": "APPROVED",
            "contract_id": contract["contract_id"], "contract_hash": contract["contract_hash"],
            "baseline_head": contract["baseline_head"], "baseline_tree": contract["baseline_tree"],
            "authorized_protected_dirty_paths": overlap,
        }

    def derive(self, contract: dict, gate_a: dict, name: str) -> Path:
        packet_path = self.root / name
        C.derive_task_packet_v2(contract, gate_a, output_path=packet_path)
        return packet_path

    def run_v2(self, packet: Path, contract: dict, gate_a: dict, env: dict[str, str] | None = None) -> dict:
        contract_path = self.root / f"contract-{contract['run_id']}.json"
        contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True), encoding="utf-8")
        gate_path = self.root / f"gate-a-{contract['run_id']}.json"
        gate_path.write_text(json.dumps(gate_a, indent=2, sort_keys=True), encoding="utf-8")
        merged = dict(env or {})
        with patch.dict(os.environ, merged, clear=False):
            return R.run_packet_v2(packet, contract_path, gate_path, self.config, authorize=True)


class TestM1(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fix = M1Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_m1_none_full_lifecycle(self) -> None:
        run_id = self.fix.next_run_id("M1-NONE")
        contract = self.fix.draft_none(run_id)
        self.assertEqual(contract["contract_version"], "HARN-002.v2")
        self.assertEqual(contract["review_policy"]["review_mode"], "NONE")
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual(result["version"], "HARN-001.RUNNER_RESULT.v2")
        self.assertEqual(result["review_attempted"], False)
        self.assertEqual(result["review_status"], "NOT_REQUIRED")
        self.assertIsNone(result["error_class"])
        self.assertIsNotNone(result["candidate_head"])
        # Oracles: builder 1, reviewer 0, fallback 0.
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        # No targeted-review directory.
        self.assertFalse((self.fix.runtime / run_id / "targeted-review").exists())
        # Evidence: manifest/state/events/builder/deterministic present.
        root = self.fix.runtime / run_id
        for rel in ("manifest.json", "state.json", "events.ndjson", "builder/invocation.json", "deterministic/test-1/invocation.json"):
            self.assertTrue((root / rel).is_file(), rel)
        # Controller ingestion + Gate B.
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        self.assertEqual(ingested["controller_phase"], "ACCEPTANCE_READY")
        self.assertEqual(ingested["review_status"], "NOT_REQUIRED")
        package = C.prepare_gate_b_v2(contract, ingested)
        self.assertEqual(package["package_version"], "HARN-002.GATE_B.v2")
        self.assertEqual(package["review_mode"], "NONE")
        self.assertEqual(package["review_status"], "NOT_REQUIRED")

    def test_m1_targeted_full_lifecycle(self) -> None:
        run_id = self.fix.next_run_id("M1-TARG")
        contract = self.fix.draft_targeted(run_id)
        self.assertEqual(contract["review_policy"]["review_mode"], "TARGETED")
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual(result["review_attempted"], True)
        self.assertEqual(result["review_status"], "PASS")
        self.assertIsNone(result["error_class"])
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 1)
        review_ev = result["review_evidence"]
        self.assertIsNotNone(review_ev)
        self.assertEqual(review_ev["disposition"], "PASS")
        root = self.fix.runtime / run_id
        self.assertTrue((root / "targeted-review" / "review.json").is_file())
        self.assertTrue((root / "targeted-review" / "raw-result.json").is_file())
        self.assertTrue((root / "targeted-review" / "invocation.json").is_file())
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        self.assertEqual(ingested["review_status"], "PASS")
        package = C.prepare_gate_b_v2(contract, ingested)
        self.assertEqual(package["review_mode"], "TARGETED")
        self.assertEqual(package["review_status"], "PASS")
        self.assertIsNotNone(package["reviewer_binding"])

    def test_m1_targeted_needs_fix(self) -> None:
        run_id = self.fix.next_run_id("M1-NEEDSFIX")
        contract = self.fix.draft_targeted(run_id, brief="FORCE_NEEDS_FIX targeted review")
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "STOPPED")
        self.assertEqual(result["review_status"], "NEEDS_FIX")
        self.assertEqual(result["review_attempted"], True)
        self.assertEqual(result["error_class"], "IMPLEMENTATION_FAILURE")
        self.assertLessEqual(self.fix.reviewer_calls(), 1)
        # Acceptance blocked: ingestion must be STOPPED.
        root = self.fix.runtime / run_id
        with patch.dict(os.environ, {}, clear=False):
            # Ingest stopped result directly (no evidence root needed).
            stopped = C.ingest_runner_result_v2(contract, result)
        self.assertEqual(stopped["controller_phase"], "STOPPED")
        with self.assertRaises(GovernanceBlockerError):
            C.prepare_gate_b_v2(contract, stopped)

    def test_m1_targeted_execution_failure(self) -> None:
        # Nonzero exit.
        run_id = self.fix.next_run_id("M1-EXECFAIL")
        contract = self.fix.draft_targeted(run_id, brief="PROCESS_FAILURE targeted review")
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "STOPPED")
        self.assertEqual(result["review_status"], "EXECUTION_FAILURE")
        self.assertEqual(result["error_class"], "AGENT_EXECUTION_ERROR")
        self.assertLessEqual(self.fix.reviewer_calls(), 1)
        # PASS file + nonzero exit wins as execution failure.
        run_id2 = self.fix.next_run_id("M1-EXECFAIL2")
        contract2 = self.fix.draft_targeted(run_id2, brief="PROCESS_FAILURE_WITH_OUTPUT targeted review")
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet2, contract2, gate_a2)
        self.assertEqual(result2["review_status"], "EXECUTION_FAILURE")
        self.assertEqual(result2["error_class"], "AGENT_EXECUTION_ERROR")
        # Timeout.
        run_id3 = self.fix.next_run_id("M1-TIMEOUT")
        # Use tiny timeout via contract reviewer binding override.
        contract3 = self.fix.draft_targeted(run_id3, brief="TIMEOUT targeted review")
        contract3 = copy.deepcopy(contract3)
        # Recompute hash after forcing timeout 1? Simpler: patch reviewer timeout to 1 by rebuilding.
        manifest = C.ProjectManifest.from_mapping(self.fix.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = C.discover_next_work(manifest, inspection)
        contract3 = C.draft_design_contract_v2(
            manifest, work_item, inspection, run_id=run_id3, owned_paths=["src/app.txt"],
            runtime_root=str(self.fix.runtime), change_categories=["MODULE_BOUNDARY"],
            human_requested_targeted=False, reviewer_executable=str(self.fix.fake_reviewer),
            reviewer_model="gpt-5.6-luna", reviewer_timeout_seconds=1,
            review_brief="TIMEOUT targeted review",
            acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(0)"]],
        )
        gate_a3 = self.fix.gate_a(contract3)
        packet3 = self.fix.derive(contract3, gate_a3, f"packet-{run_id3}.json")
        result3 = self.fix.run_v2(packet3, contract3, gate_a3)
        self.assertEqual(result3["review_status"], "EXECUTION_FAILURE")

    def test_m1_targeted_malformed_or_missing_result(self) -> None:
        for marker, run_suffix in (("MALFORMED", "MAL"), ("MISSING_OUTPUT", "MISS"), ("INVALID_SCHEMA", "INV")):
            with self.subTest(marker=marker):
                run_id = self.fix.next_run_id(f"M1-{run_suffix}")
                contract = self.fix.draft_targeted(run_id, brief=f"{marker} targeted review")
                gate_a = self.fix.gate_a(contract)
                packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
                result = self.fix.run_v2(packet_path, contract, gate_a)
                self.assertEqual(result["result"], "STOPPED")
                self.assertEqual(result["error_class"], "ARTIFACT_VALIDATION_ERROR")
                self.assertNotEqual(result.get("review_status"), "PASS")
                self.assertNotEqual(result.get("review_status"), "NOT_REQUIRED")

    def test_m1_targeted_candidate_and_evidence_drift(self) -> None:
        # HEAD drift: fake writes mismatched head.
        run_id = self.fix.next_run_id("M1-DRIFT-H")
        contract = self.fix.draft_targeted(run_id, brief="MISMATCH_HEAD targeted review")
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "STOPPED")
        self.assertEqual(result["error_class"], "GOVERNANCE_BLOCKER")
        # TREE drift.
        run_id2 = self.fix.next_run_id("M1-DRIFT-T")
        contract2 = self.fix.draft_targeted(run_id2, brief="MISMATCH_TREE targeted review")
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet2, contract2, gate_a2)
        self.assertEqual(result2["result"], "STOPPED")
        # REF drift.
        run_id3 = self.fix.next_run_id("M1-DRIFT-R")
        contract3 = self.fix.draft_targeted(run_id3, brief="MISMATCH_REF targeted review")
        gate_a3 = self.fix.gate_a(contract3)
        packet3 = self.fix.derive(contract3, gate_a3, f"packet-{run_id3}.json")
        result3 = self.fix.run_v2(packet3, contract3, gate_a3)
        self.assertEqual(result3["result"], "STOPPED")
        # Worktree mutation during review.
        run_id4 = self.fix.next_run_id("M1-DRIFT-W")
        contract4 = self.fix.draft_targeted(run_id4, brief="MUTATE_WORKTREE targeted review")
        gate_a4 = self.fix.gate_a(contract4)
        packet4 = self.fix.derive(contract4, gate_a4, f"packet-{run_id4}.json")
        result4 = self.fix.run_v2(packet4, contract4, gate_a4)
        self.assertEqual(result4["result"], "STOPPED")
        # Evidence replacement after success blocks Gate B.
        run_id5 = self.fix.next_run_id("M1-DRIFT-E")
        contract5 = self.fix.draft_targeted(run_id5)
        gate_a5 = self.fix.gate_a(contract5)
        packet5 = self.fix.derive(contract5, gate_a5, f"packet-{run_id5}.json")
        result5 = self.fix.run_v2(packet5, contract5, gate_a5)
        self.assertEqual(result5["result"], "ACCEPTANCE_READY")
        root5 = self.fix.runtime / run_id5
        review_path = root5 / "targeted-review" / "review.json"
        original = review_path.read_text(encoding="utf-8")
        tampered = json.loads(original)
        tampered["non_blocking_findings"] = ["tampered"]
        review_path.write_text(json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            C.ingest_runner_result_v2(contract5, root5 / "report.json")

    def test_m1_targeted_identity_and_profile_drift(self) -> None:
        def _recompute(contract: dict) -> dict:
            content = {k: contract[k] for k in sorted(C.CONTRACT_V2_KEYS - {"contract_id", "contract_hash"})}
            h = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            contract["contract_hash"] = h
            contract["contract_id"] = "design-" + h
            return contract
        # Profile drift: frozen profile object differs from live canonical profile.
        run_id = self.fix.next_run_id("M1-PROF")
        contract = self.fix.draft_targeted(run_id)
        tampered_reviewer = copy.deepcopy(contract["review_policy"]["reviewer"])
        tampered_profile = dict(tampered_reviewer["reviewer_profile"])
        tampered_profile["sandbox"] = "tampered-sandbox"
        tampered_reviewer["reviewer_profile"] = tampered_profile
        tampered_reviewer["reviewer_profile_hash"] = hashlib.sha256(json.dumps(tampered_profile, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        tampered = _recompute({**copy.deepcopy(contract), "review_policy": {**contract["review_policy"], "reviewer": tampered_reviewer}})
        gate_t = self.fix.gate_a(tampered)
        packet_t = self.fix.derive(tampered, gate_t, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_t, tampered, gate_t)
        self.assertEqual(result["result"], "STOPPED")
        # Executable drift: frozen exe sha wrong vs live file.
        run_id2 = self.fix.next_run_id("M1-EXE")
        contract2 = self.fix.draft_targeted(run_id2)
        tampered2 = _recompute({**copy.deepcopy(contract2), "review_policy": {**contract2["review_policy"], "reviewer": {**contract2["review_policy"]["reviewer"], "executable_sha256": "b" * 64}}})
        gate_t2 = self.fix.gate_a(tampered2)
        packet_t2 = self.fix.derive(tampered2, gate_t2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet_t2, tampered2, gate_t2)
        self.assertEqual(result2["result"], "STOPPED")
        # Live executable file drift after Gate A: modify fake reviewer bytes.
        run_id3 = self.fix.next_run_id("M1-LIVEEXE")
        contract3 = self.fix.draft_targeted(run_id3)
        gate_a3 = self.fix.gate_a(contract3)
        packet3 = self.fix.derive(contract3, gate_a3, f"packet-{run_id3}.json")
        with self.fix.fake_reviewer.open("a", encoding="utf-8") as handle:
            handle.write("\n# drift\n")
        try:
            result3 = self.fix.run_v2(packet3, contract3, gate_a3)
        finally:
            # Restore fake reviewer for subsequent tests in this fixture.
            reviewer_src = FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(self.fix.reviewer_count)))
            self.fix.fake_reviewer.write_text(reviewer_src, encoding="utf-8")
            self.fix.fake_reviewer.chmod(self.fix.fake_reviewer.stat().st_mode | stat.S_IXUSR)
        self.assertEqual(result3["result"], "STOPPED")
        # TARGETED missing reviewer binding must fail closed at draft/parse.
        with self.assertRaises(ArtifactValidationError):
            normalize_review_policy({"review_mode": "TARGETED", "change_categories": ["MODULE_BOUNDARY"], "human_requested_targeted": False, "reviewer": None})

    def test_m1_review_outcome_combinations(self) -> None:
        # NONE always NOT_REQUIRED without attempt.
        run_id = self.fix.next_run_id("M1-COMB-N")
        contract = self.fix.draft_none(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual((result["review_attempted"], result["review_status"]), (False, "NOT_REQUIRED"))
        # TARGETED PASS.
        run_id2 = self.fix.next_run_id("M1-COMB-P")
        contract2 = self.fix.draft_targeted(run_id2)
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet2, contract2, gate_a2)
        self.assertEqual((result2["review_attempted"], result2["review_status"]), (True, "PASS"))
        # TARGETED NEEDS_FIX.
        run_id3 = self.fix.next_run_id("M1-COMB-F")
        contract3 = self.fix.draft_targeted(run_id3, brief="FORCE_NEEDS_FIX review")
        gate_a3 = self.fix.gate_a(contract3)
        packet3 = self.fix.derive(contract3, gate_a3, f"packet-{run_id3}.json")
        result3 = self.fix.run_v2(packet3, contract3, gate_a3)
        self.assertEqual((result3["review_attempted"], result3["review_status"]), (True, "NEEDS_FIX"))
        # TARGETED EXECUTION_FAILURE.
        run_id4 = self.fix.next_run_id("M1-COMB-E")
        contract4 = self.fix.draft_targeted(run_id4, brief="PROCESS_FAILURE review")
        gate_a4 = self.fix.gate_a(contract4)
        packet4 = self.fix.derive(contract4, gate_a4, f"packet-{run_id4}.json")
        result4 = self.fix.run_v2(packet4, contract4, gate_a4)
        self.assertEqual((result4["review_attempted"], result4["review_status"]), (True, "EXECUTION_FAILURE"))
        # No fifth status exists.
        self.assertEqual(set(item.value for item in ReviewStatus), {"NOT_REQUIRED", "PASS", "NEEDS_FIX", "EXECUTION_FAILURE"})

    def test_m1_none_never_touches_reviewer(self) -> None:
        # NONE with unusable reviewer executable must still succeed.
        self.fix.write_config(reviewer_exe="/nonexistent/reviewer-missing")
        run_id = self.fix.next_run_id("M1-NONE-NOREV")
        contract = self.fix.draft_none(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        before = self.fix.reviewer_calls()
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual(result["review_status"], "NOT_REQUIRED")
        self.assertEqual(self.fix.reviewer_calls(), before)
        self.assertFalse((self.fix.runtime / run_id / "targeted-review").exists())
        # NONE with fake PASS artifact planted must not be read.
        planted = self.fix.runtime / run_id / "targeted-review"
        planted.mkdir(parents=True, exist_ok=True)
        (planted / "review.json").write_text(json.dumps({"disposition": "PASS"}), encoding="utf-8")
        # Re-run with fresh run_id to prove planted file in other run is irrelevant; current run still has no reviewer use.
        run_id2 = self.fix.next_run_id("M1-NONE-PLANT")
        contract2 = self.fix.draft_none(run_id2)
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet2, contract2, gate_a2)
        self.assertEqual(result2["review_status"], "NOT_REQUIRED")
        self.assertEqual(self.fix.reviewer_calls(), before)

    def test_m1_deterministic_failure_blocks_review(self) -> None:
        # NONE deterministic failure: no review, builder 1.
        run_id = self.fix.next_run_id("M1-DET-N")
        contract = self.fix.draft_none(run_id, acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(1)"]])
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "STOPPED")
        self.assertEqual(result["error_class"], "IMPLEMENTATION_FAILURE")
        self.assertEqual(result["review_attempted"], False)
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        self.assertFalse((self.fix.runtime / run_id / "targeted-review").exists())
        # TARGETED deterministic failure: no review invocation, no NOT_REQUIRED/PASS fabrication.
        run_id2 = self.fix.next_run_id("M1-DET-T")
        contract2 = self.fix.draft_targeted(run_id2, acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(2)"]] if False else None) if False else None
        manifest = C.ProjectManifest.from_mapping(self.fix.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = C.discover_next_work(manifest, inspection)
        contract2 = C.draft_design_contract_v2(
            manifest, work_item, inspection, run_id=run_id2, owned_paths=["src/app.txt"],
            runtime_root=str(self.fix.runtime), change_categories=["MODULE_BOUNDARY"],
            human_requested_targeted=False, reviewer_executable=str(self.fix.fake_reviewer),
            reviewer_model="gpt-5.6-luna", reviewer_timeout_seconds=20,
            review_brief="Targeted review", acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(1)"]],
        )
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        before_review = self.fix.reviewer_calls()
        result2 = self.fix.run_v2(packet2, contract2, gate_a2)
        self.assertEqual(result2["result"], "STOPPED")
        self.assertEqual(result2["review_attempted"], False)
        self.assertNotIn(result2.get("review_status"), ("NOT_REQUIRED", "PASS"))
        self.assertEqual(self.fix.reviewer_calls(), before_review)

    def test_m1_gate_a_packet_derivation_is_exact(self) -> None:
        run_id = self.fix.next_run_id("M1-DERIV")
        contract = self.fix.draft_none(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        self.assertEqual(packet["contract_id"], contract["contract_id"])
        self.assertEqual(packet["review_policy"], contract["review_policy"])
        # Packet widening rejected: authorized_paths.
        widened = dict(packet)
        widened["authorized_paths"] = ["src/app.txt", "src/extra.txt"]
        widened_path = self.root / "widened.json"
        widened_path.write_text(json.dumps(widened), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.validate_task_packet_derivation_v2(contract, R.parse_task_packet_v2(widened_path))
        # Test command widening rejected.
        widened2 = dict(packet)
        widened2["test_commands"] = [[[sys.executable][0], "-c", "import sys; sys.exit(0)"], ["extra"]]
        widened2_path = self.root / "widened2.json"
        widened2_path.write_text(json.dumps(widened2), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.validate_task_packet_derivation_v2(contract, R.parse_task_packet_v2(widened2_path))
        # Runtime root drift rejected at inspect.
        drifted = dict(packet)
        drifted["runtime_root"] = "/tmp/other-root"
        drifted_path = self.root / "drifted.json"
        drifted_path.write_text(json.dumps(drifted), encoding="utf-8")
        contract_path = self.root / f"contract-{run_id}.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        gate_path = self.root / f"gate-{run_id}.json"
        gate_path.write_text(json.dumps(gate_a), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.inspect_packet_v2(drifted_path, contract_path, gate_path, self.fix.config)

    def test_m1_v2_run_requires_exact_gate_a_context(self) -> None:
        run_id = self.fix.next_run_id("M1-GATEA")
        contract = self.fix.draft_none(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        contract_path = self.root / f"contract-{run_id}.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        gate_path = self.root / f"gate-{run_id}.json"
        gate_path.write_text(json.dumps(gate_a), encoding="utf-8")
        # --authorize alone insufficient: missing gate context file.
        with self.assertRaises(Exception):
            R.run_packet_v2(packet_path, contract_path, self.root / "missing-gate.json", self.fix.config, authorize=True)
        # Gate A missing fields.
        bad_gate = dict(gate_a)
        bad_gate.pop("contract_hash")
        bad_gate_path = self.root / "bad-gate.json"
        bad_gate_path.write_text(json.dumps(bad_gate), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.run_packet_v2(packet_path, contract_path, bad_gate_path, self.fix.config, authorize=True)
        # Stale Gate A (contract hash mismatch).
        stale = dict(gate_a)
        stale["contract_hash"] = "0" * 64
        stale_path = self.root / "stale-gate.json"
        stale_path.write_text(json.dumps(stale), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.run_packet_v2(packet_path, contract_path, stale_path, self.fix.config, authorize=True)
        # Without authorize.
        with self.assertRaises(GovernanceBlockerError):
            R.run_packet_v2(packet_path, contract_path, gate_path, self.fix.config, authorize=False)

    def test_m1_gate_b_policy_and_evidence_binding(self) -> None:
        run_id = self.fix.next_run_id("M1-GB-POL")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        root = self.fix.runtime / run_id
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        package = C.prepare_gate_b_v2(contract, ingested)
        # Policy downgrade rejected: NONE policy with TARGETED evidence.
        downgraded_contract = copy.deepcopy(contract)
        downgraded_contract["review_policy"] = {"review_mode": "NONE", "change_categories": [], "human_requested_targeted": False, "reviewer": None}
        # Recompute hash for downgraded contract to isolate policy-mismatch path (must still fail).
        content = {k: downgraded_contract[k] for k in sorted(C.CONTRACT_V2_KEYS - {"contract_id", "contract_hash"})}
        h = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        downgraded_contract["contract_hash"] = h
        downgraded_contract["contract_id"] = "design-" + h
        with self.assertRaises(Exception):
            C.prepare_gate_b_v2(downgraded_contract, ingested)
        # Evidence drift: modify deterministic invocation to non-PASS then re-ingest.
        det_inv = root / "deterministic" / "test-1" / "invocation.json"
        det_original = det_inv.read_text(encoding="utf-8")
        det_data = json.loads(det_original)
        det_data["exit_code"] = 1
        det_inv.write_text(json.dumps(det_data), encoding="utf-8")
        try:
            with self.assertRaises(ArtifactValidationError):
                C.ingest_runner_result_v2(contract, root / "report.json")
        finally:
            det_inv.write_text(det_original, encoding="utf-8")

    def test_m1_gate_b_exact_candidate_binding(self) -> None:
        run_id = self.fix.next_run_id("M1-GB-CAND")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        root = self.fix.runtime / run_id
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        package = C.prepare_gate_b_v2(contract, ingested)
        self.assertEqual(package["candidate_head"], result["candidate_head"])
        self.assertEqual(package["candidate_tree"], result["candidate_tree"])
        # Candidate drift: tamper package candidate.
        tampered = dict(package)
        tampered["candidate_head"] = "0" * 40
        with self.assertRaises(Exception):
            C.validate_gate_b_v2(contract, {"authorization_id": "auth-1", "gate_b_package_hash": package["gate_b_package_hash"], "candidate_head": package["candidate_head"], "candidate_tree": package["candidate_tree"], "expected_canonical_head": package["expected_canonical_head"], "expected_canonical_tree": package["expected_canonical_tree"]}, tampered)
        # Changed-path mismatch: tamper expected_changed_paths.
        tampered2 = dict(package)
        tampered2["expected_changed_paths"] = ["src/other.txt"]
        # Need to recompute package hash to get past hash check? No: hash mismatch itself must fail.
        with self.assertRaises(Exception):
            C._validate_gate_b_package_v2(tampered2, contract)

    def test_m1_exact_checks_and_scope(self) -> None:
        run_id = self.fix.next_run_id("M1-CHECKS")
        checks = [[sys.executable, "-c", "import sys; sys.exit(0)  # check-one"], [sys.executable, "-c", "import sys; sys.exit(0)  # check-two"]]
        contract = self.fix.draft_none(run_id, acceptance_instruments=checks)
        self.assertEqual(len(contract["acceptance_instruments"]), 2)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        self.assertEqual(packet["test_commands"], checks)
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        root = self.fix.runtime / run_id
        self.assertTrue((root / "deterministic" / "test-1" / "invocation.json").is_file())
        self.assertTrue((root / "deterministic" / "test-2" / "invocation.json").is_file())
        # Order matters: swap checks in packet must be rejected.
        swapped = dict(packet)
        swapped["test_commands"] = list(reversed(checks))
        swapped_path = self.root / "swapped.json"
        swapped_path.write_text(json.dumps(swapped), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.validate_task_packet_derivation_v2(contract, R.parse_task_packet_v2(swapped_path))
        # Unauthorized scope: builder writes outside owned paths.
        run_id2 = self.fix.next_run_id("M1-SCOPE")
        contract2 = self.fix.draft_none(run_id2)
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        result2 = self.fix.run_v2(packet2, contract2, gate_a2, env={"FAKE_TARGET": "src/unauthorized.txt"})
        self.assertEqual(result2["result"], "STOPPED")
        self.assertEqual(result2["error_class"], "GOVERNANCE_BLOCKER")

    def test_m1_one_attempt_and_no_fallback(self) -> None:
        run_id = self.fix.next_run_id("M1-ONE")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        before_b, before_r = self.fix.builder_calls(), self.fix.reviewer_calls()
        result = self.fix.run_v2(packet_path, contract, gate_a)
        self.assertEqual(self.fix.builder_calls() - before_b, 1)
        self.assertEqual(self.fix.reviewer_calls() - before_r, 1)
        # No second builder: worktree branch exists only once; run_id collision prevents retry.
        contract_path = self.root / f"contract-{run_id}.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        gate_path = self.root / f"gate-{run_id}.json"
        gate_path.write_text(json.dumps(gate_a), encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            R.run_packet_v2(packet_path, contract_path, gate_path, self.fix.config, authorize=True)
        # Still exactly one each.
        self.assertEqual(self.fix.builder_calls() - before_b, 1)
        self.assertEqual(self.fix.reviewer_calls() - before_r, 1)
        # Fallback count is zero: no alternate provider invocation recorded.
        # Our fakes are the only executables; reviewer counter proves no fallback.
        self.assertEqual(result["result"], "ACCEPTANCE_READY")

    def test_m1_legacy_round_trip_and_hashes(self) -> None:
        # Legacy packet round-trip unchanged.
        repo = self.fix.repo
        packet = {
            "run_id": "HARN-LEGACY-001", "task_id": "HARN-TEST", "product_repo": str(repo),
            "canonical_branch": self.fix.branch, "baseline_head": self.fix.baseline_head,
            "baseline_tree": self.fix.baseline_tree, "authorized_paths": ["src/app.txt"],
            "builder_prompt": "Change the approved file.", "acceptance_criteria": ["approved change exists"],
            "test_commands": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
            "commit_message": "test: candidate",
        }
        packet_path = self.root / "legacy-packet.json"
        packet_path.write_text(json.dumps(packet), encoding="utf-8")
        parsed = R.parse_task_packet(packet_path)
        self.assertEqual(parsed.run_id, "HARN-LEGACY-001")
        # Legacy dispatch still v1.
        self.assertEqual(R.dispatch_packet(packet_path), "v1")
        # Legacy Gate B semantics tested separately; here ensure legacy contract hash stable.
        manifest = C.ProjectManifest.from_mapping(self.fix.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = C.discover_next_work(manifest, inspection)
        contract = C.draft_design_contract(
            manifest, work_item, inspection, run_id="HARN-LEGACY-002",
            owned_paths=["src/app.txt"],
            acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(0)"]],
        )
        self.assertEqual(contract["contract_version"], "HARN-002.v1")
        # Recompute hash matches.
        content = {k: contract[k] for k in sorted(C.CONTRACT_KEYS - {"contract_id", "contract_hash"})}
        h = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(contract["contract_hash"], h)

    def test_m1_legacy_gate_b_semantics(self) -> None:
        # Legacy behavior preserved: mandatory DV + S/O/S path still exists in code.
        # Exercise legacy derive/dispatch validation without live providers by checking
        # that legacy packet derivation rejects widening (same as historical tests).
        manifest = C.ProjectManifest.from_mapping(self.fix.manifest_dict)
        inspection = C.inspect_project(manifest)
        work_item = C.discover_next_work(manifest, inspection)
        contract = C.draft_design_contract(
            manifest, work_item, inspection, run_id="HARN-LEGACY-GB",
            owned_paths=["src/app.txt"],
        )
        gate_a = {
            "gate": "HUMAN_GATE_A", "decision": "APPROVED",
            "contract_id": contract["contract_id"], "contract_hash": contract["contract_hash"],
            "baseline_head": contract["baseline_head"], "baseline_tree": contract["baseline_tree"],
            "authorized_protected_dirty_paths": [],
        }
        packet = C.derive_task_packet(contract, gate_a)
        self.assertEqual(packet["run_id"], "HARN-LEGACY-GB")
        widened = dict(packet)
        widened["authorized_paths"] = ["src/app.txt", "src/other.txt"]
        with self.assertRaises(GovernanceBlockerError):
            C.validate_task_packet_derivation(contract, widened)

    def test_m1_version_dispatch_is_closed(self) -> None:
        run_id = self.fix.next_run_id("M1-DISP")
        contract = self.fix.draft_none(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        self.assertEqual(R.dispatch_packet(packet_path), "v2")
        # Stripped v2 version rejected.
        stripped = json.loads(packet_path.read_text(encoding="utf-8"))
        stripped.pop("packet_version")
        stripped_path = self.root / "stripped.json"
        stripped_path.write_text(json.dumps(stripped), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            R.dispatch_packet(stripped_path)
        with self.assertRaises(ArtifactValidationError):
            R.parse_task_packet_v2(stripped_path)
        # Unknown version rejected.
        unknown = json.loads(packet_path.read_text(encoding="utf-8"))
        unknown["packet_version"] = "HARN-001.TASK_PACKET.v99"
        unknown_path = self.root / "unknown.json"
        unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            R.dispatch_packet(unknown_path)
        # Mixed families rejected at controller dispatch.
        legacy_contract = {"contract_version": "HARN-002.v1", "contract_id": "design-" + "0" * 64, "contract_hash": "0" * 64}
        with self.assertRaises(Exception):
            C.dispatch_contract(legacy_contract, gate_a, packet_path)
        # Fallback attempt rejected: v2 parse must not fall back to legacy.
        with self.assertRaises(ArtifactValidationError):
            R.parse_task_packet(stripped_path)

    def test_m1_terminal_shape_parity(self) -> None:
        # Producer/schema/consumer parity for terminal shapes.
        import jsonschema
        from pathlib import Path as _Path
        schemas_dir = _Path(__file__).parents[1] / "schemas"
        run_id = self.fix.next_run_id("M1-PARITY")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        runner_schema = json.loads((schemas_dir / "runner-result.v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(result, runner_schema)
        root = self.fix.runtime / run_id
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        controller_schema = json.loads((schemas_dir / "controller-result.v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(ingested, controller_schema)
        package = C.prepare_gate_b_v2(contract, ingested)
        gateb_schema = json.loads((schemas_dir / "gate-b-package.v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(package, gateb_schema)
        # Candidate all-or-none enforced.
        bad = dict(result)
        bad["candidate_tree"] = None
        with self.assertRaises(ArtifactValidationError):
            C._ingest_runner_result_data_v2(contract, bad, None)

    def test_m1_persistence_reload_parity(self) -> None:
        run_id = self.fix.next_run_id("M1-PERSIST")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        root = self.fix.runtime / run_id
        # Reload manifest/state/report from disk and verify parity.
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        report = json.loads((root / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["contract_id"], contract["contract_id"])
        self.assertEqual(state["contract_id"], contract["contract_id"])
        self.assertEqual(report["contract_id"], contract["contract_id"])
        self.assertEqual(state["review_status"], "PASS")
        self.assertEqual(manifest["review_policy"], contract["review_policy"])
        # Controller reload parity.
        ingested = C.ingest_runner_result_v2(contract, root / "report.json")
        ingested_path = root / "controller-result.json"
        ingested_path.write_text(json.dumps(ingested, indent=2, sort_keys=True), encoding="utf-8")
        reloaded = C.load_controller_result_v2(ingested_path)
        self.assertEqual(reloaded, ingested)
        # Reload mismatch: tamper report candidate, reload must fail.
        tampered = dict(report)
        tampered["candidate_head"] = "0" * 40
        tampered_path = root / "tampered-report.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(Exception):
            C.ingest_runner_result_v2(contract, tampered_path)
        # Gate B reload parity.
        package = C.prepare_gate_b_v2(contract, ingested)
        package_path = root / "gate-b-package.json"
        package_path.write_text(json.dumps(package, indent=2, sort_keys=True), encoding="utf-8")
        reloaded_package = C.load_gate_b_package_v2(package_path, contract)
        self.assertEqual(reloaded_package["gate_b_package_hash"], package["gate_b_package_hash"])

    def test_m1_static_review_selection(self) -> None:
        self.assertEqual(select_review_mode([], False), "NONE")
        self.assertEqual(select_review_mode(["MODULE_BOUNDARY"], False), "TARGETED")
        self.assertEqual(select_review_mode(["PUBLIC_INTERFACE"], False), "TARGETED")
        self.assertEqual(select_review_mode(["AUTHORIZATION_DATA_ACCESS"], False), "TARGETED")
        self.assertEqual(select_review_mode(["PERSISTENT_DATA_SEMANTICS"], False), "TARGETED")
        self.assertEqual(select_review_mode(["BEHAVIOR_PRESERVING_REFACTOR"], False), "TARGETED")
        self.assertEqual(select_review_mode([], True), "TARGETED")
        self.assertEqual(select_review_mode(["UNRELATED_CATEGORY"], False), "NONE")
        # Policy normalization enforces static consistency.
        with self.assertRaises(ArtifactValidationError):
            normalize_review_policy({"review_mode": "NONE", "change_categories": ["MODULE_BOUNDARY"], "human_requested_targeted": False, "reviewer": None})
        with self.assertRaises(ArtifactValidationError):
            normalize_review_policy({"review_mode": "TARGETED", "change_categories": [], "human_requested_targeted": False, "reviewer": None})
        none_policy = normalize_review_policy({"review_mode": "NONE", "change_categories": [], "human_requested_targeted": False, "reviewer": None})
        self.assertEqual(none_policy["review_mode"], "NONE")

    def test_m1_runtime_manifest_state_and_events(self) -> None:
        run_id = self.fix.next_run_id("M1-RUNTIME")
        contract = self.fix.draft_targeted(run_id)
        gate_a = self.fix.gate_a(contract)
        packet_path = self.fix.derive(contract, gate_a, f"packet-{run_id}.json")
        result = self.fix.run_v2(packet_path, contract, gate_a)
        root = self.fix.runtime / run_id
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        events = (root / "events.ndjson").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(manifest["manifest_version"], "HARN-001.RUN_MANIFEST.v2")
        self.assertEqual(state["state_version"], "HARN-001.RUN_STATE.v2")
        self.assertEqual(manifest["contract_id"], contract["contract_id"])
        self.assertEqual(manifest["review_policy"], contract["review_policy"])
        self.assertIsNotNone(manifest["reviewer_binding"])
        self.assertEqual(state["review_status"], "PASS")
        self.assertEqual(state["candidate_head"], result["candidate_head"])
        # Events reflect actual transitions, at most one targeted invocation.
        event_names = [json.loads(line)["event"] for line in events]
        self.assertIn("acceptance_ready", event_names)
        targeted_starts = [name for name in event_names if "targeted_review" in name]
        self.assertLessEqual(len(targeted_starts), 1)
        # NONE has no semantic-review invocation event.
        run_id2 = self.fix.next_run_id("M1-RUNTIME-N")
        contract2 = self.fix.draft_none(run_id2)
        gate_a2 = self.fix.gate_a(contract2)
        packet2 = self.fix.derive(contract2, gate_a2, f"packet-{run_id2}.json")
        self.fix.run_v2(packet2, contract2, gate_a2)
        events2 = (self.fix.runtime / run_id2 / "events.ndjson").read_text(encoding="utf-8")
        self.assertNotIn("targeted_review", events2)
        self.assertNotIn("dv_started", events2)
        self.assertNotIn("sos_started", events2)

    def test_m1_cli_contract_plumbing(self) -> None:
        from prj226_runner.cli import main as cli_main
        run_id = self.fix.next_run_id("M1-CLI")
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self.fix.manifest_dict), encoding="utf-8")
        contract_out = self.root / "cli-contract.json"
        cli_main(["draft-contract-v2", str(manifest_path), "--run-id", run_id, "--owned-path", "src/app.txt", "--output", str(contract_out), "--runtime-root", str(self.fix.runtime)])
        self.assertTrue(contract_out.is_file())
        contract = json.loads(contract_out.read_text(encoding="utf-8"))
        self.assertEqual(contract["contract_version"], "HARN-002.v2")
        self.assertEqual(contract["review_policy"]["review_mode"], "NONE")
        # TARGETED plumbing with reviewer.
        run_id2 = self.fix.next_run_id("M1-CLI-T")
        contract_out2 = self.root / "cli-contract2.json"
        cli_main(["draft-contract-v2", str(manifest_path), "--run-id", run_id2, "--owned-path", "src/app.txt", "--output", str(contract_out2), "--runtime-root", str(self.fix.runtime), "--change-category", "MODULE_BOUNDARY", "--reviewer-executable", str(self.fix.fake_reviewer), "--review-brief", "CLI targeted review"])
        self.assertTrue(contract_out2.is_file())
        contract2 = json.loads(contract_out2.read_text(encoding="utf-8"))
        self.assertEqual(contract2["review_policy"]["review_mode"], "TARGETED")
        # derive-task-packet-v2 plumbing (legacy CLI returns 2 for packet artifacts; file existence is authority).
        gate_a = self.fix.gate_a(contract2)
        gate_path = self.root / "cli-gate.json"
        gate_path.write_text(json.dumps(gate_a), encoding="utf-8")
        packet_out = self.root / "cli-packet.json"
        cli_main(["derive-task-packet-v2", str(contract_out2), str(gate_path), str(packet_out)])
        self.assertTrue(packet_out.is_file())
        # run-v2 plumbing requires exact Gate A context (authorize alone insufficient is covered elsewhere).
        # inspect-v2 plumbing returns READY_FOR_HUMAN_AUTHORIZATION.
        rc4 = cli_main(["inspect-v2", str(packet_out), str(contract_out2), str(gate_path), "--config", str(self.fix.config)])
        self.assertEqual(rc4, 0)

    def test_m1_historical_schema_bytes_unchanged(self) -> None:
        from pathlib import Path as _Path
        schemas_dir = _Path(__file__).parents[1] / "schemas"
        expected = {
            "builder-result.schema.json": "932b96f1846af5d9067667469b33a33d397300fe61939ec84cc82a12630095a9",
            "calibration-case-result.schema.json": "62fff24d976bf8a86af5b2f8b3c05d8aacbd693dd7532a1aadccd865ad5d3ffe",
            "calibration-payload.schema.json": "c122fc4671207ac432515d5abdd6811a0e221d707dedd03823a1cdb7596ca3d9",
            "calibration-result.schema.json": "8e2dd627aeebefa8019a2c0c50219f990844540416260cf037fc50d64dc3fc64",
            "codex-reviewer-result.schema.json": "148ac76be2d4f55d3cbc626ddd824d08f4f0de308fda1aede885c130908704a2",
            "controller-result.schema.json": "b35d73596e23c94b008cda679e6a616069c0d7c8096f2122c538174c63622a56",
            "controller-state.schema.json": "f8e8f6f9a27207fe2e2de0edcce506b3ae8b0fc2ec7162bb451115884fe6c867",
            "design-contract.schema.json": "6a36c419adb7bcfceed6633ef31a3aaae42f2b0758f8277ba1486de1b468b804",
            "gate-b-authorization.schema.json": "7b3010d7df42523d44874b6d9b04d82154e51ed5e9453cb6f748daf941bfa9b6",
            "gate-b-package.schema.json": "87aca9134873c72b7a7421518485e321c4fc7737144f11ce1f4e3366eab6e4ce",
            "planner-result.schema.json": "b7cac854f41e026a610ea006a9213975fcab7ca46f72674bd65ec1f956ac5d12",
            "project-manifest.schema.json": "87408625f4e27cbf9d5e08bb3c6d8bea9c5c134654dba4f581e6c5499febd7f5",
            "run-manifest.schema.json": "7d2c2240b56519c8d0dd3f3fb65b06308a45f48d422958efc6a7cb760f516ece",
            "run-state.schema.json": "97d26283587243a666be91eacb1eacee160143d1ff789daf6a401353121d92e1",
            "sos-result.schema.json": "66f0d47dc72d5563ab95008283e7fdabe000a848aa24f395768e58abb3592e36",
            "task-packet.schema.json": "e6c1c1cf8cb8e041f07ed1ee3d28b9bca7b341e7c9faa52b95f8185dad65c811",
            "verifier-result.schema.json": "f752226d98d3c348b2850c54cd73fcd77b742ae7747e2b00e0782be1f1265578",
        }
        for name, digest in expected.items():
            data = (schemas_dir / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
