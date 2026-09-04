"""HARN-002 Repair-4 closed Gate-B and filesystem-integrity controls."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from prj226_runner.codex_reviewer import build_worktree_fingerprint_manifest, fingerprint_manifest, fingerprint_worktree
from prj226_runner.controller import (
    discover_next_work,
    draft_design_contract,
    ingest_runner_result,
    inspect_project,
    prepare_gate_b,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError, ReviewStaleError


class Repair4EvidenceFixture:
    """Create one complete deterministic acceptance bundle without providers."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "project"
        subprocess.run(["git", "init", str(self.repo)], capture_output=True, text=True, check=True)
        self._git("config", "user.email", "repair4@example.test")
        self._git("config", "user.name", "Repair 4 Tests")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs").mkdir()
        (self.repo / "docs/README.md").write_text("docs\n", encoding="utf-8")
        (self.repo / "docs/CURRENT.md").write_text("**Next executable work:** ENG-012 — Acceptance\n", encoding="utf-8")
        (self.repo / "docs/PLAN.md").write_text(
            "| Task | Description | State |\n| --- | --- | --- |\n| ENG-012 | acceptance | PROPOSED |\n",
            encoding="utf-8",
        )
        (self.repo / "docs/tasks").mkdir()
        (self.repo / "docs/tasks/ENG-012.md").write_text("# ENG-012 — Acceptance\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-m", "base")
        self.branch = self._git("branch", "--show-current")
        self.baseline_head = self._git("rev-parse", "HEAD")
        self.baseline_tree = self._git("rev-parse", "HEAD^{tree}")
        self.manifest = {
            "project_id": "REPAIR4-001",
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
        inspection = inspect_project(self.manifest)
        work_item = discover_next_work(self.manifest, inspection)
        self.contract = draft_design_contract(
            self.manifest,
            work_item,
            inspection,
            run_id="HARN-002-REPAIR-4-OPS-001",
            owned_paths=["src/semantic.ts"],
            success_criteria=["acceptance passes"],
            acceptance_instruments=[["python3", "-c", "raise SystemExit(0)"]],
        )
        self.candidate_ref = "harn-candidate/ENG-012-HARN-002-REPAIR-4-OPS-001"
        self.candidate_worktree = root / "candidate-worktree"
        self.review_worktree = root / "review-worktree"
        self._git("worktree", "add", "-b", self.candidate_ref, str(self.candidate_worktree), self.baseline_head)
        (self.candidate_worktree / "src").mkdir()
        (self.candidate_worktree / "src/semantic.ts").write_text("candidate\n", encoding="utf-8")
        self._git_at(self.candidate_worktree, "add", "src/semantic.ts")
        self._git_at(self.candidate_worktree, "commit", "-m", "candidate")
        self.candidate_head = self._git_at(self.candidate_worktree, "rev-parse", "HEAD")
        self.candidate_tree = self._git_at(self.candidate_worktree, "rev-parse", "HEAD^{tree}")
        self._git("worktree", "add", "--detach", str(self.review_worktree), self.candidate_head)
        self.runtime = root / "runtime" / self.contract["run_id"]
        for directory in (self.runtime / "builder", self.runtime / "deterministic/test-1", self.runtime / "dv", self.runtime / "sos"):
            directory.mkdir(parents=True)
        self._write(self.runtime / "manifest.json", {
            "run_id": self.contract["run_id"],
            "product": {"repo": str(self.repo.resolve()), "canonical_branch": self.branch, "baseline_head": self.baseline_head, "baseline_tree": self.baseline_tree},
        })
        self._write(self.runtime / "state.json", {"run_id": self.contract["run_id"], "state": "ACCEPTANCE_READY"})
        self._write(self.runtime / "events.ndjson", {"event": "acceptance_ready", "to_state": "ACCEPTANCE_READY"}, ndjson=True)
        self._write(self.runtime / "builder/invocation.json", {"exit_code": 0, "timed_out": False})
        self._write(self.runtime / "deterministic/test-1/invocation.json", {"exit_code": 0, "timed_out": False})
        self._write(self.runtime / "dv/result.json", {"result": "PASS", "findings": []})
        self.review = {
            "disposition": "PASS",
            "reviewed_head": self.candidate_head,
            "reviewed_tree": self.candidate_tree,
            "security": {"status": "PASS", "findings": []},
            "operability": {"status": "PASS", "findings": []},
            "semantics": {"status": "PASS", "findings": []},
            "architecture": {"status": "PASS", "findings": []},
            "blocking_findings": [],
            "non_blocking_findings": [],
        }
        self._write(self.runtime / "sos/review.json", self.review)
        self._write(self.runtime / "sos/raw-result.json", self.review)
        review_manifest = build_worktree_fingerprint_manifest(self.review_worktree)
        review_fingerprint = fingerprint_manifest(review_manifest)
        self._write(self.runtime / "sos/fingerprint-pre.json", {"fingerprint": review_fingerprint, "manifest": review_manifest})
        self._write(self.runtime / "sos/fingerprint-post.json", {"fingerprint": review_fingerprint, "manifest": review_manifest})
        evidence_paths = {
            "manifest": str(self.runtime / "manifest.json"), "state": str(self.runtime / "state.json"), "events": str(self.runtime / "events.ndjson"),
            "builder": str(self.runtime / "builder"), "deterministic": str(self.runtime / "deterministic"), "dv": str(self.runtime / "dv"),
            "sos": str(self.runtime / "sos"), "worktree": str(self.candidate_worktree), "review_worktree": str(self.review_worktree),
        }
        review_artifact = str(self.runtime / "sos/review.json")
        raw_artifact = str(self.runtime / "sos/raw-result.json")
        pre_artifact = str(self.runtime / "sos/fingerprint-pre.json")
        post_artifact = str(self.runtime / "sos/fingerprint-post.json")
        references = sorted(set(evidence_paths.values()) | {review_artifact, raw_artifact, pre_artifact, post_artifact})
        self.result = {
            "result": "ACCEPTANCE_READY", "run_id": self.contract["run_id"], "candidate_head": self.candidate_head, "candidate_tree": self.candidate_tree,
            "candidate_ref": self.candidate_ref, "deterministic_result": "ACCEPTANCE_READY", "verification_disposition": "PASS",
            "reviewer_disposition": {"dv_result": "PASS", "sos_result": "ACCEPT", "review_disposition": "PASS"},
            "evidence_paths": evidence_paths, "required_evidence_references": references,
            "review_artifact": review_artifact, "review_raw_artifact": raw_artifact,
            "review_fingerprint_pre_artifact": pre_artifact, "review_fingerprint_post_artifact": post_artifact,
            "review_worktree_fingerprint": review_fingerprint, "candidate_worktree_fingerprint": fingerprint_worktree(self.candidate_worktree),
            "review_artifact_sha256": self._sha256(Path(review_artifact)), "error_class": None,
        }

    def _git(self, *args: str) -> str:
        return self._git_at(self.repo, *args)

    @staticmethod
    def _git_at(directory: Path, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(directory), *args], capture_output=True, text=True, check=True)
        return result.stdout.strip()

    @staticmethod
    def _write(path: Path, value: object, *, ndjson: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(value, sort_keys=True) + "\n"
        path.write_text(text if not ndjson else text, encoding="utf-8")

    @staticmethod
    def _sha256(path: Path) -> str:
        import hashlib
        return hashlib.sha256(path.read_bytes()).hexdigest()


class TestRepair4GateBMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Repair4EvidenceFixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _ingest(self, result: dict | None = None) -> dict:
        return ingest_runner_result(self.fixture.contract, result or self.fixture.result)

    def _prepare(self, review: dict | None = None, ingested: dict | None = None) -> dict:
        return prepare_gate_b(self.fixture.contract, ingested or self._ingest(), review or self.fixture.review)

    def test_OPS_A_no_review_artifact_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.result)
        broken.pop("review_artifact")
        with self.assertRaises(ArtifactValidationError):
            self._ingest(broken)

    def test_OPS_B_identity_only_review_rejected(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            self._prepare({"reviewed_head": self.fixture.candidate_head, "reviewed_tree": self.fixture.candidate_tree})

    def test_OPS_C_missing_disposition_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken.pop("disposition")
        with self.assertRaises(ArtifactValidationError):
            self._prepare(broken)

    def test_OPS_D_unknown_disposition_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken["disposition"] = "MAYBE"
        with self.assertRaises(ArtifactValidationError):
            self._prepare(broken)

    def test_OPS_E_needs_fix_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken["disposition"] = "NEEDS_FIX"
        broken["security"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        broken["operability"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        broken["semantics"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        broken["architecture"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        broken["blocking_findings"] = ["blocking"]
        with self.assertRaises(ArtifactValidationError):
            self._prepare(broken)

    def _inconsistent_axis(self, axis: str) -> dict:
        broken = copy.deepcopy(self.fixture.review)
        broken[axis] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        return broken

    def test_OPS_F_pass_security_needs_fix_rejected(self) -> None:
        with self.assertRaises(ArtifactValidationError): self._prepare(self._inconsistent_axis("security"))

    def test_OPS_G_pass_operability_needs_fix_rejected(self) -> None:
        with self.assertRaises(ArtifactValidationError): self._prepare(self._inconsistent_axis("operability"))

    def test_OPS_H_pass_semantics_needs_fix_rejected(self) -> None:
        with self.assertRaises(ArtifactValidationError): self._prepare(self._inconsistent_axis("semantics"))

    def test_OPS_I_pass_architecture_needs_fix_rejected(self) -> None:
        with self.assertRaises(ArtifactValidationError): self._prepare(self._inconsistent_axis("architecture"))

    def test_OPS_J_pass_with_blocking_finding_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken["blocking_findings"] = ["blocking"]
        with self.assertRaises(ArtifactValidationError): self._prepare(broken)

    def test_OPS_K_review_head_mismatch_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken["reviewed_head"] = "0" * 40
        with self.assertRaises(ReviewStaleError): self._prepare(broken)

    def test_OPS_L_review_tree_mismatch_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.review)
        broken["reviewed_tree"] = "0" * 40
        with self.assertRaises(ReviewStaleError): self._prepare(broken)

    def test_OPS_M_runner_deterministic_failure_plus_review_pass_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.result)
        broken["result"] = "STOPPED"
        broken["deterministic_result"] = "STOPPED"
        with self.assertRaises(GovernanceBlockerError):
            self._prepare(ingested=self._ingest(broken))

    def test_OPS_N_missing_runner_acceptance_evidence_rejected(self) -> None:
        broken = copy.deepcopy(self.fixture.result)
        broken.pop("verification_disposition")
        with self.assertRaises(ArtifactValidationError): self._ingest(broken)

    def test_OPS_O_fabricated_acceptance_ready_phase_cannot_bypass(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, {"result": "RESULT_INGESTED", "controller_phase": "ACCEPTANCE_READY"}, self.fixture.review)

    def test_OPS_P_complete_pass_prepares_human_gate_without_integration(self) -> None:
        before = self.fixture._git("rev-parse", "HEAD")
        gate = self._prepare()
        self.assertEqual(gate["decision"], "PENDING")
        self.assertEqual(self.fixture._git("rev-parse", "HEAD"), before)
        self.assertEqual(self.fixture._git("branch", "--show-current"), self.fixture.branch)

    def test_duplicate_exact_evidence_is_idempotent(self) -> None:
        first = self._ingest()
        second = self._ingest()
        self.assertEqual(first, second)

    def test_conflicting_review_replacement_after_ingestion_fails_closed(self) -> None:
        ingested = self._ingest()
        replacement = copy.deepcopy(self.fixture.review)
        replacement["disposition"] = "NEEDS_FIX"
        replacement["security"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        replacement["operability"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        replacement["semantics"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        replacement["architecture"] = {"status": "NEEDS_FIX", "findings": ["blocking"]}
        replacement["blocking_findings"] = ["blocking"]
        Path(self.fixture.result["review_artifact"]).write_text(json.dumps(replacement), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            self._prepare(ingested=ingested, review=replacement)


if __name__ == "__main__":
    unittest.main()
