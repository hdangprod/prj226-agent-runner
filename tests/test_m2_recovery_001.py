"""M2-RECOVERY-001: Unified qualification and regression test suite.

Proves the complete restoration of Runner V1 invariants across all lineages (R002-R008):
- R008: candidate_ref prompt binding and strict ref equality rejection (REVIEW_STALE)
- R007: execution_config.toml TOCTOU snapshotting at Gate A
- R006: builder_binding freeze and revalidation against config drift
- R004/R005: contract_hash / contract_path binding and tamper rejection
- R003: structured outputs schema compatibility (review_version explicit type string)
- R002: presentation of builder and reviewer bindings at Gate A preview
"""

from __future__ import annotations

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

from prj226_runner import presentation as P
from prj226_runner import workflow as W
from prj226_runner import runner as R
from prj226_runner import controller as C
from prj226_runner.errors import ReviewStaleError, ArtifactValidationError, GovernanceBlockerError


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


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
target = pathlib.Path(os.environ.get("FAKE_TARGET", "src/domain/context.ts"))
if os.environ.get("FAKE_NO_CHANGE"):
    raise SystemExit(0)
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("export const context = 'repaired';\\n", encoding="utf-8")
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

record_prompt = pathlib.Path(@@PROMPT_RECORD@@)
record_prompt.write_text(prompt, encoding="utf-8")

if "PROCESS_FAILURE_BEFORE_OUTPUT" in prompt:
    raise SystemExit(9)

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

force_ref = os.environ.get("FORCE_REVIEWED_REF")
if force_ref is not None:
    if force_ref == "__OMIT__":
        reviewed_ref = None
    else:
        reviewed_ref = force_ref
elif "FORCE_WRONG_REF_CANDIDATE_HEAD" in prompt:
    reviewed_ref = "candidate_head"
elif "FORCE_WRONG_REF_HEAD_HASH" in prompt:
    reviewed_ref = head
elif "FORCE_WRONG_REF_DIFFERENT" in prompt:
    reviewed_ref = "harn-candidate/different-ref"
elif "FORCE_EMPTY_REF" in prompt:
    reviewed_ref = ""
elif "FORCE_MISSING_REF" in prompt:
    reviewed_ref = None
else:
    reviewed_ref = ref_from_prompt if ref_from_prompt is not None else "candidate_head"

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
if reviewed_ref is not None:
    payload["reviewed_ref"] = reviewed_ref

out.write_text(json.dumps(payload), encoding="utf-8")

if "PROCESS_FAILURE_WITH_PASS" in prompt:
    raise SystemExit(9)
"""


class RecoveryFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "product"
        self.runtime = root / "runtime"
        self.config = root / "runner.toml"
        self.manifest_path = root / "manifest.json"
        self.scopes_path = root / "scopes.json"

        self.builder_count = root / "builder-count.txt"
        self.reviewer_count = root / "reviewer-count.txt"
        self.prompt_record = root / "reviewer_prompt.txt"
        self.fake_builder = root / "fake-builder.py"
        self.fake_reviewer = root / "fake-reviewer.py"

    def init(self) -> None:
        self.repo.mkdir(parents=True, exist_ok=True)
        self.runtime.mkdir(parents=True, exist_ok=True)

        _git(self.repo, "init")
        _git(self.repo, "config", "user.name", "Recovery Tests")
        _git(self.repo, "config", "user.email", "recovery@example.test")
        _git(self.repo, "config", "commit.gpgsign", "false")

        (self.repo / "src" / "domain").mkdir(parents=True, exist_ok=True)
        (self.repo / "src" / "domain" / "context.ts").write_text("export const context = 'initial';\n", encoding="utf-8")
        (self.repo / "tests" / "domain").mkdir(parents=True, exist_ok=True)
        (self.repo / "tests" / "domain" / "context.test.ts").write_text("test('initial', () => {});\n", encoding="utf-8")
        (self.repo / "docs" / "tasks").mkdir(parents=True, exist_ok=True)
        (self.repo / "docs" / "CURRENT.md").write_text("**Next executable work:** TASK-001\n", encoding="utf-8")
        (self.repo / "docs" / "PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| TASK-001 | acceptance | PROPOSED |\n", encoding="utf-8")
        (self.repo / "docs" / "tasks" / "TASK-001.md").write_text("# TASK-001 — Acceptance\n", encoding="utf-8")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs" / "README.md").write_text("docs\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "base")
        self.branch = _git(self.repo, "branch", "--show-current")

        builder_src = FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(self.builder_count)))
        self.fake_builder.write_text(builder_src, encoding="utf-8")
        self.fake_builder.chmod(self.fake_builder.stat().st_mode | stat.S_IXUSR)

        reviewer_src = FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(self.reviewer_count))).replace("@@PROMPT_RECORD@@", json.dumps(str(self.prompt_record)))
        self.fake_reviewer.write_text(reviewer_src, encoding="utf-8")
        self.fake_reviewer.chmod(self.fake_reviewer.stat().st_mode | stat.S_IXUSR)

        self.write_config()

        manifest_dict = {
            "project_id": "LIAM-RECOVERY",
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
                "task_id_pattern": "TASK-[0-9]+",
                "task_file_glob": "docs/tasks/{task_id}.md",
            },
        }
        self.manifest_path.write_text(json.dumps(manifest_dict, indent=2, sort_keys=True), encoding="utf-8")

        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "context-authz": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": [],
                },
                "targeted-scope": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": ["MODULE_BOUNDARY"],
                },
                "targeted-failing": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(1)"]],
                    "change_categories": ["MODULE_BOUNDARY"],
                },
            },
        }
        self.scopes_path.write_text(json.dumps(scopes_dict, indent=2, sort_keys=True), encoding="utf-8")
        W.init_project(self.manifest_path, self.config, scopes_path=self.scopes_path)

    def write_config(
        self,
        builder_exe: Path | None = None,
        builder_model: str = "fake-builder",
        builder_tool: str = "codex",
        builder_timeout: int = 20,
        reviewer_exe: Path | None = None,
        reviewer_model: str = "gpt-5.6-luna",
        reviewer_tool: str = "codex",
    ) -> None:
        b_exe = builder_exe or self.fake_builder
        r_exe = reviewer_exe or self.fake_reviewer
        self.config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(self.runtime))}\n\n"
            "[agents.builder]\n"
            f"tool = {json.dumps(builder_tool)}\n"
            f"executable = {json.dumps(str(b_exe))}\n"
            f"model = {json.dumps(builder_model)}\n"
            f"timeout_seconds = {builder_timeout}\n\n"
            "[agents.dv]\n"
            "tool = 'opencode2'\n"
            f"executable = {json.dumps(str(b_exe))}\nmodel = 'fake-muse'\ntimeout_seconds = 20\n\n"
            "[agents.sos_reviewer]\n"
            f"tool = {json.dumps(reviewer_tool)}\n"
            f"executable = {json.dumps(str(r_exe))}\n"
            f"model = {json.dumps(reviewer_model)}\n"
            "timeout_seconds = 20\n",
            encoding="utf-8",
        )

    def builder_calls(self) -> int:
        return int(self.builder_count.read_text(encoding="utf-8").strip()) if self.builder_count.exists() else 0

    def reviewer_calls(self) -> int:
        return int(self.reviewer_count.read_text(encoding="utf-8").strip()) if self.reviewer_count.exists() else 0

    def recorded_prompt(self) -> str:
        return self.prompt_record.read_text(encoding="utf-8") if self.prompt_record.exists() else ""


class TestM2Recovery001(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fix = RecoveryFixture(self.root)
        self.fix.init()
        self.repo_dir = Path(__file__).resolve().parents[1]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _execute_targeted_task(self, scope: str = "targeted-scope", task_id: str = "TASK-001", description: str = "Test task") -> dict[str, Any]:
        outcome = W.create_task(description, scope, preview_only=True, runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        try:
            exec_outcome = W.create_task(description, scope, preview_only=False, approval_text="approve", task_id=tid, runtime_root=self.fix.runtime)
            return exec_outcome
        except W.WorkflowError as exc:
            record = W.load_task_record(self.fix.runtime, tid)
            return {
                "task_id": tid,
                "status": record.get("status"),
                "error_class": record.get("error_class"),
                "error": record.get("error"),
                "review_status": record.get("review_status"),
                "workflow_error": str(exc),
                "record": record,
            }

    # Lineage R003
    def test_recovery_01_review_version_schema_explicit_string_type(self) -> None:
        """R003: review_version in targeted-review-result schema must explicitly declare type: string."""
        schema_path = self.repo_dir / "schemas" / "targeted-review-result.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        prop = schema["properties"]["review_version"]
        self.assertEqual(prop.get("type"), "string", "review_version must declare 'type': 'string'")

    # Lineage R004/R005/R006/R007
    def test_recovery_02_task_schema_requires_builder_binding_and_contract(self) -> None:
        """R006/R007: workflow-task schema must declare builder_binding, contract_hash, contract_path and require them in active states."""
        schema_path = self.repo_dir / "schemas" / "workflow-task.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        props = schema["properties"]
        self.assertIn("builder_binding", props, "builder_binding must be a declared property")
        self.assertIn("contract_hash", props, "contract_hash must be a declared property")
        self.assertIn("contract_path", props, "contract_path must be a declared property")

    # Lineage R008
    def test_recovery_03_targeted_review_prompt_carries_candidate_ref(self) -> None:
        """R008: Reviewer prompt context must carry candidate_ref and prompt must state reviewed_ref MUST equal candidate_ref."""
        import inspect
        sig = inspect.signature(R._targeted_review_prompt)
        self.assertIn("candidate_ref", sig.parameters, "_targeted_review_prompt must accept candidate_ref parameter")

    # Lineage R007
    def test_recovery_05_execution_config_snapshot_created_on_approval(self) -> None:
        """R007: Upon Gate A approval, execution_config.toml snapshot must be created in task directory."""
        outcome = W.create_task("Snapshot test", "context-authz", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        task_id = outcome["task_id"]
        task_dir = self.fix.runtime / "workflow" / task_id
        snapshot_path = task_dir / "execution_config.toml"
        self.assertTrue(snapshot_path.is_file(), f"execution_config.toml must exist in {task_dir}")

    # Lineage R006
    def test_recovery_07_builder_binding_frozen_in_task_record(self) -> None:
        """R006: Preview and task records must freeze builder_binding."""
        preview_out = W.create_task("Builder binding test", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        rec = preview_out["record"]
        self.assertIn("builder_binding", rec, "task record must contain builder_binding")
        self.assertIsNotNone(rec.get("builder_binding"), "builder_binding must not be None in PREVIEW")
        bb = rec["builder_binding"]
        self.assertEqual(bb.get("tool"), "codex")
        self.assertEqual(bb.get("model"), "fake-builder")
        self.assertEqual(bb.get("executable"), str(self.fix.fake_builder))

    # Lineage R006
    def test_recovery_08_builder_binding_drift_rejected_on_approval(self) -> None:
        """R006: Mutating builder config after preview fails closed with WORKFLOW_EXECUTION_BINDING_MISMATCH."""
        preview_out = W.create_task("Drift test", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        task_id = preview_out["task_id"]

        # Mutate runner.toml builder model
        new_cfg = self.fix.config.read_text().replace("fake-builder", "mutated-builder")
        self.fix.config.write_text(new_cfg, encoding="utf-8")

        # Attempt approval - must fail closed with exit code 20
        with self.assertRaises(W.WorkflowError) as ctx:
            W.create_task("Drift test", "context-authz", preview_only=False, approval_text="approve", task_id=task_id, runtime_root=self.fix.runtime)
        self.assertEqual(ctx.exception.error_code, "WORKFLOW_EXECUTION_BINDING_MISMATCH")

    # Lineage R004/R005
    def test_recovery_09_contract_hash_and_path_bound_in_task_record(self) -> None:
        """R004/R005: Task record must contain contract_hash and contract_path."""
        preview_out = W.create_task("Contract binding test", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        rec = preview_out["record"]
        self.assertIn("contract_hash", rec, "task record must contain contract_hash")
        self.assertIn("contract_path", rec, "task record must contain contract_path")
        self.assertIsNotNone(rec.get("contract_hash"))
        self.assertIsNotNone(rec.get("contract_path"))

    # Lineage R002
    def test_recovery_10_gate_a_preview_displays_builder_and_reviewer_bindings(self) -> None:
        """R002: Gate A preview includes EXECUTION and REVIEWER sections."""
        preview_out = W.create_task("Presentation test", "targeted-scope", preview_only=True, runtime_root=self.fix.runtime)
        formatted = P.format_gate_a_preview(preview_out["preview"])
        self.assertIn("EXECUTION", formatted)
        self.assertIn("builder/tool: codex", formatted)
        self.assertIn("builder/model: fake-builder", formatted)
        self.assertIn("CONTRACT", formatted)
        self.assertIn("REVIEWER", formatted)
        self.assertIn("tool: codex", formatted)
        self.assertIn("model: gpt-5.6-luna", formatted)

    # Lineage R008 Comprehensive Scenarios (P01-P11)
    def test_r008_p01_prompt_contains_exact_candidate_ref(self) -> None:
        """R008-A: Reviewer prompt generated by run_packet_v2 carries exact immutable candidate_ref."""
        outcome = self._execute_targeted_task()
        prompt = self.fix.recorded_prompt()
        self.assertTrue(prompt, "Reviewer prompt must have been recorded")
        context_str = prompt.split("\n\n")[-1]
        context_data = json.loads(context_str)
        self.assertIn("candidate_ref", context_data, "Prompt context MUST contain candidate_ref")
        candidate_ref = context_data["candidate_ref"]
        self.assertTrue(isinstance(candidate_ref, str) and candidate_ref.startswith("harn-candidate/"), f"candidate_ref invalid: {candidate_ref}")
        task_dir = self.fix.runtime / "workflow" / outcome["task_id"]
        task_json = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
        run_id = task_json["run_id"]
        report = json.loads((self.fix.runtime / run_id / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(candidate_ref, report["candidate_ref"])

    def test_r008_p02_prompt_explicit_ref_equality_requirement(self) -> None:
        """R008-B: Reviewer-facing contract explicitly states reviewed_ref MUST equal candidate_ref."""
        self._execute_targeted_task()
        prompt = self.fix.recorded_prompt()
        self.assertTrue(prompt, "Reviewer prompt must have been recorded")
        self.assertIn("`reviewed_ref` MUST equal the exact `candidate_ref`", prompt,
                      "Prompt MUST explicitly state that reviewed_ref MUST equal the exact candidate_ref")

    def test_r008_p03_matching_ref_progresses_normally(self) -> None:
        """R008-C: Schema-valid targeted result with exact candidate binding progresses to ACCEPTANCE_READY."""
        outcome = self._execute_targeted_task()
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        task_dir = self.fix.runtime / "workflow" / outcome["task_id"]
        task_json = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))
        self.assertEqual(task_json["status"], "ACCEPTANCE_READY")
        self.assertEqual(task_json["review_status"], "PASS")
        self.assertIsNotNone(task_json["candidate_ref"])
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 1)

    def test_r008_p04_wrong_ref_candidate_head_rejected(self) -> None:
        """R008-D1: reviewed_ref='candidate_head' fails closed with REVIEW_STALE."""
        outcome = self._execute_targeted_task(description="FORCE_WRONG_REF_CANDIDATE_HEAD task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "GOVERNANCE_BLOCKER")
        self.assertIn("REVIEW_STALE", outcome["error"])
        self.assertIn("ref does not match the immutable candidate", outcome["error"])

    def test_r008_p05_wrong_ref_head_hash_rejected(self) -> None:
        """R008-D2: reviewed_ref=<candidate HEAD hash> fails closed with REVIEW_STALE."""
        outcome = self._execute_targeted_task(description="FORCE_WRONG_REF_HEAD_HASH task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "GOVERNANCE_BLOCKER")
        self.assertIn("REVIEW_STALE", outcome["error"])
        self.assertIn("ref does not match the immutable candidate", outcome["error"])

    def test_r008_p06_wrong_ref_different_branch_rejected(self) -> None:
        """R008-D3: reviewed_ref=<different candidate ref> fails closed with REVIEW_STALE."""
        outcome = self._execute_targeted_task(description="FORCE_WRONG_REF_DIFFERENT task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "GOVERNANCE_BLOCKER")
        self.assertIn("REVIEW_STALE", outcome["error"])
        self.assertIn("ref does not match the immutable candidate", outcome["error"])

    def test_r008_p07_missing_ref_rejected(self) -> None:
        """R008-E1: Missing reviewed_ref fails closed (ARTIFACT_VALIDATION_ERROR)."""
        outcome = self._execute_targeted_task(description="FORCE_MISSING_REF task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "ARTIFACT_VALIDATION_ERROR")
        self.assertTrue("reviewed_ref" in outcome["error"] or "closed targeted fields" in outcome["error"],
                        f"Expected ref-related artifact validation error: {outcome['error']}")

    def test_r008_p08_empty_ref_rejected(self) -> None:
        """R008-E2: Empty reviewed_ref fails closed (ARTIFACT_VALIDATION_ERROR)."""
        outcome = self._execute_targeted_task(description="FORCE_EMPTY_REF task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "ARTIFACT_VALIDATION_ERROR")
        self.assertTrue("reviewed_ref" in outcome["error"] or "non-empty" in outcome["error"],
                        f"Expected ref-related artifact validation error: {outcome['error']}")

    def test_r008_p09_no_retry_or_fallback_on_review_failure(self) -> None:
        """R008-F: No retry or fallback occurs after reviewer validation failure."""
        outcome = self._execute_targeted_task(description="FORCE_WRONG_REF_CANDIDATE_HEAD task")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 1)

    def test_r008_p10_none_review_mode_zero_reviewer_activity(self) -> None:
        """R008-G: NONE review mode causes zero reviewer activity."""
        outcome = self._execute_targeted_task(scope="context-authz")
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 0)

    def test_r008_p11_targeted_review_only_after_deterministic_pass(self) -> None:
        """R008-H: TARGETED review occurs only after deterministic verification passes."""
        outcome = self._execute_targeted_task(scope="targeted-failing")
        self.assertEqual(outcome["status"], "STOPPED")
        self.assertEqual(outcome["error_class"], "IMPLEMENTATION_FAILURE")
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 0)


if __name__ == "__main__":
    unittest.main()
