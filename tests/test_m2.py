"""M2 deterministic tests: five-command golden path around frozen M1."""

from __future__ import annotations

import hashlib
import io
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
from prj226_runner import presentation as P
from prj226_runner import runner as R
from prj226_runner import workflow as W


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


class M2Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "product"
        subprocess.run(["git", "init", str(self.repo)], capture_output=True, text=True, check=True)
        _git(self.repo, "config", "user.email", "m2@example.test")
        _git(self.repo, "config", "user.name", "M2 Tests")
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
        self.manifest_path = root / "manifest.json"
        self.write_config()
        self.manifest_dict = {
            "project_id": "M2-001",
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
        self.manifest_path.write_text(json.dumps(self.manifest_dict, indent=2, sort_keys=True), encoding="utf-8")
        self.scopes_path = root / "scopes.json"
        self.scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "default",
            "scopes": {
                "default": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": [],
                },
                "targeted": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": ["MODULE_BOUNDARY"],
                },
                "failing": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(1)"]],
                    "change_categories": [],
                },
                "needs-fix": {
                    "owned_paths": ["src/app.txt"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": ["MODULE_BOUNDARY"],
                },
            },
        }
        self.scopes_path.write_text(json.dumps(self.scopes_dict, indent=2, sort_keys=True), encoding="utf-8")

    def write_config(self) -> None:
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
            "tool = 'codex'\n"
            f"executable = {json.dumps(str(self.fake_reviewer))}\nmodel = 'gpt-5.6-luna'\ntimeout_seconds = 20\n",
            encoding="utf-8",
        )

    def builder_calls(self) -> int:
        return int(self.builder_count.read_text(encoding="utf-8")) if self.builder_count.exists() else 0

    def reviewer_calls(self) -> int:
        return int(self.reviewer_count.read_text(encoding="utf-8")) if self.reviewer_count.exists() else 0

    def init(self, scopes_path: Path | str | None = ...) -> dict:
        sp = self.scopes_path if scopes_path is ... else scopes_path
        return W.init_project(self.manifest_path, self.config, scopes_path=sp)

    def task(self, desc: str, scope: str | None = None, approve: str | None = "approve", preview_only: bool = False) -> dict:
        return W.create_task(desc, scope, preview_only=preview_only, approval_text=approve, runtime_root=self.runtime)


class TestM2(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fix = M2Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_m2_init_creates_project_defaults(self) -> None:
        summary = self.fix.init()
        defaults_path = Path(summary["defaults_path"])
        self.assertTrue(defaults_path.is_file())
        data = json.loads(defaults_path.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "PRJ226.PROJECT_DEFAULTS.v1")
        self.assertEqual(data["project_id"], "M2-001")
        self.assertIn("product_repository", data)
        self.assertIn("canonical_branch", data)
        self.assertIn("runtime_root", data)
        self.assertIn("manifest_source", data)
        self.assertIn("config_source", data)
        # Must not persist generated authority as defaults.
        for forbidden in ("contract_hash", "packet_hash", "contract_id", "candidate_head", "gate_b"):
            self.assertNotIn(forbidden, json.dumps(data))
        # Validate against schema.
        import jsonschema

        schema = json.loads((Path(__file__).parents[1] / "schemas" / "project-defaults.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(data, schema)

    def test_m2_init_rejects_invalid_manifest_or_config(self) -> None:
        bad_manifest = self.root / "bad-manifest.json"
        bad_manifest.write_text(json.dumps({"project_id": "X"}), encoding="utf-8")
        with self.assertRaises(W.WorkflowError) as ctx:
            W.init_project(bad_manifest, self.fix.config)
        self.assertEqual(ctx.exception.exit_code, 2)
        bad_config = self.root / "bad-config.toml"
        bad_config.write_text("[bad]\n", encoding="utf-8")
        with self.assertRaises(W.WorkflowError) as ctx2:
            W.init_project(self.fix.manifest_path, bad_config)
        self.assertEqual(ctx2.exception.exit_code, 2)

    def test_m2_init_invokes_no_provider(self) -> None:
        self.fix.init()
        self.assertEqual(self.fix.builder_calls(), 0)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        # No run evidence.
        run_dirs = [p for p in self.fix.runtime.rglob("report.json")] if self.fix.runtime.exists() else []
        self.assertEqual(run_dirs, [])

    def test_m2_task_preview_contains_required_gate_a_fields(self) -> None:
        self.fix.init()
        outcome = W.create_task("Add bounded widget", None, preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        text = P.format_gate_a_preview(preview)
        for field in ("REQUEST", "BEHAVIOR", "FILES", "CHECKS", "EXECUTION", "REVIEW", "CONTRACT", "UNCERTAINTY"):
            self.assertIn(field, text, field)
        self.assertIn("Add bounded widget", text)
        self.assertIn("src/app.txt", text)
        # Must not normally display hashes.
        self.assertNotIn("contract_hash", text)
        self.assertNotIn("packet_hash", text)

    def test_m2_preview_only_has_no_execution_side_effects(self) -> None:
        self.fix.init()
        before_branches = _git(self.fix.repo, "branch", "--list")
        outcome = W.create_task("Preview only change", None, preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "PREVIEW")
        self.assertEqual(self.fix.builder_calls(), 0)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        after_branches = _git(self.fix.repo, "branch", "--list")
        self.assertEqual(before_branches, after_branches)
        # No run directory.
        task_id = outcome["task_id"]
        record = W.load_task_record(self.fix.runtime, task_id)
        self.assertIsNone(record["run_id"])
        self.assertEqual(record["status"], "PREVIEW")
        run_candidates = list(self.fix.runtime.glob("TASK-*-RUN"))
        # Workflow dir exists, but no M1 run evidence.
        self.assertEqual([p for p in self.fix.runtime.glob("*/report.json")], [])

    def test_m2_task_requires_literal_approve(self) -> None:
        self.fix.init()
        outcome = W.create_task("Literal approve path", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        self.assertEqual(self.fix.builder_calls(), 1)

    def test_m2_task_rejects_missing_or_wrong_approval(self) -> None:
        self.fix.init()
        for bad in (None, "", "yes", "APPROVE", "approved", "Approve"):
            with self.assertRaises(W.WorkflowError) as ctx:
                W.create_task(f"Wrong approval {bad}", None, preview_only=False, approval_text=bad, runtime_root=self.fix.runtime)
            self.assertIn(ctx.exception.exit_code, (10, 2))
        # No builder invoked for declined approvals (each declined creates a new task but no run).
        self.assertEqual(self.fix.builder_calls(), 0)
        self.assertEqual(self.fix.reviewer_calls(), 0)

    def test_m2_task_derives_m1_authority_without_manual_json(self) -> None:
        self.fix.init()
        # Operator creates zero JSON manually; workflow must construct M1 authority.
        outcome = W.create_task("Derive M1 authority", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        task_id = outcome["task_id"]
        wdir = self.fix.runtime / "workflow" / task_id
        for rel in ("contract.json", "packet.json", "gate-a.json"):
            self.assertTrue((wdir / rel).is_file(), rel)
        contract = json.loads((wdir / "contract.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["contract_version"], "HARN-002.v2")
        packet = json.loads((wdir / "packet.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["packet_version"], "HARN-001.TASK_PACKET.v2")
        # Real M1 evidence exists.
        run_id = outcome["run_id"]
        self.assertTrue((self.fix.runtime / run_id / "report.json").is_file())

    def test_m2_task_none_full_golden_path(self) -> None:
        self.fix.init()
        outcome = W.create_task("Bounded feature none path", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        self.assertEqual(outcome["plan"]["review_mode"], "NONE")
        result = outcome["result"]
        self.assertEqual(result["review_status"], "NOT_REQUIRED")
        self.assertEqual(result["review_attempted"], False)
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        # Acceptance summary contains required sections.
        acc = W.get_acceptance_data(outcome["task_id"], self.fix.runtime)
        text = P.format_acceptance_summary(acc)
        for section in ("REQUESTED", "CHANGED", "BEHAVIOR EVIDENCE", "CHECKS", "SEMANTIC REVIEW", "UNVERIFIED RISK", "RUN INFO", "NEXT ACTION"):
            self.assertIn(section, text, section)
        self.assertIn(f"prj226-runner accept {outcome['task_id']}", text)
        # Gate B approve + local integration succeeds.
        head_before = _git(self.fix.repo, "rev-parse", "HEAD")
        self.assertNotEqual(head_before, result["candidate_head"])
        integrated = W.perform_accept(outcome["task_id"], "approve", self.fix.runtime)
        head_after = _git(self.fix.repo, "rev-parse", "HEAD")
        self.assertEqual(head_after, result["candidate_head"])
        st = W.get_status(outcome["task_id"], self.fix.runtime)
        self.assertEqual(st["status"], "ACCEPTED")

    def test_m2_task_targeted_full_golden_path(self) -> None:
        self.fix.init()
        outcome = W.create_task("Targeted boundary change", "targeted", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        self.assertEqual(outcome["plan"]["review_mode"], "TARGETED")
        result = outcome["result"]
        self.assertEqual(result["review_attempted"], True)
        self.assertEqual(result["review_status"], "PASS")
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 1)
        self.assertIsNotNone(result.get("review_evidence"))
        # Ingestion + Gate B + integration.
        head_before = _git(self.fix.repo, "rev-parse", "HEAD")
        integrated = W.perform_accept(outcome["task_id"], "approve", self.fix.runtime)
        head_after = _git(self.fix.repo, "rev-parse", "HEAD")
        self.assertEqual(head_after, result["candidate_head"])
        self.assertNotEqual(head_before, head_after)

    def test_m2_task_stopped_on_deterministic_failure(self) -> None:
        self.fix.init()
        with self.assertRaises(W.WorkflowError) as ctx:
            W.create_task("Failing deterministic", "failing", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 10)
        self.assertEqual(self.fix.builder_calls(), 1)
        # Reviewer not invoked when deterministic fails.
        self.assertEqual(self.fix.reviewer_calls(), 0)
        tid = W.find_latest_task_id(self.fix.runtime)
        st = W.get_status(tid, self.fix.runtime)
        self.assertEqual(st["status"], "STOPPED")
        self.assertIsNotNone(st["first_failure"])
        # No integration.
        self.assertIsNone(st["record"].get("acceptance_ref"))

    def test_m2_task_stopped_on_targeted_failure(self) -> None:
        self.fix.init()
        with self.assertRaises(W.WorkflowError) as ctx:
            W.create_task("Needs fix targeted", "needs-fix", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 10)
        self.assertEqual(self.fix.builder_calls(), 1)
        self.assertEqual(self.fix.reviewer_calls(), 1)
        tid = W.find_latest_task_id(self.fix.runtime)
        st = W.get_status(tid, self.fix.runtime)
        self.assertEqual(st["status"], "STOPPED")
        self.assertEqual(st["review_status"], "NEEDS_FIX")

    def test_m2_no_retry_or_fallback(self) -> None:
        self.fix.init()
        # Deterministic failure must not retry builder.
        with self.assertRaises(W.WorkflowError):
            W.create_task("No retry check", "failing", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        b1 = self.fix.builder_calls()
        r1 = self.fix.reviewer_calls()
        self.assertEqual(b1, 1)
        self.assertEqual(r1, 0)
        tid = W.find_latest_task_id(self.fix.runtime)
        # Status/resume must not trigger additional invocations.
        W.get_status(tid, self.fix.runtime)
        W.build_continuation(tid, self.fix.runtime)
        self.assertEqual(self.fix.builder_calls(), b1)
        self.assertEqual(self.fix.reviewer_calls(), r1)
        # Targeted failure also exactly one review attempt.
        with self.assertRaises(W.WorkflowError):
            W.create_task("No retry targeted", "needs-fix", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        self.assertEqual(self.fix.builder_calls(), b1 + 1)
        self.assertEqual(self.fix.reviewer_calls(), r1 + 1)

    def test_m2_status_is_read_only(self) -> None:
        self.fix.init()
        outcome = W.create_task("Read only status", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        task_path = self.fix.runtime / "workflow" / tid / "task.json"
        before = task_path.read_bytes()
        report_path = self.fix.runtime / outcome["run_id"] / "report.json"
        before_report = report_path.read_bytes()
        b0 = self.fix.builder_calls()
        r0 = self.fix.reviewer_calls()
        for _ in range(3):
            W.get_status(tid, self.fix.runtime)
        self.assertEqual(task_path.read_bytes(), before)
        self.assertEqual(report_path.read_bytes(), before_report)
        self.assertEqual(self.fix.builder_calls(), b0)
        self.assertEqual(self.fix.reviewer_calls(), r0)

    def test_m2_status_json_is_stable(self) -> None:
        self.fix.init()
        outcome = W.create_task("Stable json status", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        s1 = W.get_status(tid, self.fix.runtime)
        s2 = W.get_status(tid, self.fix.runtime)
        # Stable machine-readable projection.
        def _stable(st: dict) -> dict:
            return {
                "task_id": st["task_id"],
                "status": st["status"],
                "run_id": st["run_id"],
                "candidate_head": st["candidate_head"],
                "review_mode": st["review_mode"],
                "review_status": st["review_status"],
                "next_action": st["next_action"],
            }

        self.assertEqual(_stable(s1), _stable(s2))
        # CLI --json is stable JSON.
        from prj226_runner.cli import main as cli_main

        # Need env for CLI discovery: set PRJ226_RUNTIME_ROOT.
        with patch.dict(os.environ, {"PRJ226_RUNTIME_ROOT": str(self.fix.runtime)}):
            buf1b = io.StringIO()
            with patch("sys.stdout", buf1b):
                rc1b = cli_main(["status", tid, "--json"])
            out1 = buf1b.getvalue()
            buf2b = io.StringIO()
            with patch("sys.stdout", buf2b):
                rc2b = cli_main(["status", tid, "--json"])
            out2 = buf2b.getvalue()
        self.assertEqual(rc1b, 0)
        self.assertEqual(rc2b, 0)
        self.assertEqual(json.loads(out1), json.loads(out2))

    def test_m2_resume_reconstructs_verified_facts_only(self) -> None:
        self.fix.init()
        outcome = W.create_task("Resume facts", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        cont = W.build_continuation(tid, self.fix.runtime)
        self.assertEqual(cont["task_id"], tid)
        self.assertEqual(cont["description"], "Resume facts")
        self.assertEqual(cont["run_id"], outcome["run_id"])
        self.assertEqual(cont["candidate_head"], outcome["result"]["candidate_head"])
        self.assertIn("checks", cont)
        self.assertIn("review_status", cont)
        self.assertIn("next_action", cont)
        self.assertIn("evidence_references", cont)
        self.assertIn("must_not_repeat", cont)
        # No speculative root cause as verified fact.
        self.assertNotIn("root_cause", json.dumps(cont).lower())
        import jsonschema

        schema = json.loads((Path(__file__).parents[1] / "schemas" / "continuation.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(cont, schema)

    def test_m2_resume_does_not_rerun_execution(self) -> None:
        self.fix.init()
        outcome = W.create_task("No rerun on resume", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        b0 = self.fix.builder_calls()
        r0 = self.fix.reviewer_calls()
        runs_before = sorted(p.name for p in self.fix.runtime.iterdir() if p.is_dir())
        W.build_continuation(tid, self.fix.runtime)
        W.get_status(tid, self.fix.runtime)
        # write_handoff writes continuation but must not rerun builder.
        W.write_handoff(tid, self.fix.runtime)
        self.assertEqual(self.fix.builder_calls(), b0)
        self.assertEqual(self.fix.reviewer_calls(), r0)
        runs_after = sorted(p.name for p in self.fix.runtime.iterdir() if p.is_dir())
        self.assertEqual(runs_before, runs_after)

    def test_m2_handoff_contains_exact_next_action(self) -> None:
        self.fix.init()
        ok = W.create_task("Handoff next action", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        cont_ok, _ = W.write_handoff(ok["task_id"], self.fix.runtime)
        self.assertEqual(cont_ok["next_action"], f"prj226-runner accept {ok['task_id']}")
        with self.assertRaises(W.WorkflowError):
            W.create_task("Handoff stopped", "failing", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        stopped_id = W.find_latest_task_id(self.fix.runtime)
        # Latest is stopped; fetch its continuation.
        cont_stop = W.build_continuation(stopped_id, self.fix.runtime)
        self.assertIn("resume", cont_stop["next_action"])
        self.assertIn(stopped_id, cont_stop["next_action"])

    def test_m2_handoff_rejects_missing_authoritative_result(self) -> None:
        self.fix.init()
        outcome = W.create_task("Missing evidence", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        # Remove authoritative evidence.
        report = self.fix.runtime / outcome["run_id"] / "report.json"
        report.unlink()
        with self.assertRaises(W.WorkflowError) as ctx:
            W.build_continuation(tid, self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 20)
        with self.assertRaises(W.WorkflowError) as ctx2:
            W.get_status(tid, self.fix.runtime)
        self.assertEqual(ctx2.exception.exit_code, 20)

    def test_m2_accept_requires_acceptance_ready(self) -> None:
        self.fix.init()
        with self.assertRaises(W.WorkflowError):
            W.create_task("Stopped for accept", "failing", preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = W.find_latest_task_id(self.fix.runtime)
        with self.assertRaises(W.WorkflowError) as ctx:
            W.perform_accept(tid, "approve", self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 10)

    def test_m2_accept_requires_fresh_literal_approve(self) -> None:
        self.fix.init()
        outcome = W.create_task("Fresh approve required", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        head_before = _git(self.fix.repo, "rev-parse", "HEAD")
        for bad in (None, "", "yes", "APPROVE"):
            with self.assertRaises(W.WorkflowError) as ctx:
                W.perform_accept(tid, bad, self.fix.runtime)
            self.assertEqual(ctx.exception.exit_code, 10)
        # No integration on declined approvals.
        self.assertEqual(_git(self.fix.repo, "rev-parse", "HEAD"), head_before)
        # Fresh literal approve succeeds.
        W.perform_accept(tid, "approve", self.fix.runtime)
        self.assertNotEqual(_git(self.fix.repo, "rev-parse", "HEAD"), head_before)

    def test_m2_accept_revalidates_before_integration(self) -> None:
        self.fix.init()
        outcome = W.create_task("Revalidate before integrate", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        # Dirty the canonical worktree before accept: must fail closed.
        (self.fix.repo / "untracked-dirty.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(W.WorkflowError) as ctx:
            W.perform_accept(tid, "approve", self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 20)
        # No integration happened.
        self.assertNotEqual(_git(self.fix.repo, "rev-parse", "HEAD"), outcome["result"]["candidate_head"])
        # Cleanup and accept succeeds.
        (self.fix.repo / "untracked-dirty.txt").unlink()
        W.perform_accept(tid, "approve", self.fix.runtime)
        self.assertEqual(_git(self.fix.repo, "rev-parse", "HEAD"), outcome["result"]["candidate_head"])

    def test_m2_accept_rejects_stale_candidate_or_branch(self) -> None:
        self.fix.init()
        outcome = W.create_task("Stale candidate", None, preview_only=False, approval_text="approve", runtime_root=self.fix.runtime)
        tid = outcome["task_id"]
        candidate = outcome["result"]["candidate_head"]
        # Mutate target authority: advance canonical branch.
        (self.fix.repo / "src/app.txt").write_text("external change\n", encoding="utf-8")
        _git(self.fix.repo, "add", "src/app.txt")
        _git(self.fix.repo, "commit", "-m", "external")
        new_head = _git(self.fix.repo, "rev-parse", "HEAD")
        self.assertNotEqual(new_head, candidate)
        with self.assertRaises(W.WorkflowError) as ctx:
            W.perform_accept(tid, "approve", self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 20)
        # Evidence preserved, no unauthorized integration to candidate.
        self.assertEqual(_git(self.fix.repo, "rev-parse", "HEAD"), new_head)
        self.assertTrue((self.fix.runtime / outcome["run_id"] / "report.json").is_file())

    def test_m2_legacy_and_m1_regression_surface_unchanged(self) -> None:
        # Historical CLI commands remain.
        from prj226_runner.cli import _parser

        parser = _parser()
        # Collect subparser names via actions.
        sub_actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
        self.assertTrue(sub_actions)
        names = set(sub_actions[0].choices.keys())
        for legacy in ("inspect", "run", "inspect-project", "discover-work", "draft-contract", "derive-task-packet", "ingest-result", "prepare-gate-b", "inspect-v2", "run-v2", "draft-contract-v2", "derive-task-packet-v2", "ingest-result-v2", "prepare-gate-b-v2"):
            self.assertIn(legacy, names, legacy)
        for primary in ("init", "task", "status", "resume", "accept"):
            self.assertIn(primary, names, primary)
        # No forbidden approval bypass flags.
        help_text = parser.format_help()
        self.assertNotIn("--yes", help_text)
        self.assertNotIn("--force", help_text)
        self.assertNotIn("--auto-approve", help_text)
        # Real M1 NONE lifecycle still works via frozen producers.
        import tempfile as _tf

        with _tf.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "product"
            subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
            _git(repo, "config", "user.email", "m1@example.test")
            _git(repo, "config", "user.name", "M1")
            (repo / "src").mkdir(parents=True)
            (repo / "src/app.txt").write_text("base\n", encoding="utf-8")
            (repo / "docs").mkdir(parents=True)
            (repo / "docs/tasks").mkdir(parents=True)
            (repo / "docs/CURRENT.md").write_text("**Next executable work:** ENG-001 — Acceptance\n", encoding="utf-8")
            (repo / "docs/PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| ENG-001 | acceptance | PROPOSED |\n", encoding="utf-8")
            (repo / "docs/tasks/ENG-001.md").write_text("# ENG-001 — Acceptance\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            (repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
            (repo / "docs/README.md").write_text("docs\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "base")
            branch = _git(repo, "branch", "--show-current")
            builder_count = root / "b.txt"
            reviewer_count = root / "r.txt"
            fb = root / "fb.py"
            fb.write_text(FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(builder_count))), encoding="utf-8")
            fb.chmod(fb.stat().st_mode | stat.S_IXUSR)
            fr = root / "fr.py"
            fr.write_text(FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(reviewer_count))), encoding="utf-8")
            fr.chmod(fr.stat().st_mode | stat.S_IXUSR)
            runtime = root / "runtime"
            config = root / "runner.toml"
            config.write_text(f"[runner]\nruntime_root = {json.dumps(str(runtime))}\n\n[agents.builder]\ntool='codex'\nexecutable={json.dumps(str(fb))}\nmodel='x'\ntimeout_seconds=20\n\n[agents.dv]\ntool='opencode2'\nexecutable={json.dumps(str(fb))}\nmodel='y'\ntimeout_seconds=20\n\n[agents.sos_reviewer]\ntool='opencode2'\nexecutable={json.dumps(str(fr))}\nmodel='z'\ntimeout_seconds=20\n", encoding="utf-8")
            manifest_dict = {"project_id": "M1-001", "repository_path": str(repo), "canonical_branch": branch, "canonical_docs": {"current": "docs/CURRENT.md", "engineering_plan": "docs/PLAN.md", "governance": ["AGENTS.md"], "project": ["README.md", "docs/README.md"]}, "discovery_rules": {"current_next_work_marker": "**Next executable work:**", "plan_task_column": "Task", "plan_state_column": "State", "eligible_plan_states": ["PROPOSED"], "task_id_pattern": "ENG-[0-9]{3}", "task_file_glob": "docs/tasks/{task_id}.md"}}
            manifest = C.ProjectManifest.from_mapping(manifest_dict)
            inspection = C.inspect_project(manifest)
            work_item = C.discover_next_work(manifest, inspection)
            contract = C.draft_design_contract_v2(manifest, work_item, inspection, run_id="M1-REG-001", owned_paths=["src/app.txt"], runtime_root=str(runtime), change_categories=[], human_requested_targeted=False, acceptance_instruments=[[sys.executable, "-c", "import sys; sys.exit(0)"]])
            gate_a = {"gate": "HUMAN_GATE_A", "decision": "APPROVED", "contract_id": contract["contract_id"], "contract_hash": contract["contract_hash"], "baseline_head": contract["baseline_head"], "baseline_tree": contract["baseline_tree"], "authorized_protected_dirty_paths": []}
            packet_path = root / "packet.json"
            C.derive_task_packet_v2(contract, gate_a, output_path=packet_path)
            contract_path = root / "contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            gate_path = root / "gate.json"
            gate_path.write_text(json.dumps(gate_a), encoding="utf-8")
            result = R.run_packet_v2(packet_path, contract_path, gate_path, config, authorize=True)
            self.assertEqual(result["result"], "ACCEPTANCE_READY")


import argparse  # noqa: E402  (used in legacy surface test)


if __name__ == "__main__":
    unittest.main()
