"""M2-FINGERPRINT-001: Successor regression test suite.

Proves the candidate-authority integrity invariant and transient artifact policy:
- Defect reproduction fixture: disposable dependencies present at freeze and cleaned
  by deterministic checks do not trigger false fingerprint stops.
- Candidate authority separated from reviewer mutation fingerprint.
- 34 mandatory negative regressions and positive regressions A-F.
- Reviewer mutation protection remains strictly preserved.
"""

from __future__ import annotations

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

from prj226_runner import presentation as P
from prj226_runner import workflow as W
from prj226_runner import runner as R
from prj226_runner import controller as C
from prj226_runner.errors import (
    ArtifactValidationError,
    GovernanceBlockerError,
    ReviewStaleError,
)

# Optional import of new candidate authority module (may not exist pre-fix)
try:
    from prj226_runner import candidate_authority as CA
except ImportError:
    CA = None


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=True,
    )
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

# Optional creation of transient dependency artifact (e.g. node_modules)
if os.environ.get("FAKE_CREATE_NODE_MODULES"):
    nm = pathlib.Path("node_modules")
    nm.mkdir(parents=True, exist_ok=True)
    (nm / "dep.js").write_text("module.exports = {};\\n", encoding="utf-8")
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

# If reviewer tries to mutate candidate filesystem
mutate_trigger = pathlib.Path(@@MUTATE_TRIGGER@@)
if mutate_trigger.exists():
    mut_target = mutate_trigger.read_text(encoding="utf-8").strip()
    mut = pathlib.Path(mut_target)
    mut.parent.mkdir(parents=True, exist_ok=True)
    mut.write_text("reviewer_mutated\\n", encoding="utf-8")

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


class FingerprintFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "product"
        self.runtime = root / "runtime"
        self.config = root / "runner.toml"
        self.manifest_path = root / "manifest.json"
        self.scopes_path = root / "scopes.json"

        self.builder_count = root / "builder-count.txt"
        self.reviewer_count = root / "reviewer-count.txt"
        self.reviewer_mutate_trigger = root / "reviewer-mutate-trigger.txt"
        self.fake_builder = root / "fake-builder.py"
        self.fake_reviewer = root / "fake-reviewer.py"

    def init(self, transient_paths: list[str] | None = None) -> None:
        self.repo.mkdir(parents=True, exist_ok=True)
        self.runtime.mkdir(parents=True, exist_ok=True)

        _git(self.repo, "init")
        _git(self.repo, "config", "user.name", "Fingerprint Tests")
        _git(self.repo, "config", "user.email", "fingerprint@example.test")
        _git(self.repo, "config", "commit.gpgsign", "false")

        (self.repo / ".gitignore").write_text("node_modules/\n.cache/\n", encoding="utf-8")
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

        reviewer_src = (
            FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable)
            .replace("@@COUNTER@@", json.dumps(str(self.reviewer_count)))
            .replace("@@MUTATE_TRIGGER@@", json.dumps(str(self.reviewer_mutate_trigger)))
        )
        self.fake_reviewer.write_text(reviewer_src, encoding="utf-8")
        self.fake_reviewer.chmod(self.fake_reviewer.stat().st_mode | stat.S_IXUSR)

        self.write_config()

        manifest_dict = {
            "project_id": "LIAM-FINGERPRINT",
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

        scope_def: dict[str, Any] = {
            "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
            "checks": [
                [
                    "sh",
                    "-c",
                    "set -eu; cleanup() { rm -rf node_modules; }; trap cleanup EXIT; mkdir -p node_modules; test -f src/domain/context.ts",
                ]
            ],
            "change_categories": ["AUTHORIZATION_DATA_ACCESS"],
        }
        if transient_paths is not None and CA is not None:
            scope_def["transient_paths"] = list(transient_paths)

        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "context-authz": scope_def,
                "no-transient-scope": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                    "change_categories": ["AUTHORIZATION_DATA_ACCESS"],
                },
            },
        }
        self.scopes_path.write_text(json.dumps(scopes_dict, indent=2, sort_keys=True), encoding="utf-8")
        W.init_project(self.manifest_path, self.config, scopes_path=self.scopes_path)

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


class TestM2Fingerprint001(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fix = FingerprintFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    # =========================================================================
    # REAL DEFECT REPRODUCTION FIXTURE (TASK-002 Shape)
    # =========================================================================

    def test_real_defect_reproduction_task002_shape(self) -> None:
        """Demonstrate the TASK-002 failure shape:
        - Builder creates transient dependency artifact (node_modules)
        - Candidate is frozen with node_modules present in worktree
        - Deterministic check cleans up node_modules (rm -rf node_modules)
        - Candidate HEAD/TREE/tracked files remain 100% untouched
        - PRE-FIX EXPECTATION: baseline false stop (GovernanceBlockerError: Candidate worktree filesystem fingerprint changed)
        - POST-FIX EXPECTATION: candidate authority integrity PASS
        """
        self.fix.init(transient_paths=["node_modules"])
        os.environ["FAKE_CREATE_NODE_MODULES"] = "1"
        try:
            prepared = W.create_task("Fix context auth", scope="context-authz", preview_only=True, runtime_root=self.fix.runtime)
            outcome = W.create_task(
                "Fix context auth",
                scope="context-authz",
                preview_only=False,
                approval_text="approve",
                task_id=prepared["task_id"],
                runtime_root=self.fix.runtime,
            )
            # Post-fix expectation: ACCEPTANCE_READY
            self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        except W.WorkflowError as exc:
            # On baseline, this raises WorkflowError(error_code="WORKFLOW_RUN_STOPPED")
            # wrapping GovernanceBlockerError with message 'Candidate worktree filesystem fingerprint changed'
            self.assertEqual(exc.error_code, "WORKFLOW_RUN_STOPPED")
            task_rec = W.load_task_record(self.fix.runtime, prepared["task_id"])
            self.assertEqual(task_rec["error_class"], "GOVERNANCE_BLOCKER")
            self.assertIn("fingerprint changed", task_rec["error"])
            raise AssertionError(f"PRE-FIX DEFECT REPRODUCED: {task_rec['error']}") from exc
        finally:
            os.environ.pop("FAKE_CREATE_NODE_MODULES", None)

    # =========================================================================
    # MANDATORY POSITIVE REGRESSIONS (A - F)
    # =========================================================================

    def test_positive_a_transient_dependency_creation_preserves_authority(self) -> None:
        """A. Approved transient dependency/cache creation does not alter candidate authority."""
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules", ".cache"])
        auth = CA.build_candidate_authority(
            self.fix.repo,
            _git(self.fix.repo, "rev-parse", "HEAD"),
            "refs/heads/main",
            _git(self.fix.repo, "rev-parse", "HEAD"),
            ["src/domain/context.ts"],
            transient_paths=["node_modules", ".cache"],
        )
        nm_file = self.fix.repo / "node_modules" / "test.js"
        nm_file.parent.mkdir(parents=True, exist_ok=True)
        nm_file.write_text("export default {};\\n", encoding="utf-8")
        CA.verify_candidate_authority(self.fix.repo, auth)

    def test_positive_b_transient_dependency_deletion_preserves_authority(self) -> None:
        """B. Approved transient dependency/cache deletion does not alter candidate authority."""
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        nm_file = self.fix.repo / "node_modules" / "test.js"
        nm_file.parent.mkdir(parents=True, exist_ok=True)
        nm_file.write_text("export default {};\\n", encoding="utf-8")
        auth = CA.build_candidate_authority(
            self.fix.repo,
            _git(self.fix.repo, "rev-parse", "HEAD"),
            "refs/heads/main",
            _git(self.fix.repo, "rev-parse", "HEAD"),
            ["src/domain/context.ts"],
            transient_paths=["node_modules"],
        )
        shutil.rmtree(self.fix.repo / "node_modules", ignore_errors=True)
        CA.verify_candidate_authority(self.fix.repo, auth)

    def test_positive_c_transient_at_freeze_and_cleaned_by_check_passes(self) -> None:
        """C. Dependency material present before freeze and cleaned by deterministic check succeeds."""
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        (self.fix.repo / "node_modules").mkdir(parents=True, exist_ok=True)
        (self.fix.repo / "node_modules" / "dep.js").write_text("transient\\n", encoding="utf-8")
        auth = CA.build_candidate_authority(
            self.fix.repo,
            _git(self.fix.repo, "rev-parse", "HEAD"),
            "refs/heads/main",
            _git(self.fix.repo, "rev-parse", "HEAD"),
            ["src/domain/context.ts"],
            transient_paths=["node_modules"],
        )
        shutil.rmtree(self.fix.repo / "node_modules")
        CA.verify_candidate_authority(self.fix.repo, auth)

    def test_positive_d_reconstructed_candidate_produces_equivalent_authority(self) -> None:
        """D. Exact reconstructed candidate Git state produces equivalent candidate authority."""
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        head = _git(self.fix.repo, "rev-parse", "HEAD")
        auth1 = CA.build_candidate_authority(
            self.fix.repo, head, "refs/heads/main", head, ["src/domain/context.ts"], transient_paths=["node_modules"]
        )
        auth2 = CA.build_candidate_authority(
            self.fix.repo, head, "refs/heads/main", head, ["src/domain/context.ts"], transient_paths=["node_modules"]
        )
        self.assertEqual(auth1["authority_digest"], auth2["authority_digest"])

    def test_positive_e_standard_task_no_transient_fails_closed_on_untracked(self) -> None:
        """E. Standard task with NO transient policy continues to fail closed on unknown untracked artifacts."""
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=None)
        auth = CA.build_candidate_authority(
            self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=[]
        )
        (self.fix.repo / "unknown.txt").write_text("surprise\\n", encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_positive_f_normal_targeted_supported_workflow_remains_valid(self) -> None:
        """F. Existing normal TARGETED supported workflows remain valid without transient files."""
        self.fix.init(transient_paths=None)
        prepared = W.create_task("Standard task", scope="no-transient-scope", preview_only=True, runtime_root=self.fix.runtime)
        outcome = W.create_task(
            "Standard task",
            scope="no-transient-scope",
            preview_only=False,
            approval_text="approve",
            task_id=prepared["task_id"],
            runtime_root=self.fix.runtime,
        )
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")

    # =========================================================================
    # MANDATORY NEGATIVE REGRESSIONS (1 - 34)
    # =========================================================================

    def test_negative_01_tracked_file_content_modification_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "src" / "domain" / "context.ts").write_text("mutated\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_02_tracked_file_deletion_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "README.md").unlink()
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_03_tracked_rename_substitution_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "README.md").rename(self.fix.repo / "README.old")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_04_regular_file_symlink_substitution_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "README.md").unlink()
        (self.fix.repo / "README.md").symlink_to(self.fix.repo / "AGENTS.md")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_05_tracked_mode_mutation_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        p = self.fix.repo / "src" / "domain" / "context.ts"
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_06_candidate_head_drift_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        _git(self.fix.repo, "commit", "--allow-empty", "-m", "drift")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_07_candidate_tree_mismatch_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        auth["candidate_tree"] = "0" * 40
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_08_candidate_ref_deletion_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        _git(self.fix.repo, "branch", "candidate-branch")
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/candidate-branch", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        _git(self.fix.repo, "branch", "-D", "candidate-branch")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_09_candidate_ref_repointing_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        _git(self.fix.repo, "branch", "candidate-branch")
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/candidate-branch", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        _git(self.fix.repo, "commit", "--allow-empty", "-m", "new-commit")
        _git(self.fix.repo, "branch", "-f", "candidate-branch", "HEAD")
        _git(self.fix.repo, "reset", "--hard", "HEAD~1")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_10_candidate_ref_substitution_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        auth["candidate_ref"] = "refs/heads/substitute"
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_11_authorized_source_path_mutation_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "src" / "domain" / "context.ts").write_text("tamper\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_12_tracked_file_outside_owned_paths_mutation_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "AGENTS.md").write_text("tamper\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_13_unauthorized_tracked_creation_staging_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "new.ts").write_text("console.log(1);\\n")
        _git(self.fix.repo, "add", "new.ts")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_14_non_exempt_untracked_addition_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        (self.fix.repo / "untracked.ts").write_text("evil\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_15_protected_untracked_mutation_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "src" / "extra.ts").write_text("untracked\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_16_protected_untracked_deletion_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        (self.fix.repo / "tests" / "domain" / "context.test.ts").unlink()
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_17_moving_file_into_ignored_location_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        target = self.fix.repo / "src" / "domain" / "context.ts"
        (self.fix.repo / "node_modules").mkdir(parents=True, exist_ok=True)
        target.rename(self.fix.repo / "node_modules" / "context.ts")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_18_ignored_but_semantically_relevant_tracked_file_protected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        nm_file = self.fix.repo / "node_modules" / "tracked.js"
        nm_file.parent.mkdir(parents=True, exist_ok=True)
        nm_file.write_text("tracked\\n")
        _git(self.fix.repo, "add", "-f", "node_modules/tracked.js")
        _git(self.fix.repo, "commit", "-m", "tracked-in-nm")
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD~1"), ["src/domain/context.ts", "node_modules/tracked.js"], transient_paths=["node_modules"])
        nm_file.write_text("mutated\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_19_changed_ignore_rules_cannot_create_exemption(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        (self.fix.repo / ".gitignore").write_text("node_modules/\\nsecret_dir/\\n")
        (self.fix.repo / "secret_dir").mkdir()
        (self.fix.repo / "secret_dir" / "secret.txt").write_text("secret\\n")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_20_transient_policy_substitution_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        auth["transient_paths"] = ["wildcard_allow_all"]
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_21_transient_policy_widening_after_gate_a_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        auth["transient_paths"].append(".cache")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_22_missing_policy_evidence_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, {})

    def test_negative_23_malformed_policy_evidence_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, {"schema_version": "INVALID", "candidate_head": "abc"})

    def test_negative_24_missing_candidate_authority_manifest_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        del auth["tracked_manifest"]
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_25_tampered_manifest_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        auth["tracked_manifest"][0]["sha256"] = "f" * 64
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_26_manifest_candidate_mismatch_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        auth["candidate_head"] = "e" * 40
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_27_unsupported_filesystem_nodes_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init()
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"])
        fifo_path = self.fix.repo / "test.fifo"
        try:
            os.mkfifo(fifo_path)
            with self.assertRaises(GovernanceBlockerError):
                CA.verify_candidate_authority(self.fix.repo, auth)
        finally:
            if fifo_path.exists():
                fifo_path.unlink()

    def test_negative_28_symlink_escape_bypass_rejected(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        auth = CA.build_candidate_authority(self.fix.repo, _git(self.fix.repo, "rev-parse", "HEAD"), "refs/heads/main", _git(self.fix.repo, "rev-parse", "HEAD"), ["src/domain/context.ts"], transient_paths=["node_modules"])
        (self.fix.repo / "node_modules").mkdir(parents=True, exist_ok=True)
        (self.fix.repo / "node_modules" / "escape_link").symlink_to("/etc")
        with self.assertRaises(GovernanceBlockerError):
            CA.verify_candidate_authority(self.fix.repo, auth)

    def test_negative_29_deterministic_exit_0_plus_mutation_stops_before_review(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        scope_entry = {
            "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
            "checks": [["sh", "-c", "echo 'sneaky' >> src/domain/context.ts; exit 0"]],
            "change_categories": ["AUTHORIZATION_DATA_ACCESS"],
            "transient_paths": ["node_modules"],
        }
        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "tamper-scope",
            "scopes": {"tamper-scope": scope_entry},
        }
        self.fix.scopes_path.write_text(json.dumps(scopes_dict, indent=2), encoding="utf-8")
        W.init_project(self.fix.manifest_path, self.fix.config, scopes_path=self.fix.scopes_path)

        prepared = W.create_task("Tamper test", scope="tamper-scope", preview_only=True, runtime_root=self.fix.runtime)
        with self.assertRaises(W.WorkflowError):
            W.create_task("Tamper test", scope="tamper-scope", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)

        reviewer_invocations = int(self.fix.reviewer_count.read_text()) if self.fix.reviewer_count.exists() else 0
        self.assertEqual(reviewer_invocations, 0)

    def test_negative_30_none_review_mode_reviewer_count_zero(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        scope_entry = {
            "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
            "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
            "change_categories": [],
            "transient_paths": ["node_modules"],
        }
        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "none-review-scope",
            "scopes": {"none-review-scope": scope_entry},
        }
        self.fix.scopes_path.write_text(json.dumps(scopes_dict, indent=2), encoding="utf-8")
        W.init_project(self.fix.manifest_path, self.fix.config, scopes_path=self.fix.scopes_path)

        prepared = W.create_task("None review task", scope="none-review-scope", preview_only=True, runtime_root=self.fix.runtime)
        outcome = W.create_task("None review task", scope="none-review-scope", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        reviewer_invocations = int(self.fix.reviewer_count.read_text()) if self.fix.reviewer_count.exists() else 0
        self.assertEqual(reviewer_invocations, 0)

    def test_negative_31_targeted_review_only_after_deterministic_and_integrity_pass(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        scope_entry = {
            "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
            "checks": [[sys.executable, "-c", "import sys; sys.exit(1)"]],
            "change_categories": ["AUTHORIZATION_DATA_ACCESS"],
            "transient_paths": ["node_modules"],
        }
        scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "failing-check-scope",
            "scopes": {"failing-check-scope": scope_entry},
        }
        self.fix.scopes_path.write_text(json.dumps(scopes_dict, indent=2), encoding="utf-8")
        W.init_project(self.fix.manifest_path, self.fix.config, scopes_path=self.fix.scopes_path)

        prepared = W.create_task("Failing test", scope="failing-check-scope", preview_only=True, runtime_root=self.fix.runtime)
        with self.assertRaises(W.WorkflowError):
            W.create_task("Failing test", scope="failing-check-scope", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
        reviewer_invocations = int(self.fix.reviewer_count.read_text()) if self.fix.reviewer_count.exists() else 0
        self.assertEqual(reviewer_invocations, 0)

    def test_negative_32_failure_no_retry(self) -> None:
        self.fix.init(transient_paths=["node_modules"])
        os.environ["FAKE_BUILDER_FAIL"] = "1"
        try:
            prepared = W.create_task("Fail task", scope="context-authz", preview_only=True, runtime_root=self.fix.runtime)
            with self.assertRaises(W.WorkflowError):
                W.create_task("Fail task", scope="context-authz", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
            builder_invocations = int(self.fix.builder_count.read_text()) if self.fix.builder_count.exists() else 0
            self.assertEqual(builder_invocations, 1)
        finally:
            os.environ.pop("FAKE_BUILDER_FAIL", None)

    def test_negative_33_failure_no_fallback(self) -> None:
        self.fix.init(transient_paths=["node_modules"])
        os.environ["FAKE_BUILDER_FAIL"] = "1"
        try:
            prepared = W.create_task("Fail task", scope="context-authz", preview_only=True, runtime_root=self.fix.runtime)
            with self.assertRaises(W.WorkflowError):
                W.create_task("Fail task", scope="context-authz", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
        finally:
            os.environ.pop("FAKE_BUILDER_FAIL", None)

    def test_negative_34_gate_b_rejects_stale_or_tampered_authority(self) -> None:
        if CA is None:
            self.skipTest("DIRECT_NEGATIVE_REGRESSION_JUSTIFICATION: candidate_authority module not available on baseline")
        self.fix.init(transient_paths=["node_modules"])
        prepared = W.create_task("Gate B task", scope="context-authz", preview_only=True, runtime_root=self.fix.runtime)
        outcome = W.create_task("Gate B task", scope="context-authz", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "ACCEPTANCE_READY")
        task_id = outcome["task_id"]
        task_rec = W.load_task_record(self.fix.runtime, task_id)
        run_root = self.fix.runtime / task_rec["run_id"]
        worktree = run_root / "builder" / "worktree"
        (worktree / "src" / "domain" / "context.ts").write_text("tamper_before_gate_b\n")
        with self.assertRaises((W.WorkflowError, GovernanceBlockerError)):
            W.perform_accept(task_id, "accept", runtime_root=self.fix.runtime)

    # =========================================================================
    # REVIEWER MUTATION REGRESSION
    # =========================================================================

    def test_reviewer_mutation_detected_and_rejected(self) -> None:
        self.fix.init(transient_paths=["node_modules"])
        self.fix.reviewer_mutate_trigger.write_text("src/domain/context.ts\n", encoding="utf-8")
        try:
            prepared = W.create_task("Reviewer mutate task", scope="context-authz", preview_only=True, runtime_root=self.fix.runtime)
            with self.assertRaises(W.WorkflowError):
                W.create_task("Reviewer mutate task", scope="context-authz", preview_only=False, approval_text="approve", task_id=prepared["task_id"], runtime_root=self.fix.runtime)
            task_rec = W.load_task_record(self.fix.runtime, prepared["task_id"])
            self.assertEqual(task_rec["error_class"], "GOVERNANCE_BLOCKER")
            self.assertIn("REVIEW_STALE", task_rec["error"])
        finally:
            if self.fix.reviewer_mutate_trigger.exists():
                self.fix.reviewer_mutate_trigger.unlink()


if __name__ == "__main__":
    unittest.main()
