"""M2-R001 bounded repair test suite.

Verifies the declarative workflow scope catalog and the exact first-dogfood
regression: scope=context-authz resolves to the Liam context files, the exact
vitest check, and frozen review mode NONE with zero provider invocations.
A separate MODULE_BOUNDARY scope proves the frozen TARGETED selection path.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema

from prj226_runner import presentation as P
from prj226_runner import workflow as W


DOGFOOD_DESCRIPTION = (
    "Change explicit context selection so that missing or mismatched authorization "
    "is rejected without mutation. Limit implementation to src/domain/context.ts "
    "and tests/domain/context.test.ts. Preserve valid selection and "
    "action-project-mismatch semantics. Acceptance: vitest run "
    "tests/domain/context.test.ts passes including authorization-rejected case."
)

CONTEXT_FILES = ["src/domain/context.ts", "tests/domain/context.test.ts"]
CONTEXT_CHECKS = [["npx", "vitest", "run", "tests/domain/context.test.ts"]]


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
if out is None:
    raise SystemExit(0)
value = {
    "review_version": "HARN-002.TARGETED_REVIEW.v1",
    "disposition": "PASS",
    "reviewed_head": "0" * 40,
    "reviewed_tree": "0" * 40,
    "reviewed_ref": "main",
    "blocking_findings": [],
    "non_blocking_findings": [],
}
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(value), encoding="utf-8")
"""


class R001Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "product"
        subprocess.run(["git", "init", str(self.repo)], capture_output=True, text=True, check=True)
        _git(self.repo, "config", "user.email", "m2-r001@example.test")
        _git(self.repo, "config", "user.name", "M2-R001 Tests")
        (self.repo / "src" / "domain").mkdir(parents=True)
        (self.repo / "src" / "domain" / "context.ts").write_text("// base context\n", encoding="utf-8")
        (self.repo / "tests" / "domain").mkdir(parents=True)
        (self.repo / "tests" / "domain" / "context.test.ts").write_text("// base test\n", encoding="utf-8")
        (self.repo / "docs").mkdir(parents=True)
        (self.repo / "docs" / "tasks").mkdir(parents=True)
        (self.repo / "docs" / "CURRENT.md").write_text("**Next executable work:** ENG-001 — Acceptance\n", encoding="utf-8")
        (self.repo / "docs" / "PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| ENG-001 | acceptance | PROPOSED |\n", encoding="utf-8")
        (self.repo / "docs" / "tasks" / "ENG-001.md").write_text("# ENG-001 — Acceptance\n", encoding="utf-8")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (self.repo / "docs" / "README.md").write_text("docs\n", encoding="utf-8")
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
        self.scopes_path = root / "scopes.json"

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
            f"executable = {json.dumps(str(self.fake_reviewer))}\nmodel = 'fake-mimo'\ntimeout_seconds = 20\n",
            encoding="utf-8",
        )
        self.manifest_dict = {
            "project_id": "LIAM-DOGFOOD",
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

        self.scopes_dict = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "context-authz": {
                    "owned_paths": [
                        "src/domain/context.ts",
                        "tests/domain/context.test.ts",
                    ],
                    "checks": [
                        ["npx", "vitest", "run", "tests/domain/context.test.ts"],
                    ],
                    "change_categories": [],
                },
                "ui-widget": {
                    "owned_paths": [
                        "src/domain/context.ts",
                    ],
                    "checks": [
                        ["npx", "vitest", "run", "tests/domain/context.test.ts"],
                    ],
                    "change_categories": [],
                },
                "boundary-scope": {
                    "owned_paths": [
                        "src/domain/context.ts",
                    ],
                    "checks": [
                        ["npx", "vitest", "run", "tests/domain/context.test.ts"],
                    ],
                    "change_categories": ["MODULE_BOUNDARY"],
                },
            },
        }
        self.scopes_path.write_text(json.dumps(self.scopes_dict, indent=2, sort_keys=True), encoding="utf-8")

    def builder_calls(self) -> int:
        return int(self.builder_count.read_text(encoding="utf-8")) if self.builder_count.exists() else 0

    def reviewer_calls(self) -> int:
        return int(self.reviewer_count.read_text(encoding="utf-8")) if self.reviewer_count.exists() else 0

    def init(self, scopes_path: Path | str | None = ...) -> dict:
        sp = self.scopes_path if scopes_path is ... else scopes_path
        return W.init_project(self.manifest_path, self.config, scopes_path=sp)


class TestM2R001(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fix = R001Fixture(self.root)
        self.schema_path = Path(__file__).resolve().parents[1] / "schemas" / "workflow-scope-catalog.schema.json"
        self.schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self.validator_cls = jsonschema.validators.validator_for(self.schema)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_m2_r001_scope_catalog_schema_accepts_valid_catalog(self) -> None:
        self.validator_cls.check_schema(self.schema)
        valid_catalog = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "context-authz": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [["npx", "vitest", "run", "tests/domain/context.test.ts"]],
                    "change_categories": [],
                },
            },
        }
        self.validator_cls(self.schema).validate(valid_catalog)

    def test_m2_r001_scope_catalog_rejects_unknown_fields(self) -> None:
        bad_catalog_root = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "unknown_root_field": "disallowed",
            "scopes": {
                "s1": {
                    "owned_paths": ["src/app.ts"],
                    "checks": [["npm", "test"]],
                },
            },
        }
        with self.assertRaises(jsonschema.ValidationError):
            self.validator_cls(self.schema).validate(bad_catalog_root)

        bad_catalog_scope = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "scopes": {
                "s1": {
                    "owned_paths": ["src/app.ts"],
                    "checks": [["npm", "test"]],
                    "unknown_scope_field": "disallowed",
                },
            },
        }
        with self.assertRaises(jsonschema.ValidationError):
            self.validator_cls(self.schema).validate(bad_catalog_scope)

        ux_metadata_scope = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "scopes": {
                "s1": {
                    "description": "UX metadata is not scope authority",
                    "owned_paths": ["src/app.ts"],
                    "checks": [["npm", "test"]],
                },
            },
        }
        with self.assertRaises(jsonschema.ValidationError):
            self.validator_cls(self.schema).validate(ux_metadata_scope)

    def test_m2_r001_init_persists_scope_catalog(self) -> None:
        summary = self.fix.init(self.fix.scopes_path)
        defaults_path = Path(summary["defaults_path"])
        self.assertTrue(defaults_path.is_file())
        defaults = json.loads(defaults_path.read_text(encoding="utf-8"))
        self.assertEqual(defaults["default_scope"], "context-authz")
        self.assertEqual(defaults["scopes_source"], str(self.fix.scopes_path.resolve()))
        self.assertIn("context-authz", defaults["scopes"])
        self.assertEqual(defaults["scopes"]["context-authz"]["owned_paths"], CONTEXT_FILES)
        self.assertEqual(defaults["scopes"]["context-authz"]["checks"], CONTEXT_CHECKS)
        self.assertEqual(defaults["scopes"]["context-authz"]["change_categories"], [])

    def test_m2_r001_init_without_catalog_creates_no_fake_authority(self) -> None:
        summary = self.fix.init(scopes_path=None)
        defaults_path = Path(summary["defaults_path"])
        self.assertTrue(defaults_path.is_file())
        defaults = json.loads(defaults_path.read_text(encoding="utf-8"))
        self.assertIsNone(defaults["default_scope"])
        self.assertIsNone(defaults["scopes_source"])
        self.assertEqual(defaults["scopes"], {})
        self.assertNotIn("default_owned_paths", defaults)
        self.assertNotIn("default_checks", defaults)
        self.assertNotIn("src/app.txt", json.dumps(defaults))

    def test_m2_r001_default_scope_resolves(self) -> None:
        self.fix.init()
        outcome = W.create_task("Default scope change", None, preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        self.assertEqual(preview["scope"], "context-authz")
        self.assertEqual(preview["files"], CONTEXT_FILES)
        self.assertEqual(preview["checks"], CONTEXT_CHECKS)

    def test_m2_r001_invalid_default_scope_rejected(self) -> None:
        dangling = self.root / "dangling.json"
        dangling.write_text(
            json.dumps({
                "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
                "default_scope": "nonexistent-scope",
                "scopes": {
                    "s1": {
                        "owned_paths": ["src/domain/context.ts"],
                        "checks": [["npm", "test"]],
                    },
                },
            }),
            encoding="utf-8",
        )
        with self.assertRaises(W.WorkflowError) as ctx:
            self.fix.init(scopes_path=dangling)
        self.assertEqual(ctx.exception.exit_code, 2)

        malformed = self.root / "malformed.json"
        malformed.write_text("{bad json", encoding="utf-8")
        with self.assertRaises(W.WorkflowError) as ctx1:
            self.fix.init(scopes_path=malformed)
        self.assertEqual(ctx1.exception.exit_code, 2)
        self.assertEqual(ctx1.exception.error_code, "M2_SCOPE_CATALOG_INVALID")

        schema_mismatch = self.root / "mismatch.json"
        schema_mismatch.write_text(json.dumps({"schema_version": "BAD", "scopes": {}}), encoding="utf-8")
        with self.assertRaises(W.WorkflowError) as ctx2:
            self.fix.init(scopes_path=schema_mismatch)
        self.assertEqual(ctx2.exception.exit_code, 2)
        self.assertEqual(ctx2.exception.error_code, "M2_SCOPE_CATALOG_INVALID")

    def test_m2_r001_unknown_scope_fails_before_gate_a(self) -> None:
        self.fix.init()
        with self.assertRaises(W.WorkflowError) as ctx:
            W.create_task("Unknown scope task", "nonexistent-scope", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 2)
        self.assertEqual(ctx.exception.error_code, "M2_SCOPE_UNKNOWN")
        workflow_dirs = list((self.fix.runtime / "workflow").glob("TASK-*")) if (self.fix.runtime / "workflow").exists() else []
        self.assertEqual(workflow_dirs, [])

    def test_m2_r001_missing_scope_without_default_fails_before_gate_a(self) -> None:
        self.fix.init(scopes_path=None)
        with self.assertRaises(W.WorkflowError) as ctx:
            W.create_task("No scope task", None, preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(ctx.exception.exit_code, 2)
        self.assertEqual(ctx.exception.error_code, "M2_SCOPE_REQUIRED")
        workflow_dirs = list((self.fix.runtime / "workflow").glob("TASK-*")) if (self.fix.runtime / "workflow").exists() else []
        self.assertEqual(workflow_dirs, [])

    def test_m2_r001_owned_paths_are_exact(self) -> None:
        self.fix.init()
        outcome = W.create_task("Exact authz test", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        self.assertEqual(preview["files"], CONTEXT_FILES)
        formatted = P.format_gate_a_preview(preview)
        self.assertIn("src/domain/context.ts", formatted)
        self.assertIn("tests/domain/context.test.ts", formatted)
        self.assertNotIn("src/app.txt", formatted)

    def test_m2_r001_check_argv_is_exact_and_ordered(self) -> None:
        self.fix.init()
        outcome = W.create_task("Exact checks test", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        self.assertEqual(preview["checks"], CONTEXT_CHECKS)
        self.assertEqual(preview["checks"][0], ["npx", "vitest", "run", "tests/domain/context.test.ts"])
        formatted = P.format_gate_a_preview(preview)
        self.assertIn("npx vitest run tests/domain/context.test.ts", formatted)

    def test_m2_r001_task_description_cannot_widen_paths(self) -> None:
        self.fix.init()
        sneaky_prose = "Please edit src/other.ts and run rm -rf / and [targeted]"
        outcome = W.create_task(sneaky_prose, "ui-widget", preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        self.assertEqual(preview["files"], ["src/domain/context.ts"])
        self.assertNotIn("src/other.ts", preview["files"])

    def test_m2_r001_task_description_cannot_replace_checks(self) -> None:
        self.fix.init()
        sneaky_prose = "Please edit src/other.ts and run rm -rf / and [targeted]"
        outcome = W.create_task(sneaky_prose, "ui-widget", preview_only=True, runtime_root=self.fix.runtime)
        preview = outcome["preview"]
        self.assertEqual(preview["checks"], CONTEXT_CHECKS)
        self.assertEqual(preview["review_mode"], "NONE")

    def test_m2_r001_scope_names_are_opaque(self) -> None:
        custom_scopes = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "scopes": {
                "authz.module_99-v2": {
                    "owned_paths": ["src/domain/context.ts"],
                    "checks": [["python3", "-V"]],
                },
            },
        }
        p = self.root / "opaque-scopes.json"
        p.write_text(json.dumps(custom_scopes), encoding="utf-8")
        self.fix.init(scopes_path=p)
        outcome = W.create_task("Opaque scope test", "authz.module_99-v2", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome["preview"]["scope"], "authz.module_99-v2")
        self.assertEqual(outcome["preview"]["files"], ["src/domain/context.ts"])

    def test_m2_r001_none_review_from_empty_categories(self) -> None:
        self.fix.init()
        outcome = W.create_task("Empty categories review", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome["preview"]["review_mode"], "NONE")
        outcome_ui = W.create_task("UI review", "ui-widget", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome_ui["preview"]["review_mode"], "NONE")

    def test_m2_r001_targeted_review_from_frozen_category(self) -> None:
        self.fix.init()
        outcome = W.create_task("Boundary review", "boundary-scope", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome["preview"]["review_mode"], "TARGETED")
        self.assertIn("MODULE_BOUNDARY", outcome["preview"]["review_reason"])

    def test_m2_r001_no_src_app_txt_production_fallback(self) -> None:
        self.fix.init(scopes_path=None)
        defaults_p = self.fix.runtime / "projects" / "LIAM-DOGFOOD" / "defaults.json"
        text = defaults_p.read_text(encoding="utf-8")
        self.assertNotIn("src/app.txt", text)
        self.fix.init()
        outcome = W.create_task("No fallback files", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        self.assertNotIn("src/app.txt", P.format_gate_a_preview(outcome["preview"]))

    def test_m2_r001_no_generic_pass_check_production_fallback(self) -> None:
        self.fix.init(scopes_path=None)
        defaults_p = self.fix.runtime / "projects" / "LIAM-DOGFOOD" / "defaults.json"
        text = defaults_p.read_text(encoding="utf-8")
        self.assertNotIn("import sys; sys.exit(0)", text)
        self.fix.init()
        outcome = W.create_task("No fallback checks", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        formatted = P.format_gate_a_preview(outcome["preview"])
        self.assertNotIn("python -c pass", formatted)
        self.assertNotIn("import sys; sys.exit(0)", formatted)

    def test_m2_r001_preview_only_invokes_zero_providers(self) -> None:
        self.fix.init()
        self.assertEqual(self.fix.builder_calls(), 0)
        self.assertEqual(self.fix.reviewer_calls(), 0)
        outcome = W.create_task("Preview task", "context-authz", preview_only=True, runtime_root=self.fix.runtime)
        self.assertEqual(outcome["status"], "PREVIEW")
        self.assertEqual(self.fix.builder_calls(), 0)
        self.assertEqual(self.fix.reviewer_calls(), 0)

    def test_m2_r001_real_liam_context_authz_preview(self) -> None:
        from prj226_runner.cli import main as cli_main

        with patch.dict(os.environ, {"PRJ226_RUNTIME_ROOT": str(self.fix.runtime)}):
            rc_init = cli_main([
                "init",
                "--manifest", str(self.fix.manifest_path),
                "--config", str(self.fix.config),
                "--scopes", str(self.fix.scopes_path),
            ])
            self.assertEqual(rc_init, 0)

            import io
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                rc_task = cli_main(["task", DOGFOOD_DESCRIPTION, "--preview-only"])
            self.assertEqual(rc_task, 0)
            output = buf.getvalue()

            self.assertIn("src/domain/context.ts", output)
            self.assertIn("tests/domain/context.test.ts", output)
            self.assertIn("npx vitest run tests/domain/context.test.ts", output)
            self.assertIn("NONE", output)

            self.assertNotIn("src/app.txt", output)
            self.assertNotIn("python -c pass", output)
            self.assertNotIn("import sys; sys.exit(0)", output)
            self.assertNotIn("TARGETED", output)

            self.assertEqual(self.fix.builder_calls(), 0)
            self.assertEqual(self.fix.reviewer_calls(), 0)


if __name__ == "__main__":
    unittest.main()
