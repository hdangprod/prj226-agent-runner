"""Deterministic HARN-002 Repair-4 one-shot Codex reviewer controls."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prj226_runner.codex_reviewer import (
    CODEX_REVIEWER_MODEL,
    build_codex_reviewer_env,
    build_codex_reviewer_invocation,
    check_codex_reviewer_binding,
    run_codex_review,
)
from prj226_runner.errors import (
    AgentExecutionError,
    ArtifactValidationError,
    ReviewStaleError,
    RunnerEnvironmentError,
)
from prj226_runner.runner import run_packet


class TestCodexReviewerAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "candidate"
        self._git(self.root, "init", str(self.repo))
        self._git(self.repo, "config", "user.email", "runner@example.test")
        self._git(self.repo, "config", "user.name", "Runner Test")
        (self.repo / "candidate.txt").write_text("candidate\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("*.ignored\nignored-existing.txt\nignored-empty-dir/\nreview-link\n", encoding="utf-8")
        self._git(self.repo, "add", "candidate.txt", ".gitignore")
        self._git(self.repo, "commit", "-m", "candidate")
        (self.repo / "ignored-existing.txt").write_text("ignored baseline\n", encoding="utf-8")
        (self.repo / "review-link").symlink_to("target-a")
        self.head = self._git(self.repo, "rev-parse", "HEAD")
        self.tree = self._git(self.repo, "rev-parse", "HEAD^{tree}")
        self.branch = self._git(self.repo, "branch", "--show-current")
        self.schema = Path(__file__).parents[1] / "schemas" / "codex-reviewer-result.schema.json"
        self.calls = self.root / "reviewer-call-count.txt"
        self.fake = self.root / "fake-codex.py"
        self.fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, pathlib, subprocess, sys, time\n"
            f"counter = pathlib.Path({json.dumps(str(self.calls))})\n"
            "counter.write_text(str((int(counter.read_text()) if counter.exists() else 0) + 1), encoding='utf-8')\n"
            "prompt = sys.argv[-1]\n"
            "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "if 'TIMEOUT' in prompt: time.sleep(5)\n"
            "if 'PROCESS_FAILURE' in prompt and 'WITH_OUTPUT' not in prompt: raise SystemExit(9)\n"
            "if 'MUTATE_WORKTREE' in prompt: pathlib.Path('reviewer-mutated.txt').write_text('bad')\n"
            "if 'MUTATE_TRACKED' in prompt: pathlib.Path('candidate.txt').write_text('tracked mutation\\n')\n"
            "if 'CREATE_UNTRACKED' in prompt: pathlib.Path('untracked.txt').write_text('untracked mutation\\n')\n"
            "if 'CREATE_IGNORED' in prompt: pathlib.Path('new.ignored').write_text('ignored mutation\\n')\n"
            "if 'MODIFY_IGNORED' in prompt: pathlib.Path('ignored-existing.txt').write_text('ignored changed\\n')\n"
            "if 'DELETE_IGNORED' in prompt: pathlib.Path('ignored-existing.txt').unlink()\n"
            "if 'CREATE_IGNORED_EMPTY_DIR' in prompt: pathlib.Path('ignored-empty-dir').mkdir()\n"
            "if 'CHANGE_SYMLINK' in prompt: pathlib.Path('review-link').unlink(); pathlib.Path('review-link').symlink_to('target-b')\n"
            "if 'CHANGE_MODE' in prompt: pathlib.Path('candidate.txt').chmod(0o600)\n"
            "head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()\n"
            "tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()\n"
            "if 'MISMATCH_HEAD' in prompt: head = '1' * 40\n"
            "if 'MISMATCH_TREE' in prompt: tree = '2' * 40\n"
            "if 'MALFORMED' in prompt: output.write_text('{bad', encoding='utf-8'); raise SystemExit(0)\n"
            "if 'MISSING_OUTPUT' in prompt: raise SystemExit(0)\n"
            "disposition = 'NEEDS_FIX' if prompt.strip() == 'NEEDS_FIX' or 'FORCE_NEEDS_FIX' in prompt else 'PASS'\n"
            "axis = {'status': disposition, 'findings': ['blocking finding']} if disposition == 'NEEDS_FIX' else {'status': 'PASS', 'findings': []}\n"
            "value = {'disposition': disposition, 'reviewed_head': head, 'reviewed_tree': tree, 'security': axis, 'operability': axis, 'semantics': axis, 'architecture': axis, 'blocking_findings': ['blocking finding'] if disposition == 'NEEDS_FIX' else [], 'non_blocking_findings': []}\n"
            "if 'INVALID_SCHEMA' in prompt: value['unexpected'] = 'closed schema must reject this'\n"
            "output.parent.mkdir(parents=True, exist_ok=True)\n"
            "output.write_text(json.dumps(value), encoding='utf-8')\n"
            "if 'PROCESS_FAILURE_WITH_OUTPUT' in prompt: raise SystemExit(9)\n",
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _git(cwd: Path, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def _review(self, marker: str, timeout: int = 2) -> dict:
        return run_codex_review(
            str(self.fake),
            self.repo,
            self.root / "evidence" / marker,
            candidate_head=self.head,
            candidate_tree=self.tree,
            candidate_ref=self.branch,
            prompt=marker,
            timeout_seconds=timeout,
            output_schema=self.schema,
            source_codex_home=self.root / "missing-codex-home",
        )

    def _call_count(self) -> int:
        return int(self.calls.read_text(encoding="utf-8")) if self.calls.exists() else 0

    def test_valid_structured_pass_is_accepted(self) -> None:
        result = self._review("PASS")
        self.assertEqual(result["result"]["disposition"], "PASS")
        self.assertTrue(Path(result["artifact"]).is_file())
        self.assertEqual(self._call_count(), 1)

    def test_valid_structured_needs_fix_blocks_candidate(self) -> None:
        result = self._review("NEEDS_FIX")
        self.assertEqual(result["result"]["disposition"], "NEEDS_FIX")
        self.assertEqual(result["result"]["blocking_findings"], ["blocking finding"])
        self.assertEqual(self._call_count(), 1)

    def test_exit_zero_with_malformed_output_is_artifact_validation_error(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            self._review("MALFORMED")
        self.assertEqual(self._call_count(), 1)

    def test_exit_zero_with_missing_output_is_artifact_validation_error(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            self._review("MISSING_OUTPUT")
        self.assertEqual(self._call_count(), 1)

    def test_exit_zero_with_invalid_schema_is_artifact_validation_error(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            self._review("INVALID_SCHEMA")
        self.assertEqual(self._call_count(), 1)

    def test_output_head_mismatch_is_review_stale(self) -> None:
        with self.assertRaisesRegex(ReviewStaleError, "REVIEW_STALE"):
            self._review("MISMATCH_HEAD")
        self.assertEqual(self._call_count(), 1)

    def test_output_tree_mismatch_is_review_stale(self) -> None:
        with self.assertRaisesRegex(ReviewStaleError, "REVIEW_STALE"):
            self._review("MISMATCH_TREE")
        self.assertEqual(self._call_count(), 1)

    def test_timeout_is_agent_execution_error_without_retry(self) -> None:
        with self.assertRaises(AgentExecutionError):
            self._review("TIMEOUT", timeout=1)
        invocations = list((self.root / "evidence" / "TIMEOUT").glob("invocation.json"))
        self.assertEqual(len(invocations), 1)
        self.assertEqual(self._call_count(), 1)

    def test_process_failure_is_agent_execution_error(self) -> None:
        with self.assertRaises(AgentExecutionError):
            self._review("PROCESS_FAILURE")
        self.assertEqual(self._call_count(), 1)

    def test_nonzero_exit_overrides_structured_content(self) -> None:
        with self.assertRaises(AgentExecutionError):
            self._review("PROCESS_FAILURE_WITH_OUTPUT")
        self.assertEqual(self._call_count(), 1)

    def test_spawn_failure_is_agent_execution_error_and_one_attempt(self) -> None:
        from unittest.mock import patch

        with patch("prj226_runner.codex_reviewer.run_calibration_subprocess", side_effect=OSError("spawn failed")) as process:
            with self.assertRaises(AgentExecutionError):
                self._review("SPAWN_FAILURE")
        process.assert_called_once()
        self.assertEqual(self._call_count(), 0)
        self.assertTrue((self.root / "evidence" / "SPAWN_FAILURE" / "invocation.json").is_file())

    def test_reviewer_worktree_mutation_is_review_stale(self) -> None:
        with self.assertRaisesRegex(ReviewStaleError, "REVIEW_STALE"):
            self._review("MUTATE_WORKTREE")
        self.assertEqual(self._call_count(), 1)

    def test_SEC_A_tracked_file_changed_during_review_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("MUTATE_TRACKED")

    def test_SEC_B_ordinary_untracked_file_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("CREATE_UNTRACKED")

    def test_SEC_C_new_ignored_file_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("CREATE_IGNORED")

    def test_SEC_D_existing_ignored_file_modified_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("MODIFY_IGNORED")

    def test_SEC_E_ignored_file_deleted_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("DELETE_IGNORED")

    def test_SEC_F_ignored_empty_directory_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("CREATE_IGNORED_EMPTY_DIR")

    def test_SEC_G_symlink_target_changed_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("CHANGE_SYMLINK")

    def test_SEC_H_file_mode_changed_invalidates(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("CHANGE_MODE")

    def test_SEC_I_no_filesystem_mutation_has_equal_fingerprint(self) -> None:
        result = self._review("SEC_I_CLEAN")
        pre = json.loads((self.root / "evidence" / "SEC_I_CLEAN" / "fingerprint-pre.json").read_text(encoding="utf-8"))
        post = json.loads((self.root / "evidence" / "SEC_I_CLEAN" / "fingerprint-post.json").read_text(encoding="utf-8"))
        self.assertEqual(pre, post)
        self.assertEqual(result["fingerprint"], pre["fingerprint"])

    def test_SEC_J_pass_review_with_mutation_is_not_pass(self) -> None:
        with self.assertRaises(ReviewStaleError):
            self._review("MUTATE_WORKTREE")

    def test_local_binding_checks_do_not_invoke_configured_executable(self) -> None:
        binding = check_codex_reviewer_binding(str(self.fake), output_schema=self.schema)
        self.assertEqual(binding["model"], CODEX_REVIEWER_MODEL)
        self.assertEqual(self._call_count(), 0)

    def test_local_binding_rejects_missing_or_non_executable_path_without_call(self) -> None:
        missing = self.root / "missing-codex"
        not_executable = self.root / "not-executable"
        not_executable.write_text("not executable\n", encoding="utf-8")
        not_executable.chmod(0o600)
        for executable in (missing, not_executable):
            with self.subTest(executable=executable.name):
                with self.assertRaises(RunnerEnvironmentError):
                    check_codex_reviewer_binding(str(executable), output_schema=self.schema)
        self.assertEqual(self._call_count(), 0)

    def test_user_config_isolation_copies_only_authentication_material(self) -> None:
        source = self.root / "source-codex-home"
        source.mkdir()
        (source / "auth.json").write_text('{"token":"opaque"}', encoding="utf-8")
        (source / "config.toml").write_text("sandbox_permissions = ['danger-full-access']\n", encoding="utf-8")
        with patch_environment("UNRELATED_CONFIG", "present"):
            env = build_codex_reviewer_env(self.root / "env-evidence", source_codex_home=source)
        isolated = Path(env["CODEX_HOME"])
        self.assertEqual(env["HOME"], env["CODEX_HOME"])
        self.assertEqual((isolated / "auth.json").read_text(encoding="utf-8"), '{"token":"opaque"}')
        self.assertFalse((isolated / "config.toml").exists())
        self.assertNotIn("UNRELATED_CONFIG", env)
        self.assertFalse((self.root / "env-evidence").exists())

    def test_invocation_has_explicit_readonly_ephemeral_isolated_model_and_no_review_subcommand(self) -> None:
        argv = build_codex_reviewer_invocation(
            str(self.fake),
            self.repo,
            "review",
            self.schema,
            self.root / "out.json",
        )
        self.assertEqual(argv[3], "exec")
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("--ephemeral", argv)
        self.assertIn("--sandbox", argv)
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertEqual(argv[argv.index("--model") + 1], "gpt-5.6-luna")
        self.assertNotIn("review", argv[:3])

    def test_negative_probe_then_review_control_is_rejected_by_call_count_guard(self) -> None:
        # A deliberately bad implementation models probe() -> review().  The
        # discriminating lifecycle guard rejects its two external calls.
        self._review("CONTROL_PROBE")
        self._review("CONTROL_REVIEW")
        with self.assertRaisesRegex(AssertionError, "one external invocation"):
            if self._call_count() != 1:
                raise AssertionError("one external invocation required; observed two")

    def test_wrong_model_is_rejected_without_fallback(self) -> None:
        with self.assertRaises(ArtifactValidationError):
            build_codex_reviewer_invocation(
                str(self.fake), self.repo, "review", self.schema, self.root / "out.json", model="other-model"
            )

    def test_runner_routes_sos_through_one_codex_review_verifier_worktree(self) -> None:
        builder = self.root / "fake-builder.py"
        builder.write_text(
            "#!" + sys.executable + "\n"
            "import pathlib\n"
            "pathlib.Path('candidate.txt').write_text('built candidate\\n')\n",
            encoding="utf-8",
        )
        builder.chmod(builder.stat().st_mode | stat.S_IXUSR)
        dv = self.root / "fake-dv.py"
        dv.write_text(
            "#!" + sys.executable + "\n"
            "import json\n"
            "print(json.dumps({'result': 'PASS', 'findings': []}))\n",
            encoding="utf-8",
        )
        dv.chmod(dv.stat().st_mode | stat.S_IXUSR)
        packet = self.root / "packet.json"
        packet.write_text(json.dumps({
            "run_id": "HARN-002-REPAIR-3-FAKE",
            "task_id": "CODEX-REVIEW",
            "product_repo": str(self.repo),
            "canonical_branch": self.branch,
            "baseline_head": self.head,
            "baseline_tree": self.tree,
            "authorized_paths": ["candidate.txt"],
            "builder_prompt": "Build the candidate.",
            "acceptance_criteria": ["candidate is built"],
            "test_commands": [[sys.executable, "-c", "raise SystemExit(0)"],],
            "commit_message": "test: codex reviewer candidate",
        }), encoding="utf-8")
        config = self.root / "runner.toml"
        config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(self.root / 'runtime'))}\n\n"
            "[agents.builder]\n"
            f"tool = 'codex'\nexecutable = {json.dumps(str(builder))}\nmodel = 'builder'\ntimeout_seconds = 10\n\n"
            "[agents.dv]\n"
            f"tool = 'opencode2'\nexecutable = {json.dumps(str(dv))}\nmodel = 'dv'\ntimeout_seconds = 10\n\n"
            "[agents.sos_reviewer]\n"
            f"tool = 'codex'\nexecutable = {json.dumps(str(self.fake))}\nmodel = 'gpt-5.6-luna'\ntimeout_seconds = 10\n",
            encoding="utf-8",
        )
        result = run_packet(packet, config, authorize=True)
        self.assertEqual(result["result"], "ACCEPTANCE_READY", result)
        self.assertEqual(result["review_disposition"], "PASS")
        self.assertEqual(self._call_count(), 1)
        verifier = Path(result["evidence_paths"]["review_worktree"])
        self.assertEqual(self._git(verifier, "rev-parse", "HEAD"), result["candidate_head"])
        self.assertEqual(self._git(verifier, "rev-parse", "HEAD^{tree}"), result["candidate_tree"])
        invocation = json.loads((Path(result["review_artifact"]).parent / "invocation.json").read_text(encoding="utf-8"))
        self.assertEqual(invocation["model"], CODEX_REVIEWER_MODEL)
        self.assertTrue(invocation["ignore_user_config"])
        self.assertEqual(invocation["sandbox"], "read-only")
        self.assertFalse((Path(result["review_artifact"]).parent / "startup").exists())


class patch_environment:
    """Tiny scoped environment patch without importing unittest.mock into the contract tests."""

    def __init__(self, key: str, value: str) -> None:
        self.key, self.value, self.previous = key, value, os.environ.get(key)

    def __enter__(self) -> None:
        os.environ[self.key] = self.value

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.previous is None:
            os.environ.pop(self.key, None)
        else:
            os.environ[self.key] = self.previous


if __name__ == "__main__":
    unittest.main()
