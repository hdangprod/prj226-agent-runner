"""HARN-001 runner tests using temporary Git repositories and fake providers only."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner.candidate_authority import build_candidate_authority
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError
from prj226_runner.runner import (
    RoleConfig,
    _safe_relative_path,
    _validate_confinement_overlap,
    _fresh_reviewer_env,
    _parse_reviewer_result,
    build_confined_sandbox_profile,
    build_builder_invocation,
    build_reviewer_invocation,
    candidate_branch_name,
    encode_sbpl_string,
    inspect_packet,
    load_config,
    parse_task_packet,
    run_packet,
    run_strict_verifier,
)


class TestHarn001Runner(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "product"
        self._git(self.root, "init", str(self.repo))
        self._git(self.repo, "config", "user.email", "runner@example.test")
        self._git(self.repo, "config", "user.name", "Runner Test")
        (self.repo / "src").mkdir()
        (self.repo / "src/app.txt").write_text("base\n", encoding="utf-8")
        self._git(self.repo, "add", "src/app.txt")
        self._git(self.repo, "commit", "-m", "base")
        self.baseline = self._git(self.repo, "rev-parse", "HEAD")
        self.tree = self._git(self.repo, "rev-parse", "HEAD^{tree}")
        self.branch = self._git(self.repo, "branch", "--show-current")
        self.fake = self.root / "fake-provider.py"
        self.fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, pathlib, subprocess, sys\n"
            "prompt = sys.argv[-1]\n"
            "if 'Review SECURITY' in prompt:\n"
            "  if os.environ.get('FAKE_REVIEW_MUTATE'): pathlib.Path('reviewer.txt').write_text('bad')\n"
            "  print(json.dumps({'recommendation': os.environ.get('FAKE_SOS', 'ACCEPT'), 'findings': []}))\n"
            "elif 'Review this candidate' in prompt:\n"
            "  if os.environ.get('FAKE_REVIEW_MUTATE'): pathlib.Path('reviewer.txt').write_text('bad')\n"
            "  print(json.dumps({'result': os.environ.get('FAKE_DV', 'PASS'), 'findings': []}))\n"
            "else:\n"
            "  target = pathlib.Path(os.environ.get('FAKE_TARGET', 'src/app.txt'))\n"
            "  target.parent.mkdir(parents=True, exist_ok=True)\n"
            "  target.write_text('builder change\\n')\n"
            "  if os.environ.get('FAKE_STDIN'): pathlib.Path(os.environ['FAKE_STDIN']).write_bytes(sys.stdin.buffer.read())\n"
            "  if os.environ.get('FAKE_COMMIT'):\n"
            "    subprocess.run(['git','add','--',str(target)], check=True)\n"
            "    subprocess.run(['git','commit','-m','unexpected'], check=True)\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)
        self.runtime = self.root / "runtime"
        self.config = self.root / "runner.toml"
        self.config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(self.runtime))}\n\n"
            "[agents.builder]\n"
            "tool = 'codex'\n"
            f"executable = {json.dumps(str(self.fake))}\nmodel = 'fake-builder'\ntimeout_seconds = 20\n\n"
            "[agents.dv]\n"
            "tool = 'opencode2'\n"
            f"executable = {json.dumps(str(self.fake))}\nmodel = 'fake-muse'\ntimeout_seconds = 20\n\n"
            "[agents.sos_reviewer]\n"
            "tool = 'opencode2'\n"
            f"executable = {json.dumps(str(self.fake))}\nmodel = 'fake-mimo'\ntimeout_seconds = 20\n",
            encoding="utf-8",
        )
        self.packet_path = self.root / "packet.json"
        self.write_packet()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _git(cwd: Path, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def write_packet(self, **updates: object) -> None:
        value: dict[str, object] = {
            "run_id": "HARN-TEST-001", "task_id": "HARN-TEST", "product_repo": str(self.repo),
            "canonical_branch": self.branch, "baseline_head": self.baseline, "baseline_tree": self.tree,
            "authorized_paths": ["src/app.txt"], "builder_prompt": "Change the approved file.",
            "acceptance_criteria": ["approved change exists"],
            "test_commands": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
            "commit_message": "test: candidate",
        }
        value.update(updates)
        self.packet_path.write_text(json.dumps(value), encoding="utf-8")

    def inspect(self) -> dict:
        return inspect_packet(self.packet_path, self.config)

    def execute_runner(self, **env: str) -> dict:
        with patch.dict(os.environ, env, clear=False):
            return run_packet(self.packet_path, self.config, authorize=True)

    def test_valid_task_packet(self) -> None:
        self.assertEqual(parse_task_packet(self.packet_path).run_id, "HARN-TEST-001")

    def test_invalid_packet_rejected(self) -> None:
        self.write_packet(run_id="../bad")
        with self.assertRaises(ArtifactValidationError):
            parse_task_packet(self.packet_path)

    def test_safe_relative_path_rejects_raw_dot_components(self) -> None:
        for value in ("./foo", "foo/./bar", "foo/.", "./", "foo//bar", "foo/", "/foo", "../foo", "foo/../bar", "foo/.git"):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactValidationError):
                    _safe_relative_path(value)

    def test_strict_verifier_requires_qualified_sandbox_host(self) -> None:
        with patch("prj226_runner.runner.sys.platform", "linux"):
            with self.assertRaisesRegex(GovernanceBlockerError, "UNSUPPORTED_VERIFIER_CONFINEMENT"):
                run_strict_verifier(
                    self.repo,
                    baseline_head=self.baseline,
                    candidate_head=self.baseline,
                    candidate_ref=self.branch,
                    authority={},
                    test_commands=[[sys.executable, "-c", "pass"]],
                )

    def test_confinement_overlap_is_bidirectional(self) -> None:
        candidate = self.root / "candidate"
        canonical = self.root / "canonical"
        disjoint = self.root / "scratch"
        candidate_container = self.root / "candidate-container"
        canonical_container = self.root / "canonical-container"
        cases = (
            ("scratch inside candidate", candidate, canonical, candidate / "scratch"),
            ("scratch inside canonical", candidate, canonical, canonical / "scratch"),
            ("candidate inside scratch", candidate_container / "nested", canonical, candidate_container),
            ("canonical inside scratch", candidate, canonical_container / "nested", canonical_container),
            ("scratch equals candidate", candidate, canonical, candidate),
            ("scratch equals canonical", candidate, canonical, canonical),
        )
        for name, repo_candidate, repo_canonical, scratch in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(GovernanceBlockerError, "overlap"):
                    _validate_confinement_overlap(
                        [repo_candidate, repo_canonical],
                        [scratch, scratch / "home"],
                    )

        repositories, writable = _validate_confinement_overlap(
            [candidate, canonical], [disjoint, disjoint / "home"]
        )
        self.assertEqual(repositories, [candidate.resolve(), canonical.resolve()])
        self.assertEqual(writable, [disjoint.resolve(), (disjoint / "home").resolve()])

    def test_sbpl_paths_with_spaces_and_parentheses_are_quoted(self) -> None:
        path = "/private/tmp/path with (parentheses)"
        encoded = encode_sbpl_string(path)
        self.assertEqual(encoded, '"/private/tmp/path with (parentheses)"')
        profile = build_confined_sandbox_profile(
            [self.root / "candidate"], [Path(path), Path(path) / "home"]
        )
        self.assertIn(f"(subpath {encoded})", profile)

    def test_sbpl_quotes_and_backslashes_are_escaped(self) -> None:
        path = r'/private/tmp/quote"and\slash (safe)'
        self.assertEqual(
            encode_sbpl_string(path),
            '"/private/tmp/quote\\"and\\\\slash (safe)"',
        )

    def test_sbpl_rejects_nul_and_newline(self) -> None:
        for value in ("/private/tmp/bad\x00path", "/private/tmp/bad\npath", "/private/tmp/bad\rpath"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(GovernanceBlockerError):
                    encode_sbpl_string(value)

    def test_sbpl_rule_injection_attempt_remains_one_quoted_subpath(self) -> None:
        malicious = '/private/tmp/evil") (allow file-write* (subpath "/outside'
        encoded = encode_sbpl_string(malicious)
        profile = build_confined_sandbox_profile(
            [self.root / "candidate"], [Path(malicious)]
        )
        self.assertIn(f"(subpath {encoded})", profile)
        self.assertNotIn('(subpath "/outside")', profile)
        self.assertEqual(profile.count("\n(allow file-write*"), 1)

    @unittest.skipUnless(
        sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"),
        "qualified sandbox-exec is required",
    )
    def test_strict_verifier_denies_candidate_and_canonical_writes(self) -> None:
        probe = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default)", sys.executable, "-c", "pass"],
            capture_output=True,
            check=False,
        )
        if probe.returncode != 0:
            self.skipTest("sandbox-exec cannot be applied by this host runner")
        authority = build_candidate_authority(
            self.repo, self.baseline, self.branch, self.baseline, []
        )
        scratch = self.root / "verifier-scratch"
        canonical_target = self.repo / "canonical-write.txt"
        script = (
            "import errno, pathlib\n"
            "targets = [pathlib.Path('candidate-write.txt'), pathlib.Path(%r)]\n"
            "for target in targets:\n"
            "    try:\n"
            "        target.write_text('blocked')\n"
            "    except OSError as exc:\n"
            "        if exc.errno != errno.EPERM:\n"
            "            raise\n"
            "    else:\n"
            "        raise SystemExit('write unexpectedly succeeded')\n"
            "pathlib.Path(__import__('os').environ['TMPDIR'], 'allowed.txt').write_text('allowed')\n"
        ) % str(canonical_target)
        result = run_strict_verifier(
            self.repo,
            baseline_head=self.baseline,
            candidate_head=self.baseline,
            candidate_ref=self.branch,
            authority=authority,
            test_commands=[[sys.executable, "-c", script]],
            canonical_repository=self.repo,
            canonical_branch=self.branch,
            baseline_tree=self.tree,
            runtime_directories=[scratch],
        )
        self.assertTrue(result["ok"])
        self.assertFalse((self.repo / "candidate-write.txt").exists())
        self.assertFalse(canonical_target.exists())
        self.assertFalse(scratch.exists())

    def test_inspect_is_read_only(self) -> None:
        before = self._git(self.repo, "status", "--porcelain")
        self.assertEqual(self.inspect()["result"], "READY_FOR_HUMAN_AUTHORIZATION")
        self.assertEqual(before, self._git(self.repo, "status", "--porcelain"))
        self.assertFalse(self.runtime.exists())

    def test_inspect_performs_zero_provider_calls(self) -> None:
        marker = self.root / "stdin"
        with patch.dict(os.environ, {"FAKE_STDIN": str(marker)}, clear=False):
            self.inspect()
        self.assertFalse(marker.exists())

    def test_run_refuses_without_authorize(self) -> None:
        with self.assertRaises(GovernanceBlockerError):
            run_packet(self.packet_path, self.config, authorize=False)
        self.assertFalse(self.runtime.exists())

    def test_baseline_branch_drift_rejected(self) -> None:
        self.write_packet(canonical_branch="other-branch")
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_baseline_head_drift_rejected(self) -> None:
        self.write_packet(baseline_head="0" * 40)
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_baseline_tree_drift_rejected(self) -> None:
        self.write_packet(baseline_tree="0" * 40)
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_dirty_canonical_worktree_rejected(self) -> None:
        (self.repo / "dirty.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_run_id_collision_rejected(self) -> None:
        (self.runtime / "HARN-TEST-001").mkdir(parents=True)
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_builder_worktree_isolated(self) -> None:
        result = self.execute_runner()
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual((self.repo / "src/app.txt").read_text(encoding="utf-8"), "base\n")

    def test_builder_receives_approved_prompt(self) -> None:
        argv = build_builder_invocation(load_config(self.config).agents["builder"], self.root, parse_task_packet(self.packet_path))
        self.assertIn("Change the approved file.", argv[-1])
        self.assertIn("src/app.txt", argv[-1])

    def test_builder_stdin_is_devnull(self) -> None:
        marker = self.root / "stdin-bytes"
        self.execute_runner(FAKE_STDIN=str(marker))
        self.assertEqual(marker.read_bytes(), b"")

    def test_unauthorized_modified_path_rejected(self) -> None:
        result = self.execute_runner(FAKE_TARGET="src/nope.txt")
        self.assertEqual(result["error_class"], "GOVERNANCE_BLOCKER")

    def test_unauthorized_untracked_path_rejected(self) -> None:
        result = self.execute_runner(FAKE_TARGET="untracked.txt")
        self.assertIn("unauthorized", result["error"].lower())

    def test_builder_created_commit_rejected(self) -> None:
        result = self.execute_runner(FAKE_COMMIT="1")
        self.assertIn("unexpected commit", result["error"])

    def test_explicit_staging_only_changed_path(self) -> None:
        result = self.execute_runner()
        changed = self._git(Path(result["evidence_paths"]["worktree"]), "diff", "--name-only", f"{self.baseline}..HEAD")
        self.assertEqual(changed, "src/app.txt")

    def test_candidate_has_one_parent(self) -> None:
        result = self.execute_runner()
        parents = self._git(Path(result["evidence_paths"]["worktree"]), "rev-list", "--parents", "-n", "1", "HEAD").split()
        self.assertEqual(len(parents), 2)

    def test_candidate_parent_is_baseline(self) -> None:
        result = self.execute_runner()
        parent = self._git(Path(result["evidence_paths"]["worktree"]), "rev-parse", "HEAD^")
        self.assertEqual(parent, self.baseline)

    def test_candidate_head_and_tree_frozen(self) -> None:
        result = self.execute_runner()
        worktree = Path(result["evidence_paths"]["worktree"])
        self.assertEqual(self._git(worktree, "rev-parse", "HEAD"), result["candidate_head"])
        self.assertEqual(self._git(worktree, "rev-parse", "HEAD^{tree}"), result["candidate_tree"])

    def test_deterministic_commands_are_argv_arrays(self) -> None:
        result = self.execute_runner()
        self.assertEqual(result["tests"][0]["argv"][0], sys.executable)

    def test_deterministic_failure_is_fail_fast(self) -> None:
        self.write_packet(test_commands=[[sys.executable, "-c", "import sys;sys.exit(1)"], [sys.executable, "-c", "raise RuntimeError"]])
        result = self.execute_runner()
        self.assertEqual(result["result"], "STOPPED")
        self.assertFalse((self.runtime / "HARN-TEST-001" / "deterministic" / "test-2").exists())

    def test_deterministic_failure_never_calls_dv(self) -> None:
        self.write_packet(test_commands=[[sys.executable, "-c", "import sys;sys.exit(1)"]])
        self.execute_runner()
        self.assertFalse((self.runtime / "HARN-TEST-001" / "dv" / "invocation.json").exists())

    def test_dv_runs_after_deterministic_pass(self) -> None:
        self.execute_runner()
        self.assertTrue((self.runtime / "HARN-TEST-001" / "dv" / "invocation.json").exists())

    def test_dv_fail_prevents_sos(self) -> None:
        result = self.execute_runner(FAKE_DV="FAIL")
        self.assertEqual(result["result"], "STOPPED")
        self.assertFalse((self.runtime / "HARN-TEST-001" / "sos" / "invocation.json").exists())

    def test_sos_runs_after_dv_pass(self) -> None:
        self.execute_runner()
        self.assertTrue((self.runtime / "HARN-TEST-001" / "sos" / "invocation.json").exists())

    def test_sos_reject_prevents_acceptance_ready(self) -> None:
        result = self.execute_runner(FAKE_SOS="REJECT")
        self.assertEqual(result["result"], "STOPPED")

    def test_opencode_text_event_normalizes_run_004_reviewer_result(self) -> None:
        stdout = self.root / "opencode-stdout.log"
        stdout.write_text(
            "{\"type\":\"step_start\",\"part\":{\"type\":\"step-start\"}}\n"
            "{\"type\":\"text\",\"part\":{\"type\":\"text\",\"text\":\"checking evidence\"}}\n"
            + json.dumps({
                "type": "text",
                "part": {"type": "text", "text": json.dumps({"result": "PASS", "findings": []})},
            })
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_parse_reviewer_result(stdout, "dv"), ("PASS", []))

    def test_opencode_text_event_supports_sos_reviewer_contract(self) -> None:
        stdout = self.root / "opencode-sos-stdout.log"
        stdout.write_text(
            "{\"type\":\"step_start\",\"part\":{\"type\":\"step-start\"}}\n"
            + json.dumps({
                "type": "text",
                "part": {"type": "text", "text": json.dumps({"recommendation": "ACCEPT", "findings": []})},
            })
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(_parse_reviewer_result(stdout, "sos"), ("ACCEPT", []))

    def test_opencode_text_event_arbitrary_or_malformed_text_is_rejected(self) -> None:
        for text in ("Looks good", "{not json"):
            with self.subTest(text=text):
                stdout = self.root / f"opencode-{len(text)}.log"
                stdout.write_text(
                    "{\"type\":\"step_start\"}\n" + json.dumps({"type": "text", "part": {"text": text}}) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ArtifactValidationError):
                    _parse_reviewer_result(stdout, "dv")

    def test_opencode_text_event_invalid_review_result_is_rejected(self) -> None:
        stdout = self.root / "opencode-invalid-result.log"
        stdout.write_text(
            "{\"type\":\"step_start\"}\n" + json.dumps({
                "type": "text",
                "part": {"text": json.dumps({"result": "UNKNOWN", "findings": []})},
            })
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ArtifactValidationError):
            _parse_reviewer_result(stdout, "dv")

    def test_opencode_text_event_conflicting_review_results_fail_closed(self) -> None:
        stdout = self.root / "opencode-conflicting-results.log"
        stdout.write_text(
            "{\"type\":\"step_start\"}\n" + "\n".join(
                json.dumps({"type": "text", "part": {"text": json.dumps({"result": result, "findings": []})}})
                for result in ("PASS", "FAIL")
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ArtifactValidationError):
            _parse_reviewer_result(stdout, "dv")

    def test_reviewer_worktree_mutation_detected(self) -> None:
        result = self.execute_runner(FAKE_REVIEW_MUTATE="1")
        self.assertEqual(result["error_class"], "GOVERNANCE_BLOCKER")

    def test_no_fallback_or_retry_or_merge_or_push(self) -> None:
        source = (Path(__file__).parents[1] / "src/prj226_runner/runner.py").read_text(encoding="utf-8")
        self.assertNotIn("git push", source)
        self.assertNotIn("cherry-pick", source)
        self.assertNotIn("while attempts", source.lower())

    def test_immutable_run_collision_after_execution(self) -> None:
        self.execute_runner()
        with self.assertRaises(GovernanceBlockerError): self.inspect()

    def test_full_mocked_happy_path_reaches_acceptance_ready(self) -> None:
        result = self.execute_runner()
        self.assertEqual(result["result"], "ACCEPTANCE_READY")
        self.assertEqual(result["dv_result"], "PASS")
        self.assertEqual(result["sos_result"], "ACCEPT")

    def test_state_machine_records_human_authorization(self) -> None:
        self.execute_runner()
        events = (self.runtime / "HARN-TEST-001" / "events.ndjson").read_text(encoding="utf-8")
        self.assertIn('"to_state": "HUMAN_AUTHORIZED"', events)

    def test_candidate_branch_is_deterministic(self) -> None:
        self.assertEqual(candidate_branch_name(parse_task_packet(self.packet_path)), "harn-candidate/HARN-TEST-HARN-TEST-001")

    def test_dv_and_sos_reviewer_argv_places_standalone_after_run(self) -> None:
        """Both OpenCode reviewer roles must use the current run-level standalone contract."""
        for name, model in (("dv", "fake-muse"), ("sos", "fake-mimo")):
            with self.subTest(role=name):
                role = RoleConfig("opencode2", "/bin/opencode2", model, 20)
                argv = build_reviewer_invocation(role, "Review this candidate")
                self.assertEqual(argv[0], "/bin/opencode2")
                self.assertLess(argv.index("run"), argv.index("--standalone"))
                self.assertLess(argv.index("--standalone"), argv.index("--format"))
                self.assertLess(argv.index("--format"), argv.index("--agent"))
                self.assertLess(argv.index("--agent"), argv.index("--model"))

    def test_reviewer_delivers_readonly_policy_in_env_and_correct_xdg_path(self) -> None:
        expected_permissions = [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "read", "resource": "*", "effect": "allow"},
            {"action": "glob", "resource": "*", "effect": "allow"},
            {"action": "grep", "resource": "*", "effect": "allow"},
        ]
        for role in ("dv", "sos"):
            with self.subTest(role=role):
                role_runtime = self.runtime / "HARN-TEST-001" / role
                env = _fresh_reviewer_env(role_runtime)
                policy = json.loads(env["OPENCODE_CONFIG_CONTENT"])
                persisted = role_runtime / "xdg-config" / "opencode" / "opencode.json"

                self.assertEqual(env["XDG_CONFIG_HOME"], str(role_runtime / "xdg-config"))
                self.assertEqual(env["XDG_DATA_HOME"], str(role_runtime / "xdg-data"))
                self.assertEqual(env["XDG_STATE_HOME"], str(role_runtime / "xdg-state"))
                self.assertEqual(policy["default_agent"], "harn-readonly")
                self.assertIn("harn-readonly", policy["agents"])
                self.assertEqual(policy["agents"]["harn-readonly"]["mode"], "primary")
                self.assertEqual(policy["agents"]["harn-readonly"]["permissions"], expected_permissions)
                self.assertTrue(persisted.is_file())
                self.assertFalse((role_runtime / "xdg-config" / "opencode.json").exists())
                self.assertEqual(persisted.read_text(encoding="utf-8"), env["OPENCODE_CONFIG_CONTENT"])
                self.assertEqual(json.loads(persisted.read_text(encoding="utf-8")), policy)

    def test_manifest_excludes_environment_values(self) -> None:
        self.execute_runner(SECRET_TOKEN="do-not-record")
        manifest = (self.runtime / "HARN-TEST-001" / "manifest.json").read_text(encoding="utf-8")
        self.assertNotIn("do-not-record", manifest)
