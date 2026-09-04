"""HARN-002 Repair-10 focused closure controls."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner.controller import _fast_forward_exact_baseline
from prj226_runner.errors import GovernanceBlockerError, RunnerEnvironmentError
from prj226_runner.reviewer_profile import build_codex_reviewer_env


class TestRepair10Controls(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_home = self.root / "source-codex-home"
        self.source_home.mkdir()
        self.source_auth = self.source_home / "auth.json"
        self.source_auth.write_text("authorized-auth\n", encoding="utf-8")
        self.isolated_homes: list[Path] = []

    def tearDown(self) -> None:
        for isolated_home in self.isolated_homes:
            shutil.rmtree(isolated_home, ignore_errors=True)
        self.temp.cleanup()

    def _build_env(self, **ambient: str) -> dict[str, str]:
        with patch.dict(os.environ, ambient, clear=False):
            env = build_codex_reviewer_env(source_codex_home=self.source_home)
        self.isolated_homes.append(Path(env["CODEX_HOME"]))
        return env

    def test_PROXY_01_proxy_userinfo_is_not_inherited(self) -> None:
        ambient = {
            "HTTP_PROXY": "http://repair10-user:repair10-password@proxy.example:8080",
            "HTTPS_PROXY": "https://repair10-user:repair10-password@proxy.example:8443/path",
            "ALL_PROXY": "socks5://repair10-user:repair10-password@proxy.example:1080",
            "http_proxy": "http://repair10-lower-user:repair10-lower-password@proxy.example:8080",
            "https_proxy": "https://repair10-lower-user:repair10-lower-password@proxy.example:8443",
            "all_proxy": "socks5://repair10-lower-user:repair10-lower-password@proxy.example:1080",
        }
        env = self._build_env(**ambient)
        for key, value in ambient.items():
            self.assertIn(key, env)
            self.assertNotIn("repair10-", env[key])
            self.assertNotIn("@", env[key].split("://", 1)[-1].split("/", 1)[0])
            self.assertNotIn(value, env.values())

    def test_PROXY_02_credential_free_proxy_routing_is_retained(self) -> None:
        env = self._build_env(
            HTTP_PROXY="http://proxy.example:8080",
            HTTPS_PROXY="https://proxy.example:8443",
            ALL_PROXY="socks5://proxy.example:1080",
        )
        self.assertEqual(env["HTTP_PROXY"], "http://proxy.example:8080")
        self.assertEqual(env["HTTPS_PROXY"], "https://proxy.example:8443")
        self.assertEqual(env["ALL_PROXY"], "socks5://proxy.example:1080")

    def test_AUTH_01_open_descriptor_remains_authoritative_after_path_replacement(self) -> None:
        replacement = self.source_home / "replacement-auth.json"
        replaced = False

        original_is_file = Path.is_file

        def replace_after_path_check(path: Path) -> bool:
            nonlocal replaced
            result = original_is_file(path)
            if path == self.source_auth and not replaced:
                replaced = True
                self.source_auth.rename(replacement)
                replacement.write_text("attacker-auth\n", encoding="utf-8")
                self.source_auth.symlink_to(replacement)
            return result

        # This replacement lands after the legacy is_file() check but before
        # shutil.copyfile(source_auth, ...) would reopen the pathname.
        with patch("pathlib.Path.is_file", side_effect=replace_after_path_check):
            env = build_codex_reviewer_env(source_codex_home=self.source_home)
        self.isolated_homes.append(Path(env["CODEX_HOME"]))
        self.assertEqual((Path(env["CODEX_HOME"]) / "auth.json").read_text(encoding="utf-8"), "authorized-auth\n")

    def test_AUTH_02_path_symlink_is_rejected(self) -> None:
        target = self.root / "target-auth.json"
        target.write_text("target\n", encoding="utf-8")
        self.source_auth.unlink()
        self.source_auth.symlink_to(target)
        with self.assertRaises(RunnerEnvironmentError):
            build_codex_reviewer_env(source_codex_home=self.source_home)

    def test_GIT_01_fast_forward_does_not_split_ref_and_worktree_transitions(self) -> None:
        expected_head = "a" * 40
        candidate_head = "b" * 40
        calls: list[list[str]] = []

        def fake_git(repo: Path, args: list[str]) -> str:
            calls.append(args)
            if args == ["symbolic-ref", "-q", "HEAD"]:
                return "refs/heads/main"
            if args == ["rev-parse", "HEAD"]:
                return expected_head
            if args == ["merge-base", "--is-ancestor", expected_head, candidate_head]:
                return ""
            if args[0] == "merge":
                raise GovernanceBlockerError("simulated Git transition failure")
            raise AssertionError(f"unexpected Git command: {args}")

        with patch("prj226_runner.controller._git", side_effect=fake_git):
            with self.assertRaises(GovernanceBlockerError):
                _fast_forward_exact_baseline(Path("/repo"), expected_head, candidate_head, "main")

        self.assertTrue(any(args[0] == "merge" for args in calls))
        self.assertFalse(any(args[0] in {"update-ref", "read-tree"} for args in calls))


if __name__ == "__main__":
    unittest.main()
