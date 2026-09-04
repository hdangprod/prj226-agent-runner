"""HARN-002 Repair-9 ambient credential isolation controls."""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner.codex_reviewer import (
    build_codex_reviewer_env,
    build_codex_reviewer_invocation,
    build_codex_reviewer_qualification_invocation,
    build_codex_reviewer_qualification_env,
)
from prj226_runner.reviewer_profile import (
    CODEX_REVIEWER_MODEL,
    assert_codex_reviewer_profile_parity,
    build_codex_reviewer_profile,
    normalize_codex_reviewer_profile,
)


class TestRepair9AmbientCredentialIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_home = self.root / "source-codex-home"
        self.source_home.mkdir()
        (self.source_home / "auth.json").write_text('{"auth":"authorized-material"}\n', encoding="utf-8")
        (self.source_home / "config.toml").write_text(
            "sandbox_permissions = ['danger-full-access']\n", encoding="utf-8"
        )
        self.executable = self.root / "codex"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.schema = self.root / "schema.json"
        self.schema.write_text("{}\n", encoding="utf-8")
        self.synthetic_workspace = self.root / "synthetic"
        self.production_workspace = self.root / "production"
        self.synthetic_workspace.mkdir()
        self.production_workspace.mkdir()
        self.synthetic_output = self.root / "synthetic-output.json"
        self.production_output = self.root / "production-output.json"
        self.profile = build_codex_reviewer_profile(str(self.executable))
        self._isolated_homes: list[Path] = []

    def tearDown(self) -> None:
        for isolated_home in self._isolated_homes:
            shutil.rmtree(isolated_home, ignore_errors=True)
        self.temp.cleanup()

    def _build_env(self, **ambient: str) -> dict[str, str]:
        with patch.dict(os.environ, ambient, clear=False):
            env = build_codex_reviewer_env(source_codex_home=self.source_home)
        self._isolated_homes.append(Path(env["CODEX_HOME"]))
        return env

    def test_NEG_A_CODEX_ACCESS_TOKEN_is_not_forwarded(self) -> None:
        sentinel = "repair9-codex-access-token-sentinel"
        env = self._build_env(CODEX_ACCESS_TOKEN=sentinel)
        self.assertNotIn("CODEX_ACCESS_TOKEN", env)
        self.assertNotIn(sentinel, env.values())

    def test_NEG_B_OPENAI_API_KEY_is_not_forwarded(self) -> None:
        sentinel = "repair9-openai-api-key-sentinel"
        env = self._build_env(OPENAI_API_KEY=sentinel)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn(sentinel, env.values())

    def test_NEG_C_both_provider_credentials_are_not_forwarded(self) -> None:
        codex_sentinel = "repair9-codex-both-sentinel"
        openai_sentinel = "repair9-openai-both-sentinel"
        env = self._build_env(CODEX_ACCESS_TOKEN=codex_sentinel, OPENAI_API_KEY=openai_sentinel)
        self.assertNotIn("CODEX_ACCESS_TOKEN", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn(codex_sentinel, env.values())
        self.assertNotIn(openai_sentinel, env.values())

    def test_NEG_C2_unrelated_ambient_credentials_are_not_forwarded(self) -> None:
        ambient = {
            "GITHUB_TOKEN": "repair9-github-token-sentinel",
            "AWS_SECRET_ACCESS_KEY": "repair9-aws-secret-sentinel",
            "SERVICE_API_KEY": "repair9-service-key-sentinel",
        }
        env = self._build_env(**ambient)
        for key, sentinel in ambient.items():
            self.assertNotIn(key, env)
            self.assertNotIn(sentinel, env.values())

    def test_NEG_D_sentinels_are_absent_from_sanitized_profile_evidence(self) -> None:
        sentinels = ("repair9-codex-evidence-sentinel", "repair9-openai-evidence-sentinel")
        env = self._build_env(CODEX_ACCESS_TOKEN=sentinels[0], OPENAI_API_KEY=sentinels[1])
        argv = build_codex_reviewer_invocation(
            str(self.executable), self.production_workspace, "review", self.schema, self.production_output,
        )
        normalized = normalize_codex_reviewer_profile(argv, profile=self.profile, env=env)
        evidence = self.root / "evidence" / "reviewer-profile.json"
        evidence.parent.mkdir()
        evidence.write_text(json.dumps({
            "authority": normalized["authority"],
            "environment": normalized["environment"],
            "reviewer_profile_hash": normalized["reviewer_profile_hash"],
        }, sort_keys=True) + "\n", encoding="utf-8")
        evidence_bytes = evidence.read_bytes()
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode("utf-8"), evidence_bytes)
        self.assertNotIn("CODEX_ACCESS_TOKEN", evidence_bytes.decode("utf-8"))
        self.assertNotIn("OPENAI_API_KEY", evidence_bytes.decode("utf-8"))

    def test_NEG_E_fresh_codex_home_contains_only_authorized_auth_material(self) -> None:
        env = self._build_env(
            CODEX_ACCESS_TOKEN="repair9-home-token-sentinel",
            OPENAI_API_KEY="repair9-home-key-sentinel",
        )
        isolated = Path(env["CODEX_HOME"])
        try:
            self.assertEqual(env["HOME"], env["CODEX_HOME"])
            self.assertEqual(sorted(path.name for path in isolated.iterdir()), ["auth.json"])
            self.assertEqual(
                (isolated / "auth.json").read_text(encoding="utf-8"),
                '{"auth":"authorized-material"}\n',
            )
            self.assertFalse((isolated / "config.toml").exists())
        finally:
            shutil.rmtree(isolated, ignore_errors=True)

    def test_NEG_F_synthetic_and_production_use_equivalent_environment_constructor(self) -> None:
        with patch.dict(os.environ, {
            "CODEX_ACCESS_TOKEN": "repair9-parity-token-sentinel",
            "OPENAI_API_KEY": "repair9-parity-key-sentinel",
        }, clear=False):
            synthetic_env = build_codex_reviewer_qualification_env()
            production_env = build_codex_reviewer_env(source_codex_home=self.source_home)
        self._isolated_homes.extend((Path(synthetic_env["CODEX_HOME"]), Path(production_env["CODEX_HOME"])))
        try:
            self.assertEqual(set(synthetic_env), set(production_env))
            for key in set(synthetic_env) - {"CODEX_HOME", "HOME"}:
                self.assertEqual(synthetic_env[key], production_env[key])
            self.assertNotIn("CODEX_ACCESS_TOKEN", synthetic_env)
            self.assertNotIn("OPENAI_API_KEY", synthetic_env)
            self.assertNotIn("CODEX_ACCESS_TOKEN", production_env)
            self.assertNotIn("OPENAI_API_KEY", production_env)
        finally:
            shutil.rmtree(synthetic_env["CODEX_HOME"], ignore_errors=True)
            shutil.rmtree(production_env["CODEX_HOME"], ignore_errors=True)

    def test_NEG_G_normal_runtime_requirements_remain_available(self) -> None:
        with patch.dict(os.environ, {
            "PATH": "/repair9/runtime/bin",
            "LANG": "C.UTF-8",
            "TMPDIR": "/repair9/runtime/tmp",
        }, clear=False):
            env = build_codex_reviewer_env(source_codex_home=self.source_home)
        try:
            self.assertEqual(env["PATH"], "/repair9/runtime/bin")
            self.assertEqual(env["LANG"], "C.UTF-8")
            self.assertEqual(env["TMPDIR"], "/repair9/runtime/tmp")
        finally:
            shutil.rmtree(env["CODEX_HOME"], ignore_errors=True)

    def test_NEG_H_credential_fix_does_not_bypass_sandbox_or_network_governance(self) -> None:
        with patch.dict(os.environ, {
            "CODEX_SANDBOX": "workspace-write",
            "CODEX_APPROVAL_POLICY": "on-request",
            "CODEX_ACCESS_TOKEN": "repair9-governance-token-sentinel",
        }, clear=False):
            env = build_codex_reviewer_env(source_codex_home=self.source_home)
        try:
            argv = build_codex_reviewer_invocation(
                str(self.executable), self.production_workspace, "review", self.schema, self.production_output,
            )
            self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
            self.assertEqual(argv[argv.index("--ask-for-approval") + 1], "never")
            self.assertNotIn("--full-auto", argv)
            self.assertNotIn("CODEX_SANDBOX", env)
            self.assertNotIn("CODEX_APPROVAL_POLICY", env)
            self.assertNotIn("CODEX_ACCESS_TOKEN", env)
        finally:
            shutil.rmtree(env["CODEX_HOME"], ignore_errors=True)

    def test_NEG_I_canonical_profile_hash_and_argv_contract_are_unchanged(self) -> None:
        synthetic_argv = build_codex_reviewer_qualification_invocation(
            str(self.executable), self.synthetic_workspace, "synthetic", self.schema, self.synthetic_output,
        )
        production_argv = build_codex_reviewer_invocation(
            str(self.executable), self.production_workspace, "production", self.schema, self.production_output,
        )
        parity = assert_codex_reviewer_profile_parity(
            synthetic_argv, production_argv, synthetic_profile=self.profile, production_profile=self.profile,
        )
        self.assertEqual(parity["reviewer_profile_hash"], self.profile.reviewer_profile_hash)
        self.assertEqual(parity["authority"]["provider"], "OpenAI")
        self.assertEqual(parity["authority"]["model"], CODEX_REVIEWER_MODEL)
        self.assertEqual(parity["authority"]["codex_home_policy"], "fresh-isolated-auth-only")


if __name__ == "__main__":
    unittest.main()
