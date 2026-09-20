import os
import stat
import tempfile
import unittest
from pathlib import Path

from prj226_runner.control_environment import DesignatedFileAuth, create_role_environment


class ControlEnvironmentTests(unittest.TestCase):
    def test_environment_allowlist_strips_host_secrets(self):
        with create_role_environment(parent_env={"PATH": "/bin", "OPENAI_API_KEY": "test-dummy-api-key", "AWS_SECRET_ACCESS_KEY": "secret"}) as isolated:
            self.assertEqual(isolated.environment["PATH"], "/bin")
            self.assertNotIn("OPENAI_API_KEY", isolated.environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", isolated.environment)

    def test_fresh_private_directories_mode_0700(self):
        with create_role_environment() as isolated:
            for path in (isolated.root, isolated.home, isolated.codex_home):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_designated_auth_provisioned_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "credential"
            source.write_text("test-dummy-api-key")
            with create_role_environment(DesignatedFileAuth(source)) as isolated:
                destination = isolated.codex_home / "designated-credential"
                self.assertEqual(destination.read_text(), "test-dummy-api-key")
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_auth_contents_redacted_from_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "credential"
            source.write_text("test-dummy-api-key")
            with create_role_environment(DesignatedFileAuth(source)) as isolated:
                self.assertNotIn("test-dummy-api-key", str(isolated.sanitized({"output": "test-dummy-api-key"})))

    def test_home_isolation_prevents_user_codex_access(self):
        with tempfile.TemporaryDirectory() as temp:
            host_codex = Path(temp) / ".codex"
            host_codex.mkdir()
            with create_role_environment(parent_env={"HOME": temp}) as isolated:
                self.assertNotEqual(isolated.environment["HOME"], temp)
                self.assertNotEqual(isolated.environment["CODEX_HOME"], str(host_codex))


if __name__ == "__main__":
    unittest.main()
