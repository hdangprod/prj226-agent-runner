import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from prj226_runner.control_attestation import attest_session
from prj226_runner.errors import ArtifactValidationError


SESSION_ID = "session-test-001"
MODEL = "test-model"
PROVIDER = "openai"


class ControlAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "codex-home"
        self.sessions = self.home / "sessions"
        self.sessions.mkdir(parents=True)
        self.sqlite_path = self.home / "state_5.sqlite"
        self.rollout = self.sessions / "rollout.jsonl"
        self._write_sqlite()
        self._write_rollout()

    def tearDown(self):
        self.temp.cleanup()

    def _write_sqlite(
        self,
        *,
        session_id=SESSION_ID,
        model=MODEL,
        provider=PROVIDER,
        cli_version="test-cli",
        rollout_path=None,
        rows=None,
    ):
        if self.sqlite_path.exists() or self.sqlite_path.is_symlink():
            self.sqlite_path.unlink()
        connection = sqlite3.connect(self.sqlite_path)
        connection.execute(
            "CREATE TABLE threads (id TEXT, model TEXT, model_provider TEXT, cli_version TEXT, "
            "rollout_path TEXT, tokens_used INTEGER, created_at TEXT)"
        )
        if rows is None:
            rows = [(session_id, model, provider, cli_version, str(rollout_path or self.rollout), 12, "now")]
        connection.executemany("INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        connection.commit()
        connection.close()

    def _write_rollout(self, records=None):
        if records is None:
            records = [
                {"type": "thread.started", "thread_id": SESSION_ID},
                {"type": "turn_context", "payload": {"model": MODEL}},
                {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_tokens": 12}}},
            ]
        self.rollout.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    def test_valid_sqlite_and_rollout_attestation_passes(self):
        result = attest_session(self.home, SESSION_ID, MODEL)
        self.assertTrue(result.attestation_passed)
        self.assertEqual(result.session_model, MODEL)
        self.assertEqual(result.cli_version, "test-cli")
        self.assertEqual(result.rollout_events_count, 3)
        self.assertEqual(result.tokens_used, 12)
        self.assertFalse(hasattr(result, "sqlite_row"))
        self.assertFalse(hasattr(result, "token_usage"))

    def test_missing_sqlite_fails_closed(self):
        self.sqlite_path.unlink()
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_symlink_sqlite_rejected(self):
        source = Path(self.temp.name) / "real.sqlite"
        os.link(self.sqlite_path, source)
        self.sqlite_path.unlink()
        self.sqlite_path.symlink_to(source)
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_hardlink_sqlite_rejected(self):
        os.link(self.sqlite_path, Path(self.temp.name) / "state-hardlink.sqlite")
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_missing_exact_session_row_fails_closed(self):
        self._write_sqlite(rows=[])
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, "missing-session", MODEL)

    def test_wrong_model_in_sqlite_fails_closed(self):
        self._write_sqlite(model="different-model")
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_wrong_provider_in_sqlite_fails_closed(self):
        self._write_sqlite(provider="other-provider")
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_rollout_outside_codex_home_rejected(self):
        outside = Path(self.temp.name) / "outside.jsonl"
        outside.write_text(json.dumps({"type": "turn_context", "payload": {"model": MODEL}}) + "\n", encoding="utf-8")
        self._write_sqlite(rollout_path=outside)
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_missing_rollout_fails_closed(self):
        self.rollout.unlink()
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_symlink_rollout_rejected(self):
        outside = Path(self.temp.name) / "outside.jsonl"
        outside.write_text("{}\n", encoding="utf-8")
        self.rollout.unlink()
        self.rollout.symlink_to(outside)
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_hardlink_rollout_rejected(self):
        os.link(self.rollout, Path(self.temp.name) / "rollout-hardlink.jsonl")
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_malformed_rollout_jsonl_fails_closed(self):
        self.rollout.write_text("{not-json}\n", encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_missing_model_observation_in_rollout_fails_closed(self):
        self._write_rollout([{"type": "thread.started", "thread_id": SESSION_ID}])
        with self.assertRaises(ArtifactValidationError):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_missing_affirmative_session_observation_in_rollout_fails_closed(self):
        self._write_rollout([{"type": "turn_context", "payload": {"model": MODEL}}])
        with self.assertRaisesRegex(ArtifactValidationError, "missing affirmative session observation in rollout"):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_conflicting_model_observation_in_rollout_fails_closed(self):
        self._write_rollout([
            {"type": "thread.started", "thread_id": SESSION_ID},
            {"type": "turn_context", "payload": {"model": "other-model"}},
        ])
        with self.assertRaisesRegex(ArtifactValidationError, "conflicting model observation"):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_conflicting_session_observation_in_rollout_fails_closed(self):
        self._write_rollout([
            {"type": "thread.started", "thread_id": "other-session"},
            {"type": "turn_context", "payload": {"model": MODEL}},
        ])
        with self.assertRaisesRegex(ArtifactValidationError, "conflicting session ID"):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_matching_real_session_meta_observation_passes(self):
        self._write_rollout([
            {
                "type": "session_meta",
                "payload": {
                    "id": SESSION_ID,
                    "timestamp": "2026-09-20T00:00:00Z",
                    "cwd": str(self.home),
                    "cli_version": "test-cli",
                    "model_provider": PROVIDER,
                    "model": MODEL,
                },
            },
            {"type": "turn_context", "payload": {"model": MODEL}},
        ])
        result = attest_session(self.home, SESSION_ID, MODEL)
        self.assertTrue(result.attestation_passed)

    def test_contradictory_real_session_meta_observation_fails_closed(self):
        self._write_rollout([
            {
                "type": "session_meta",
                "payload": {
                    "id": "other-session",
                    "timestamp": "2026-09-20T00:00:00Z",
                    "cwd": str(self.home),
                    "cli_version": "test-cli",
                    "model_provider": PROVIDER,
                    "model": MODEL,
                },
            },
            {"type": "turn_context", "payload": {"model": MODEL}},
        ])
        with self.assertRaisesRegex(ArtifactValidationError, "conflicting session ID"):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_session_meta_without_payload_id_fails_closed(self):
        self._write_rollout([
            {
                "type": "session_meta",
                "payload": {
                    "timestamp": "2026-09-20T00:00:00Z",
                    "cwd": str(self.home),
                    "cli_version": "test-cli",
                    "model_provider": PROVIDER,
                    "model": MODEL,
                },
            },
            {"type": "turn_context", "payload": {"model": MODEL}},
        ])
        with self.assertRaisesRegex(ArtifactValidationError, "missing affirmative session observation in rollout"):
            attest_session(self.home, SESSION_ID, MODEL)

    def test_empty_or_missing_cli_version_fails_closed(self):
        for cli_version in ("", None):
            with self.subTest(cli_version=cli_version):
                self._write_sqlite(cli_version=cli_version)
                with self.assertRaisesRegex(ArtifactValidationError, "invalid cli_version format"):
                    attest_session(self.home, SESSION_ID, MODEL)

    def test_unsafe_or_oversized_cli_version_fails_closed(self):
        for cli_version in ("test-cli;secret", "x" * 101, "test-cli\nsecret"):
            with self.subTest(cli_version=cli_version):
                self._write_sqlite(cli_version=cli_version)
                with self.assertRaisesRegex(ArtifactValidationError, "invalid cli_version format"):
                    attest_session(self.home, SESSION_ID, MODEL)

    def test_provider_effective_model_is_always_null(self):
        result = attest_session(self.home, SESSION_ID, MODEL, expected_provider=PROVIDER)
        self.assertIsNone(result.provider_effective_model)


if __name__ == "__main__":
    unittest.main()
