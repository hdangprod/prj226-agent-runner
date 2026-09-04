"""HARN-002 Repair-5 trust-boundary closure matrices."""

from __future__ import annotations

import copy
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

from prj226_runner.codex_reviewer import (
    build_worktree_fingerprint_manifest,
    fingerprint_worktree,
    read_validated_artifact_snapshot,
)
from prj226_runner.controller import (
    ingest_runner_result,
    integrate_after_gate_b,
    load_gate_b_package,
    prepare_gate_b,
    validate_gate_b,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError, WorktreeIntegrityError

try:
    from test_repair4 import Repair4EvidenceFixture
except ModuleNotFoundError:  # direct module execution from the repository root
    from tests.test_repair4 import Repair4EvidenceFixture


class TestRepair5FilesystemMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "regular.txt").write_text("regular\n", encoding="utf-8")
        (self.root / "empty").mkdir()
        (self.root / "target").write_text("target\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_FS_01_regular_file_and_FS_02_directory_are_accepted(self) -> None:
        manifest = build_worktree_fingerprint_manifest(self.root)
        self.assertEqual({entry["type"] for entry in manifest}, {"file", "directory"})
        self.assertRegex(fingerprint_worktree(self.root), r"^[0-9a-f]{64}$")

    def test_FS_03_symlink_is_recorded_without_traversal(self) -> None:
        (self.root / "link").symlink_to("target")
        manifest = build_worktree_fingerprint_manifest(self.root)
        link = next(entry for entry in manifest if entry["path"] == "link")
        self.assertEqual(link["type"], "symlink")
        self.assertEqual(link["target"], "target")

    def test_FS_04_fifo_is_an_explicit_integrity_failure(self) -> None:
        os.mkfifo(self.root / "fifo")
        with self.assertRaisesRegex(WorktreeIntegrityError, "WORKTREE_UNSUPPORTED_NODE"):
            fingerprint_worktree(self.root)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are not supported")
    def test_FS_05_unix_socket_is_an_explicit_integrity_failure(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = self.root / "socket"
        try:
            try:
                server.bind(str(path))
            except PermissionError:
                self.skipTest("sandbox does not permit Unix socket creation")
            with self.assertRaisesRegex(WorktreeIntegrityError, "WORKTREE_UNSUPPORTED_NODE"):
                build_worktree_fingerprint_manifest(self.root)
        finally:
            server.close()

    def test_FS_06_unknown_node_type_fails_closed(self) -> None:
        from unittest.mock import patch
        import stat

        real_lstat = os.lstat

        def fake_lstat(path):
            info = real_lstat(path)
            if Path(path).name == "regular.txt":
                values = list(info)
                values[stat.ST_MODE] = 0o6000
                return os.stat_result(values)
            return info

        # Synthetic unsupported-node tests patch the verifier's classification
        # boundary rather than manufacturing a platform-specific node.
        with patch("prj226_runner.codex_reviewer.os.lstat", side_effect=fake_lstat):
            with self.assertRaisesRegex(WorktreeIntegrityError, "WORKTREE_UNSUPPORTED_NODE"):
                build_worktree_fingerprint_manifest(self.root)


class TestRepair5ArtifactSnapshotMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact = self.root / "review.json"
        self.head = "a" * 40
        self.tree = "b" * 40
        axis = {"status": "PASS", "findings": []}
        self.value = {
            "disposition": "PASS", "reviewed_head": self.head, "reviewed_tree": self.tree,
            "security": axis, "operability": axis, "semantics": axis, "architecture": axis,
            "blocking_findings": [], "non_blocking_findings": [],
        }
        self.artifact.write_text(json.dumps(self.value), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_ART_01_valid_artifact_is_one_validated_snapshot(self) -> None:
        snapshot = read_validated_artifact_snapshot(self.artifact, expected_head=self.head, expected_tree=self.tree)
        self.assertEqual(snapshot.value, self.value)
        self.assertEqual(snapshot.sha256, __import__("hashlib").sha256(snapshot.raw_bytes).hexdigest())

    def test_ART_02_symlink_artifact_is_rejected(self) -> None:
        target = self.root / "target.json"
        target.write_bytes(self.artifact.read_bytes())
        self.artifact.unlink()
        self.artifact.symlink_to(target)
        with self.assertRaises(ArtifactValidationError):
            read_validated_artifact_snapshot(self.artifact, expected_head=self.head, expected_tree=self.tree)

    def test_ART_03_missing_ART_04_malformed_and_ART_05_schema_are_rejected(self) -> None:
        self.artifact.unlink()
        with self.assertRaises(ArtifactValidationError):
            read_validated_artifact_snapshot(self.artifact)
        self.artifact.write_text("{bad", encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            read_validated_artifact_snapshot(self.artifact)
        self.artifact.write_text(json.dumps({"reviewed_head": self.head}), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            read_validated_artifact_snapshot(self.artifact)

    def test_ART_06_hash_rejects_persisted_content_change(self) -> None:
        snapshot = read_validated_artifact_snapshot(self.artifact, expected_head=self.head, expected_tree=self.tree)
        self.artifact.write_text(json.dumps({**self.value, "non_blocking_findings": ["changed"]}), encoding="utf-8")
        current = read_validated_artifact_snapshot(self.artifact, expected_head=self.head, expected_tree=self.tree)
        self.assertNotEqual(current.sha256, snapshot.sha256)

    def test_ART_07_snapshot_remains_the_authoritative_bytes_after_path_replacement(self) -> None:
        snapshot = read_validated_artifact_snapshot(self.artifact, expected_head=self.head, expected_tree=self.tree)
        replacement = copy.deepcopy(self.value)
        replacement["non_blocking_findings"] = ["replacement"]
        self.artifact.write_text(json.dumps(replacement), encoding="utf-8")
        self.assertEqual(snapshot.value["non_blocking_findings"], [])
        self.assertNotEqual(snapshot.sha256, __import__("hashlib").sha256(self.artifact.read_bytes()).hexdigest())


class TestRepair5GateBMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Repair4EvidenceFixture(Path(self.temp.name))
        self.ingested = ingest_runner_result(self.fixture.contract, self.fixture.result)
        self.package = prepare_gate_b(self.fixture.contract, self.ingested, self.fixture.review)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _authorization(self, **changes):
        auth = {
            "authorization_id": "human-gate-b-001",
            "gate_b_package_hash": self.package["gate_b_package_hash"],
            "candidate_head": self.package["candidate_head"],
            "candidate_tree": self.package["candidate_tree"],
            "expected_canonical_head": self.package["expected_canonical_head"],
            "expected_canonical_tree": self.package["expected_canonical_tree"],
        }
        auth.update(changes)
        return auth

    def test_GB_01_to_GB_03_package_review_and_old_state_are_not_authority(self) -> None:
        with self.assertRaises(GovernanceBlockerError):
            integrate_after_gate_b(self.fixture.contract, self._authorization(), perform=True)
        with self.assertRaises(GovernanceBlockerError):
            integrate_after_gate_b(self.fixture.contract, {}, package=self.package, perform=True)

    def test_GB_04_to_GB_06_authorization_bindings_are_exact(self) -> None:
        for changes in (
            {"gate_b_package_hash": "0" * 64},
            {"candidate_head": "0" * 40},
            {"expected_canonical_tree": "0" * 40},
        ):
            with self.subTest(changes=changes), self.assertRaises(GovernanceBlockerError):
                validate_gate_b(self.fixture.contract, self._authorization(**changes), self.package)

    def test_GB_07_to_GB_08_authorization_is_one_shot_even_after_failure(self) -> None:
        auth = self._authorization()
        broken = copy.deepcopy(self.fixture.review)
        broken["non_blocking_findings"] = ["provider path changed"]
        Path(self.fixture.result["review_artifact"]).write_text(json.dumps(broken), encoding="utf-8")
        with self.assertRaises(ArtifactValidationError):
            integrate_after_gate_b(self.fixture.contract, auth, package=self.package, perform=True)
        with self.assertRaisesRegex(GovernanceBlockerError, "REUSED"):
            integrate_after_gate_b(self.fixture.contract, auth, package=self.package, perform=True)

    def test_GB_09_to_GB_11_live_baseline_and_evidence_drift_fail_closed(self) -> None:
        stale_auth = self._authorization(authorization_id="human-gate-b-stale")
        self.fixture._git("commit", "--allow-empty", "-m", "baseline drift")
        with self.assertRaisesRegex(GovernanceBlockerError, "STALE_GATE_B_AUTHORITY"):
            integrate_after_gate_b(self.fixture.contract, stale_auth, package=self.package, perform=True)

    def test_GB_12_candidate_identity_drift_is_rejected(self) -> None:
        auth = self._authorization(authorization_id="human-gate-b-candidate")
        (self.fixture.candidate_worktree / "src/semantic.ts").write_text("retargeted\n", encoding="utf-8")
        self.fixture._git_at(self.fixture.candidate_worktree, "add", "src/semantic.ts")
        self.fixture._git_at(self.fixture.candidate_worktree, "commit", "-m", "retarget candidate")
        with self.assertRaises(GovernanceBlockerError):
            integrate_after_gate_b(self.fixture.contract, auth, package=self.package, perform=True)

    def test_GB_13_dirty_canonical_and_GB_14_exact_authorized_integration(self) -> None:
        dirty_auth = self._authorization(authorization_id="human-gate-b-dirty")
        (self.fixture.repo / "human.txt").write_text("protected\n", encoding="utf-8")
        with self.assertRaisesRegex(GovernanceBlockerError, "STALE_GATE_B_AUTHORITY"):
            integrate_after_gate_b(self.fixture.contract, dirty_auth, package=self.package, perform=True)

        # Recreate the fixture for the positive case because the failed attempt
        # is intentionally consumed and the dirty worktree is intentionally not repaired.
        self.tearDown()
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Repair4EvidenceFixture(Path(self.temp.name))
        self.ingested = ingest_runner_result(self.fixture.contract, self.fixture.result)
        self.package = prepare_gate_b(self.fixture.contract, self.ingested, self.fixture.review)
        auth = self._authorization(authorization_id="human-gate-b-positive")
        validate_gate_b(self.fixture.contract, auth, self.package)
        result = integrate_after_gate_b(self.fixture.contract, auth, package=self.package, perform=True)
        self.assertEqual(result["result"], "CANONICAL_INTEGRATED")
        self.assertEqual(self.fixture._git("rev-parse", "HEAD"), self.fixture.candidate_head)
        self.assertEqual(self.fixture._git("rev-parse", "HEAD^{tree}"), self.fixture.candidate_tree)

    def test_GB_15_gate_b_does_not_push_and_package_load_is_snapshot_validated(self) -> None:
        package_path = self.fixture.root / "gate-b-package.json"
        package_path.write_text(json.dumps(self.package, sort_keys=True), encoding="utf-8")
        loaded = load_gate_b_package(package_path, self.fixture.contract)
        self.assertEqual(loaded["gate_b_package_hash"], self.package["gate_b_package_hash"])
        self.assertNotIn("push", json.dumps(self.package).lower())


if __name__ == "__main__":
    unittest.main()
