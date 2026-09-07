"""HARN-002 Repair-6 root-anchoring and closed-result contract matrices."""

from __future__ import annotations

import copy
import json
import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import jsonschema
except ImportError:  # pragma: no cover - the verification environment supplies it
    jsonschema = None

from prj226_runner.codex_reviewer import EvidenceRoot, read_artifact_snapshot
from prj226_runner.controller import (
    ingest_runner_result,
    load_controller_result,
    prepare_gate_b,
    validate_gate_b,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError

try:
    from test_repair4 import Repair4EvidenceFixture
except ModuleNotFoundError:  # direct module execution from the repository root
    from tests.test_repair4 import Repair4EvidenceFixture


@unittest.skipUnless(jsonschema is not None, "jsonschema is required for closed-schema verification")
class TestRepair6RootAnchoredEvidence(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "nested").mkdir()
        self.artifact = self.evidence / "nested" / "artifact.json"
        self.artifact.write_bytes(b'{"authority":"original"}\n')

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_PATH_01_and_PATH_11_normal_relative_evidence_is_accepted(self) -> None:
        with EvidenceRoot(self.evidence) as root:
            snapshot = root.snapshot("nested/artifact.json")
        self.assertEqual(snapshot.raw_bytes, b'{"authority":"original"}\n')
        self.assertEqual(read_artifact_snapshot(self.artifact).raw_bytes, snapshot.raw_bytes)

    def test_PATH_02_absolute_locator_is_rejected_before_read(self) -> None:
        with EvidenceRoot(self.evidence) as root, self.assertRaises(ArtifactValidationError):
            root.snapshot(str(self.artifact))

    def test_PATH_03_traversal_and_PATH_07_symlink_chain_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.write_text("outside", encoding="utf-8")
        with EvidenceRoot(self.evidence) as root:
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("../outside")
            (self.evidence / "chain-a").symlink_to(self.root / "chain-b", target_is_directory=True)
            (self.root / "chain-b").symlink_to(self.root / "chain-c", target_is_directory=True)
            (self.root / "chain-c").mkdir()
            (self.root / "chain-c" / "artifact.json").write_text("outside", encoding="utf-8")
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("chain-a/artifact.json")

    def test_PATH_04_final_and_PATH_05_parent_symlink_are_rejected(self) -> None:
        outside = self.root / "outside-dir"
        outside.mkdir()
        (outside / "artifact.json").write_text("outside", encoding="utf-8")
        (self.evidence / "final-link").symlink_to(outside / "artifact.json")
        (self.evidence / "parent-link").symlink_to(outside, target_is_directory=True)
        with EvidenceRoot(self.evidence) as root:
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("final-link")
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("parent-link/artifact.json")

    def test_PATH_06_authorized_root_itself_cannot_be_a_symlink(self) -> None:
        root_link = self.root / "root-link"
        root_link.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(ArtifactValidationError):
            with EvidenceRoot(root_link):
                pass

    def test_PATH_08_unsupported_nodes_and_hard_links_fail_closed(self) -> None:
        fifo = self.evidence / "fifo"
        os.mkfifo(fifo)
        with EvidenceRoot(self.evidence) as root:
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("fifo")
            hard_link = self.evidence / "hard-link.json"
            os.link(self.artifact, hard_link)
            with self.assertRaises(ArtifactValidationError):
                root.snapshot("nested/artifact.json")

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        socket_path = self.evidence / "socket"
        try:
            try:
                server.bind(str(socket_path))
            except PermissionError:
                self.skipTest("sandbox does not permit Unix socket creation")
            with EvidenceRoot(self.evidence) as root, self.assertRaises(ArtifactValidationError):
                root.snapshot("socket")
        finally:
            server.close()

    def test_PATH_09_pathname_replacement_does_not_change_open_snapshot(self) -> None:
        replacement = self.evidence / "replacement.json"
        real_rename = os.rename
        real_read = os.read
        changed = False

        def replace_before_first_read(fd: int, size: int) -> bytes:
            nonlocal changed
            if not changed:
                changed = True
                real_rename(self.artifact, replacement)
                self.artifact.write_bytes(b'{"authority":"replacement"}\n')
            return real_read(fd, size)

        with patch("prj226_runner.codex_reviewer.os.read", side_effect=replace_before_first_read):
            with EvidenceRoot(self.evidence) as root:
                snapshot = root.snapshot("nested/artifact.json")
        self.assertEqual(snapshot.raw_bytes, b'{"authority":"original"}\n')


@unittest.skipUnless(jsonschema is not None, "jsonschema is required for closed-schema verification")
class TestRepair6ClosedControllerResult(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Repair4EvidenceFixture(Path(self.temp.name))
        self.ingested = ingest_runner_result(self.fixture.contract, self.fixture.result)
        self.schema = json.loads((Path(__file__).parents[1] / "schemas/controller-result.schema.json").read_text(encoding="utf-8"))
        self.package_schema = json.loads((Path(__file__).parents[1] / "schemas/gate-b-package.schema.json").read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_schema(self, value: dict, schema: dict | None = None) -> None:
        jsonschema.Draft7Validator(schema or self.schema).validate(value)

    def test_SCHEMA_01_actual_acceptance_result_is_closed_schema_valid(self) -> None:
        self._assert_schema(self.ingested)
        self.assertNotIn("review", self.ingested)
        self.assertNotIn("runner_acceptance_evidence_sha256", self.ingested)
        self.assertTrue(all(not Path(value).is_absolute() for key, value in self.ingested["evidence_paths"].items() if key not in {"worktree", "review_worktree"}))

    def test_SCHEMA_02_actual_stopped_terminal_result_is_schema_valid(self) -> None:
        stopped = ingest_runner_result(self.fixture.contract, {
            "result": "STOPPED",
            "run_id": self.fixture.contract["run_id"],
            "candidate_head": None,
            "candidate_tree": None,
            "error_class": "IMPLEMENTATION_FAILURE",
        })
        self._assert_schema(stopped)

    def test_SCHEMA_03_to_SCHEMA_06_structural_and_enum_defects_fail(self) -> None:
        missing = copy.deepcopy(self.ingested)
        missing.pop("verification_disposition")
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, missing, self.fixture.review)

        extra = copy.deepcopy(self.ingested)
        extra["unknown"] = True
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, extra, self.fixture.review)

        invalid_enum = copy.deepcopy(self.fixture.result)
        invalid_enum["reviewer_disposition"]["dv_result"] = "MAYBE"
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(self.fixture.contract, invalid_enum)

        invalid_nested = copy.deepcopy(self.fixture.result)
        invalid_nested["reviewer_disposition"] = {"dv_result": "PASS"}
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(self.fixture.contract, invalid_nested)

    def test_SCHEMA_07_to_SCHEMA_10_identity_semantics_old_output_and_defaults_fail(self) -> None:
        identity = copy.deepcopy(self.fixture.result)
        identity["candidate_head"] = "0" * 40
        with self.assertRaises(GovernanceBlockerError):
            ingest_runner_result(self.fixture.contract, identity)

        old_representation = copy.deepcopy(self.fixture.result)
        old_representation["result"] = "RESULT_INGESTED"
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(self.fixture.contract, old_representation)

        inconsistent = copy.deepcopy(self.ingested)
        inconsistent["deterministic_result"] = "STOPPED"
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, inconsistent, self.fixture.review)

        no_default = copy.deepcopy(self.ingested)
        no_default.pop("verification_disposition")
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, no_default, self.fixture.review)

    def test_SCHEMA_08_negative_control_rejects_the_repair5_extra_output_class(self) -> None:
        repair5_output = copy.deepcopy(self.ingested)
        repair5_output["review"] = copy.deepcopy(self.fixture.review)
        repair5_output["runner_acceptance_evidence_sha256"] = "0" * 64
        repair5_output["evidence_file_sha256"] = {}
        with self.assertRaises(ArtifactValidationError):
            prepare_gate_b(self.fixture.contract, repair5_output, self.fixture.review)

    def test_PATH_10_locator_cannot_bind_a_different_authorized_run_root(self) -> None:
        other_root = Path(self.temp.name) / "other-run"
        other_root.mkdir()
        (other_root / "manifest.json").write_text("{}", encoding="utf-8")
        broken = copy.deepcopy(self.fixture.result)
        broken["runtime_root"] = str(self.fixture.runtime)
        broken["evidence_paths"]["manifest"] = str(other_root / "manifest.json")
        with self.assertRaises(ArtifactValidationError):
            ingest_runner_result(self.fixture.contract, broken)

    def test_SCHEMA_11_round_trip_persistence_reload_and_gate_b_revalidation(self) -> None:
        encoded = json.dumps(self.ingested, sort_keys=True, separators=(",", ":"))
        parsed = json.loads(encoded)
        self._assert_schema(parsed)
        self.assertEqual(parsed, self.ingested)

        output_path = self.fixture.runtime / "controller-result.json"
        persisted = ingest_runner_result(self.fixture.contract, self.fixture.result, output_path=output_path)
        loaded = load_controller_result(output_path)
        self.assertEqual(loaded, persisted)
        package = prepare_gate_b(self.fixture.contract, loaded, self.fixture.review)
        self._assert_schema(package, self.package_schema)
        validate_gate_b(self.fixture.contract, {
            "authorization_id": "repair6-round-trip",
            "gate_b_package_hash": package["gate_b_package_hash"],
            "candidate_head": package["candidate_head"],
            "candidate_tree": package["candidate_tree"],
            "expected_canonical_head": package["expected_canonical_head"],
            "expected_canonical_tree": package["expected_canonical_tree"],
        }, package)


if __name__ == "__main__":
    unittest.main()
