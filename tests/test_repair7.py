"""HARN-002 Repair-7 terminal controller-result schema/consumer parity."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - the verification environment supplies it
    jsonschema = None

from prj226_runner.controller import (
    _validate_controller_result,
    ingest_runner_result,
    prepare_gate_b,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError, ReviewStaleError

try:
    from test_repair4 import Repair4EvidenceFixture
except ModuleNotFoundError:  # direct module execution from the repository root
    from tests.test_repair4 import Repair4EvidenceFixture


@unittest.skipUnless(jsonschema is not None, "jsonschema is required for closed-schema verification")
class TestRepair7TerminalControllerResultParity(unittest.TestCase):
    """Exercise the actual schema and the actual controller-result consumer."""

    def setUp(self) -> None:
        import tempfile

        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Repair4EvidenceFixture(Path(self.temp.name))
        self.accepted = ingest_runner_result(self.fixture.contract, self.fixture.result)
        self.schema = json.loads((Path(__file__).parents[1] / "schemas/controller-result.schema.json").read_text(encoding="utf-8"))
        self.validator = jsonschema.Draft7Validator(self.schema)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_parity_accepts(self, value: dict, label: str) -> None:
        self.validator.validate(value)
        try:
            _validate_controller_result(value)
        except Exception as exc:  # keep the failure tied to the parity oracle
            self.fail(f"consumer rejected schema-valid {label}: {exc}")

    def _assert_parity_rejects(self, value: dict, label: str) -> None:
        with self.assertRaises(jsonschema.ValidationError, msg=f"schema accepted invalid {label}"):
            self.validator.validate(value)
        with self.assertRaises(ArtifactValidationError, msg=f"consumer accepted invalid {label}"):
            _validate_controller_result(value)

    def _stopped(self, *, candidate: bool = False) -> dict:
        return ingest_runner_result(self.fixture.contract, {
            "result": "STOPPED",
            "run_id": self.fixture.contract["run_id"],
            "candidate_head": self.fixture.result["candidate_head"] if candidate else None,
            "candidate_tree": self.fixture.result["candidate_tree"] if candidate else None,
            "error_class": "IMPLEMENTATION_FAILURE",
        })

    def test_TERM_ACCEPTANCE_ready_real_normalized_shape_is_schema_and_consumer_valid(self) -> None:
        """The complete acceptance result emitted by normalization has one contract."""
        self._assert_parity_accepts(self.accepted, "ACCEPTANCE_READY")

    def test_TERM_STOPPED_optional_candidate_power_set_is_schema_and_consumer_valid(self) -> None:
        """STOPPED permits exactly the empty or paired candidate-ID combination."""
        self._assert_parity_accepts(self._stopped(), "STOPPED without candidate")
        self._assert_parity_accepts(self._stopped(candidate=True), "STOPPED with candidate")

    def test_STOPPED_forbids_every_acceptance_only_field(self) -> None:
        stopped = self._stopped()
        acceptance_only = (
            "candidate_ref",
            "verification_disposition",
            "evidence_root",
            "required_evidence_references",
            "evidence_paths",
            "candidate_worktree_fingerprint",
            "review_worktree_fingerprint",
            "review_artifact",
            "review_raw_artifact",
            "review_fingerprint_pre_artifact",
            "review_fingerprint_post_artifact",
            "review_artifact_sha256",
        )
        for field in acceptance_only:
            with self.subTest(field=field):
                broken = copy.deepcopy(stopped)
                broken[field] = copy.deepcopy(self.accepted.get(field, "unexpected"))
                self._assert_parity_rejects(broken, f"STOPPED with {field}")

    def test_REPAIR6_blocker_STOPPED_verification_disposition_is_rejected_by_both(self) -> None:
        stopped = self._stopped()
        stopped["verification_disposition"] = "STOPPED"
        self._assert_parity_rejects(stopped, "STOPPED verification_disposition")

    def test_STOPPED_partial_candidate_identity_is_rejected_by_both(self) -> None:
        for field in ("candidate_head", "candidate_tree"):
            with self.subTest(field=field):
                broken = self._stopped()
                broken[field] = self.accepted[field]
                self._assert_parity_rejects(broken, f"STOPPED partial {field}")

    def test_ACCEPTANCE_required_fields_and_nullability_are_closed(self) -> None:
        required = set(self.accepted)
        for field in sorted(required):
            with self.subTest(missing=field):
                broken = copy.deepcopy(self.accepted)
                broken.pop(field)
                self._assert_parity_rejects(broken, f"ACCEPTANCE_READY missing {field}")

        for field in (
            "candidate_head",
            "candidate_tree",
            "candidate_ref",
            "evidence_root",
            "candidate_worktree_fingerprint",
            "review_worktree_fingerprint",
            "review_artifact_sha256",
        ):
            with self.subTest(nullability=field):
                broken = copy.deepcopy(self.accepted)
                broken[field] = None
                self._assert_parity_rejects(broken, f"ACCEPTANCE_READY null {field}")

    def test_terminal_enums_nested_shape_and_unknown_keys_are_closed(self) -> None:
        cases = []
        invalid_enum = copy.deepcopy(self.accepted)
        invalid_enum["controller_phase"] = "STOPPED"
        cases.append((invalid_enum, "wrong terminal phase"))
        invalid_nested = copy.deepcopy(self.accepted)
        invalid_nested["reviewer_disposition"] = {"dv_result": "PASS"}
        cases.append((invalid_nested, "incomplete reviewer disposition"))
        empty_references = copy.deepcopy(self.accepted)
        empty_references["evidence_references"] = []
        empty_references["required_evidence_references"] = []
        cases.append((empty_references, "empty acceptance evidence references"))
        relative_worktree = copy.deepcopy(self.accepted)
        relative_worktree["evidence_paths"]["worktree"] = "undocumented-worktree"
        cases.append((relative_worktree, "relative undocumented worktree locator"))
        unknown = copy.deepcopy(self.accepted)
        unknown["undocumented"] = True
        cases.append((unknown, "unknown key"))
        for value, label in cases:
            with self.subTest(case=label):
                self._assert_parity_rejects(value, label)

    def test_schema_consumer_parity_oracle_covers_all_canonical_terminal_shapes(self) -> None:
        """No canonical terminal shape is rejected by the consumer key contract."""
        for label, value in (
            ("ACCEPTANCE_READY", self.accepted),
            ("STOPPED-minimum", self._stopped()),
            ("STOPPED-maximum", self._stopped(candidate=True)),
        ):
            with self.subTest(terminal=label):
                self._assert_parity_accepts(value, label)

    def test_semantic_negative_controls_remain_fail_closed(self) -> None:
        stale_candidate = copy.deepcopy(self.fixture.result)
        stale_candidate["candidate_head"] = "0" * 40
        with self.assertRaises(GovernanceBlockerError):
            ingest_runner_result(self.fixture.contract, stale_candidate)

        stale_review = copy.deepcopy(self.fixture.review)
        stale_review["reviewed_head"] = "0" * 40
        with self.assertRaises(ReviewStaleError):
            prepare_gate_b(self.fixture.contract, self.accepted, stale_review)


if __name__ == "__main__":
    unittest.main()
