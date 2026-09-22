"""Focused R3C lifecycle tests using deterministic role doubles."""

from __future__ import annotations

import hashlib
import json
import errno
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prj226_runner.control import DurableController, StrictExecutionController, _read_first_journal_line
from prj226_runner.control_protocol import STRICT_VERSION, _validate_strict_binding, strict_gate_binding
from prj226_runner.errors import ArtifactValidationError


def sandbox_is_usable() -> bool:
    if sys.platform != "darwin" or not os.path.exists("/usr/bin/sandbox-exec"):
        return False
    probe = subprocess.run(
        ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default)", sys.executable, "-c", "pass"],
        capture_output=True,
        check=False,
    )
    return probe.returncode == 0


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class PlannerDouble:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return {"session_id": "planner-session", "disposition": "SUCCESS", "exit_code": 0,
                "attested_session_id": "planner-session", "supervision": {"quiescent": True},
                "attestation_passed": True,
                "proposal": {"summary": "strict lifecycle", "scope": ["src/app.txt"]}}


class BuilderDouble:
    def __init__(self, *, sessions: list[str] | None = None, outside: bool = False, quiescent: bool = True) -> None:
        self.calls = 0
        self.sessions = sessions or []
        self.outside = outside
        self.quiescent = quiescent

    def execute(self, request):
        self.calls += 1
        Path(request.worktree, "src").mkdir(exist_ok=True)
        Path(request.worktree, "src/app.txt").write_text(f"attempt-{self.calls}\n", encoding="utf-8")
        if self.outside:
            Path(request.worktree, "unauthorized.txt").write_text("breach\n", encoding="utf-8")
        session = self.sessions[self.calls - 1] if self.calls <= len(self.sessions) else f"builder-{self.calls}"
        return {"session_id": session, "disposition": "SUCCESS", "exit_code": 0,
                "attested_session_id": session, "supervision": {"quiescent": self.quiescent},
                "attestation_passed": True}


class ReviewerDouble:
    def __init__(self, verdicts: list[str] | None = None) -> None:
        self.calls = 0
        self.verdicts = verdicts or ["PASS"]

    def execute(self, request):
        self.calls += 1
        verdict = self.verdicts[min(self.calls - 1, len(self.verdicts) - 1)]
        text = json.dumps({"verdict": verdict, "findings": []}, separators=(",", ":"))
        return {"session_id": f"reviewer-{self.calls}", "disposition": "SUCCESS", "exit_code": 0,
                "attested_session_id": f"reviewer-{self.calls}", "supervision": {"quiescent": True},
                "attestation_passed": True,
                "semantic_result": {"kind": "TEXT", "text": text, "message_count": 1,
                                     "sha256": hashlib.sha256(text.encode()).hexdigest()}}


class StrictLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ctrl-r3c-", dir="/private/tmp")
        self.root = Path(self.temp.name)
        self.repo = self.root / "product"
        self.repo.mkdir()
        subprocess.run(["git", "-C", str(self.repo), "init"], capture_output=True, check=True)
        git(self.repo, "config", "user.email", "r3c@example.test")
        git(self.repo, "config", "user.name", "R3C")
        (self.repo / "src").mkdir()
        (self.repo / "src/app.txt").write_text("base\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "base")
        self.baseline = {
            "repository": str(self.repo.resolve()),
            "branch": git(self.repo, "branch", "--show-current"),
            "head": git(self.repo, "rev-parse", "HEAD"),
            "tree": git(self.repo, "rev-parse", "HEAD^{tree}"),
        }
        self.planner = PlannerDouble()
        self.builder = BuilderDouble()
        self.reviewer = ReviewerDouble()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def require_sandbox(self) -> None:
        if not sandbox_is_usable():
            self.skipTest("sandbox-exec cannot be applied by this host runner")

    def controller(self, **kwargs):
        runtime = {"roles": {
            "planner": {"profile_ref": "planner-profile"},
            "builder": {"profile_ref": "builder-profile"},
            "reviewer": {"profile_ref": "reviewer-profile", "model": "gpt-6-astra"},
        }}
        return StrictExecutionController.start(
            self.root / kwargs.pop("name", "control"), controller_id="R3C-TEST", task_id="TASK-1",
            goal="strict lifecycle", baseline=self.baseline, scope=["src/app.txt"],
            contract=kwargs.pop("contract", {"commit_message": "candidate", "acceptance_instruments": []}),
            runtime=runtime, planner=kwargs.pop("planner", self.planner),
            builder=kwargs.pop("builder", self.builder), reviewer=kwargs.pop("reviewer", self.reviewer),
            verifier=kwargs.pop("verifier", None), max_repair_cycles=kwargs.pop("max_repair_cycles", 2),
            **kwargs,
        )

    def approve(self, controller: StrictExecutionController) -> dict:
        gate = controller.state()["pending_gate"]
        return controller.reply(gate_id=gate["gate_id"], revision=gate["revision"],
                                binding_digest=gate["binding_digest"], response="approve")

    def reach_gate_a(self, controller: StrictExecutionController) -> None:
        self.assertEqual(controller.resume()["phase"], "WAITING_HUMAN_GATE_A")
        self.approve(controller)

    def finish_gate_b(self, controller: StrictExecutionController) -> None:
        report = controller.resume()
        self.assertEqual(report["status"], "HUMAN_GATE_REQUIRED", report)
        self.approve(controller)
        self.assertEqual(controller.state()["terminal_reason"], "INTEGRATION_PREPARED_ONLY")

    def test_full_lifecycle_and_gate_bindings(self) -> None:
        self.require_sandbox()
        controller = self.controller()
        self.assertEqual(controller.state()["schema_version"], STRICT_VERSION)
        self.reach_gate_a(controller)
        self.finish_gate_b(controller)
        state = controller.state()
        self.assertEqual(state["phase"], "COMPLETE")
        self.assertEqual((state["planner_session"], state["builder_session"], state["reviewer_session"]),
                         ("planner-session", "builder-1", "reviewer-1"))
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.baseline["head"])
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_deterministic_failure_repairs_with_fresh_attempt(self) -> None:
        self.require_sandbox()
        command = [sys.executable, "-c", (
            "import os; from pathlib import Path; p=Path(os.environ['TMPDIR']) / 'verification-count'; "
            "n=int(p.read_text()) if p.exists() else 0; "
            "p.write_text(str(n+1)); raise SystemExit(1 if n == 0 else 0)"
        )]
        controller = self.controller(contract={"commit_message": "candidate", "acceptance_instruments": [command]})
        self.reach_gate_a(controller)
        report = controller.resume()
        self.assertEqual(report["status"], "HUMAN_GATE_REQUIRED")
        state = controller.state()
        self.assertEqual(state["attempt_index"], 1)
        self.assertEqual(state["repair_cycles"], 1)
        self.assertEqual(self.builder.calls, 2)
        self.assertEqual(controller.state()["phase"], "WAITING_HUMAN_GATE_B")
        self.approve(controller)
        self.assertEqual(controller.state()["phase"], "COMPLETE")

    @unittest.skipUnless(sandbox_is_usable(), "qualified sandbox-exec is required")
    def test_production_verifier_confines_repositories_scratch_and_descendant(self) -> None:
        canonical_target = self.repo / "production-canonical-write.txt"
        child_target = self.root / "production-child-write.txt"
        child_script = (
            "import errno, pathlib, sys\n"
            "target = pathlib.Path(sys.argv[1])\n"
            "try:\n"
            "    target.write_text('blocked')\n"
            "except OSError as exc:\n"
            "    if exc.errno != errno.EPERM:\n"
            "        raise\n"
            "else:\n"
            "    raise SystemExit(4)\n"
        )
        script = (
            "import errno, os, pathlib, subprocess, sys\n"
            "def assert_denied(target):\n"
            "    try:\n"
            "        target.write_text('blocked')\n"
            "    except OSError as exc:\n"
            "        if exc.errno != errno.EPERM:\n"
            "            raise\n"
            "    else:\n"
            "        raise SystemExit('write unexpectedly succeeded')\n"
            f"assert_denied(pathlib.Path({str(Path('production-candidate-write.txt'))!r}))\n"
            f"assert_denied(pathlib.Path({str(canonical_target)!r}))\n"
            "scratch = pathlib.Path(os.environ['TMPDIR'])\n"
            "(scratch / 'allowed.txt').write_text('allowed')\n"
            f"child = subprocess.run([sys.executable, '-c', {child_script!r}, {str(child_target)!r}], check=False)\n"
            "if child.returncode != 0:\n"
            "    raise SystemExit(child.returncode)\n"
        )
        controller = self.controller(
            name="production-confinement",
            contract={"commit_message": "candidate", "acceptance_instruments": [[sys.executable, "-c", script]]},
        )
        self.reach_gate_a(controller)
        report = controller.resume()
        self.assertEqual(report["status"], "HUMAN_GATE_REQUIRED", report)
        scratch_target = controller.store.root / "verifier-scratch" / "allowed.txt"
        candidate_target = Path(controller.state()["candidate"]["worktree"]) / "production-candidate-write.txt"
        self.assertTrue(scratch_target.is_file())
        self.assertFalse(canonical_target.exists())
        self.assertFalse(child_target.exists())
        self.assertFalse(candidate_target.exists())
        self.approve(controller)

    def test_reviewer_needs_fix_repairs_and_budget_exhaustion_blocks(self) -> None:
        self.require_sandbox()
        reviewer = ReviewerDouble(["NEEDS_FIX", "PASS"])
        controller = self.controller(reviewer=reviewer)
        self.reach_gate_a(controller)
        self.finish_gate_b(controller)
        self.assertEqual(reviewer.calls, 2)

        failing_verifier = lambda request: {"status": "FAIL", "eligible_repair": True, "reason": "test"}
        exhausted = self.controller(name="exhausted", verifier=failing_verifier)
        self.reach_gate_a(exhausted)
        result = exhausted.resume()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["terminal_reason"], "REPAIR_BUDGET_EXHAUSTED")
        self.assertEqual(exhausted.state()["attempt_index"], 2)
        self.assertEqual(self.builder.calls, 5)

    def test_prepared_and_started_recovery_never_replays_started_builder(self) -> None:
        controller = self.controller()
        self.reach_gate_a(controller)
        self.assertEqual(controller.resume(max_steps=1)["pending_action"]["status"], "PREPARED")
        resumed = StrictExecutionController(controller.store.root, builder=self.builder, planner=self.planner, reviewer=self.reviewer)
        resumed.resume(max_steps=1)
        self.assertEqual(self.builder.calls, 1)

        controller = self.controller(name="started-recovery")
        self.reach_gate_a(controller)
        controller.resume(max_steps=1)
        with patch.object(controller, "_complete_action", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                controller.resume(max_steps=1)
        self.assertEqual(controller.state()["pending_action"]["status"], "STARTED")
        action_id = controller.state()["pending_action"]["id"]
        self.assertTrue((controller.store.root / f"{action_id}.result.json").exists())
        resumed = StrictExecutionController(controller.store.root, builder=self.builder, planner=self.planner, reviewer=self.reviewer)
        resumed.resume(max_steps=1)
        self.assertEqual(self.builder.calls, 2)

    def test_scope_and_non_quiescence_fail_closed(self) -> None:
        scope_breach = self.controller(name="scope", builder=BuilderDouble(outside=True))
        self.reach_gate_a(scope_breach)
        self.assertEqual(scope_breach.resume()["status"], "BLOCKED")
        self.assertIn("SCOPE_BREACH", scope_breach.state()["terminal_reason"])

        non_quiescent = self.controller(name="quiescence", builder=BuilderDouble(quiescent=False))
        self.reach_gate_a(non_quiescent)
        self.assertEqual(non_quiescent.resume()["status"], "BLOCKED")

    def test_duplicate_session_id_is_governance_block(self) -> None:
        builder = BuilderDouble(sessions=["planner-session", "builder-2"])
        controller = self.controller(builder=builder)
        self.reach_gate_a(controller)
        self.assertEqual(controller.resume()["status"], "BLOCKED")
        self.assertIn("duplicate session", controller.state()["terminal_reason"].lower())

    def test_missing_explicit_attested_session_id_fails_closed(self) -> None:
        controller = self.controller(name="missing-attestation")
        receipt = controller._normalize_receipt(
            {
                "session_id": "session-1",
                "disposition": "SUCCESS",
                "exit_code": 0,
                "supervision": {"quiescent": True},
                "attestation_passed": True,
            },
            "builder",
        )
        self.assertFalse(receipt["ok"])
        self.assertIsNone(receipt["attested_session_id"])
        self.assertEqual(receipt["failure_reason"], "SESSION_ATTESTATION_MISMATCH")

    def test_missing_planner_proposal_fails_closed(self) -> None:
        with self.assertRaisesRegex(ArtifactValidationError, "affirmative proposal"):
            StrictExecutionController._planner_proposal(
                {"session_id": "planner-session"},
                {"goal": "strict lifecycle", "scope": ["src/app.txt"]},
            )

    def test_gate_a_binding_rejects_repair_budget_above_authoritative_cap(self) -> None:
        controller = self.controller(name="invalid-gate-binding")
        binding = strict_gate_binding(controller.state(), "GATE_A")
        binding["repair_policy"]["max_repair_cycles"] = 3
        with self.assertRaisesRegex(ArtifactValidationError, "cannot exceed 2"):
            _validate_strict_binding(binding, "GATE_A")

    def test_first_journal_event_streams_through_two_mebibytes(self) -> None:
        journal = self.root / "streaming-journal.ndjson"
        for size in (1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 2 * 1024 * 1024 - 1, 2 * 1024 * 1024):
            with self.subTest(size=size):
                event = b"x" * size
                journal.write_bytes(event + b"\n" + b"tail")
                self.assertEqual(_read_first_journal_line(journal), event)

    def test_first_journal_event_over_two_mebibytes_is_rejected(self) -> None:
        journal = self.root / "oversized-event.ndjson"
        journal.write_bytes(b"x" * (2 * 1024 * 1024 + 1) + b"\n")
        with self.assertRaisesRegex(ArtifactValidationError, "2 MiB"):
            _read_first_journal_line(journal)

    def test_large_journal_with_small_first_event_is_accepted(self) -> None:
        journal = self.root / "large-journal.ndjson"
        first_event = json.dumps({"schema_version": STRICT_VERSION}, separators=(",", ":")).encode()
        journal.write_bytes(first_event + b"\n" + b"x" * (2 * 1024 * 1024))
        self.assertEqual(_read_first_journal_line(journal), first_event)

    def test_journal_over_sixteen_mebibytes_is_rejected(self) -> None:
        journal = self.root / "too-large-journal.ndjson"
        journal.write_bytes(b"{}\n" + b"x" * (16 * 1024 * 1024))
        with self.assertRaisesRegex(ArtifactValidationError, "bounded"):
            _read_first_journal_line(journal)

    def test_malformed_first_controller_event_is_rejected(self) -> None:
        journal_root = self.root / "malformed-journal"
        journal_root.mkdir()
        (journal_root / "events.ndjson").write_bytes(b"not-json\n")
        with self.assertRaises(ArtifactValidationError):
            DurableController(journal_root)._strict_delegate()

    def test_strict_delegate_accepts_journal_between_two_and_sixteen_mebibytes(self) -> None:
        journal_root = self.root / "large-journal"
        journal_root.mkdir()
        first_event = json.dumps({"schema_version": STRICT_VERSION}, separators=(",", ":")).encode()
        (journal_root / "events.ndjson").write_bytes(
            first_event + b"\n" + b"x" * (2 * 1024 * 1024)
        )
        delegate = DurableController(journal_root)._strict_delegate()
        self.assertIsInstance(delegate, StrictExecutionController)


if __name__ == "__main__":
    unittest.main()
