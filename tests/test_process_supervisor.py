import signal
import sys
import time
import unittest
from unittest import mock

from prj226_runner.errors import AgentExecutionError, GovernanceBlockerError
from prj226_runner.process_supervisor import SupervisionEvidence
from prj226_runner.process_supervisor import SupervisedProcessRunner


PYTHON = sys.executable


class ProcessSupervisorTests(unittest.TestCase):
    def test_normal_completion(self):
        result = SupervisedProcessRunner().run([PYTHON, "-c", "print('ok')"])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.supervision.final_group_quiescent)
        self.assertFalse(result.supervision.term_event)

    def test_parent_exits_while_child_survives(self):
        result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run(
            ["/bin/sh", "-c", "sleep 100 & exit 0"])
        self.assertTrue(result.supervision.final_group_quiescent)
        self.assertTrue(result.supervision.term_event)

    def test_child_ignores_sigterm(self):
        try:
            result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run(
                ["/bin/sh", "-c", "trap '' TERM; sleep 100"], timeout=.1)
        except GovernanceBlockerError as exc:
            # Restricted runners without either approved inspection source must
            # fail closed when a killed descendant remains unreaped.
            evidence = exc.details["supervision"]
            self.assertTrue(evidence.kill_event)
            self.assertFalse(evidence.final_group_quiescent)
        else:
            self.assertTrue(result.supervision.final_group_quiescent)
            self.assertTrue(result.supervision.kill_event)
            self.assertTrue(result.supervision.survivors_after_term)

    def test_permission_error_does_not_prove_quiescence(self):
        evidence = SupervisionEvidence(123, 123)
        with mock.patch("prj226_runner.process_supervisor._inspect_group", return_value=(False, [], [])), \
                mock.patch("prj226_runner.process_supervisor.os.killpg", side_effect=PermissionError):
            with self.assertRaises(GovernanceBlockerError):
                SupervisedProcessRunner(term_grace=.01, kill_grace=.01)._quiesce(evidence)

    def test_output_flood_enforced_while_streaming(self):
        with self.assertRaisesRegex(AgentExecutionError, "Process log limit exceeded"):
            SupervisedProcessRunner(stdout_limit=4096, term_grace=.2, kill_grace=.2).run(["/usr/bin/yes"])

    def test_timeout_escalation_and_bounded_wait(self):
        started = time.monotonic()
        result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run([PYTHON, "-c", "import time; time.sleep(100)"], timeout=.1)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertTrue(result.supervision.timeout_event)
        self.assertTrue(result.supervision.final_group_quiescent)

    def test_closed_streams_timeout_preserves_deadline(self):
        started = time.monotonic()
        result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run(
            [PYTHON, "-c", "import os, time; os.close(1); os.close(2); time.sleep(100)"],
            timeout=.1,
        )
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertTrue(result.supervision.timeout_event)
        self.assertTrue(result.supervision.final_group_quiescent)

    def test_closed_streams_prompt_exit_succeeds(self):
        result = SupervisedProcessRunner().run(
            [PYTHON, "-c", "import os; os.close(1); os.close(2)"],
            timeout=1,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.supervision.timeout_event)
        self.assertTrue(result.supervision.final_group_quiescent)


if __name__ == "__main__":
    unittest.main()
