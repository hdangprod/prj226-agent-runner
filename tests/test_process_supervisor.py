import signal
import sys
import time
import unittest

from prj226_runner.errors import AgentExecutionError
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
        result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run(
            ["/bin/sh", "-c", "trap '' TERM; sleep 100"], timeout=.1)
        self.assertTrue(result.supervision.final_group_quiescent)
        self.assertTrue(result.supervision.kill_event)
        self.assertTrue(result.supervision.survivors_after_term)

    def test_output_flood_enforced_while_streaming(self):
        with self.assertRaisesRegex(AgentExecutionError, "Process log limit exceeded"):
            SupervisedProcessRunner(stdout_limit=4096, term_grace=.2, kill_grace=.2).run(["/usr/bin/yes"])

    def test_timeout_escalation_and_bounded_wait(self):
        started = time.monotonic()
        result = SupervisedProcessRunner(term_grace=.2, kill_grace=.2).run([PYTHON, "-c", "import time; time.sleep(100)"], timeout=.1)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertTrue(result.supervision.timeout_event)
        self.assertTrue(result.supervision.final_group_quiescent)


if __name__ == "__main__":
    unittest.main()
