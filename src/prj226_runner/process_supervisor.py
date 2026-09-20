"""Bounded subprocess execution with process-group quiescence evidence."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Sequence

from prj226_runner.errors import AgentExecutionError, GovernanceBlockerError


@dataclass
class SupervisionEvidence:
    leader_pid: int
    pgid: int
    observed_group_members: list[int] = field(default_factory=list)
    timeout_event: bool = False
    term_event: bool = False
    survivors_after_term: list[int] = field(default_factory=list)
    kill_event: bool = False
    survivors_after_kill: list[int] = field(default_factory=list)
    final_group_quiescent: bool = False


@dataclass
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    supervision: SupervisionEvidence
    output_flood: bool = False


def _group_members(pgid: int) -> list[int]:
    members = []
    proc = "/proc"
    try:
        entries = os.listdir(proc)
    except OSError:
        return members
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, "stat"), encoding="utf-8") as handle:
                fields = handle.read().split()
            if len(fields) > 4 and int(fields[4]) == pgid and fields[2] != "Z":
                members.append(int(entry))
        except (OSError, ValueError):
            continue
    return sorted(members)


class SupervisedProcessRunner:
    def __init__(self, *, stdout_limit: int = 8 * 1024 * 1024, stderr_limit: int = 8 * 1024 * 1024,
                 term_grace: float = 2.0, kill_grace: float = 1.0) -> None:
        self.stdout_limit, self.stderr_limit = stdout_limit, stderr_limit
        self.term_grace, self.kill_grace = term_grace, kill_grace

    def _quiesce(self, evidence: SupervisionEvidence) -> None:
        evidence.observed_group_members = _group_members(evidence.pgid)
        try:
            os.killpg(evidence.pgid, 0)
        except ProcessLookupError:
            evidence.final_group_quiescent = True
            return
        except PermissionError:
            pass
        evidence.term_event = True
        try:
            os.killpg(evidence.pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + self.term_grace
        while time.monotonic() < deadline:
            try:
                os.killpg(evidence.pgid, 0)
            except ProcessLookupError:
                evidence.final_group_quiescent = True
                return
            except PermissionError:
                pass
            time.sleep(0.05)
        evidence.survivors_after_term = _group_members(evidence.pgid) or [evidence.pgid]
        evidence.kill_event = True
        try:
            os.killpg(evidence.pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + self.kill_grace
        while time.monotonic() < deadline:
            try:
                os.killpg(evidence.pgid, 0)
            except ProcessLookupError:
                evidence.final_group_quiescent = True
                return
            except PermissionError:
                # macOS may report EPERM for an otherwise existing private
                # group; the post-KILL member scan remains authoritative there.
                if not _group_members(evidence.pgid):
                    evidence.final_group_quiescent = True
                    return
            time.sleep(0.05)
        evidence.survivors_after_kill = _group_members(evidence.pgid) or [evidence.pgid]
        evidence.final_group_quiescent = False
        raise GovernanceBlockerError("BLOCK_PROCESS_SURVIVORS_DETECTED", {"supervision": evidence})

    def run(self, argv: Sequence[str], *, timeout: float | None = None, env: dict[str, str] | None = None,
            cwd: str | None = None) -> ProcessResult:
        proc = subprocess.Popen(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env=env, cwd=cwd)
        evidence = SupervisionEvidence(proc.pid, proc.pid)
        selector = selectors.DefaultSelector()
        assert proc.stdout and proc.stderr
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": self.stdout_limit, "stderr": self.stderr_limit}
        started = time.monotonic()
        flood = False
        timed_out = False
        try:
            while selector.get_map():
                if timeout is not None and time.monotonic() - started >= timeout:
                    timed_out = evidence.timeout_event = True
                    break
                events = selector.select(0.05)
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    outputs[name].extend(chunk)
                    if len(outputs[name]) > limits[name]:
                        flood = True
                        break
                if flood:
                    break
                # A leader can exit while descendants keep inherited pipes open.
                # Group quiescence must be checked immediately, not after EOF.
                if proc.poll() is not None:
                    break
            if timed_out or flood:
                self._quiesce(evidence)
                if proc.poll() is None:
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            else:
                proc.wait()
                self._quiesce(evidence)
        finally:
            selector.close()
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            proc.wait()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        result = ProcessResult(proc.returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]), evidence, flood)
        if flood:
            raise AgentExecutionError("Process log limit exceeded while streaming", {"supervision": evidence})
        return result
