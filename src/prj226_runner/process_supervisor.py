"""Bounded subprocess execution with process-group quiescence evidence."""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
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


def _proc_group_members(pgid: int) -> tuple[list[int], list[int]] | None:
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    members, zombies = [], []
    try:
        entries = os.listdir(proc)
    except OSError:
        return None
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            fields = Path(proc / entry / "stat").read_text(encoding="utf-8")
            match = re.match(r"^(\d+) \(.*\) (\S) \d+ (\d+)", fields)
            if match and int(match.group(3)) == pgid:
                pid = int(entry)
                (zombies if match.group(2) == "Z" else members).append(pid)
        except (OSError, ValueError):
            continue
    return sorted(members), sorted(zombies)


def _inspect_group(pgid: int) -> tuple[bool, list[int], list[int]]:
    """Return (available, running members, zombie members)."""
    try:
        completed = subprocess.run(
            ["/bin/ps", "-A", "-o", "pid,pgid,state"],
            capture_output=True, text=True, timeout=2.0, check=False,
        )
        if completed.returncode == 0:
            members, zombies = [], []
            for line in completed.stdout.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 3:
                    continue
                try:
                    pid, member_pgid = int(fields[0]), int(fields[1])
                except ValueError:
                    continue
                if member_pgid == pgid:
                    (zombies if fields[2].startswith("Z") else members).append(pid)
            return True, sorted(members), sorted(zombies)
    except (OSError, subprocess.TimeoutExpired):
        pass
    fallback = _proc_group_members(pgid)
    if fallback is None:
        return False, [], []
    return True, *fallback


def _group_members(pgid: int) -> list[int]:
    available, members, zombies = _inspect_group(pgid)
    return sorted(members + zombies) if available else []


class SupervisedProcessRunner:
    def __init__(self, *, stdout_limit: int = 8 * 1024 * 1024, stderr_limit: int = 8 * 1024 * 1024,
                 term_grace: float = 2.0, kill_grace: float = 1.0) -> None:
        self.stdout_limit, self.stderr_limit = stdout_limit, stderr_limit
        self.term_grace, self.kill_grace = term_grace, kill_grace

    def _reap_leader(self, proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None or proc.poll() is None:
            return
        try:
            proc.wait(timeout=min(max(self.kill_grace, 0.05), 1.0))
        except subprocess.TimeoutExpired:
            pass

    def _quiesce(self, evidence: SupervisionEvidence, proc: subprocess.Popen[bytes] | None = None) -> None:
        available, members, zombies = _inspect_group(evidence.pgid)
        evidence.observed_group_members = sorted(members + zombies) if available else []
        if available and not members and not zombies:
            evidence.final_group_quiescent = True
            return
        try:
            os.killpg(evidence.pgid, 0)
        except ProcessLookupError:
            # ESRCH is direct proof that the tracked group is empty.
            evidence.final_group_quiescent = True
            return
        except PermissionError:
            # EPERM proves only that a group-related permission check failed.
            # It is never evidence that the group is empty.
            pass
        evidence.term_event = True
        try:
            os.killpg(evidence.pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + self.term_grace
        while time.monotonic() < deadline:
            available, members, zombies = _inspect_group(evidence.pgid)
            if available and not members and not zombies:
                evidence.final_group_quiescent = True
                return
            try:
                os.killpg(evidence.pgid, 0)
            except ProcessLookupError:
                evidence.final_group_quiescent = True
                return
            except PermissionError:
                pass
            time.sleep(0.05)
        self._reap_leader(proc)
        available, members, zombies = _inspect_group(evidence.pgid)
        evidence.survivors_after_term = sorted(members + zombies) if available else [evidence.pgid]
        evidence.kill_event = True
        try:
            os.killpg(evidence.pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + self.kill_grace
        while time.monotonic() < deadline:
            available, members, zombies = _inspect_group(evidence.pgid)
            if available and not members and not zombies:
                evidence.final_group_quiescent = True
                return
            try:
                os.killpg(evidence.pgid, 0)
            except ProcessLookupError:
                evidence.final_group_quiescent = True
                return
            except PermissionError:
                pass
            time.sleep(0.05)
        self._reap_leader(proc)
        available, members, zombies = _inspect_group(evidence.pgid)
        evidence.survivors_after_kill = sorted(members + zombies) if available else [evidence.pgid]
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
                self._quiesce(evidence, proc)
                if proc.poll() is None:
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1)
            else:
                proc.wait()
                self._quiesce(evidence, proc)
        finally:
            selector.close()
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        result = ProcessResult(proc.returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]), evidence, flood)
        if flood:
            raise AgentExecutionError("Process log limit exceeded while streaming", {"supervision": evidence})
        return result
