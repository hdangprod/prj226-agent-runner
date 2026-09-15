"""PRJ226 Supervised Process Isolation Boundary for OpenHands.

Ported directly from accepted OH-Q001 qualification authority:
- Dedicated process group / session (os.setsid)
- Execution nonce tracking (PRJ226_PROCESS_NONCE=<uuid>)
- Isolated ephemeral HOME and CODEX_HOME
- Strict environment variable allowlisting (blocks inherited MCP/provider credentials)
- Private pipe FD for session key transport
- Dual-source macOS process inspection (libproc + sysctl KERN_PROCARGS2)
- Fail-closed quiescence verification barrier
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

# Native macOS C libraries
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libproc = ctypes.CDLL(ctypes.util.find_library("proc"), use_errno=True)

CTL_KERN = 1
KERN_PROCARGS2 = 49
PROC_ALL_PIDS = 1


class ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("pbi_e_unum", ctypes.c_uint32),
        ("pbi_e_gnum", ctypes.c_uint32),
    ]


def _get_ancestor_pids() -> Set[int]:
    """Return the set of PIDs comprising current process and its ancestors up to PID 1."""
    ancestors = {os.getpid()}
    try:
        ancestors.add(os.getppid())
        p = os.getpid()
        while p > 1:
            out = subprocess.run(
                ["ps", "-o", "ppid=", "-p", str(p)],
                capture_output=True,
                text=True,
                timeout=0.5,
                check=False,
            )
            if out.returncode != 0:
                break
            val = out.stdout.strip()
            if not val.isdigit():
                break
            ppid = int(val)
            if ppid in ancestors or ppid < 1:
                break
            ancestors.add(ppid)
            p = ppid
    except Exception:
        ancestors.add(os.getppid())
    return ancestors


def _get_all_pids() -> List[int]:
    """Enumerate system PIDs using libproc.proc_listpids. Fail-closed on error."""
    needed = libproc.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
    if needed <= 0:
        raise RuntimeError(f"libproc.proc_listpids query failed with code {needed}")
    buf = (ctypes.c_int * (needed // 4))()
    ret = libproc.proc_listpids(PROC_ALL_PIDS, 0, buf, needed)
    if ret <= 0:
        raise RuntimeError(f"libproc.proc_listpids population failed with code {ret}")
    return [buf[i] for i in range(ret // 4) if buf[i] > 0]


def _get_proc_args_and_env(pid: int) -> Tuple[Optional[str], Optional[List[str]], Optional[Dict[str, str]], int]:
    """Inspect process executable path, argv, and env using sysctl KERN_PROCARGS2."""
    mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
    size = ctypes.c_size_t(0)
    res = libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0)
    if res != 0 or size.value == 0:
        return None, None, None, ctypes.get_errno()

    buf = ctypes.create_string_buffer(size.value)
    res2 = libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0)
    if res2 != 0:
        return None, None, None, ctypes.get_errno()

    data = buf.raw
    if len(data) < 4:
        return None, None, None, -1

    argc = int.from_bytes(data[:4], byteorder="little")
    idx = 4
    while idx < len(data) and data[idx] != 0:
        idx += 1
    exec_path = data[4:idx].decode("utf-8", "replace")

    while idx < len(data) and data[idx] == 0:
        idx += 1

    args = []
    for _ in range(argc):
        start = idx
        while idx < len(data) and data[idx] != 0:
            idx += 1
        args.append(data[start:idx].decode("utf-8", "replace"))
        idx += 1

    envs: Dict[str, str] = {}
    while idx < len(data):
        start = idx
        while idx < len(data) and data[idx] != 0:
            idx += 1
        if start == idx:
            break
        entry = data[start:idx].decode("utf-8", "replace")
        idx += 1
        if "=" in entry:
            k, v = entry.split("=", 1)
            envs[k] = v

    return exec_path, args, envs, 0


class OpenHandsProcessSupervisor:
    """Supervises the OpenHands Agent Server process group with authoritative quiescence."""

    def __init__(
        self,
        run_id: str,
        session_key: str,
        isolated_home: Path,
        isolated_codex_home: Path,
        deadline_seconds: float = 60.0,
    ) -> None:
        self.run_id = run_id
        self.session_key = session_key
        self.isolated_home = str(isolated_home.resolve())
        self.isolated_codex_home = str(isolated_codex_home.resolve())
        self.deadline_seconds = deadline_seconds
        self.nonce = f"prj226-oh-{run_id}-{uuid.uuid4().hex[:12]}"
        self.process: Optional[subprocess.Popen[Any]] = None
        self.pgid: Optional[int] = None
        self.pid: Optional[int] = None
        self.audit_log: List[Dict[str, Any]] = []

    def get_child_env(self, extra_env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        """Construct a minimal explicit allowlisted environment.

        Strictly locks protected keys (PATH, HOME, CODEX_HOME, TMPDIR, LANG, PRJ226_PROCESS_NONCE).
        Excludes inherited provider tokens, MCP variables, or unapproved host variables.
        """
        child_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": self.isolated_home,
            "CODEX_HOME": self.isolated_codex_home,
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "PRJ226_PROCESS_NONCE": self.nonce,
            "ACP_PROMPT_MAX_RETRIES": "0",
        }
        if extra_env:
            for k, v in extra_env.items():
                if k in ("PYTHONUNBUFFERED", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"):
                    child_env[k] = str(v)
        return child_env

    def spawn_server_with_key_pipe(
        self,
        base_command: List[str],
        port: int,
        cwd: Path,
        env_overrides: Optional[Mapping[str, str]] = None,
    ) -> Tuple[int, int]:
        """Spawn the Agent Server with private anonymous pipe passing session API key.

        Returns (pid, port).
        """
        pipe_r, pipe_w = os.pipe()
        child_env = self.get_child_env(env_overrides)
        child_env["SESSION_KEY_FD"] = str(pipe_r)

        cmd = list(base_command) + [str(port), str(pipe_r)]

        def _preexec() -> None:
            os.setsid()

        self.process = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(pipe_r,),
            preexec_fn=_preexec,
        )

        # Write session key strictly once and close parent handles
        os.write(pipe_w, (self.session_key + "\n").encode("utf-8"))
        os.close(pipe_w)
        try:
            os.close(pipe_r)
        except OSError:
            pass

        self.pid = self.process.pid
        self.pgid = os.getpgid(self.pid)
        self.audit_log.append({
            "event": "PROCESS_SPAWNED",
            "pid": self.pid,
            "pgid": self.pgid,
            "port": port,
            "nonce": self.nonce,
        })
        return self.pid, port

    def terminate_boundary(self, timeout: float = 5.0) -> None:
        """Gracefully terminate process group with SIGTERM then escalate to SIGKILL."""
        if not self.pgid:
            return

        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

        start = time.time()
        while time.time() - start < timeout:
            if not self._is_pid_running(self.pid):
                break
            time.sleep(0.1)

        if self._is_pid_running(self.pid):
            try:
                os.killpg(self.pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

        if self.process:
            try:
                if self.process.stdout:
                    self.process.stdout.close()
                if self.process.stderr:
                    self.process.stderr.close()
                self.process.poll()
            except Exception:
                pass

    def _is_pid_running(self, pid: Optional[int]) -> bool:
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def find_associated_processes(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Dual-source process discovery using libproc and sysctl KERN_PROCARGS2.

        Fails closed on enumeration failure or inspection failure of an associated process.
        Returns: (associated_processes, inspection_ok)
        """
        associated: List[Dict[str, Any]] = []
        inspection_ok = True

        try:
            pids = _get_all_pids()
        except Exception as e:
            self.audit_log.append({"event": "PID_ENUMERATION_FAILED", "error": str(e)})
            return [], False

        ancestor_pids = _get_ancestor_pids()

        for pid in pids:
            if pid in ancestor_pids:
                continue

            is_in_pgid = False
            try:
                proc_pgid = os.getpgid(pid)
                if self.pgid is not None and proc_pgid == self.pgid:
                    is_in_pgid = True
            except (ProcessLookupError, PermissionError):
                pass

            exec_path, args, envs, err = _get_proc_args_and_env(pid)
            if err != 0:
                if err == 3:  # ESRCH: process exited
                    continue
                if is_in_pgid:
                    self.audit_log.append({
                        "event": "ASSOCIATED_INSPECTION_FAILED",
                        "pid": pid,
                        "pgid": self.pgid,
                        "errno": err,
                    })
                    inspection_ok = False
                continue

            match_reasons = []
            if is_in_pgid:
                match_reasons.append(f"process_group_{self.pgid}")

            if envs:
                if envs.get("PRJ226_PROCESS_NONCE") == self.nonce:
                    match_reasons.append(f"nonce_{self.nonce}")
                if envs.get("HOME") == self.isolated_home:
                    match_reasons.append("isolated_home_match")
                if envs.get("CODEX_HOME") == self.isolated_codex_home:
                    match_reasons.append("isolated_codex_home_match")

            if match_reasons:
                associated.append({
                    "pid": pid,
                    "pgid": is_in_pgid,
                    "cmd": " ".join(args) if args else (exec_path or ""),
                    "reasons": match_reasons,
                })

        return associated, inspection_ok

    def verify_process_quiescence(self, timeout: float = 5.0) -> Tuple[bool, List[int], bool]:
        """Verify authoritative process quiescence barrier.

        Returns: (quiescence_passed, remaining_pids, inspection_ok)
        """
        start = time.time()
        remaining_pids: List[int] = []
        inspection_ok = True

        while time.time() - start < timeout:
            associated, ok = self.find_associated_processes()
            inspection_ok = ok
            remaining_pids = [item["pid"] for item in associated]

            if not remaining_pids and inspection_ok:
                return True, [], True
            time.sleep(0.2)

        quiesced = (len(remaining_pids) == 0) and inspection_ok
        return quiesced, remaining_pids, inspection_ok
