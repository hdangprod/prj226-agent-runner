"""Single-writer journal with atomic, reconstructible state snapshots.

The journal is authoritative. A lagging snapshot can be replaced only with a
fully validated journal state. Torn journals and conflicting snapshots block;
neither is truncated or silently repaired.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from prj226_runner.control_protocol import (
    STRICT_VERSION,
    VERSION,
    closed,
    decode,
    digest,
    encode,
    reference,
    validate_state,
    validate_strict_event,
    validate_transition,
)
from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_file(path: Path, *, limit: int = 2 * 1024 * 1024) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ArtifactValidationError("Evidence must be a bounded single-link regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ArtifactValidationError("Evidence exceeds byte limit")
        return data
    finally:
        os.close(fd)


class ControlStore:
    def __init__(self, root: Path | str) -> None:
        raw = Path(root).absolute()
        if raw.is_symlink():
            raise GovernanceBlockerError("Controller root cannot be a symlink")
        self.root = raw.resolve()
        self._locked = False

    @contextmanager
    def writer(self) -> Iterator[None]:
        if self._locked:
            raise GovernanceBlockerError("CONTROLLER_BUSY")
        fd = os.open(self.root / "writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
                raise GovernanceBlockerError("Invalid controller lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise GovernanceBlockerError("CONTROLLER_BUSY") from exc
            self._locked = True
            yield
        finally:
            self._locked = False
            os.close(fd)

    def _require_writer(self) -> None:
        if not self._locked:
            raise GovernanceBlockerError("Controller mutation requires its writer lock")

    def _path(self, name: str) -> Path:
        if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."} or "\\" in name:
            raise ArtifactValidationError("Artifact locator must be a local filename")
        return self.root / name

    def artifact(self, name: str, value: Any) -> dict[str, str]:
        """Publish a complete immutable artifact; identical deterministic reuse is safe."""
        self._require_writer()
        path = self._path(name)
        payload = encode(value)
        ref = {"path": name, "sha256": hashlib.sha256(payload).hexdigest()}
        if path.exists() or path.is_symlink():
            if read_file(path) != payload:
                raise GovernanceBlockerError("Immutable artifact collision")
            return ref
        # Publish only after all bytes are durable. The writer lock excludes peers.
        self._atomic(path, payload)
        return ref

    def read_artifact(self, ref: dict[str, str]) -> Any:
        if isinstance(ref, dict) and "ref" in ref:
            if set(ref) != {"ref", "sha256"}:
                raise ArtifactValidationError("Invalid strict artifact reference")
            name = ref["ref"]
            if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."} or "\\" in name:
                raise ArtifactValidationError("Strict artifact locator must be a local filename")
        else:
            reference(ref)
            name = ref["path"]
        payload = read_file(self._path(name))
        if hashlib.sha256(payload).hexdigest() != ref["sha256"]:
            raise ArtifactValidationError("Controller artifact digest mismatch")
        return decode(payload)

    def _verify_strict_artifacts(self, state: dict[str, Any]) -> None:
        """Resolve every strict reference before its state event is published."""
        if state.get("schema_version") != STRICT_VERSION:
            return

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                if set(value) == {"ref", "sha256"}:
                    self.read_artifact(value)
                    return
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(state)

    def _atomic(self, path: Path, payload: bytes) -> None:
        self._require_writer()
        fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        # Interrupted temporary files are retained as evidence; never reused.
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(self.root)

    def _journal(self) -> list[dict[str, Any]]:
        raw = read_file(self.root / "events.ndjson", limit=16 * 1024 * 1024)
        if not raw or not raw.endswith(b"\n"):
            raise ArtifactValidationError("Incomplete controller journal")
        events: list[dict[str, Any]] = []
        previous = None
        for line in raw.splitlines():
            event = closed(decode(line), {"schema_version", "kind", "revision", "previous_digest", "state", "digest"}, "controller event")
            if event["revision"] != len(events) + 1:
                raise ArtifactValidationError("Controller event sequence/version mismatch")
            if event["schema_version"] == STRICT_VERSION:
                if events and events[-1]["schema_version"] != STRICT_VERSION:
                    raise ArtifactValidationError("Legacy and strict controller journals cannot be mixed")
                validate_strict_event(event, events[-1] if events else None)
            elif event["schema_version"] == VERSION:
                if events and events[-1]["schema_version"] != VERSION:
                    raise ArtifactValidationError("Legacy and strict controller journals cannot be mixed")
                if event["previous_digest"] != previous or digest({k:v for k,v in event.items() if k != "digest"}) != event["digest"]:
                    raise ArtifactValidationError("Controller event chain mismatch")
                validate_state(event["state"])
                if event["state"]["revision"] != event["revision"]:
                    raise ArtifactValidationError("State/event revision mismatch")
                if events:
                    validate_transition(events[-1]["state"], event["state"])
                elif event["state"]["phase"] != "START":
                    raise ArtifactValidationError("Controller journal must begin at START")
            else:
                raise ArtifactValidationError("Controller event sequence/version mismatch")
            events.append(event)
            previous = event["digest"]
        return events

    def load(self, *, recover: bool = False) -> dict[str, Any]:
        events = self._journal()
        latest = events[-1]["state"]
        snapshot_path = self.root / "state.json"
        try:
            snapshot = validate_state(decode(read_file(snapshot_path)))
        except FileNotFoundError:
            snapshot = None
        if snapshot is not None:
            revision = snapshot["revision"]
            if revision > len(events) or snapshot != events[revision - 1]["state"]:
                raise ArtifactValidationError("Snapshot conflicts with durable controller journal")
        # Strict R3C loads are normally made under the writer lock during
        # resume.  Rebuild the cache whenever that lock is held, even when a
        # caller did not spell out ``recover=True``; the journal remains the
        # sole authority.  Legacy callers retain their historical read-only
        # load behavior unless they request recovery explicitly.
        if snapshot != latest and latest.get("schema_version") == STRICT_VERSION and not self._locked:
            # A strict snapshot is explicitly a rebuildable cache.  Acquire
            # the same single-writer lock used by commits so a read-side
            # recovery cannot race another controller.
            with self.writer():
                return self.load(recover=True)
        if (recover or (self._locked and latest.get("schema_version") == STRICT_VERSION)) and snapshot != latest:
            self._require_writer()
            self._atomic(snapshot_path, encode(latest))
        return latest

    def commit(self, state: dict[str, Any], kind: str) -> dict[str, Any]:
        self._require_writer()
        validate_state(state)
        # A state event is never durable authority for an artifact whose
        # bytes have not already been resolved and digest-checked.
        self._verify_strict_artifacts(state)
        journal = self.root / "events.ndjson"
        previous = None
        if journal.exists():
            events = self._journal()
            if events[-1]["schema_version"] != state["schema_version"]:
                raise GovernanceBlockerError("Legacy and strict controller journals cannot be mixed")
            validate_transition(events[-1]["state"], state)
            previous = events[-1]["digest"]
        elif state["revision"] != 1 or state["phase"] != "START":
            raise GovernanceBlockerError("Controller must initialize at START revision 1")
        event = {"schema_version": state["schema_version"], "kind": kind, "revision": state["revision"], "previous_digest": previous, "state": state}
        event["digest"] = digest(event)
        fd = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(encode(event) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(self.root)
        self._atomic(self.root / "state.json", encode(state))
        return decode(encode(state))
