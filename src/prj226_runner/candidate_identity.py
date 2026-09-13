"""PRJ226 Candidate Identity and Ref Safety.

Single version-aware derivation authority for candidate references across:
- preflight / inspect
- builder worktree creation
- execution adaptation
- candidate authority
- reviewer prompt and verification
- runner result
- controller ingestion and validation
- Gate B package validation

Derivation rules:
- Historical V1 / V2:
    harn-candidate/{safe_task}-{safe_run}
- New V3 authority:
    harn-candidate/v3-{safe_task}-{safe_run}-{contract_hash}
  Uniqueness is provided by the full, lowercase 64-hex SHA-256 hash of the frozen Design Contract.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

from prj226_runner.errors import (
    ArtifactValidationError,
    GovernanceBlockerError,
)

V1_CONTRACT_VERSION = "HARN-002.v1"
V2_CONTRACT_VERSION = "HARN-002.v2"
V3_CONTRACT_VERSION = "HARN-002.v3"

V2_PACKET_VERSION = "HARN-001.TASK_PACKET.v2"
V3_PACKET_VERSION = "HARN-001.TASK_PACKET.v3"

CANDIDATE_PREFIX = "harn-candidate/"
V3_CANDIDATE_PREFIX = "harn-candidate/v3-"

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
LABEL_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def normalize_label(label: str, fallback: str) -> str:
    """Normalize human-readable label for ref syntax without providing uniqueness."""
    if not isinstance(label, str):
        return fallback
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip(".-")
    return safe if safe else fallback


def validate_candidate_ref(ref: str) -> None:
    """Validate that candidate ref strictly adheres to Git ref rules and candidate invariants.
    
    Rejects:
    - empty / non-string
    - missing 'harn-candidate/' prefix
    - traversal-like syntax ('..')
    - invalid separators ('//', trailing '/')
    - control characters (ord < 32 or ord == 127)
    - whitespace (spaces, tabs, newlines)
    - Git-forbidden revision characters ('~', '^', ':', '?', '*', '[', ']', '\', '@')
    - empty path components
    - components starting with '.' or ending with '.lock' or '.'
    - for V3 refs: missing or malformed full 64-hex contract hash
    """
    if not isinstance(ref, str) or not ref:
        raise ArtifactValidationError("Candidate ref must be a non-empty string")
    if not ref.startswith(CANDIDATE_PREFIX):
        raise ArtifactValidationError(f"Candidate ref must start with '{CANDIDATE_PREFIX}': {ref}")
    if ".." in ref:
        raise ArtifactValidationError(f"Candidate ref contains '..' traversal syntax: {ref}")
    if "//" in ref or ref.endswith("/"):
        raise ArtifactValidationError(f"Candidate ref contains invalid slash separators: {ref}")
    if any(ord(c) < 32 or ord(c) == 127 for c in ref):
        raise ArtifactValidationError(f"Candidate ref contains control characters: {ref!r}")
    if any(c.isspace() for c in ref):
        raise ArtifactValidationError(f"Candidate ref contains whitespace: {ref!r}")
    for ch in ("~", "^", ":", "?", "*", "[", "]", "\\", "@"):
        if ch in ref:
            raise ArtifactValidationError(f"Candidate ref contains invalid Git ref character '{ch}': {ref}")

    components = ref.split("/")
    for comp in components:
        if not comp:
            raise ArtifactValidationError(f"Candidate ref contains empty path component: {ref}")
        if comp.startswith("."):
            raise ArtifactValidationError(f"Candidate ref component starts with dot: {comp}")
        if comp.endswith(".lock"):
            raise ArtifactValidationError(f"Candidate ref component ends with .lock: {comp}")
        if comp.endswith("."):
            raise ArtifactValidationError(f"Candidate ref component ends with dot: {comp}")

    if ref.startswith(V3_CANDIDATE_PREFIX):
        suffix = ref[len(V3_CANDIDATE_PREFIX):]
        parts = suffix.rsplit("-", 1)
        if len(parts) != 2 or not SHA256_HEX_RE.fullmatch(parts[1]):
            raise ArtifactValidationError(
                f"V3 candidate ref must end with 64-char lowercase hex contract hash: {ref}"
            )
        labels = parts[0]
        if not LABEL_SAFE_RE.fullmatch(labels):
            raise ArtifactValidationError(f"V3 candidate ref contains invalid characters in labels: {ref}")


def assert_candidate_ref_available(repo: Path | str, ref: str) -> None:
    """Check that the intended candidate ref does not already exist anywhere in the target repository.
    
    If the ref exists, STOP immediately with GovernanceBlockerError.
    Even if it points to the expected commit.
    Automatic adoption, reset, overwrite, deletion, or alternate-naming is prohibited.
    """
    repo_path = Path(repo).resolve()
    if not repo_path.is_dir() or not (repo_path / ".git").exists():
        raise GovernanceBlockerError(f"Target repository not found or not a git repository: {repo_path}")

    for check_target in (f"refs/heads/{ref}", f"refs/{ref}", ref):
        res = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--verify", "--quiet", check_target],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        if res.returncode == 0:
            commit = res.stdout.strip()
            raise GovernanceBlockerError(
                f"Candidate ref already exists in target repository: {ref} (points to {commit}). "
                "Automatic adoption, reset, overwrite, deletion, or renaming is strictly prohibited."
            )


def derive_candidate_ref(
    *,
    authority_version: str,
    task_id: str,
    run_id: str,
    contract_hash: str | None = None,
) -> str:
    """Single semantic authority for deriving candidate refs based on version.
    
    V1: harn-candidate/{safe_task}-{safe_run}
    V2: harn-candidate/{safe_task}-{safe_run}
    V3: harn-candidate/v3-{safe_task}-{safe_run}-{contract_hash}
    """
    if not isinstance(authority_version, str) or not authority_version.strip():
        raise ArtifactValidationError("authority_version must be a non-empty string")

    safe_task = normalize_label(task_id, "task")
    safe_run = normalize_label(run_id, "run")

    ver = authority_version.strip()
    if ver in {V1_CONTRACT_VERSION, "v1", "V1"}:
        ref = f"harn-candidate/{safe_task}-{safe_run}"
    elif ver in {V2_CONTRACT_VERSION, V2_PACKET_VERSION, "v2", "V2"}:
        ref = f"harn-candidate/{safe_task}-{safe_run}"
    elif ver in {V3_CONTRACT_VERSION, V3_PACKET_VERSION, "v3", "V3"}:
        if not contract_hash or not isinstance(contract_hash, str) or not SHA256_HEX_RE.fullmatch(contract_hash):
            raise ArtifactValidationError(
                "V3 candidate ref derivation requires valid 64-char lowercase hex contract_hash"
            )
        ref = f"harn-candidate/v3-{safe_task}-{safe_run}-{contract_hash}"
    else:
        raise ArtifactValidationError(f"Unsupported authority version for candidate ref derivation: {authority_version}")

    validate_candidate_ref(ref)
    return ref


def derive_candidate_ref_for_contract(contract: Mapping[str, Any]) -> str:
    """Derive candidate ref directly from a validated Design Contract mapping."""
    if not isinstance(contract, Mapping):
        raise ArtifactValidationError("Design Contract must be a mapping")
    version = contract.get("contract_version")
    if not version or not isinstance(version, str):
        raise ArtifactValidationError("Design Contract missing contract_version")
    task_id = contract.get("work_item_id") or contract.get("task_id")
    if not task_id or not isinstance(task_id, str):
        raise ArtifactValidationError("Design Contract missing task/work_item identity")
    run_id = contract.get("run_id")
    if not run_id or not isinstance(run_id, str):
        raise ArtifactValidationError("Design Contract missing run_id")
    contract_hash = contract.get("contract_hash")
    return derive_candidate_ref(
        authority_version=version,
        task_id=task_id,
        run_id=run_id,
        contract_hash=contract_hash,
    )


def derive_candidate_ref_for_packet(packet: Any) -> str:
    """Derive candidate ref directly from a TaskPacket instance or mapping."""
    if hasattr(packet, "packet_version"):
        version = packet.packet_version
        task_id = packet.task_id
        run_id = packet.run_id
        contract_hash = getattr(packet, "contract_hash", None)
    elif isinstance(packet, Mapping):
        version = packet.get("packet_version")
        task_id = packet.get("task_id")
        run_id = packet.get("run_id")
        contract_hash = packet.get("contract_hash")
        if not version:
            version = "v1"
    else:
        task_id = getattr(packet, "task_id", None)
        run_id = getattr(packet, "run_id", None)
        version = "v1"
        contract_hash = None

    if not task_id or not isinstance(task_id, str):
        raise ArtifactValidationError("Task Packet missing task_id")
    if not run_id or not isinstance(run_id, str):
        raise ArtifactValidationError("Task Packet missing run_id")

    return derive_candidate_ref(
        authority_version=version,
        task_id=task_id,
        run_id=run_id,
        contract_hash=contract_hash,
    )
