"""Candidate authority manifest generation and validation.

Schema: PRJ226.M2.FINGERPRINT_001.CANDIDATE.v1

Separates candidate authority (Git HEAD, TREE, REF, topology, approved changes,
tracked files manifest, and explicit transient artifact policy) from naive
whole-worktree hashing, while strictly enforcing candidate integrity and
reviewer mutation detection.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

from prj226_runner.errors import GovernanceBlockerError

SCHEMA_VERSION_CANDIDATE_AUTHORITY = "PRJ226.M2.FINGERPRINT_001.CANDIDATE.v1"


def _git(cwd: Path | str, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise GovernanceBlockerError(f"Git command failed: {' '.join(args)}: {stderr}") from exc


def compute_authority_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of candidate authority manifest fields."""
    body = {k: v for k, v in payload.items() if k != "authority_digest"}
    normalized = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def normalize_transient_paths(paths: Iterable[str]) -> list[str]:
    """Validate and normalize transient paths according to strict governance invariants."""
    normalized: list[str] = []
    for p in paths:
        if not isinstance(p, str):
            raise GovernanceBlockerError("Transient path must be a string")
        p_clean = p.strip().strip("/")
        if not p_clean or p_clean == "." or p_clean == "..":
            raise GovernanceBlockerError(f"Invalid transient path: {p!r}")
        parts = Path(p_clean).parts
        if ".." in parts:
            raise GovernanceBlockerError(f"Transient path cannot traverse directories: {p!r}")
        if parts[0] == ".git":
            raise GovernanceBlockerError(f"Transient path cannot target .git: {p!r}")
        if "*" in p_clean or "?" in p_clean:
            raise GovernanceBlockerError(f"Wildcards not allowed in transient path: {p!r}")
        normalized.append(p_clean)
    return sorted(set(normalized))


def is_under_transient(rel_path: str, transient_paths: list[str]) -> bool:
    """Check if relative path matches or is nested inside an authorized transient path."""
    for tp in transient_paths:
        if rel_path == tp or rel_path.startswith(tp + "/"):
            return True
    return False


def build_candidate_authority(
    repo: Path | str,
    candidate_head: str,
    candidate_ref: str,
    baseline_head: str,
    approved_changed_paths: Iterable[str],
    transient_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Construct a frozen candidate authority manifest binding Git truth, tracked files, and transient policy."""
    repo_path = Path(repo).resolve()
    head = _git(repo_path, ["rev-parse", candidate_head]).lower()
    tree = _git(repo_path, ["rev-parse", f"{head}^{{tree}}"]).lower()
    clean_transient = normalize_transient_paths(transient_paths or [])

    # Collect tracked files from candidate Git tree
    try:
        raw_tree = subprocess.run(
            ["git", "-C", str(repo_path), "ls-tree", "-r", "-z", head],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise GovernanceBlockerError(f"Failed to inspect candidate Git tree: {exc.stderr}") from exc

    tracked_manifest: list[dict[str, Any]] = []
    if raw_tree:
        for entry_str in raw_tree.split("\0"):
            if not entry_str:
                continue
            # Format: <mode> <type> <sha>\t<path>
            parts = entry_str.split("\t", 1)
            if len(parts) != 2:
                continue
            meta, rel_path = parts
            meta_parts = meta.split()
            if len(meta_parts) < 3:
                continue

            item_path = repo_path / rel_path
            if not item_path.exists() and not item_path.is_symlink():
                raise GovernanceBlockerError(f"Tracked file missing in worktree at freeze: {rel_path}")

            st = os.lstat(item_path)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(item_path)
                tracked_manifest.append({
                    "path": rel_path,
                    "type": "symlink",
                    "mode": stat.S_IMODE(st.st_mode),
                    "target": target,
                    "sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
                })
            elif stat.S_ISREG(st.st_mode):
                tracked_manifest.append({
                    "path": rel_path,
                    "type": "file",
                    "mode": stat.S_IMODE(st.st_mode),
                    "sha256": hashlib.sha256(item_path.read_bytes()).hexdigest(),
                })
            else:
                raise GovernanceBlockerError(f"Unsupported filesystem node in tracked tree: {rel_path}")

    tracked_manifest.sort(key=lambda x: x["path"])

    authority: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION_CANDIDATE_AUTHORITY,
        "candidate_head": head,
        "candidate_tree": tree,
        "candidate_ref": candidate_ref,
        "baseline_head": baseline_head.lower(),
        "approved_changed_paths": sorted(approved_changed_paths),
        "transient_paths": clean_transient,
        "tracked_manifest": tracked_manifest,
    }
    authority["authority_digest"] = compute_authority_digest(authority)
    return authority


def verify_candidate_authority(
    repo: Path,
    authority: Mapping[str, Any],
    expected_ref: str | None = None,
) -> None:
    """Verify candidate authority against current filesystem and Git state.

    Enforces:
    1. Schema version and authority digest integrity (fails closed if manifest is tampered).
    2. Exact Git HEAD, TREE, ref binding, topology, and approved changed paths.
    3. Exact content hash, mode, and type for all tracked files (including those under transient prefixes).
    4. Worktree filesystem cleanliness: no unsupported special nodes (FIFOs, sockets, device nodes),
       no symlink escapes outside the repository root.
    5. Untracked file policy: any untracked file or directory not explicitly covered by an approved
       transient path fails closed immediately.
    """
    if not isinstance(authority, (dict, Mapping)):
        raise GovernanceBlockerError("Candidate authority manifest must be a mapping")
    if authority.get("schema_version") != SCHEMA_VERSION_CANDIDATE_AUTHORITY:
        raise GovernanceBlockerError(f"Invalid candidate authority schema_version: {authority.get('schema_version')}")

    required_keys = {
        "schema_version",
        "candidate_head",
        "candidate_tree",
        "candidate_ref",
        "baseline_head",
        "approved_changed_paths",
        "transient_paths",
        "tracked_manifest",
        "authority_digest",
    }
    if not required_keys.issubset(authority.keys()):
        missing = sorted(required_keys - set(authority.keys()))
        raise GovernanceBlockerError(f"Candidate authority manifest missing required fields: {missing}")

    if not isinstance(authority["tracked_manifest"], list):
        raise GovernanceBlockerError("Candidate authority tracked_manifest must be a list")
    if not isinstance(authority["transient_paths"], list):
        raise GovernanceBlockerError("Candidate authority transient_paths must be a list")

    # Cryptographic digest verification
    expected_digest = compute_authority_digest(authority)
    if authority.get("authority_digest") != expected_digest:
        raise GovernanceBlockerError("Candidate authority digest mismatch: manifest has been tampered with")

    repo_path = Path(repo).resolve()

    # 1. Git truth invariants
    curr_head = _git(repo_path, ["rev-parse", "HEAD"]).lower()
    if curr_head != authority["candidate_head"].lower():
        raise GovernanceBlockerError(f"Candidate HEAD changed after freeze: {curr_head} != {authority['candidate_head']}")

    curr_tree = _git(repo_path, ["rev-parse", "HEAD^{tree}"]).lower()
    if curr_tree != authority["candidate_tree"].lower():
        raise GovernanceBlockerError(f"Candidate TREE changed after freeze: {curr_tree} != {authority['candidate_tree']}")

    cand_ref = authority.get("candidate_ref")
    if expected_ref is not None:
        if not cand_ref or cand_ref != expected_ref:
            raise GovernanceBlockerError(
                f"Candidate authority ref mismatch: expected {expected_ref}, observed {cand_ref}"
            )
    if cand_ref:
        ref_head = _git(repo_path, ["rev-parse", cand_ref]).lower()
        if ref_head != curr_head:
            raise GovernanceBlockerError(f"Candidate reference {cand_ref} does not point to candidate HEAD: {ref_head} != {curr_head}")

    # Topology check
    parents = _git(repo_path, ["rev-list", "--parents", "-n", "1", "HEAD"]).split()
    baseline = authority["baseline_head"].lower()
    if len(parents) == 2 and parents[1].lower() != baseline:
        raise GovernanceBlockerError("Candidate topology no longer has the baseline as its sole parent")

    # Changed paths diff against baseline
    if baseline != curr_head:
        changed = _git(repo_path, ["diff", "--name-only", f"{baseline}..{curr_head}"]).splitlines()
        if sorted(changed) != sorted(authority["approved_changed_paths"]):
            raise GovernanceBlockerError("Effective changed paths differ from frozen candidate")

    # Index cleanliness check
    staged = _git(repo_path, ["diff", "--cached", "--name-only"]).splitlines()
    if staged:
        raise GovernanceBlockerError(f"Candidate git index has staged changes: {staged}")

    # Tracked working-tree diff check
    unstaged = _git(repo_path, ["diff", "--name-only"]).splitlines()
    if unstaged:
        raise GovernanceBlockerError(f"Tracked files modified in candidate worktree: {unstaged}")

    # 2. Tracked manifest physical verification
    tracked_set: set[str] = set()
    for entry in authority["tracked_manifest"]:
        if not isinstance(entry, dict) or "path" not in entry or "sha256" not in entry:
            raise GovernanceBlockerError("Malformed entry in candidate authority tracked_manifest")
        rel_path = entry["path"]
        tracked_set.add(rel_path)
        item_path = repo_path / rel_path

        if not item_path.exists() and not item_path.is_symlink():
            raise GovernanceBlockerError(f"Tracked file missing in candidate worktree: {rel_path}")

        try:
            st = os.lstat(item_path)
        except OSError as exc:
            raise GovernanceBlockerError(f"Cannot stat tracked file {rel_path}: {exc}") from exc

        expected_type = entry.get("type", "file")
        if expected_type == "symlink":
            if not stat.S_ISLNK(st.st_mode):
                raise GovernanceBlockerError(f"Tracked symlink replaced by non-symlink: {rel_path}")
            target = os.readlink(item_path)
            target_sha = hashlib.sha256(target.encode("utf-8")).hexdigest()
            if target_sha != entry["sha256"]:
                raise GovernanceBlockerError(f"Tracked symlink target changed for {rel_path}")
        else:
            if stat.S_ISLNK(st.st_mode):
                raise GovernanceBlockerError(f"Tracked file replaced by symlink: {rel_path}")
            if not stat.S_ISREG(st.st_mode):
                raise GovernanceBlockerError(f"Tracked file is not a regular file: {rel_path}")
            # Mode check
            current_mode = stat.S_IMODE(st.st_mode)
            if "mode" in entry and current_mode != entry["mode"]:
                raise GovernanceBlockerError(
                    f"Tracked file mode changed for {rel_path}: {oct(current_mode)} != {oct(entry['mode'])}"
                )
            # Content hash check
            content_sha = hashlib.sha256(item_path.read_bytes()).hexdigest()
            if content_sha != entry["sha256"]:
                raise GovernanceBlockerError(f"Tracked file content modified for {rel_path}")

    # 3. Worktree walk: validate untracked artifacts, symlink escapes, special nodes
    transient_paths = authority["transient_paths"]

    for root, dirs, files in os.walk(repo_path, topdown=True):
        root_p = Path(root)
        if ".git" in dirs:
            dirs.remove(".git")

        for name in dirs + files:
            if name == ".git":
                continue
            item_p = root_p / name
            try:
                rel_path = str(item_p.relative_to(repo_path))
            except ValueError:
                continue
            if rel_path == ".git" or rel_path.startswith(".git/"):
                continue

            try:
                st = os.lstat(item_p)
            except OSError as exc:
                raise GovernanceBlockerError(f"Cannot stat path {rel_path}: {exc}") from exc

            # Disallow unsupported nodes (FIFOs, sockets, devices) anywhere in worktree
            if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                raise GovernanceBlockerError(f"Unsupported filesystem node found: {rel_path}")

            # Symlink escape verification
            if stat.S_ISLNK(st.st_mode):
                raw_target = os.readlink(item_p)
                t_path = Path(raw_target)
                if t_path.is_absolute():
                    raise GovernanceBlockerError(f"Symlink escapes repository root: {rel_path} -> {raw_target}")
                resolved = (item_p.parent / t_path).resolve()
                try:
                    resolved.relative_to(repo_path)
                except ValueError:
                    raise GovernanceBlockerError(f"Symlink escapes repository root: {rel_path} -> {raw_target}")

            # Directory vs file untracked checks
            if not stat.S_ISDIR(st.st_mode):
                if rel_path not in tracked_set:
                    if not is_under_transient(rel_path, transient_paths):
                        raise GovernanceBlockerError(f"Unknown untracked filesystem artifact: {rel_path}")
            else:
                # If directory is completely untracked and outside transient paths
                if not is_under_transient(rel_path, transient_paths):
                    if rel_path not in tracked_set and not any(p.startswith(rel_path + "/") for p in tracked_set):
                        raise GovernanceBlockerError(f"Unknown untracked directory: {rel_path}")
