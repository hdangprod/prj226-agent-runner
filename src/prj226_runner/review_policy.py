"""Pure V2 review-policy validation and static selection helpers.

No subprocess, no filesystem access, no provider calls. All functions are
deterministic and fail closed on malformed input.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from prj226_runner.errors import ArtifactValidationError
from prj226_runner.models import ReviewMode, ReviewStatus


TARGETED_CATEGORIES = frozenset({
    "PUBLIC_INTERFACE",
    "AUTHORIZATION_DATA_ACCESS",
    "PERSISTENT_DATA_SEMANTICS",
    "MODULE_BOUNDARY",
    "BEHAVIOR_PRESERVING_REFACTOR",
})

REVIEWER_DESCRIPTOR_KEYS = frozenset({
    "tool",
    "provider",
    "model",
    "executable",
    "resolved_executable",
    "executable_sha256",
    "reviewer_profile",
    "reviewer_profile_hash",
    "output_schema",
    "output_schema_sha256",
    "timeout_seconds",
    "review_brief",
})


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def review_policy_hash(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(dict(policy)).encode("utf-8")).hexdigest()


def select_review_mode(
    change_categories: list[str],
    human_requested_targeted: bool,
) -> str:
    """Static frozen selection. No LLM, no diff, no filename inference."""
    if not isinstance(change_categories, list) or not isinstance(human_requested_targeted, bool):
        raise ArtifactValidationError("review selection inputs are malformed")
    for item in change_categories:
        if not isinstance(item, str) or not item.strip():
            raise ArtifactValidationError("change_categories must be an array of non-empty strings")
    if len(set(change_categories)) != len(change_categories):
        raise ArtifactValidationError("change_categories must not contain duplicates")
    if human_requested_targeted:
        return ReviewMode.TARGETED.value
    for category in change_categories:
        if category in TARGETED_CATEGORIES:
            return ReviewMode.TARGETED.value
    return ReviewMode.NONE.value


def normalize_reviewer_descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(REVIEWER_DESCRIPTOR_KEYS):
        raise ArtifactValidationError("reviewer descriptor must contain exactly the frozen reviewer fields")
    tool = value["tool"]
    provider = value["provider"]
    model = value["model"]
    executable = value["executable"]
    resolved = value["resolved_executable"]
    exe_sha = value["executable_sha256"]
    profile = value["reviewer_profile"]
    profile_hash = value["reviewer_profile_hash"]
    schema_path = value["output_schema"]
    schema_sha = value["output_schema_sha256"]
    timeout = value["timeout_seconds"]
    brief = value["review_brief"]
    if tool != "codex":
        raise ArtifactValidationError("reviewer tool must be exactly codex")
    if provider != "OpenAI":
        raise ArtifactValidationError("reviewer provider must be exactly OpenAI")
    if not isinstance(model, str) or not model.strip():
        raise ArtifactValidationError("reviewer model must be a non-empty string")
    if not isinstance(executable, str) or not executable.strip():
        raise ArtifactValidationError("reviewer executable must be a non-empty string")
    if not isinstance(resolved, str) or not resolved.strip() or not resolved.startswith("/"):
        raise ArtifactValidationError("reviewer resolved_executable must be an absolute path")
    if not isinstance(exe_sha, str) or len(exe_sha) != 64 or any(c not in "0123456789abcdef" for c in exe_sha):
        raise ArtifactValidationError("reviewer executable_sha256 must be lowercase SHA-256")
    if not isinstance(profile, dict) or not profile:
        raise ArtifactValidationError("reviewer profile must be a non-empty object")
    expected_profile_hash = hashlib.sha256(_canonical_json(profile).encode("utf-8")).hexdigest()
    if not isinstance(profile_hash, str) or profile_hash != expected_profile_hash:
        raise ArtifactValidationError("reviewer reviewer_profile_hash does not match reviewer_profile")
    if not isinstance(schema_path, str) or not schema_path.strip() or not schema_path.startswith("/"):
        raise ArtifactValidationError("reviewer output_schema must be an absolute path")
    if not isinstance(schema_sha, str) or len(schema_sha) != 64 or any(c not in "0123456789abcdef" for c in schema_sha):
        raise ArtifactValidationError("reviewer output_schema_sha256 must be lowercase SHA-256")
    if not isinstance(timeout, int) or timeout <= 0:
        raise ArtifactValidationError("reviewer timeout_seconds must be a positive integer")
    if not isinstance(brief, str) or not brief.strip():
        raise ArtifactValidationError("reviewer review_brief must be a non-empty string")
    return dict(value)


def normalize_review_policy(value: Any) -> dict[str, Any]:
    """Validate closed review_policy shape and static selection consistency."""
    if not isinstance(value, dict) or set(value) != {"review_mode", "change_categories", "human_requested_targeted", "reviewer"}:
        raise ArtifactValidationError("review_policy must contain exactly the frozen policy fields")
    mode = value["review_mode"]
    if mode not in (ReviewMode.NONE.value, ReviewMode.TARGETED.value):
        raise ArtifactValidationError("review_mode must be exactly NONE or TARGETED")
    categories = value["change_categories"]
    human_flag = value["human_requested_targeted"]
    reviewer = value["reviewer"]
    if not isinstance(categories, list):
        raise ArtifactValidationError("change_categories must be an array")
    for item in categories:
        if not isinstance(item, str) or not item.strip():
            raise ArtifactValidationError("change_categories must be an array of non-empty strings")
    if len(set(categories)) != len(categories):
        raise ArtifactValidationError("change_categories must not contain duplicates")
    if not isinstance(human_flag, bool):
        raise ArtifactValidationError("human_requested_targeted must be a boolean")
    expected = select_review_mode(list(categories), human_flag)
    if mode != expected:
        raise ArtifactValidationError(f"review_mode {mode} contradicts static selection {expected}")
    if mode == ReviewMode.NONE.value:
        if categories != []:
            raise ArtifactValidationError("NONE review_policy must have empty change_categories")
        if human_flag is not False:
            raise ArtifactValidationError("NONE review_policy must have human_requested_targeted=false")
        if reviewer is not None:
            raise ArtifactValidationError("NONE review_policy must have reviewer=null")
        return {"review_mode": mode, "change_categories": [], "human_requested_targeted": False, "reviewer": None}
    # TARGETED
    if reviewer is None:
        raise ArtifactValidationError("TARGETED review_policy requires an exact reviewer binding")
    normalized_reviewer = normalize_reviewer_descriptor(reviewer)
    return {
        "review_mode": mode,
        "change_categories": list(categories),
        "human_requested_targeted": human_flag,
        "reviewer": normalized_reviewer,
    }
