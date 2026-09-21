"""Closed, provider-neutral contracts for the bounded CTRL-R001 kernel."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError

VERSION = "PRJ226.CONTROL.v1"
# R3C deliberately uses a separate state version.  VERSION is kept as the
# legacy CTRL-R001 protocol and must continue to be accepted by old stores.
STRICT_VERSION = "PRJ226.CONTROL_STATE.v1"
DECISION_VERSION = "PRJ226.CONTROL_DECISION.v1"
CONTEXT_LIMIT = 32 * 1024
ATTACHMENT_LIMIT = 64 * 1024
PHASES = {
    "START": {"DISCOVERY"},
    "DISCOVERY": {"PLANNING"},
    "PLANNING": {"WAITING_HUMAN_GATE_A"},
    "WAITING_HUMAN_GATE_A": {"EXECUTION_PREP"},
    "EXECUTION_PREP": {"RUNNER_ACTIVE"},
    "RUNNER_ACTIVE": {"RESULT_INGESTION"},
    "RESULT_INGESTION": {"PLANNER_ASSESSMENT"},
    "PLANNER_ASSESSMENT": {"WAITING_HUMAN_GATE_B"},
    "WAITING_HUMAN_GATE_B": {"CANONICAL_INTEGRATION_PREP"},
    "CANONICAL_INTEGRATION_PREP": {"COMPLETE"},
    "COMPLETE": set(),
    "BLOCKED": set(),
}
STRICT_PHASES = {
    "START": {"PLANNING"},
    "PLANNING": {"WAITING_HUMAN_GATE_A"},
    "WAITING_HUMAN_GATE_A": {"BUILDING"},
    "BUILDING": {"FREEZING"},
    "FREEZING": {"VERIFYING"},
    "VERIFYING": {"REVIEWING"},
    "REVIEWING": {"ASSESSING"},
    "ASSESSING": {"BUILDING", "WAITING_HUMAN_GATE_B"},
    "WAITING_HUMAN_GATE_B": {"COMPLETE"},
    "COMPLETE": set(),
    "BLOCKED": set(),
}
STRICT_ACTION_KINDS = {"PLANNER", "BUILDER", "FREEZE", "VERIFIER", "REVIEWER"}
DECISIONS = {
    "PLANNING": {"PROPOSE_TASK", "BLOCK"},
    "PLANNER_ASSESSMENT": {"PREPARE_GATE_B", "BLOCK"},
}
COUNTERS = ("planner_invocations", "builder_invocations", "retry_count", "fallback_count", "blocker_count")
STATE_KEYS = {
    "schema_version", "controller_id", "goal", "task_id", "revision", "baseline",
    "phase", "planner_profile_ref", "builder_profile_ref", "contract_ref", "packet_ref",
    "scope", "candidate", "gate_a_history", "gate_b_history", "pending_gate",
    *COUNTERS, "planner_budget", "latest_decision_ref", "pending_action",
    "verification_summary", "terminal_state", "terminal_reason", "evidence_refs",
}


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw: str | bytes, *, limit: int = 2 * 1024 * 1024) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ArtifactValidationError("Duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_: str) -> None:
        raise ArtifactValidationError("Non-finite JSON number")

    if not isinstance(raw, (str, bytes)) or len(raw.encode("utf-8") if isinstance(raw, str) else raw) > limit:
        raise ArtifactValidationError("JSON input exceeds its byte budget")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArtifactValidationError("Malformed JSON") from exc


def closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ArtifactValidationError(f"{label} has missing or unknown fields")
    return value


def string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise ArtifactValidationError(f"Invalid {label}")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ArtifactValidationError(f"Invalid {label}")
    return value


def hex_digest(value: Any, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        raise ArtifactValidationError("Invalid digest")
    return value


def reference(value: Any) -> dict[str, str]:
    closed(value, {"path", "sha256"}, "artifact reference")
    string(value["path"], "artifact path")
    hex_digest(value["sha256"])
    return value


def strict_reference(value: Any, label: str = "strict artifact reference") -> dict[str, str]:
    """Validate the strict, immutable artifact locator shape.

    Legacy CTRL-R001 references intentionally retain their ``path`` member.
    R3C references use ``ref`` so the strict store and the legacy store cannot
    be confused by an apparently valid but differently-shaped locator.
    """
    closed(value, {"ref", "sha256"}, label)
    string(value["ref"], f"{label} ref", maximum=4096)
    if "/" in value["ref"] or "\\" in value["ref"] or value["ref"] in {".", ".."}:
        # Strict references are resolved by ControlStore under its evidence
        # root.  A path separator would turn a reference into traversal.
        raise ArtifactValidationError(f"Invalid {label}")
    hex_digest(value["sha256"])
    return value


def gate_binding(state: dict[str, Any], package: dict[str, Any] | None) -> dict[str, Any]:
    return {key: state[key] for key in (
        "controller_id", "task_id", "baseline", "scope", "planner_profile_ref", "builder_profile_ref", "contract_ref", "candidate"
    )} | {"package": package}


def validate_gate(gate: Any) -> None:
    closed(gate, {"gate_id", "gate_type", "revision", "binding", "binding_digest", "question"}, "gate")
    string(gate["gate_id"], "gate ID", maximum=160)
    if not isinstance(gate["gate_type"], str) or gate["gate_type"] not in {"GATE_A", "GATE_B"}:
        raise ArtifactValidationError("Invalid gate type")
    integer(gate["revision"], "gate revision", minimum=1)
    string(gate["question"], "gate question", maximum=32768)
    closed(gate["binding"], {"controller_id", "task_id", "baseline", "scope", "planner_profile_ref", "builder_profile_ref", "contract_ref", "candidate", "package"}, "gate binding")
    if digest(gate["binding"]) != gate["binding_digest"]:
        raise ArtifactValidationError("Gate binding digest mismatch")


def validate_state(state: Any) -> dict[str, Any]:
    if isinstance(state, dict) and state.get("schema_version") == STRICT_VERSION:
        return validate_strict_state(state)
    closed(state, STATE_KEYS, "controller state")
    if state["schema_version"] != VERSION or not isinstance(state["phase"], str) or state["phase"] not in PHASES:
        raise ArtifactValidationError("Unsupported controller state/version")
    for key in ("controller_id", "task_id", "planner_profile_ref", "builder_profile_ref"):
        string(state[key], key, maximum=160)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", state[key]):
            raise ArtifactValidationError(f"Invalid identifier: {key}")
    string(state["goal"], "goal", maximum=8192)
    for key in (*COUNTERS, "revision", "planner_budget"):
        integer(state[key], key, minimum=1 if key in {"revision", "planner_budget"} else 0)
    if state["planner_budget"] > 16:
        raise ArtifactValidationError("Planner budget exceeds bounded core limit")
    closed(state["baseline"], {"repository", "branch", "head", "tree"}, "baseline")
    for key in ("repository", "branch"):
        string(state["baseline"][key], key)
    for key in ("head", "tree"):
        hex_digest(state["baseline"][key], 40)
    scope = state["scope"]
    if not isinstance(scope, list) or not scope or not all(isinstance(path, str) for path in scope) or len(scope) != len(set(scope)):
        raise ArtifactValidationError("Invalid authorized scope")
    from prj226_runner.runner import _safe_relative_path
    for path in scope:
        _safe_relative_path(path)
    reference(state["contract_ref"])
    for key in ("packet_ref", "latest_decision_ref"):
        if state[key] is not None:
            reference(state[key])
    if not isinstance(state["evidence_refs"], list):
        raise ArtifactValidationError("Invalid evidence references")
    for ref in state["evidence_refs"]:
        reference(ref)
    if state["candidate"] is not None:
        closed(state["candidate"], {"head", "tree", "ref"}, "candidate")
        hex_digest(state["candidate"]["head"], 40)
        hex_digest(state["candidate"]["tree"], 40)
        from prj226_runner.candidate_identity import validate_candidate_ref
        validate_candidate_ref(state["candidate"]["ref"])
    if state["verification_summary"] is not None:
        summary = closed(state["verification_summary"], {"deterministic", "review", "report_ref"}, "verification summary")
        if summary["deterministic"] != "PASS" or not isinstance(summary["review"], str) or summary["review"] not in {"PASS", "NOT_REQUIRED"}:
            raise ArtifactValidationError("Invalid verification summary")
        reference(summary["report_ref"])
    for key, kind in (("gate_a_history", "GATE_A"), ("gate_b_history", "GATE_B")):
        if not isinstance(state[key], list) or len(state[key]) > 1:
            raise ArtifactValidationError("Invalid gate history")
        for entry in state[key]:
            closed(entry, {"gate", "human_response", "source", "authorization"}, "gate response")
            validate_gate(entry["gate"])
            if entry["gate"]["gate_type"] != kind or not isinstance(entry["human_response"], str) or entry["human_response"] not in {"approve", "deny"} or entry["source"] != "local-cli":
                raise ArtifactValidationError("Invalid human response")
            auth = entry["authorization"]
            if entry["human_response"] == "deny":
                if auth is not None:
                    raise ArtifactValidationError("Denied gate cannot authorize")
            elif auth != {"gate_id": entry["gate"]["gate_id"], "binding_digest": entry["gate"]["binding_digest"], "decision": "APPROVED"}:
                raise ArtifactValidationError("Invalid gate authorization")
    if state["pending_gate"] is not None:
        validate_gate(state["pending_gate"])
        gate = state["pending_gate"]
        if state["phase"] != "WAITING_HUMAN_" + gate["gate_type"] or gate["revision"] != state["revision"]:
            raise ArtifactValidationError("Pending gate phase/revision mismatch")
        if gate["binding"] != gate_binding(state, gate["binding"]["package"]):
            raise ArtifactValidationError("Pending gate authority mismatch")
    elif state["phase"].startswith("WAITING_HUMAN_"):
        raise ArtifactValidationError("Waiting phase requires a gate")
    action = state["pending_action"]
    if action is not None:
        closed(action, {"id", "kind", "status", "revision"}, "action claim")
        if not isinstance(action["id"], str) or not re.fullmatch(r"action-[0-9]+", action["id"]) or not isinstance(action["kind"], str) or action["kind"] not in {"PLANNER", "BUILDER"} or not isinstance(action["status"], str) or action["status"] not in {"PREPARED", "STARTED"}:
            raise ArtifactValidationError("Invalid action claim")
        integer(action["revision"], "action revision", minimum=1)
        if action["revision"] != state["revision"]:
            raise ArtifactValidationError("Action revision mismatch")
        allowed = set(DECISIONS) if action["kind"] == "PLANNER" else {"RUNNER_ACTIVE"}
        if state["phase"] not in allowed:
            raise ArtifactValidationError("Action phase mismatch")
    terminal = state["phase"] in {"COMPLETE", "BLOCKED"}
    if state["terminal_state"] != (state["phase"] if terminal else None):
        raise ArtifactValidationError("Terminal state mismatch")
    if terminal:
        string(state["terminal_reason"], "terminal reason", maximum=2048)
        if state["pending_gate"] is not None or state["pending_action"] is not None:
            raise ArtifactValidationError("Terminal state retains active authority")
    elif state["terminal_reason"] is not None:
        raise ArtifactValidationError("Unexpected terminal reason")
    return state


def validate_transition(before: dict[str, Any], after: dict[str, Any]) -> None:
    if (isinstance(before, dict) and before.get("schema_version") == STRICT_VERSION) or (
        isinstance(after, dict) and after.get("schema_version") == STRICT_VERSION
    ):
        return validate_strict_transition(before, after)
    validate_state(after)
    if before["phase"] in {"COMPLETE", "BLOCKED"}:
        raise GovernanceBlockerError("Terminal controller cannot advance")
    if after["revision"] != before["revision"] + 1:
        raise GovernanceBlockerError("Controller revision must advance exactly once")
    immutable = {"schema_version", "controller_id", "goal", "task_id", "baseline", "planner_profile_ref", "builder_profile_ref", "contract_ref", "scope", "planner_budget"}
    if any(before[key] != after[key] for key in immutable):
        raise GovernanceBlockerError("Frozen controller authority changed")
    if after["phase"] not in PHASES[before["phase"]] | {before["phase"], "BLOCKED"}:
        raise GovernanceBlockerError("Illegal controller transition")
    for key in COUNTERS:
        if after[key] < before[key]:
            raise GovernanceBlockerError("Controller counter decreased")
    for key in ("gate_a_history", "gate_b_history", "evidence_refs"):
        if after[key][:len(before[key])] != before[key]:
            raise GovernanceBlockerError("Controller history is append-only")
    if before["phase"] == "WAITING_HUMAN_GATE_A" and after["phase"] == "EXECUTION_PREP":
        if not after["gate_a_history"] or after["gate_a_history"][-1]["human_response"] != "approve":
            raise GovernanceBlockerError("Gate A approval required")
    if before["phase"] == "WAITING_HUMAN_GATE_B" and after["phase"] == "CANONICAL_INTEGRATION_PREP":
        if not after["gate_b_history"] or after["gate_b_history"][-1]["human_response"] != "approve":
            raise GovernanceBlockerError("Gate B approval required")
    if after["phase"] == "COMPLETE" and (not after["gate_b_history"] or after["verification_summary"] is None):
        raise GovernanceBlockerError("Completion lacks verified evidence or Gate B")


# ---------------------------------------------------------------------------
# CTRL-R002A R3C strict execution protocol
# ---------------------------------------------------------------------------

STRICT_COUNTERS = (
    "planner_invocations",
    "builder_invocations",
    "freeze_invocations",
    "verifier_invocations",
    "reviewer_invocations",
)
STRICT_STATE_KEYS = {
    "schema_version",
    "controller_id",
    "task_id",
    "goal",
    "revision",
    "baseline",
    "scope",
    "approved_scope",
    "contract_ref",
    "runtime_ref",
    "packet_ref",
    "planner_profile_ref",
    "builder_profile_ref",
    "reviewer_profile_ref",
    "repair_policy",
    "phase",
    "attempt_index",
    "repair_cycles",
    "planner_session",
    "builder_session",
    "reviewer_session",
    "planner_sessions",
    "builder_sessions",
    "reviewer_sessions",
    "gate_a",
    "gate_b",
    "gate_a_history",
    "gate_b_history",
    "pending_gate",
    "pending_action",
    "action_history",
    "candidate",
    "verification",
    "review",
    "repair_history",
    "evidence_refs",
    "latest_result_ref",
    *STRICT_COUNTERS,
    "terminal_state",
    "terminal_reason",
}
STRICT_GATE_KEYS = {"gate_id", "gate_type", "revision", "binding", "binding_digest", "question"}
STRICT_GATE_ENTRY_KEYS = {"gate", "human_response", "source", "authorization"}
STRICT_ACTION_KEYS = {"id", "kind", "status", "attempt_index", "revision"}
STRICT_COMPLETED_ACTION_KEYS = {
    "id", "kind", "status", "attempt_index", "result_ref", "session_id", "revision"
}
STRICT_GATE_A_BINDING_KEYS = {
    "controller_id", "task_id", "goal", "baseline", "scope", "contract_ref", "runtime_ref",
    "packet_ref", "planner_profile_ref", "builder_profile_ref", "reviewer_profile_ref", "repair_policy",
}
STRICT_GATE_B_BINDING_KEYS = STRICT_GATE_A_BINDING_KEYS | {
    "candidate", "verification_ref", "reviewer_receipt_ref", "review_verdict",
}
STRICT_REPAIR_RECORD_KEYS = {
    "failed_candidate_identity",
    "verification_summary",
    "review_findings",
    "previous_attempt_index",
}

# Planner output is deliberately a small closed contract.  Optional fields
# are still closed: adding a control-looking property is never silently
# accepted just because it is not currently consumed by the controller.
STRICT_PLANNER_PROPOSAL_KEYS = {
    "summary",
    "scope",
    "acceptance_criteria",
    "test_commands",
    "commit_message",
    "risks",
    "assumptions",
    "non_goals",
}


def _strict_identifier(value: Any, label: str, maximum: int = 160) -> str:
    string(value, label, maximum=maximum)
    if re.fullmatch(r"[A-Za-z0-9._-]+", value) is None:
        raise ArtifactValidationError(f"Invalid identifier: {label}")
    return value


def _strict_sha(value: Any, label: str, length: int) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{%d}" % length, value) is None:
        raise ArtifactValidationError(f"Invalid {label}")
    return value.lower()


def _strict_ref_or_none(value: Any, label: str) -> None:
    if value is not None:
        try:
            strict_reference(value, label)
        except ArtifactValidationError as exc:
            raise ArtifactValidationError(f"Invalid {label}") from exc


def _strict_baseline(value: Any) -> dict[str, Any]:
    closed(value, {"repository", "branch", "head", "tree"}, "strict baseline")
    string(value["repository"], "baseline repository")
    string(value["branch"], "baseline branch")
    _strict_sha(value["head"], "baseline HEAD", 40)
    _strict_sha(value["tree"], "baseline TREE", 40)
    return value


def _strict_scope(value: Any, label: str = "approved scope") -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ArtifactValidationError(f"Invalid {label}")
    if len(value) != len(set(value)):
        raise ArtifactValidationError(f"Invalid {label}")
    from prj226_runner.runner import _safe_relative_path
    for item in value:
        if not isinstance(item, str):
            raise ArtifactValidationError(f"Invalid {label}")
        _safe_relative_path(item)
    return value


def validate_strict_planner_proposal(
    value: Any,
    *,
    approved_scope: list[str] | None = None,
) -> dict[str, Any]:
    """Validate the closed proposal object used before strict Gate A.

    ``summary`` is the only mandatory proposal datum because the frozen
    contract remains the authority for execution.  The other fields are
    optional, but their names and complete value shapes are closed here.
    """
    if not isinstance(value, dict):
        raise ArtifactValidationError("Strict planner proposal must be a dictionary")
    if not set(value).issubset(STRICT_PLANNER_PROPOSAL_KEYS) or "summary" not in value:
        raise ArtifactValidationError("Strict planner proposal has missing or unknown fields")
    string(value["summary"], "planner proposal summary", maximum=8192)
    if "scope" in value:
        proposal_scope = _strict_scope(value["scope"], "planner proposal scope")
        if approved_scope is not None and not set(proposal_scope).issubset(set(approved_scope)):
            raise GovernanceBlockerError("Planner proposal widens the approved scope")
    for key in ("acceptance_criteria", "risks", "assumptions", "non_goals"):
        if key in value:
            items = value[key]
            if not isinstance(items, list) or not items or not all(
                isinstance(item, str) and item.strip() for item in items
            ) or len(items) != len(set(items)):
                raise ArtifactValidationError(f"Invalid planner proposal {key}")
    if "test_commands" in value:
        commands = value["test_commands"]
        if not isinstance(commands, list) or not commands or not all(
            isinstance(command, list) and command and all(
                isinstance(argument, str) and argument for argument in command
            ) for command in commands
        ):
            raise ArtifactValidationError("Invalid planner proposal test_commands")
    if "commit_message" in value:
        string(value["commit_message"], "planner proposal commit_message", maximum=4096)
    return value


def validate_task_packet_v3(value: Any, *, approved_scope: list[str] | None = None) -> dict[str, Any]:
    """Validate a scoped HARN-001 Task Packet v3 without a permissive parser."""
    required = {
        "packet_version", "contract_id", "contract_hash", "runtime_root", "review_policy",
        "run_id", "task_id", "product_repo", "canonical_branch", "baseline_head",
        "baseline_tree", "authorized_paths", "builder_prompt", "acceptance_criteria",
        "test_commands", "commit_message",
    }
    allowed = required | {"transient_paths"}
    if not isinstance(value, dict) or not required.issubset(set(value)) or not set(value).issubset(allowed):
        raise ArtifactValidationError("Task packet v3 has missing or unknown fields")
    if value["packet_version"] != "HARN-001.TASK_PACKET.v3":
        raise ArtifactValidationError("Unsupported Task Packet v3 version")
    if not isinstance(value["contract_id"], str) or re.fullmatch(r"design-[0-9a-f]{64}", value["contract_id"]) is None:
        raise ArtifactValidationError("Invalid Task Packet v3 contract_id")
    hex_digest(value["contract_hash"])
    runtime_root = value["runtime_root"]
    if not isinstance(runtime_root, str) or not runtime_root.startswith("/") or not runtime_root.strip():
        raise ArtifactValidationError("Invalid Task Packet v3 runtime_root")
    if "\x00" in runtime_root:
        raise ArtifactValidationError("Invalid Task Packet v3 runtime_root")
    if not isinstance(value["review_policy"], dict):
        raise ArtifactValidationError("Invalid Task Packet v3 review_policy")
    from prj226_runner.review_policy import normalize_review_policy
    normalize_review_policy(value["review_policy"])
    if not isinstance(value["run_id"], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["run_id"]) is None:
        raise ArtifactValidationError("Invalid Task Packet v3 run_id")
    for key in ("task_id", "product_repo", "canonical_branch", "builder_prompt", "commit_message"):
        string(value[key], f"Task Packet v3 {key}", maximum=65536 if key == "builder_prompt" else 8192)
    for key in ("baseline_head", "baseline_tree"):
        _strict_sha(value[key], f"Task Packet v3 {key}", 40)
    packet_scope = _strict_scope(value["authorized_paths"], "Task Packet v3 authorized_paths")
    if approved_scope is not None and packet_scope != approved_scope:
        raise GovernanceBlockerError("Task Packet v3 scope is not bound to Gate A authority")
    criteria = value["acceptance_criteria"]
    if not isinstance(criteria, list) or not criteria or not all(isinstance(item, str) and item.strip() for item in criteria):
        raise ArtifactValidationError("Invalid Task Packet v3 acceptance_criteria")
    commands = value["test_commands"]
    if not isinstance(commands, list) or not commands or not all(
        isinstance(command, list) and command and all(isinstance(argument, str) and argument for argument in command)
        for command in commands
    ):
        raise ArtifactValidationError("Task Packet v3 test_commands must contain at least one argv array")
    if "transient_paths" in value:
        transient = value["transient_paths"]
        if not isinstance(transient, list) or len(transient) != len(set(transient)):
            raise ArtifactValidationError("Invalid Task Packet v3 transient_paths")
        for item in transient:
            _strict_scope([item], "Task Packet v3 transient_paths")
    return value


# Descriptive alias used by callers that emphasize Gate-A scoping.
validate_scoped_task_packet = validate_task_packet_v3


def strict_gate_binding(state: dict[str, Any], gate_type: str) -> dict[str, Any]:
    """Return the immutable authority bound by a strict human gate."""
    if gate_type == "GATE_A":
        keys = STRICT_GATE_A_BINDING_KEYS
    elif gate_type == "GATE_B":
        keys = STRICT_GATE_B_BINDING_KEYS
    else:
        raise ArtifactValidationError("Invalid strict gate type")
    result: dict[str, Any] = {}
    for key in keys:
        if key in state:
            result[key] = state[key]
        elif gate_type == "GATE_B" and key == "verification_ref":
            verification = state.get("verification")
            if isinstance(verification, dict) and isinstance(verification.get("report_ref"), dict):
                result[key] = verification["report_ref"]
        elif gate_type == "GATE_B" and key == "reviewer_receipt_ref":
            review = state.get("review")
            if isinstance(review, dict) and isinstance(review.get("receipt_ref"), dict):
                result[key] = review["receipt_ref"]
        elif gate_type == "GATE_B" and key == "review_verdict":
            review = state.get("review")
            if isinstance(review, dict):
                result[key] = review.get("status")
    if set(result) != keys:
        raise ArtifactValidationError("Strict gate binding is incomplete")
    return result


def _validate_strict_binding(binding: Any, gate_type: str) -> dict[str, Any]:
    """Validate every nested value of a strict gate binding."""
    expected_keys = STRICT_GATE_A_BINDING_KEYS if gate_type == "GATE_A" else STRICT_GATE_B_BINDING_KEYS
    closed(binding, expected_keys, "strict gate binding")
    _strict_identifier(binding["controller_id"], "gate binding controller_id")
    _strict_identifier(binding["task_id"], "gate binding task_id")
    string(binding["goal"], "gate binding goal", maximum=8192)
    _strict_baseline(binding["baseline"])
    _strict_scope(binding["scope"], "gate binding scope")
    strict_reference(binding["contract_ref"], "gate binding contract_ref")
    strict_reference(binding["runtime_ref"], "gate binding runtime_ref")
    _strict_ref_or_none(binding["packet_ref"], "gate binding packet_ref")
    for key in ("planner_profile_ref", "builder_profile_ref", "reviewer_profile_ref"):
        string(binding[key], f"gate binding {key}", maximum=512)
    closed(binding["repair_policy"], {"max_repair_cycles"}, "gate binding repair policy")
    integer(binding["repair_policy"]["max_repair_cycles"], "gate binding max repair cycles", minimum=0)
    if binding["repair_policy"]["max_repair_cycles"] > 2:
        raise ArtifactValidationError("Gate binding max_repair_cycles cannot exceed 2")
    if gate_type == "GATE_B":
        _validate_strict_candidate(binding["candidate"])
        if binding["candidate"] is None:
            raise ArtifactValidationError("Gate B binding requires a candidate")
        strict_reference(binding["verification_ref"], "gate binding verification_ref")
        strict_reference(binding["reviewer_receipt_ref"], "gate binding reviewer_receipt_ref")
        if binding["review_verdict"] not in {"PASS", "NEEDS_FIX", "BLOCKED"}:
            raise ArtifactValidationError("Invalid gate binding review_verdict")
    return binding


def _validate_strict_gate(value: Any, expected_type: str | None = None) -> dict[str, Any]:
    closed(value, STRICT_GATE_KEYS, "strict gate")
    string(value["gate_id"], "strict gate ID", maximum=200)
    if value["gate_type"] not in {"GATE_A", "GATE_B"}:
        raise ArtifactValidationError("Invalid strict gate type")
    if expected_type is not None and value["gate_type"] != expected_type:
        raise ArtifactValidationError("Strict gate type mismatch")
    integer(value["revision"], "strict gate revision", minimum=1)
    string(value["question"], "strict gate question", maximum=32768)
    binding = value["binding"]
    _validate_strict_binding(binding, value["gate_type"])
    if digest(binding) != value["binding_digest"]:
        raise ArtifactValidationError("Strict gate binding digest mismatch")
    return value


def _validate_strict_gate_history(value: Any, expected_type: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 1:
        raise ArtifactValidationError("Invalid strict gate history")
    for entry in value:
        closed(entry, STRICT_GATE_ENTRY_KEYS, "strict gate response")
        gate = _validate_strict_gate(entry["gate"], expected_type)
        if entry["human_response"] not in {"approve", "deny"} or entry["source"] != "local-cli":
            raise ArtifactValidationError("Invalid strict human gate response")
        authorization = entry["authorization"]
        if entry["human_response"] == "deny":
            if authorization is not None:
                raise ArtifactValidationError("Denied strict gate cannot authorize")
        elif authorization != {
            "gate_id": gate["gate_id"],
            "binding_digest": gate["binding_digest"],
            "decision": "APPROVED",
        }:
            raise ArtifactValidationError("Invalid strict gate authorization")
    return value


def _validate_strict_action(value: Any, *, completed: bool = False) -> dict[str, Any]:
    keys = STRICT_COMPLETED_ACTION_KEYS if completed else STRICT_ACTION_KEYS
    closed(value, keys, "strict action")
    if not isinstance(value["id"], str) or re.fullmatch(r"action-[A-Za-z0-9._-]+", value["id"]) is None:
        raise ArtifactValidationError("Invalid strict action ID")
    if value["kind"] not in STRICT_ACTION_KINDS:
        raise ArtifactValidationError("Invalid strict action kind")
    expected_status = "COMPLETED" if completed else None
    if expected_status is not None and value["status"] != expected_status:
        raise ArtifactValidationError("Invalid completed strict action status")
    if expected_status is None and value["status"] not in {"PREPARED", "STARTED"}:
        raise ArtifactValidationError("Invalid strict action status")
    integer(value["attempt_index"], "strict action attempt", minimum=0)
    if value["attempt_index"] > 2:
        raise ArtifactValidationError("Strict action attempt exceeds bounded limit")
    integer(value["revision"], "strict action revision", minimum=1)
    if completed:
        strict_reference(value["result_ref"], "strict action result reference")
        if value["session_id"] is not None:
            string(value["session_id"], "strict action session", maximum=256)
    return value


def _validate_strict_candidate(value: Any) -> None:
    if value is None:
        return
    closed(value, {"head", "tree", "ref", "authority_ref", "worktree", "attempt_index", "changed_paths"}, "strict candidate")
    _strict_sha(value["head"], "candidate HEAD", 40)
    _strict_sha(value["tree"], "candidate TREE", 40)
    string(value["ref"], "candidate ref", maximum=256)
    strict_reference(value["authority_ref"], "candidate authority reference")
    string(value["worktree"], "candidate worktree", maximum=4096)
    integer(value["attempt_index"], "candidate attempt", minimum=0)
    if value["attempt_index"] > 2:
        raise ArtifactValidationError("Candidate attempt exceeds bounded limit")
    _strict_scope(value["changed_paths"], "candidate changed paths")


def _validate_strict_result(value: Any, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or not isinstance(value.get("status"), str):
        raise ArtifactValidationError(f"Invalid strict {label}")
    if label == "verification" and value["status"] not in {"PASS", "FAIL", "BLOCKED"}:
        raise ArtifactValidationError("Invalid strict verification status")
    if label == "review" and value["status"] not in {"PASS", "NEEDS_FIX", "BLOCKED"}:
        raise ArtifactValidationError("Invalid strict review status")
    if "eligible_repair" in value and not isinstance(value["eligible_repair"], bool):
        raise ArtifactValidationError(f"Invalid strict {label} eligible_repair")
    for key in ("report_ref", "receipt_ref"):
        if key in value:
            strict_reference(value[key], f"strict {label} {key}")


def _validate_strict_repair_record(value: Any) -> dict[str, Any]:
    closed(value, STRICT_REPAIR_RECORD_KEYS, "strict repair feedback")
    _validate_strict_candidate(value["failed_candidate_identity"])
    if value["failed_candidate_identity"] is None:
        raise ArtifactValidationError("Strict repair feedback requires a failed candidate")
    _validate_strict_result(value["verification_summary"], "verification")
    _validate_strict_result(value["review_findings"], "review")
    integer(value["previous_attempt_index"], "previous repair attempt index", minimum=0)
    return value


def validate_strict_state(state: Any) -> dict[str, Any]:
    """Validate the R3C state snapshot without weakening the legacy schema."""
    closed(state, STRICT_STATE_KEYS, "strict controller state")
    if state["schema_version"] != STRICT_VERSION or state["phase"] not in STRICT_PHASES:
        raise ArtifactValidationError("Unsupported strict controller state/version")
    for key in ("controller_id", "task_id"):
        _strict_identifier(state[key], key)
    string(state["goal"], "goal", maximum=8192)
    integer(state["revision"], "revision", minimum=1)
    _strict_baseline(state["baseline"])
    scope = _strict_scope(state["scope"])
    if state["approved_scope"] != scope:
        raise GovernanceBlockerError("Approved strict scope changed")
    for key in ("contract_ref", "runtime_ref"):
        strict_reference(state[key], key)
    _strict_ref_or_none(state["packet_ref"], "packet reference")
    for key in ("planner_profile_ref", "builder_profile_ref", "reviewer_profile_ref"):
        string(state[key], key, maximum=512)
    closed(state["repair_policy"], {"max_repair_cycles"}, "repair policy")
    integer(state["repair_policy"]["max_repair_cycles"], "max repair cycles", minimum=0)
    if state["repair_policy"]["max_repair_cycles"] > 2:
        raise ArtifactValidationError("Maximum repair cycles is 2")
    integer(state["attempt_index"], "attempt index", minimum=0)
    integer(state["repair_cycles"], "repair cycles", minimum=0)
    if state["attempt_index"] > 2 or state["repair_cycles"] > 2:
        raise ArtifactValidationError("Strict attempt or repair cycle exceeds bounded limit")
    if state["repair_cycles"] != state["attempt_index"]:
        raise GovernanceBlockerError("Repair cycle and attempt index diverged")
    for key in ("planner_session", "builder_session", "reviewer_session"):
        if state[key] is not None:
            string(state[key], key, maximum=256)
    for key in ("planner_sessions", "builder_sessions", "reviewer_sessions"):
        values = state[key]
        if not isinstance(values, list) or not all(isinstance(session, str) for session in values) or len(values) != len(set(values)):
            raise ArtifactValidationError(f"Invalid {key}")
        for session in values:
            string(session, f"{key} session", maximum=256)
    all_sessions = [
        *state["planner_sessions"], *state["builder_sessions"], *state["reviewer_sessions"]
    ]
    if len(all_sessions) != len(set(all_sessions)):
        raise GovernanceBlockerError("GOVERNANCE BLOCK: duplicate role session ID")
    current = [item for item in (state["planner_session"], state["builder_session"], state["reviewer_session"]) if item]
    if len(current) != len(set(current)):
        raise GovernanceBlockerError("GOVERNANCE BLOCK: pairwise role session IDs must be distinct")
    for key, sessions, current_id in (
        ("planner_session", state["planner_sessions"], state["planner_session"]),
        ("builder_session", state["builder_sessions"], state["builder_session"]),
        ("reviewer_session", state["reviewer_sessions"], state["reviewer_session"]),
    ):
        if current_id is not None and (not sessions or sessions[-1] != current_id):
            raise GovernanceBlockerError(f"{key} is not the latest durable session")
    for key, expected in (("gate_a_history", "GATE_A"), ("gate_b_history", "GATE_B")):
        _validate_strict_gate_history(state[key], expected)
    for key, expected_gate_type in (("gate_a", "GATE_A"), ("gate_b", "GATE_B")):
        if state[key] is not None:
            gate = _validate_strict_gate(state[key], expected_gate_type)
            if gate["binding"] != strict_gate_binding(state, expected_gate_type):
                raise GovernanceBlockerError(f"Strict {expected_gate_type} authority binding drift")
    pending_gate = state["pending_gate"]
    if pending_gate is not None:
        _validate_strict_gate(pending_gate)
        if state["phase"] != "WAITING_HUMAN_" + pending_gate["gate_type"] or pending_gate["revision"] != state["revision"]:
            raise ArtifactValidationError("Strict pending gate phase/revision mismatch")
        expected_binding = strict_gate_binding(state, pending_gate["gate_type"])
        if pending_gate["binding"] != expected_binding:
            raise GovernanceBlockerError("Strict pending gate authority drift")
    elif state["phase"].startswith("WAITING_HUMAN_"):
        raise ArtifactValidationError("Strict waiting phase requires a pending gate")
    if state["pending_action"] is not None:
        action = _validate_strict_action(state["pending_action"])
        if action["revision"] != state["revision"] or action["attempt_index"] != state["attempt_index"]:
            raise ArtifactValidationError("Strict action revision/attempt mismatch")
        phase_for_kind = {
            "PLANNER": "PLANNING", "BUILDER": "BUILDING", "FREEZE": "FREEZING",
            "VERIFIER": "VERIFYING", "REVIEWER": "REVIEWING",
        }[action["kind"]]
        if state["phase"] != phase_for_kind:
            raise ArtifactValidationError("Strict action phase mismatch")
    if not isinstance(state["action_history"], list):
        raise ArtifactValidationError("Invalid strict action history")
    action_ids: set[str] = set()
    for action in state["action_history"]:
        _validate_strict_action(action, completed=True)
        if action["id"] in action_ids:
            raise ArtifactValidationError("Duplicate strict action ID")
        action_ids.add(action["id"])
    if state["pending_action"] is not None and state["pending_action"]["id"] in action_ids:
        raise ArtifactValidationError("Active strict action was already completed")
    if not isinstance(state["repair_history"], list) or len(state["repair_history"]) > 2:
        raise ArtifactValidationError("Invalid strict repair history")
    for feedback in state["repair_history"]:
        _validate_strict_repair_record(feedback)
    for key in ("candidate", "verification", "review"):
        if key == "candidate":
            _validate_strict_candidate(state[key])
        else:
            _validate_strict_result(state[key], key)
    if not isinstance(state["evidence_refs"], list):
        raise ArtifactValidationError("Invalid strict evidence references")
    for item in state["evidence_refs"]:
        strict_reference(item, "strict evidence reference")
    _strict_ref_or_none(state["latest_result_ref"], "latest result reference")
    for key in STRICT_COUNTERS:
        integer(state[key], key, minimum=0)
    terminal = state["phase"] in {"COMPLETE", "BLOCKED"}
    if state["terminal_state"] != (state["phase"] if terminal else None):
        raise ArtifactValidationError("Strict terminal state mismatch")
    if terminal:
        string(state["terminal_reason"], "strict terminal reason", maximum=2048)
        if state["pending_gate"] is not None or state["pending_action"] is not None:
            raise ArtifactValidationError("Strict terminal state retains active authority")
    elif state["terminal_reason"] is not None:
        raise ArtifactValidationError("Unexpected strict terminal reason")
    return state


def validate_strict_transition(before: dict[str, Any], after: dict[str, Any]) -> None:
    validate_strict_state(before)
    validate_strict_state(after)
    if before["schema_version"] != STRICT_VERSION or after["schema_version"] != STRICT_VERSION:
        raise GovernanceBlockerError("Strict and legacy controller states cannot be mixed")
    if before["phase"] in {"COMPLETE", "BLOCKED"}:
        raise GovernanceBlockerError("Terminal strict controller cannot advance")
    if after["revision"] != before["revision"] + 1:
        raise GovernanceBlockerError("Strict controller revision must advance exactly once")
    immutable = {
        "schema_version", "controller_id", "task_id", "goal", "baseline", "scope", "approved_scope",
        "contract_ref", "runtime_ref", "packet_ref", "planner_profile_ref", "builder_profile_ref", "reviewer_profile_ref",
        "repair_policy",
    }
    if any(before[key] != after[key] for key in immutable):
        raise GovernanceBlockerError("Frozen strict controller authority changed")
    if after["phase"] not in STRICT_PHASES[before["phase"]] | {before["phase"], "BLOCKED"}:
        raise GovernanceBlockerError("Illegal strict controller transition")
    for key in ("gate_a_history", "gate_b_history", "action_history", "evidence_refs",
                "planner_sessions", "builder_sessions", "reviewer_sessions"):
        if after[key][:len(before[key])] != before[key]:
            raise GovernanceBlockerError("Strict controller history is append-only")
    if after["gate_a"] != before["gate_a"] and before["gate_a"] is not None:
        raise GovernanceBlockerError("Strict Gate A authority is immutable")
    if after["gate_b"] != before["gate_b"] and before["gate_b"] is not None:
        raise GovernanceBlockerError("Strict Gate B authority is immutable")

    repair_edge = before["phase"] == "ASSESSING" and after["phase"] == "BUILDING"
    if repair_edge:
        if before["repair_policy"]["max_repair_cycles"] == 0:
            raise GovernanceBlockerError("Strict repair transition is disabled")
        if before["repair_cycles"] >= before["repair_policy"]["max_repair_cycles"]:
            raise GovernanceBlockerError("Strict repair budget is exhausted")
        if not (
            (isinstance(before.get("verification"), dict)
             and before["verification"].get("status") == "FAIL"
             and before["verification"].get("eligible_repair") is True)
            or (isinstance(before.get("review"), dict)
                and before["review"].get("status") == "NEEDS_FIX")
        ):
            raise GovernanceBlockerError("Strict repair transition lacks an eligible failure")
    expected_counter = 1 if repair_edge else 0
    if after["attempt_index"] - before["attempt_index"] != expected_counter or after["repair_cycles"] - before["repair_cycles"] != expected_counter:
        raise GovernanceBlockerError("Strict attempt and repair counters may change only on an authorized repair")

    if after["repair_history"][:len(before["repair_history"])] != before["repair_history"]:
        raise GovernanceBlockerError("Strict repair history is append-only")
    if repair_edge:
        if len(after["repair_history"]) != len(before["repair_history"]) + 1:
            raise GovernanceBlockerError("Strict repair transition must append exactly one feedback record")
        expected_feedback = {
            "failed_candidate_identity": before["candidate"],
            "verification_summary": before["verification"],
            "review_findings": before["review"],
            "previous_attempt_index": before["attempt_index"],
        }
        if after["repair_history"][-1] != expected_feedback:
            raise GovernanceBlockerError("Strict repair feedback is not bound to the preceding attempt")
    elif after["repair_history"] != before["repair_history"]:
        raise GovernanceBlockerError("Strict repair history may change only on an authorized repair")

    before_action = before["pending_action"]
    after_action = after["pending_action"]
    completed_delta = after["action_history"][len(before["action_history"]):]
    started_transition = False
    if before_action is None and after_action is not None:
        if after_action["status"] != "PREPARED" or after["action_history"] != before["action_history"]:
            raise GovernanceBlockerError("Strict action must be durably PREPARED before STARTED")
    elif before_action is not None and after_action is not None:
        if (
            before_action["id"] != after_action["id"]
            or before_action["kind"] != after_action["kind"]
            or before_action["attempt_index"] != after_action["attempt_index"]
            or before_action["status"] != "PREPARED"
            or after_action["status"] != "STARTED"
            or after["action_history"] != before["action_history"]
        ):
            raise GovernanceBlockerError("Strict action must advance PREPARED -> STARTED exactly once")
        started_transition = True
    elif before_action is not None and after_action is None:
        if after["phase"] == "BLOCKED":
            if before_action["status"] == "PREPARED" and completed_delta:
                raise GovernanceBlockerError("Prepared strict action cannot be completed while blocking")
            if len(completed_delta) > 1:
                raise GovernanceBlockerError("Strict action completion was appended more than once")
            if completed_delta:
                completed = completed_delta[0]
                if (
                    before_action["status"] != "STARTED"
                    or completed["id"] != before_action["id"]
                    or completed["kind"] != before_action["kind"]
                    or completed["attempt_index"] != before_action["attempt_index"]
                    or completed["status"] != "COMPLETED"
                    or completed["result_ref"] is None
                ):
                    raise GovernanceBlockerError("Completed action identity does not match the pending action")
        else:
            if before_action["status"] != "STARTED":
                raise GovernanceBlockerError("Strict action must be STARTED before completion")
            if len(completed_delta) != 1:
                raise GovernanceBlockerError("Strict action completion is not journaled exactly once")
            completed = completed_delta[0]
            if (
                completed["id"] != before_action["id"]
                or completed["kind"] != before_action["kind"]
                or completed["attempt_index"] != before_action["attempt_index"]
                or completed["status"] != "COMPLETED"
                or completed["result_ref"] is None
            ):
                raise GovernanceBlockerError("Completed action identity does not match the pending action")
    elif before_action is None and after_action is None and after["action_history"] != before["action_history"]:
        raise GovernanceBlockerError("Strict action history advanced without an active action")

    counter_kind = before_action["kind"] if started_transition and before_action is not None else None
    counter_for_kind = {
        "PLANNER": "planner_invocations",
        "BUILDER": "builder_invocations",
        "FREEZE": "freeze_invocations",
        "VERIFIER": "verifier_invocations",
        "REVIEWER": "reviewer_invocations",
    }
    for key in STRICT_COUNTERS:
        expected_delta = 1 if counter_kind is not None and counter_for_kind[counter_kind] == key else 0
        if after[key] - before[key] != expected_delta:
            raise GovernanceBlockerError("Strict invocation counters must advance only on PREPARED -> STARTED")

    required_completed_kind = {
        "BUILDING": "BUILDER", "FREEZING": "FREEZE", "VERIFYING": "VERIFIER", "REVIEWING": "REVIEWER",
    }.get(before["phase"])
    if required_completed_kind is not None and before["phase"] != after["phase"] and after["phase"] != "BLOCKED":
        if not after["action_history"] or after["action_history"][-1]["kind"] != required_completed_kind:
            raise GovernanceBlockerError("Strict phase advanced without the required completed action")
    if before["phase"] == "PLANNING" and after["phase"] == "WAITING_HUMAN_GATE_A":
        if not after["action_history"]:
            raise GovernanceBlockerError("Gate A requires a completed planner action")
        planner_action = after["action_history"][-1]
        if planner_action["kind"] != "PLANNER" or planner_action["status"] != "COMPLETED" or planner_action["attempt_index"] != before["attempt_index"]:
            raise GovernanceBlockerError("Gate A requires a completed PLANNER action for the current attempt")
    if before["phase"] == "WAITING_HUMAN_GATE_A" and after["phase"] == "BUILDING":
        if not after["gate_a_history"] or after["gate_a_history"][-1]["human_response"] != "approve":
            raise GovernanceBlockerError("Gate A approval required")
        if before["pending_gate"] is None or after["gate_a_history"][-1]["gate"] != before["pending_gate"]:
            raise GovernanceBlockerError("Gate A response is not bound to the pending authority")
        if after["attempt_index"] != 0 or after["repair_cycles"] != 0:
            raise GovernanceBlockerError("Initial Gate A approval must start attempt zero")
    if before["phase"] == "WAITING_HUMAN_GATE_B" and after["phase"] == "COMPLETE":
        if not after["gate_b_history"] or after["gate_b_history"][-1]["human_response"] != "approve":
            raise GovernanceBlockerError("Gate B approval required")
        if before["pending_gate"] is None or after["gate_b_history"][-1]["gate"] != before["pending_gate"]:
            raise GovernanceBlockerError("Gate B response is not bound to the pending authority")
        if after["terminal_reason"] != "INTEGRATION_PREPARED_ONLY":
            raise GovernanceBlockerError("Strict completion reason is not integration-prepared-only")
    if before["phase"] == "ASSESSING" and after["phase"] == "WAITING_HUMAN_GATE_B":
        if not (
            isinstance(before.get("verification"), dict)
            and before["verification"].get("status") == "PASS"
            and isinstance(before.get("review"), dict)
            and before["review"].get("status") == "PASS"
        ):
            raise GovernanceBlockerError("Gate B requires verification PASS and review PASS")
    if after["phase"] == "COMPLETE" and (not after["gate_b_history"] or after["review"] is None or after["verification"] is None):
        raise GovernanceBlockerError("Strict completion lacks Gate B or verified evidence")


def validate_strict_event(event: Any, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate one strict journal event, including its hash-chain link."""
    closed(event, {"schema_version", "kind", "revision", "previous_digest", "state", "digest"}, "strict controller event")
    if event["schema_version"] != STRICT_VERSION:
        raise ArtifactValidationError("Unsupported strict controller event version")
    string(event["kind"], "strict event kind", maximum=256)
    integer(event["revision"], "strict event revision", minimum=1)
    validate_strict_state(event["state"])
    if event["state"]["revision"] != event["revision"]:
        raise ArtifactValidationError("Strict state/event revision mismatch")
    expected_previous = previous["digest"] if previous is not None else None
    if event["previous_digest"] != expected_previous:
        raise ArtifactValidationError("Strict controller event chain mismatch")
    if digest({key: value for key, value in event.items() if key != "digest"}) != event["digest"]:
        raise ArtifactValidationError("Strict controller event digest mismatch")
    if previous is not None:
        validate_strict_transition(previous["state"], event["state"])
    elif event["revision"] != 1 or event["state"]["phase"] != "START":
        raise ArtifactValidationError("Strict journal must begin at START revision 1")
    return event


@dataclass(frozen=True)
class PlannerContext:
    """Serialized immutable inputs: adapters never receive mutable controller state."""

    document: bytes
    digest: str
    attachment: bytes | None = None


@dataclass(frozen=True)
class BuilderRequest:
    action_id: str
    task_id: str
    profile_ref: str
    contract_json: bytes
    packet_json: bytes
    gate_a_json: bytes


@dataclass(frozen=True)
class StrictExecutionRequest:
    """Immutable R3C request passed to a role or deterministic executor."""

    action_id: str
    task_id: str
    attempt_index: int
    worktree: str
    scope: tuple[str, ...]
    context_json: bytes
    contract_json: bytes
    runtime_json: bytes
    candidate_json: bytes | None = None


class ControllerPlannerPort(Protocol):
    profile_ref: str

    def decide(self, context: PlannerContext) -> str: ...


class BuilderExecutorPort(Protocol):
    profile_ref: str

    def execute(self, request: BuilderRequest) -> str: ...


def parse_decision(raw: str | bytes, state: dict[str, Any], context_digest: str) -> dict[str, Any]:
    value = closed(decode(raw, limit=8192), {"schema_version", "controller_id", "task_id", "revision", "context_digest", "action", "reason"}, "planner decision")
    if value["schema_version"] != DECISION_VERSION:
        raise ArtifactValidationError("Unsupported decision version")
    integer(value["revision"], "decision revision", minimum=1)
    for field in ("controller_id", "task_id", "revision"):
        if value[field] != state[field]:
            raise GovernanceBlockerError(f"Planner decision {field} mismatch")
    if hex_digest(value["context_digest"]) != context_digest:
        raise GovernanceBlockerError("Planner context digest mismatch")
    if not isinstance(value["action"], str) or value["action"] not in {"PROPOSE_TASK", "PREPARE_GATE_B", "BLOCK"}:
        raise ArtifactValidationError("Unknown planner action")
    if value["action"] not in DECISIONS.get(state["phase"], set()):
        raise GovernanceBlockerError("Illegal planner action for current phase")
    string(value["reason"], "decision reason", maximum=2048)
    return value
