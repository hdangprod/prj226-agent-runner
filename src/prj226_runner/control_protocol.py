"""Closed, provider-neutral contracts for the bounded CTRL-R001 kernel."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from prj226_runner.errors import ArtifactValidationError, GovernanceBlockerError

VERSION = "PRJ226.CONTROL.v1"
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
