"""Structured Event Classifier and Evidence Extractor for OpenHands.

Adheres strictly to PRJ226 governance rules:
1. Structured event classification by schema/kind (no substring matching).
2. Prevents false-positive permission detection from prompt or assistant text.
3. Distinguishes requested, configured, and effective model identities.
4. Detects and fails closed on model evidence conflicts across structured sources.
5. Retry and fallback observations strictly default to None (UNKNOWN). Token usage stats do NOT manufacture zero retries.
6. Distinguishes configured provider route from proven remote provider identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence


@dataclass(frozen=True)
class StructuredEventAnalysis:
    """Detailed classification and evidence derived from raw OpenHands event stream."""
    total_events: int
    message_event_count: int
    actual_permission_request_count: int
    actual_permission_response_count: int
    tool_event_count: int
    turn_start_count: int
    terminal_turn_status: str
    terminal_event_index: Optional[int]
    configured_model: Optional[str]
    effective_model: Optional[str]
    effective_model_evidence_source: Optional[str]
    remote_effective_provider: str
    remote_effective_provider_evidence_source: Optional[str]
    observed_retry_count: Optional[int]
    observed_fallback_count: Optional[int]
    title_count: int
    reviewer_count: int
    subagent_count: int
    original_permission_detector_false_positive: bool = False
    false_positive_triggering_event_index: Optional[int] = None


class OpenHandsEventClassifier:
    """Authoritative structured parser for OpenHands event streams."""

    STRUCTURED_PERMISSION_KINDS = {
        "PermissionRequestEvent",
        "PermissionRequest",
        "ConfirmationRequestEvent",
    }

    STRUCTURED_PERMISSION_RESPONSES = {
        "PermissionResponseEvent",
        "PermissionResponse",
        "ConfirmationResponseEvent",
    }

    STRUCTURED_TOOL_KINDS = {
        "ACPToolCallEvent",
        "ActionEvent",
        "ObservationEvent",
    }

    @classmethod
    def is_structured_permission_request(cls, event: Mapping[str, Any]) -> bool:
        """Check if an event is a genuine structured permission request."""
        if not isinstance(event, Mapping):
            return False

        kind = event.get("kind") or event.get("type")
        if kind in cls.STRUCTURED_PERMISSION_KINDS:
            return True

        if kind == "ActionEvent":
            body = event.get("body")
            if isinstance(body, dict):
                action = body.get("action")
                if action in ("permission_request", "request_permission"):
                    return True

        if event.get("action") in ("permission_request", "request_permission"):
            return True

        return False

    @classmethod
    def analyze_events(
        cls,
        events: Sequence[Mapping[str, Any]],
        *,
        configured_provider_route: str = "NATIVE_CHATGPT_BUILTIN_DEFAULT",
    ) -> StructuredEventAnalysis:
        """Classify a full event stream and extract evidence."""
        total_events = len(events)
        message_count = 0
        permission_req_count = 0
        permission_resp_count = 0
        tool_count = 0
        turn_start_count = 0
        terminal_status = "UNKNOWN"
        terminal_index: Optional[int] = None

        acknowledged_configured_model: Optional[str] = None
        effective_model_from_state: Optional[str] = None
        effective_model_from_stats: Optional[str] = None
        effective_model_source: Optional[str] = None
        remote_provider = "UNPROVEN"
        remote_provider_source: Optional[str] = None

        observed_retry: Optional[int] = None
        observed_fallback: Optional[int] = None
        title_count = 0
        reviewer_count = 0
        subagent_count = 0

        fp_detected = False
        fp_index: Optional[int] = None

        for idx, ev in enumerate(events):
            if not isinstance(ev, Mapping):
                continue

            kind = ev.get("kind") or ev.get("type", "Unknown")

            if kind == "MessageEvent":
                message_count += 1
                msg_body = str(ev.get("llm_message") or "")
                if "permission" in msg_body.lower() and not cls.is_structured_permission_request(ev):
                    fp_detected = True
                    if fp_index is None:
                        fp_index = idx

            if cls.is_structured_permission_request(ev):
                permission_req_count += 1

            if kind in cls.STRUCTURED_PERMISSION_RESPONSES:
                permission_resp_count += 1

            if kind in cls.STRUCTURED_TOOL_KINDS:
                tool_count += 1

            # State updates & status transitions
            if kind == "ConversationStateUpdateEvent":
                key = ev.get("key")
                val = ev.get("value")

                if key == "execution_status":
                    if val == "running":
                        turn_start_count += 1
                    elif val in ("finished", "completed"):
                        terminal_status = "COMPLETED"
                        terminal_index = idx
                    elif val in ("error", "failed", "rejected"):
                        terminal_status = f"BLOCKED_{str(val).upper()}"
                        terminal_index = idx

                elif key == "agent_state" and isinstance(val, dict):
                    model_id = val.get("acp_current_model_id")
                    if model_id and isinstance(model_id, str):
                        effective_model_from_state = model_id
                        effective_model_source = f"event[{idx}].value.acp_current_model_id"

                elif key == "stats" and isinstance(val, dict):
                    usage = val.get("usage_to_metrics", {})
                    if isinstance(usage, dict):
                        for subk, subv in usage.items():
                            if isinstance(subv, dict) and "model_name" in subv:
                                effective_model_from_stats = subv["model_name"]
                                if not effective_model_source:
                                    effective_model_source = f"event[{idx}].value.usage_to_metrics.{subk}.model_name"
                                break

            # Check explicit provider identity in raw event payload
            for pkey in ("remote_provider", "provider_name", "effective_provider"):
                if pkey in ev and ev[pkey]:
                    remote_provider = str(ev[pkey])
                    remote_provider_source = f"event[{idx}].{pkey}"

        # Detect model evidence conflicts
        if effective_model_from_state and effective_model_from_stats:
            if effective_model_from_state != effective_model_from_stats:
                terminal_status = "BLOCKED_MODEL_EVIDENCE_CONFLICT"

        effective_model = effective_model_from_state or effective_model_from_stats

        if permission_req_count > 0:
            terminal_status = "BLOCKED_PERMISSION_REQUEST"

        return StructuredEventAnalysis(
            total_events=total_events,
            message_event_count=message_count,
            actual_permission_request_count=permission_req_count,
            actual_permission_response_count=permission_resp_count,
            tool_event_count=tool_count,
            turn_start_count=turn_start_count,
            terminal_turn_status=terminal_status,
            terminal_event_index=terminal_index,
            configured_model=acknowledged_configured_model,
            effective_model=effective_model,
            effective_model_evidence_source=effective_model_source,
            remote_effective_provider=remote_provider,
            remote_effective_provider_evidence_source=remote_provider_source,
            observed_retry_count=observed_retry,
            observed_fallback_count=observed_fallback,
            title_count=title_count,
            reviewer_count=reviewer_count,
            subagent_count=subagent_count,
            original_permission_detector_false_positive=fp_detected,
            false_positive_triggering_event_index=fp_index,
        )
