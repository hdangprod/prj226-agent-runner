"""PRJ226 Exactly-Once Control Plane Client for OpenHands.

Enforces:
1. Pinned OpenHands Agent Server 1.47.0 schema (StartConversationRequest with worktree=false, autotitle=false).
2. Header: X-Session-API-Key.
3. Durable append-only ledger with flush and fsync before network dispatch.
4. Full crash-recovery without replay across process restarts.
5. Stable event-ID watermark reconciliation against earlier turn history.
6. Fail-closed on unreconcilable state ambiguity. Zero replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from prj226_runner.errors import GovernanceBlockerError


class ExactlyOnceProtocolError(GovernanceBlockerError):
    """Raised when control plane violates exactly-once state invariants."""


class OpenHandsExactlyOnceClient:
    """Client implementing the qualified exactly-once protocol with durable ledger logging."""

    def __init__(
        self,
        base_url: str,
        session_api_key: str,
        run_id: str,
        ledger_path: Path,
        *,
        conversation_uuid: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session_api_key = session_api_key
        self.run_id = run_id
        self.ledger_path = Path(ledger_path)
        self.conversation_uuid = conversation_uuid or str(uuid.uuid4())
        self.timeout = timeout
        self._history: List[str] = []
        self._intents: Dict[str, Mapping[str, Any]] = {}

        # Outbound dispatch counters
        self.create_dispatch_count = 0
        self.prompt_dispatch_count = 0
        self.run_dispatch_count = 0

        if self.ledger_path.exists():
            self._recover_ledger()

    def _recover_ledger(self) -> None:
        with self.ledger_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    phase = entry["phase"]
                    self._history.append(phase)
                    self._intents[phase] = entry

        # Reconstruct dispatch counts from recovered durable ledger
        if "CREATE_INTENT" in self._history:
            self.create_dispatch_count = max(self.create_dispatch_count, 1)
        if "PROMPT_INTENT" in self._history:
            self.prompt_dispatch_count = max(self.prompt_dispatch_count, 1)
        if "RUN_INTENT" in self._history:
            self.run_dispatch_count = max(self.run_dispatch_count, 1)

    def _persist_transition(self, phase: str, digest: str, metadata: Optional[Mapping[str, Any]] = None) -> None:
        """Durable record append with flush and fsync before side-effects."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "run_id": self.run_id,
            "conversation_uuid": self.conversation_uuid,
            "phase": phase,
            "digest": digest,
            "metadata": metadata or {},
            "timestamp": time.time(),
        }
        with self.ledger_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._history.append(phase)
        self._intents[phase] = entry

    def _http_request(self, method: str, path: str, payload: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "X-Session-API-Key": self.session_api_key,
        }
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body = {"error": str(exc)}
            raise AmbiguousTransportError(exc.code, str(exc), body) from exc
        except Exception as exc:
            raise AmbiguousTransportError(-1, str(exc), {}) from exc

    def create_conversation(
        self,
        workspace_path: Path,
        *,
        acp_command: List[str],
        acp_model: str = "gpt-5.6-luna",
    ) -> str:
        """Execute exactly-once conversation creation matching StartConversationRequest schema."""
        if "CONVERSATION_CONFIRMED" in self._history:
            return self.conversation_uuid

        # Crash recovery: CREATE_INTENT already recorded -> reconcile first, NEVER dispatch second POST
        if "CREATE_INTENT" in self._history:
            if self._reconcile_conversation():
                self._persist_transition("CONVERSATION_CONFIRMED", self.conversation_uuid, {"recovered": True})
                return self.conversation_uuid
            raise ExactlyOnceProtocolError("Crash recovery: unresolved CREATE_INTENT could not be reconciled on server. Replay forbidden.")

        if not acp_command or not isinstance(acp_command, list):
            raise GovernanceBlockerError("acp_command must be an explicit non-empty list of arguments")

        resolved_workspace = str(workspace_path.resolve())
        payload = {
            "conversation_id": self.conversation_uuid,
            "workspace": {
                "working_dir": resolved_workspace,
                "kind": "LocalWorkspace",
            },
            "worktree": False,
            "autotitle": False,
            "confirmation_policy": {
                "kind": "NeverConfirm",
            },
            "agent": {
                "kind": "ACPAgent",
                "acp_command": acp_command,
                "acp_model": acp_model,
                "acp_session_mode": "read-only",
            },
        }

        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        self._persist_transition("CREATE_INTENT", digest, {"workspace": resolved_workspace, "model": acp_model})

        # Track outbound dispatch attempt
        self.create_dispatch_count += 1

        try:
            self._http_request("POST", "/api/conversations", payload)
            self._persist_transition("CONVERSATION_CONFIRMED", self.conversation_uuid)
        except AmbiguousTransportError as exc:
            if self._reconcile_conversation():
                self._persist_transition("CONVERSATION_CONFIRMED", self.conversation_uuid, {"reconciled": True})
            else:
                raise ExactlyOnceProtocolError(f"Conversation creation failed and could not be reconciled: {exc}")

        return self.conversation_uuid

    def _reconcile_conversation(self) -> bool:
        """Check if the conversation exists on server with exact conversation UUID."""
        try:
            resp = self._http_request("GET", f"/api/conversations/{self.conversation_uuid}")
            return bool(resp.get("conversation_id") == self.conversation_uuid or resp.get("id") == self.conversation_uuid)
        except Exception:
            return False

    def send_prompt(self, prompt: str) -> None:
        """Execute exactly-once prompt submission with stable watermark-based reconciliation."""
        if "CONVERSATION_CONFIRMED" not in self._history:
            raise ExactlyOnceProtocolError("Cannot submit prompt before CONVERSATION_CONFIRMED")
        if "PROMPT_CONFIRMED" in self._history:
            return

        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        # Crash recovery: PROMPT_INTENT already recorded -> reconcile first, NEVER dispatch second POST
        if "PROMPT_INTENT" in self._history:
            intent_meta = self._intents.get("PROMPT_INTENT", {}).get("metadata", {})
            watermark_id = intent_meta.get("watermark_event_id")
            if self._reconcile_prompt(prompt, digest, watermark_id):
                self._persist_transition("PROMPT_CONFIRMED", digest, {"recovered": True})
                return
            raise ExactlyOnceProtocolError("Crash recovery: unresolved PROMPT_INTENT could not be reconciled on server. Replay forbidden.")

        # Query existing events to establish stable event-ID watermark
        events = self.get_events(limit=100)
        if events and not (isinstance(events[-1], dict) and events[-1].get("id")):
            raise ExactlyOnceProtocolError("Event stream lacks stable event ID; cannot establish exactly-once boundary")
        watermark_event_id: str = events[-1].get("id") if events and isinstance(events[-1], dict) else "__EMPTY__"

        self._persist_transition("PROMPT_INTENT", digest, {"prompt_length": len(prompt), "watermark_event_id": watermark_event_id})

        payload = {
            "role": "user",
            "content": [{"type": "text", "text": prompt}],
            "run": False,
        }

        # Track outbound dispatch attempt
        self.prompt_dispatch_count += 1

        try:
            self._http_request("POST", f"/api/conversations/{self.conversation_uuid}/events", payload)
            self._persist_transition("PROMPT_CONFIRMED", digest)
        except AmbiguousTransportError as exc:
            if self._reconcile_prompt(prompt, digest, watermark_event_id):
                self._persist_transition("PROMPT_CONFIRMED", digest, {"reconciled": True})
            else:
                raise ExactlyOnceProtocolError(f"Prompt submission failed and could not be reconciled: {exc}")

    def _reconcile_prompt(self, expected_prompt: str, expected_digest: str, watermark_event_id: Optional[str]) -> bool:
        """Exact reconciliation: ensures a remote user MessageEvent newer than watermark matches exact prompt."""
        try:
            events = self.get_events(limit=100)
            if not events:
                return False

            if watermark_event_id and watermark_event_id != "__EMPTY__":
                # Find position of watermark_event_id
                idx = -1
                for i, ev in enumerate(events):
                    if ev.get("id") == watermark_event_id:
                        idx = i
                        break
                if idx == -1:
                    # Watermark event was not found in returned history -> fail closed
                    return False
                newer_events = events[idx + 1:]
            else:
                newer_events = events

            for item in newer_events:
                if item.get("kind") == "MessageEvent" and item.get("source") == "user":
                    llm_msg = item.get("llm_message", {})
                    content_list = llm_msg.get("content", [])
                    for block in content_list:
                        if isinstance(block, dict) and block.get("type") == "text":
                            txt = block.get("text", "")
                            if txt == expected_prompt or hashlib.sha256(txt.encode("utf-8")).hexdigest() == expected_digest:
                                return True
            return False
        except Exception:
            return False

    def submit_run(self) -> None:
        """Execute exactly-once /run command with stable watermark-based reconciliation."""
        if "PROMPT_CONFIRMED" not in self._history:
            raise ExactlyOnceProtocolError("Cannot submit /run before PROMPT_CONFIRMED")
        if "RUN_SUBMITTED" in self._history:
            return

        # Crash recovery: RUN_INTENT already recorded -> reconcile first, NEVER dispatch second POST
        if "RUN_INTENT" in self._history:
            intent_meta = self._intents.get("RUN_INTENT", {}).get("metadata", {})
            watermark_id = intent_meta.get("watermark_event_id")
            if self._reconcile_run(watermark_id):
                self._persist_transition("RUN_SUBMITTED", "run_confirmed", {"recovered": True})
                return
            raise ExactlyOnceProtocolError("Crash recovery: unresolved RUN_INTENT could not be reconciled on server. Replay forbidden.")

        events = self.get_events(limit=100)
        if events and not (isinstance(events[-1], dict) and events[-1].get("id")):
            raise ExactlyOnceProtocolError("Event stream lacks stable event ID; cannot establish exactly-once boundary")
        watermark_event_id: str = events[-1].get("id") if events and isinstance(events[-1], dict) else "__EMPTY__"

        self._persist_transition("RUN_INTENT", "run_once", {"watermark_event_id": watermark_event_id})

        # Track outbound dispatch attempt
        self.run_dispatch_count += 1

        try:
            self._http_request("POST", f"/api/conversations/{self.conversation_uuid}/run", {})
            self._persist_transition("RUN_SUBMITTED", "run_confirmed")
        except AmbiguousTransportError as exc:
            if self._reconcile_run(watermark_event_id):
                self._persist_transition("RUN_SUBMITTED", "run_confirmed", {"reconciled": True})
            else:
                raise ExactlyOnceProtocolError(f"/run submission failed and could not be reconciled: {exc}")

    def _reconcile_run(self, watermark_event_id: Optional[str]) -> bool:
        """Exact reconciliation: requires an execution status transition strictly newer than watermark."""
        try:
            events = self.get_events(limit=100)
            if not events:
                return False

            if watermark_event_id and watermark_event_id != "__EMPTY__":
                idx = -1
                for i, ev in enumerate(events):
                    if ev.get("id") == watermark_event_id:
                        idx = i
                        break
                if idx == -1:
                    return False
                newer_events = events[idx + 1:]
            else:
                newer_events = events

            for item in newer_events:
                if item.get("kind") == "ConversationStateUpdateEvent" and item.get("key") == "execution_status":
                    status_val = item.get("value")
                    if status_val in ("running", "finished", "completed"):
                        return True
            return False
        except Exception:
            return False

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch all events paginated."""
        all_events: List[Dict[str, Any]] = []
        page_id = None

        while True:
            path = f"/api/conversations/{self.conversation_uuid}/events/search?limit={limit}"
            if page_id:
                path += f"&page_id={page_id}"

            resp = self._http_request("GET", path)
            items = resp.get("items", [])
            all_events.extend(items)

            page_id = resp.get("next_page_id")
            if not page_id or not items:
                break

        return all_events


class AmbiguousTransportError(Exception):
    def __init__(self, status_code: int, message: str, body: Any) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.body = body
