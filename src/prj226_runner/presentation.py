"""M2 human-facing formatting. No authority decisions."""

from __future__ import annotations

import json
from typing import Any, Mapping


def _fmt_argv(argv: Any) -> str:
    if isinstance(argv, list):
        return " ".join(str(a) for a in argv)
    return str(argv)


def format_gate_a_preview(preview: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Gate A preview for {preview.get('task_id', 'TASK-?')}")
    lines.append("")
    lines.append("REQUEST")
    lines.append(f"- {preview.get('request', '')}")
    lines.append("")
    lines.append("BEHAVIOR")
    lines.append(f"- {preview.get('behavior', '')}")
    lines.append("")
    lines.append("FILES")
    files = preview.get("files") or []
    if files:
        for path in files:
            lines.append(f"- {path}")
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("CHECKS")
    checks = preview.get("checks") or []
    if checks:
        for idx, argv in enumerate(checks, start=1):
            lines.append(f"- check {idx}: {_fmt_argv(argv)}")
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("EXECUTION")
    execution = preview.get("execution") or {}
    tool = execution.get("builder_tool", "")
    model = execution.get("builder_model", "")
    exe = execution.get("builder_executable", "")
    lines.append(f"- builder/tool: {tool or '<bound by config>'}")
    lines.append(f"- builder/model: {model or '<bound by config>'}")
    if exe:
        lines.append(f"- builder/executable: {exe}")
    lines.append(f"- scope: {preview.get('scope') or 'default'}")
    lines.append(f"- branch: {preview.get('canonical_branch', '')}")
    lines.append("")
    lines.append("REVIEW")
    lines.append(f"- {preview.get('review_mode', 'UNKNOWN')}")
    reason = preview.get("review_reason", "")
    if reason:
        lines.append(f"- reason: {reason}")
    lines.append("")
    lines.append("UNCERTAINTY")
    uncertainties = preview.get("uncertainties") or []
    if uncertainties:
        for item in uncertainties:
            lines.append(f"- {item}")
    else:
        lines.append("- none material")
    lines.append("")
    lines.append("To authorize execution, type exactly: approve")
    return "\n".join(lines)


def format_acceptance_summary(data: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Acceptance summary for {data.get('task_id', '')}")
    lines.append("")
    lines.append("REQUESTED")
    lines.append(f"- {data.get('description', '')}")
    lines.append("")
    lines.append("CHANGED")
    changed = data.get("changed_paths") or []
    if changed:
        for path in changed:
            lines.append(f"- {path}")
    else:
        lines.append("- <none>")
    diff = str(data.get("diff_summary") or "").strip()
    if diff:
        lines.append(f"- diff: {diff[:2000]}")
    lines.append("")
    lines.append("BEHAVIOR EVIDENCE")
    report = data.get("report") or {}
    det = report.get("deterministic_result") or report.get("verification_disposition") or ""
    if det:
        lines.append(f"- deterministic: {det}")
    ver = report.get("verification_disposition", "")
    if ver:
        lines.append(f"- verification: {ver}")
    lines.append(f"- run: {data.get('run_id', '')}")
    lines.append("")
    lines.append("CHECKS")
    details = data.get("check_details") or []
    if details:
        for entry in details:
            argv = _fmt_argv(entry.get("argv"))
            code = entry.get("exit_code")
            if code == 0:
                lines.append(f"- PASS: {argv}")
            elif code is None:
                lines.append(f"- UNKNOWN: {argv}")
            else:
                lines.append(f"- FAIL({code}): {argv}")
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("SEMANTIC REVIEW")
    mode = str(data.get("review_mode") or "UNKNOWN")
    rstatus = data.get("review_status")
    if mode == "NONE":
        lines.append("- NOT_REQUIRED")
    elif rstatus == "PASS":
        lines.append("- PASS (targeted review bound to exact candidate/evidence)")
    else:
        lines.append(f"- {rstatus or 'UNKNOWN'}")
    lines.append("")
    lines.append("UNVERIFIED RISK")
    lines.append("- deterministic and targeted evidence do not prove absence of all defects;")
    lines.append("  review is bounded to the frozen candidate and stated checks.")
    lines.append("")
    lines.append("RUN INFO")
    lines.append(f"- run: {data.get('run_id', '')}")
    report_info = data.get("report") or {}
    # Elapsed/duration where available (never invent tokens/costs).
    tests = report_info.get("tests") or []
    if tests:
        total_ms = sum(int(t.get("duration_ms") or 0) for t in tests if isinstance(t, dict))
        lines.append(f"- deterministic tests: {len(tests)} passed, {total_ms}ms total")
    else:
        lines.append("- deterministic tests: as recorded in evidence")
    lines.append("- provider/token/cost data: only as recorded in evidence (none invented)")
    lines.append("")
    lines.append("NEXT ACTION")
    lines.append(f"- prj226-runner accept {data.get('task_id', '')}")
    return "\n".join(lines)


def format_stopped_summary(data: Mapping[str, Any]) -> str:
    task_id = str(data.get("task_id") or data.get("record", {}).get("task_id") or "TASK-?")
    run_id = str(data.get("run_id") or data.get("record", {}).get("run_id") or "<none>")
    error = str(data.get("error") or data.get("record", {}).get("error") or "Run STOPPED.")
    lines: list[str] = []
    lines.append("STOPPED")
    lines.append("")
    lines.append("What happened:")
    lines.append(f"- Task {task_id} stopped. {error[:1000]}")
    # Check count if available.
    report = data.get("report") or data.get("result") or {}
    if isinstance(report, dict) and report.get("tests") is not None:
        lines.append(f"- deterministic evidence preserved for run {run_id}.")
    lines.append("")
    lines.append("Preserved:")
    lines.append(f"- Task {task_id} and run {run_id} evidence remain available.")
    lines.append("")
    lines.append("Not done:")
    lines.append("- Candidate was not integrated.")
    lines.append("- Target branch was not changed by acceptance.")
    lines.append("")
    lines.append("Next:")
    lines.append(f"- prj226-runner status {task_id}")
    lines.append(f"- prj226-runner resume {task_id} --handoff")
    return "\n".join(lines)


def format_status(status: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"TASK {status.get('task_id', '')}")
    lines.append(f"STATUS {status.get('status', '')}")
    lines.append("")
    if status.get("candidate_head"):
        lines.append(f"CANDIDATE {status.get('candidate_head')}")
        if status.get("candidate_ref"):
            lines.append(f"REF {status.get('candidate_ref')}")
    else:
        lines.append("CANDIDATE <none>")
    lines.append("")
    lines.append("CHECKS")
    details = status.get("check_details") or []
    if details:
        for entry in details:
            argv = _fmt_argv(entry.get("argv"))
            code = entry.get("exit_code")
            if code == 0:
                lines.append(f"- PASS: {argv}")
            elif code is None:
                lines.append(f"- PENDING: {argv}")
            else:
                lines.append(f"- FAIL({code}): {argv}")
    else:
        checks = status.get("checks") or []
        for argv in checks:
            lines.append(f"- {_fmt_argv(argv)}")
    lines.append("")
    lines.append(f"REVIEW {status.get('review_mode', '')}/{status.get('review_status') or '<none>'}")
    lines.append("")
    first = status.get("first_failure")
    if first:
        lines.append("FIRST FAILURE")
        lines.append(f"- {str(first)[:1500]}")
        lines.append("")
    lines.append("NEXT ACTION")
    lines.append(f"- {status.get('next_action', '')}")
    return "\n".join(lines)


def format_continuation(continuation: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Handoff for {continuation.get('task_id', '')} [{continuation.get('status', '')}]")
    lines.append("")
    lines.append(f"Request: {continuation.get('description', '')}")
    lines.append(f"Status: {continuation.get('status', '')}")
    if continuation.get("run_id"):
        lines.append(f"Run: {continuation.get('run_id')}")
    if continuation.get("candidate_head"):
        lines.append(f"Candidate: {continuation.get('candidate_head')}")
    lines.append(f"Review: {continuation.get('review_mode')}/{continuation.get('review_status') or '<none>'}")
    blocking = continuation.get("blocking_failure")
    if blocking:
        lines.append(f"Blocking: {blocking}")
    lines.append("")
    lines.append("Evidence:")
    for ref in continuation.get("evidence_references") or []:
        lines.append(f"- {ref}")
    lines.append("")
    lines.append("Must not repeat:")
    for item in continuation.get("must_not_repeat") or []:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(f"Next: {continuation.get('next_action', '')}")
    fresh = continuation.get("fresh_authorization_required")
    lines.append(f"Fresh authorization required: {'yes' if fresh else 'no'}")
    return "\n".join(lines)


def format_init_summary(summary: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Initialized project {summary.get('project_id', '')}")
    lines.append(f"- repository: {summary.get('product_repository', '')}")
    lines.append(f"- branch: {summary.get('canonical_branch', '')}")
    lines.append(f"- head: {summary.get('head', '')}")
    lines.append(f"- runtime: {summary.get('runtime_root', '')}")
    lines.append(f"- defaults: {summary.get('defaults_path', '')}")
    lines.append("- providers: not invoked (0 calls)")
    lines.append("- next: prj226-runner task \"DESCRIPTION\"")
    return "\n".join(lines)
