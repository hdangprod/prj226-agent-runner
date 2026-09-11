"""Command-line interface for the single-project human-gated runner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from prj226_runner.controller import (
    Controller,
    derive_task_packet,
    derive_task_packet_v2,
    discover_next_work,
    ingest_runner_result,
    ingest_runner_result_v2,
    inspect_project,
    load_project_manifest,
    prepare_gate_b,
    prepare_gate_b_v2,
    resume_controller,
)
from prj226_runner.errors import ArtifactValidationError, RunnerEnvironmentError, RunnerError
from prj226_runner.runner import inspect_packet, inspect_packet_v2, run_packet, run_packet_v2


def _json_artifact(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunnerEnvironmentError(f"Cannot read CLI artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(f"CLI artifact is not valid JSON: {path}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prj226-runner")
    sub = parser.add_subparsers(dest="command", required=True)
    # M2 primary workflow commands (exactly five).
    item = sub.add_parser("init")
    item.add_argument("--manifest", type=Path, required=True)
    item.add_argument("--config", type=Path, required=True)
    item.add_argument("--scopes", type=Path, default=None)
    item = sub.add_parser("task")
    item.add_argument("description", type=str)
    item.add_argument("--scope", type=str, default=None)
    item.add_argument("--preview-only", action="store_true")
    item = sub.add_parser("status")
    item.add_argument("task_id", type=str, nargs="?")
    item.add_argument("--json", dest="as_json", action="store_true")
    item = sub.add_parser("resume")
    item.add_argument("arg1", type=str, nargs="?")
    item.add_argument("arg2", type=str, nargs="?")
    item.add_argument("--handoff", action="store_true")
    item = sub.add_parser("accept")
    item.add_argument("task_id", type=str)
    # Historical/secondary compatibility commands.
    for command in ("inspect", "run"):
        item = sub.add_parser(command)
        item.add_argument("packet", type=Path)
        item.add_argument("--config", type=Path, default=None)
        if command == "run":
            item.add_argument("--authorize", action="store_true")
    item = sub.add_parser("inspect-project")
    item.add_argument("manifest", type=Path)
    item = sub.add_parser("discover-work")
    item.add_argument("manifest", type=Path)
    item = sub.add_parser("draft-contract")
    item.add_argument("manifest", type=Path)
    item.add_argument("--run-id", required=True)
    item.add_argument("--owned-path", action="append", required=True)
    item.add_argument("--output", type=Path, required=True)
    item.add_argument("--success-criterion", action="append", default=None)
    item.add_argument("--test-command", action="append", default=None, help="JSON argv array")
    item = sub.add_parser("derive-task-packet")
    item.add_argument("contract", type=Path)
    item.add_argument("gate_a", type=Path)
    item.add_argument("output", type=Path)
    item = sub.add_parser("ingest-result")
    item.add_argument("contract", type=Path)
    item.add_argument("result_artifact", type=Path)
    item = sub.add_parser("prepare-gate-b")
    item.add_argument("contract", type=Path)
    item.add_argument("result_artifact", type=Path)
    item.add_argument("review", type=Path)
    # M1 V2 plumbing only: versioned contract/packet/runner context arguments.
    item = sub.add_parser("inspect-v2")
    item.add_argument("packet", type=Path)
    item.add_argument("contract", type=Path)
    item.add_argument("gate_a", type=Path)
    item.add_argument("--config", type=Path, default=None)
    item = sub.add_parser("run-v2")
    item.add_argument("packet", type=Path)
    item.add_argument("contract", type=Path)
    item.add_argument("gate_a", type=Path)
    item.add_argument("--config", type=Path, default=None)
    item.add_argument("--authorize", action="store_true")
    item = sub.add_parser("draft-contract-v2")
    item.add_argument("manifest", type=Path)
    item.add_argument("--run-id", required=True)
    item.add_argument("--owned-path", action="append", required=True)
    item.add_argument("--output", type=Path, required=True)
    item.add_argument("--runtime-root", required=True)
    item.add_argument("--change-category", action="append", default=None)
    item.add_argument("--human-requested-targeted", action="store_true")
    item.add_argument("--reviewer-executable", default=None)
    item.add_argument("--review-brief", default=None)
    item.add_argument("--success-criterion", action="append", default=None)
    item.add_argument("--test-command", action="append", default=None, help="JSON argv array")
    item = sub.add_parser("derive-task-packet-v2")
    item.add_argument("contract", type=Path)
    item.add_argument("gate_a", type=Path)
    item.add_argument("output", type=Path)
    item = sub.add_parser("ingest-result-v2")
    item.add_argument("contract", type=Path)
    item.add_argument("result_artifact", type=Path)
    item = sub.add_parser("prepare-gate-b-v2")
    item.add_argument("contract", type=Path)
    item.add_argument("result_artifact", type=Path)
    return parser


def _read_approval() -> str:
    try:
        line = sys.stdin.readline()
    except Exception:
        return ""
    if line is None:
        return ""
    if line == "":
        return ""
    return line.strip()


def _cmd_init(args: argparse.Namespace) -> int:
    from prj226_runner import presentation as P
    from prj226_runner import workflow as W

    try:
        summary = W.init_project(args.manifest, args.config, scopes_path=args.scopes)
    except W.WorkflowError as exc:
        print(f"Init blocked: {exc.message}", file=sys.stderr)
        if exc.exit_code == 2 or exc.error_code in ("WORKFLOW_INPUT_ERROR", "M2_SCOPE_CATALOG_INVALID"):
            return 2
        return 20
    print(P.format_init_summary(summary))
    return 0


def _cmd_task(args: argparse.Namespace) -> int:
    from prj226_runner import presentation as P
    from prj226_runner import workflow as W

    description = args.description
    scope = args.scope
    preview_only = bool(args.preview_only)
    if preview_only:
        try:
            outcome = W.create_task(description, scope, preview_only=True)
        except W.WorkflowError as exc:
            print(f"Task preview blocked: {exc.message}", file=sys.stderr)
            return exc.exit_code if exc.exit_code in (2, 10, 20) else 2
        print(P.format_gate_a_preview(outcome["preview"]))
        print("")
        print(f"TASK_ID {outcome['task_id']} (preview only; no execution)")
        return 0
    # Normal path: show preview first, then require literal approval.
    try:
        prepared = W.create_task(description, scope, preview_only=True)
        print(P.format_gate_a_preview(prepared["preview"]))
        print("")
        print("Type exactly 'approve' to authorize one M1 execution, or anything else to abort:")
        approval = _read_approval()
        outcome = W.create_task(description, scope, preview_only=False, approval_text=approval, task_id=prepared["task_id"])
    except W.WorkflowError as exc:
        # Distinguish declined Gate A (10) from blockers (20) and input errors (2).
        if exc.error_code == "WORKFLOW_GATE_A_DECLINED":
            print(f"Gate A not approved. {exc.message}", file=sys.stderr)
            print("STOPPED")
            print("")
            print("What happened:")
            print("- Gate A was not approved with literal 'approve'.")
            print("")
            print("Preserved:")
            print("- Task record preserved without execution.")
            print("")
            print("Not done:")
            print("- No builder invoked; no candidate created.")
            print("")
            print("Next:")
            print("- Re-run prj226-runner task with explicit approval when ready.")
            return 10
        if exc.error_code == "WORKFLOW_RUN_STOPPED":
            # Execution ran but M1 stopped: show stopped summary, exit 10.
            print(f"{exc.message}", file=sys.stderr)
            # Try to load status for richer summary.
            try:
                # Find latest task for this description? Fall back to generic.
                tid = W.find_latest_task_id()
                st = W.get_status(tid)
                print(P.format_stopped_summary({"task_id": st["task_id"], "run_id": st["run_id"], "error": st["error"] or exc.message, "report": st["report"]}))
            except Exception:
                print("STOPPED")
            return 10
        print(f"Task blocked: {exc.message}", file=sys.stderr)
        return exc.exit_code if exc.exit_code in (2, 10, 20) else 2
    # Success: ACCEPTANCE_READY.
    try:
        from prj226_runner import workflow as W2

        acc = W2.get_acceptance_data(outcome["task_id"])
        print("")
        print(P.format_acceptance_summary(acc))
    except Exception:
        print(f"TASK_ID {outcome['task_id']} ACCEPTANCE_READY")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    from prj226_runner import presentation as P
    from prj226_runner import workflow as W

    task_id = args.task_id
    as_json = bool(args.as_json)
    try:
        st = W.get_status(task_id, None, as_json=as_json)
    except W.WorkflowError as exc:
        print(f"Status blocked: {exc.message}", file=sys.stderr)
        if as_json:
            print(json.dumps({"result": "NOT_READY", "error": exc.message, "error_code": exc.error_code}, indent=2, sort_keys=True))
        return exc.exit_code if exc.exit_code in (2, 10, 20) else 2
    if as_json:
        stable = {
            "task_id": st["task_id"],
            "project_id": st["project_id"],
            "status": st["status"],
            "run_id": st["run_id"],
            "candidate_head": st["candidate_head"],
            "candidate_tree": st["candidate_tree"],
            "candidate_ref": st.get("record", {}).get("candidate_ref"),
            "checks": st["checks"],
            "review_mode": st["review_mode"],
            "review_status": st["review_status"],
            "error_class": st["error_class"],
            "error": st["error"],
            "next_action": st["next_action"],
        }
        print(json.dumps(stable, indent=2, sort_keys=True))
        return 0
    print(P.format_status(st))
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    from prj226_runner import presentation as P
    from prj226_runner import workflow as W

    # Legacy form: resume MANIFEST STATE (two positionals, no --handoff).
    if args.arg2 is not None:
        if args.handoff:
            print("Legacy resume does not support --handoff", file=sys.stderr)
            return 2
        try:
            result = resume_controller(args.arg1, args.arg2)
        except RunnerError as exc:
            print(json.dumps({"result": "NOT_READY", "error_class": exc.error_class.value, "error": exc.message}, indent=2))
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("result") in {
            "READY_FOR_HUMAN_AUTHORIZATION", "ACCEPTANCE_READY", "PROJECT_INSPECTED", "NEXT_WORK_DISCOVERED",
            "RESULT_INGESTED", "RESUME_VERIFIED",
        } else 2
    # M2 form: resume TASK_ID [--handoff].
    if not args.arg1:
        print("resume requires TASK_ID", file=sys.stderr)
        return 2
    task_id = args.arg1
    if args.handoff:
        try:
            continuation, dest = W.write_handoff(task_id)
        except W.WorkflowError as exc:
            print(f"Resume blocked: {exc.message}", file=sys.stderr)
            return exc.exit_code if exc.exit_code in (2, 10, 20) else 20
        print(P.format_continuation(continuation))
        print("")
        print(f"Continuation written to {dest}")
        return 0
    try:
        st = W.get_status(task_id)
        continuation = W.build_continuation(task_id)
    except W.WorkflowError as exc:
        print(f"Resume blocked: {exc.message}", file=sys.stderr)
        return exc.exit_code if exc.exit_code in (2, 10, 20) else 20
    print(P.format_status(st))
    print("")
    print(P.format_continuation(continuation))
    return 0


def _cmd_accept(args: argparse.Namespace) -> int:
    from prj226_runner import presentation as P
    from prj226_runner import workflow as W

    task_id = args.task_id
    try:
        acc = W.get_acceptance_data(task_id)
    except W.WorkflowError as exc:
        print(f"Accept blocked: {exc.message}", file=sys.stderr)
        # Not acceptance-ready -> exit 10; integrity/staleness -> 20.
        if exc.exit_code in (2, 10, 20):
            # Show stopped-style guidance for not-ready.
            if exc.exit_code == 10 or "not ACCEPTANCE_READY" in exc.message or "NOT_ACCEPTANCE" in exc.error_code:
                print("STOPPED")
                return 10
            return exc.exit_code
        return 10
    print(P.format_acceptance_summary(acc))
    print("")
    print("Type exactly 'approve' to authorize local Git integration (no push), or anything else to abort:")
    approval = _read_approval()
    try:
        outcome = W.perform_accept(task_id, approval)
    except W.WorkflowError as exc:
        print(f"Accept blocked: {exc.message}", file=sys.stderr)
        return exc.exit_code if exc.exit_code in (2, 10, 20) else 10
    print(f"Integrated {outcome['task_id']} -> {outcome['candidate_head']} (local only, no push)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # M2 primary commands.
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "task":
        return _cmd_task(args)
    if args.command == "status":
        return _cmd_status(args)
    if args.command == "resume":
        return _cmd_resume(args)
    if args.command == "accept":
        return _cmd_accept(args)
    try:
        if args.command == "inspect":
            result = inspect_packet(args.packet, args.config)
        elif args.command == "run":
            result = run_packet(args.packet, args.config, authorize=args.authorize)
        elif args.command == "inspect-project":
            result = inspect_project(load_project_manifest(args.manifest))
            result.pop("_document_contents", None)
        elif args.command == "discover-work":
            result = discover_next_work(load_project_manifest(args.manifest))
            result.pop("_task_content", None)
        elif args.command == "draft-contract":
            manifest = load_project_manifest(args.manifest)
            controller = Controller(manifest)
            instruments = [_json_artifact(Path(command)) if command.endswith(".json") else json.loads(command) for command in args.test_command or []]
            result = controller.draft(
                run_id=args.run_id,
                owned_paths=args.owned_path,
                success_criteria=args.success_criterion,
                acceptance_instruments=instruments,
                output_path=args.output,
            )
        elif args.command == "derive-task-packet":
            result = derive_task_packet(args.contract, _json_artifact(args.gate_a), output_path=args.output)
        elif args.command == "ingest-result":
            result = ingest_runner_result(args.contract, args.result_artifact)
        elif args.command == "prepare-gate-b":
            contract = _json_artifact(args.contract)
            result = prepare_gate_b(
                contract,
                ingest_runner_result(contract, args.result_artifact),
                args.review,
            )
        elif args.command == "inspect-v2":
            result = inspect_packet_v2(args.packet, args.contract, args.gate_a, args.config)
        elif args.command == "run-v2":
            result = run_packet_v2(args.packet, args.contract, args.gate_a, args.config, authorize=args.authorize)
        elif args.command == "draft-contract-v2":
            from prj226_runner.controller import draft_design_contract_v2
            manifest = load_project_manifest(args.manifest)
            controller = Controller(manifest)
            inspection = controller.inspect()
            work_item = controller.discover()
            instruments = [_json_artifact(Path(command)) if command.endswith(".json") else json.loads(command) for command in args.test_command or []]
            result = draft_design_contract_v2(
                manifest,
                work_item,
                inspection,
                run_id=args.run_id,
                owned_paths=args.owned_path,
                runtime_root=args.runtime_root,
                change_categories=args.change_category or [],
                human_requested_targeted=args.human_requested_targeted,
                reviewer_executable=args.reviewer_executable,
                review_brief=args.review_brief,
                success_criteria=args.success_criterion,
                acceptance_instruments=instruments or None,
                output_path=args.output,
            )
        elif args.command == "derive-task-packet-v2":
            result = derive_task_packet_v2(args.contract, _json_artifact(args.gate_a), output_path=args.output)
        elif args.command == "ingest-result-v2":
            result = ingest_runner_result_v2(args.contract, args.result_artifact)
        elif args.command == "prepare-gate-b-v2":
            contract = _json_artifact(args.contract)
            result = prepare_gate_b_v2(
                contract,
                ingest_runner_result_v2(contract, args.result_artifact),
            )
        else:
            # Legacy resume with two positionals.
            result = resume_controller(args.arg1, args.arg2)
    except RunnerError as exc:
        print(json.dumps({"result": "NOT_READY", "error_class": exc.error_class.value, "error": exc.message}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("result") in {
        "READY_FOR_HUMAN_AUTHORIZATION", "ACCEPTANCE_READY", "PROJECT_INSPECTED", "NEXT_WORK_DISCOVERED",
        "RESULT_INGESTED", "RESUME_VERIFIED",
    } else 2
