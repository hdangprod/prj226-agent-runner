"""Command-line interface for the single-project human-gated runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from prj226_runner.controller import (
    Controller,
    derive_task_packet,
    discover_next_work,
    ingest_runner_result,
    inspect_project,
    load_project_manifest,
    prepare_gate_b,
    resume_controller,
)
from prj226_runner.errors import ArtifactValidationError, RunnerEnvironmentError, RunnerError
from prj226_runner.runner import inspect_packet, run_packet


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
    item = sub.add_parser("resume")
    item.add_argument("manifest", type=Path)
    item.add_argument("state", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
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
        else:
            result = resume_controller(args.manifest, args.state)
    except RunnerError as exc:
        print(json.dumps({"result": "NOT_READY", "error_class": exc.error_class.value, "error": exc.message}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("result") in {
        "READY_FOR_HUMAN_AUTHORIZATION", "ACCEPTANCE_READY", "PROJECT_INSPECTED", "NEXT_WORK_DISCOVERED",
        "RESULT_INGESTED", "RESUME_VERIFIED",
    } else 2
