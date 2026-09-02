"""Command-line interface for the single-project human-gated runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from prj226_runner.errors import RunnerError
from prj226_runner.runner import inspect_packet, run_packet


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prj226-runner")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "run"):
        item = sub.add_parser(command)
        item.add_argument("packet", type=Path)
        item.add_argument("--config", type=Path, default=None)
        if command == "run":
            item.add_argument("--authorize", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_packet(args.packet, args.config)
        else:
            result = run_packet(args.packet, args.config, authorize=args.authorize)
    except RunnerError as exc:
        print(json.dumps({"result": "NOT_READY", "error_class": exc.error_class.value, "error": exc.message}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("result") in {"READY_FOR_HUMAN_AUTHORIZATION", "ACCEPTANCE_READY"} else 2
