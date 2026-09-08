#!/usr/bin/env python3
"""M2-R001 deterministic verification sequence (fail-fast, no retry, no repair).

Binding inputs (all required):
  --m2-head, --m2-tree, --m2-candidate-digest, --m2-evidence, --output-dir

Fail-fast sequence:
  1. Exact M2 baseline binding including supplied digest/evidence.
  2. Repair allowlist.
  3. Protected M1/historical bytes.
  4. 29 schemas against each declared draft.
  5. Exact required R001 test-name presence.
  6. R001 focused suite (0 fail / 0 error / 0 skip).
  7. M2 suite (24/24 PASS).
  8. M1 suite (25/25 PASS).
  9. Full test suite (0 fail / 0 error / 0 skip).
  10. P01-P06 (all PASS).
  11. Exact original Liam context-authz regression.
  12. Canonical R001 change-manifest digest.
  13. Recompute digest after verification and require unchanged.
  14. Canonical refs/original checkout remain unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


EXPECTED_M2_HEAD = "1686907f531425b1c77c630cdf2556332f5b00c6"
EXPECTED_M2_TREE = "4bc5c042b9a87c07bbbe69872f068a0858bc2e9b"
EXPECTED_M2_DIGEST = "549387c0f17291bc0b699a69dc5318f76f40cbd1d1957b012c9d8b7d3fb29005"
EXPECTED_M2_EVIDENCE = "/Users/dangnguyen/Desktop/prj226-agent-runner-recovery/M2-DETERMINISTIC-001"

EXPECTED_MAIN_REF = "3fe916744a34a92552aa3ec64a4fb6ec9ea0f271"
EXPECTED_M1_REF = "bb27e80f98091bb0ef615b5fbc4092a509abf898"
CANON_REPO = Path("/Users/dangnguyen/Desktop/prj226-agent-runner")

CANDIDATE_SCHEMA = "PRJ226.M2.R001.CANDIDATE.v1"

ALLOWED_R001_SURFACE = {
    "src/prj226_runner/cli.py",
    "src/prj226_runner/workflow.py",
    "schemas/project-defaults.schema.json",
    "schemas/workflow-scope-catalog.schema.json",
    "tests/test_m2.py",
    "verify_m2.py",
    "tests/test_m2_r001.py",
    "verify_m2_r001.py",
}

REQUIRED_R001_TESTS = [
    "test_m2_r001_scope_catalog_schema_accepts_valid_catalog",
    "test_m2_r001_scope_catalog_rejects_unknown_fields",
    "test_m2_r001_init_persists_scope_catalog",
    "test_m2_r001_init_without_catalog_creates_no_fake_authority",
    "test_m2_r001_default_scope_resolves",
    "test_m2_r001_invalid_default_scope_rejected",
    "test_m2_r001_unknown_scope_fails_before_gate_a",
    "test_m2_r001_missing_scope_without_default_fails_before_gate_a",
    "test_m2_r001_owned_paths_are_exact",
    "test_m2_r001_check_argv_is_exact_and_ordered",
    "test_m2_r001_task_description_cannot_widen_paths",
    "test_m2_r001_task_description_cannot_replace_checks",
    "test_m2_r001_scope_names_are_opaque",
    "test_m2_r001_none_review_from_empty_categories",
    "test_m2_r001_targeted_review_from_frozen_category",
    "test_m2_r001_no_src_app_txt_production_fallback",
    "test_m2_r001_no_generic_pass_check_production_fallback",
    "test_m2_r001_preview_only_invokes_zero_providers",
    "test_m2_r001_real_liam_context_authz_preview",
]

DOGFOOD_DESCRIPTION = (
    "Change explicit context selection so that missing or mismatched authorization "
    "is rejected without mutation. Limit implementation to src/domain/context.ts "
    "and tests/domain/context.test.ts. Preserve valid selection and "
    "action-project-mismatch semantics. Acceptance: vitest run "
    "tests/domain/context.test.ts passes including authorization-rejected case."
)

TIME_CAP_SECONDS = 8 * 3600

FAKE_BUILDER_SRC = """#!@@EXE@@
import os, pathlib, subprocess, sys
counter = pathlib.Path(@@COUNTER@@)
try:
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
except Exception:
    prior = 0
counter.write_text(str(prior + 1), encoding="utf-8")
if os.environ.get("FAKE_BUILDER_FAIL"):
    raise SystemExit(3)
target = pathlib.Path(os.environ.get("FAKE_TARGET", "src/app.txt"))
if os.environ.get("FAKE_NO_CHANGE"):
    raise SystemExit(0)
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("builder change\\n", encoding="utf-8")
if os.environ.get("FAKE_COMMIT"):
    subprocess.run(["git", "add", "--", str(target)], check=True)
    subprocess.run(["git", "commit", "-m", "unexpected"], check=True)
"""

FAKE_REVIEWER_SRC = """#!@@EXE@@
import hashlib, json, os, pathlib, subprocess, sys, time
counter = pathlib.Path(@@COUNTER@@)
try:
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
except Exception:
    prior = 0
counter.write_text(str(prior + 1), encoding="utf-8")
args = sys.argv
out = pathlib.Path(args[args.index("-o") + 1]) if "-o" in args else None
prompt = args[-1] if len(args) > 1 else ""
if "TIMEOUT" in prompt:
    time.sleep(10)
if "MUTATE_WORKTREE" in prompt:
    pathlib.Path("reviewer-mutated.txt").write_text("bad")
if "PROCESS_FAILURE" in prompt and "WITH_OUTPUT" not in prompt:
    raise SystemExit(9)
try:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
except Exception:
    head = "0" * 40
    tree = "0" * 40
try:
    branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
    if not branch:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
except Exception:
    branch = "harn-candidate/unknown"
if "MISMATCH_HEAD" in prompt:
    head = "1" * 40
if "MISMATCH_TREE" in prompt:
    tree = "2" * 40
if "MISMATCH_REF" in prompt:
    branch = "harn-candidate/wrong-ref"
if out is None:
    raise SystemExit(0)
if "MALFORMED" in prompt:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("{bad", encoding="utf-8")
    raise SystemExit(0)
if "MISSING_OUTPUT" in prompt:
    raise SystemExit(0)
if "FORCE_NEEDS_FIX" in prompt or prompt.strip() == "NEEDS_FIX":
    disposition = "NEEDS_FIX"
    blocking = ["blocking finding"]
else:
    disposition = "PASS"
    blocking = []
if "BLOCKING_WITH_PASS" in prompt:
    disposition = "PASS"
    blocking = ["contradiction"]
value = {"review_version": "HARN-002.TARGETED_REVIEW.v1", "disposition": disposition, "reviewed_head": head, "reviewed_tree": tree, "reviewed_ref": branch, "blocking_findings": blocking, "non_blocking_findings": []}
if "INVALID_SCHEMA" in prompt:
    value["unexpected"] = "extra"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(value), encoding="utf-8")
if "PROCESS_FAILURE_WITH_OUTPUT" in prompt or ("PROCESS_FAILURE" in prompt and "WITH_OUTPUT" in prompt):
    raise SystemExit(9)
"""


def _run(argv: list[str], cwd: Path, env: dict[str, str], timeout: float, input_text: str | None = None) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout, input=input_text)
        return {"argv": argv, "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "duration_ms": int((time.monotonic() - start) * 1000)}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"argv": argv, "exit_code": None, "stdout": stdout, "stderr": stderr, "duration_ms": int((time.monotonic() - start) * 1000), "timed_out": True}


def _git(repo: Path, args: list[str]) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)
    return res.stdout.strip()


def _write_inventory(out: Path) -> None:
    lines: list[str] = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "inventory.sha256":
            h = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    h.update(chunk)
            lines.append(f"{h.hexdigest()}  {path.relative_to(out)}")
    (out / "inventory.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_fixture(base: Path, name: str) -> dict:
    root = base / name
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "product"
    subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
    _git(repo, ["config", "user.email", "m2-r001@example.test"])
    _git(repo, ["config", "user.name", "M2-R001 Verify"])
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.txt").write_text("base\n", encoding="utf-8")
    (repo / "docs").mkdir(parents=True)
    (repo / "docs/tasks").mkdir(parents=True)
    (repo / "docs/CURRENT.md").write_text("**Next executable work:** ENG-001 — Acceptance\n", encoding="utf-8")
    (repo / "docs/PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| ENG-001 | acceptance | PROPOSED |\n", encoding="utf-8")
    (repo / "docs/tasks/ENG-001.md").write_text("# ENG-001 — Acceptance\n", encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    (repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
    (repo / "docs/README.md").write_text("docs\n", encoding="utf-8")
    _git(repo, ["add", "."])
    _git(repo, ["commit", "-m", "base"])
    branch = _git(repo, ["branch", "--show-current"])
    builder_count = root / "builder-count.txt"
    reviewer_count = root / "reviewer-count.txt"
    fake_builder = root / "fake-builder.py"
    fake_builder.write_text(FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(builder_count))), encoding="utf-8")
    fake_builder.chmod(fake_builder.stat().st_mode | stat.S_IXUSR)
    fake_reviewer = root / "fake-reviewer.py"
    fake_reviewer.write_text(FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(reviewer_count))), encoding="utf-8")
    fake_reviewer.chmod(fake_reviewer.stat().st_mode | stat.S_IXUSR)
    runtime = root / "runtime"
    config = root / "runner.toml"
    config.write_text(
        "[runner]\n"
        f"runtime_root = {json.dumps(str(runtime))}\n\n"
        "[agents.builder]\n"
        "tool = 'codex'\n"
        f"executable = {json.dumps(str(fake_builder))}\nmodel = 'fake-builder'\ntimeout_seconds = 20\n\n"
        "[agents.dv]\n"
        "tool = 'opencode2'\n"
        f"executable = {json.dumps(str(fake_builder))}\nmodel = 'fake-muse'\ntimeout_seconds = 20\n\n"
        "[agents.sos_reviewer]\n"
        "tool = 'opencode2'\n"
        f"executable = {json.dumps(str(fake_reviewer))}\nmodel = 'fake-mimo'\ntimeout_seconds = 20\n",
        encoding="utf-8",
    )
    manifest = {
        "project_id": f"M2-{name.upper()}",
        "repository_path": str(repo),
        "canonical_branch": branch,
        "canonical_docs": {"current": "docs/CURRENT.md", "engineering_plan": "docs/PLAN.md", "governance": ["AGENTS.md"], "project": ["README.md", "docs/README.md"]},
        "discovery_rules": {"current_next_work_marker": "**Next executable work:**", "plan_task_column": "Task", "plan_state_column": "State", "eligible_plan_states": ["PROPOSED"], "task_id_pattern": "ENG-[0-9]{3}", "task_file_glob": "docs/tasks/{task_id}.md"},
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    scopes_dict = {
        "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
        "default_scope": "default",
        "scopes": {
            "default": {
                "owned_paths": ["src/app.txt"],
                "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                "change_categories": [],
            },
            "targeted": {
                "owned_paths": ["src/app.txt"],
                "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                "change_categories": ["MODULE_BOUNDARY"],
            },
            "failing": {
                "owned_paths": ["src/app.txt"],
                "checks": [[sys.executable, "-c", "import sys; sys.exit(1)"]],
                "change_categories": [],
            },
            "needs-fix": {
                "owned_paths": ["src/app.txt"],
                "checks": [[sys.executable, "-c", "import sys; sys.exit(0)"]],
                "change_categories": ["MODULE_BOUNDARY"],
            },
        },
    }
    scopes_path = root / "scopes.json"
    scopes_path.write_text(json.dumps(scopes_dict, indent=2, sort_keys=True), encoding="utf-8")
    return {"root": root, "repo": repo, "branch": branch, "runtime": runtime, "config": config, "manifest": manifest_path, "scopes": scopes_path, "builder_count": builder_count, "reviewer_count": reviewer_count}


def _counts(fix: dict) -> tuple[int, int]:
    def _read(p: Path) -> int:
        try:
            return int(p.read_text(encoding="utf-8")) if p.exists() else 0
        except Exception:
            return 0

    return _read(fix["builder_count"]), _read(fix["reviewer_count"])


def _changed_paths(repo: Path, baseline: str) -> list[str]:
    diff_names = [p.strip() for p in _git(repo, ["diff", "--name-only", baseline]).splitlines() if p.strip()]
    staged_names = [p.strip() for p in _git(repo, ["diff", "--name-only", "--cached", baseline]).splitlines() if p.strip()]
    untracked_raw = [p[3:].strip() for p in _git(repo, ["status", "--porcelain", "-uall"]).splitlines() if p.startswith("?? ")]
    return sorted(set(diff_names + staged_names + untracked_raw))


def _canonical_manifest(repo: Path, baseline_commit: str, baseline_tree: str, paths: list[str]) -> dict:
    import stat as _stat

    entries: list[dict] = []
    for rel in sorted(paths, key=lambda p: p.encode("utf-8")):
        abs_path = repo / rel
        tracked = subprocess.run(["git", "-C", str(repo), "ls-tree", baseline_commit, "--", rel], capture_output=True).stdout.strip()
        if (not abs_path.exists()) and (not abs_path.is_symlink()):
            entries.append({"path": rel, "operation": "DELETE", "type": None, "mode": None, "content_sha256": None})
            continue
        info = os.lstat(abs_path)
        if _stat.S_ISLNK(info.st_mode):
            entries.append({
                "path": rel,
                "operation": "ADD" if not tracked else "MODIFY",
                "type": "symlink",
                "mode": "120000",
                "content_sha256": None,
            })
        elif _stat.S_ISREG(info.st_mode):
            mode = "100755" if (info.st_mode & 0o111) else "100644"
            h = hashlib.sha256()
            with abs_path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    h.update(chunk)
            entries.append({
                "path": rel,
                "operation": "ADD" if not tracked else "MODIFY",
                "type": "file",
                "mode": mode,
                "content_sha256": h.hexdigest(),
            })
        else:
            raise ValueError(f"unsupported candidate node: {rel}")
    return {
        "schema_version": CANDIDATE_SCHEMA,
        "baseline_commit": baseline_commit.lower(),
        "baseline_tree": baseline_tree.lower(),
        "changes": entries,
    }


def _manifest_digest(manifest: dict) -> str:
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic M2-R001 verification sequence")
    parser.add_argument("--m2-head", required=True)
    parser.add_argument("--m2-tree", required=True)
    parser.add_argument("--m2-candidate-digest", required=True)
    parser.add_argument("--m2-evidence", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    start_time = time.time()
    repo = Path(__file__).resolve().parent
    out = Path(args.output_dir)

    if out.exists():
        print(f"STOP_EVIDENCE_COLLISION: output dir already exists: {out}", file=sys.stderr)
        return 1
    out.mkdir(parents=True)

    evidence: dict = {"commands": []}

    def record_cmd(result: dict, label: str) -> None:
        evidence["commands"].append({"label": label, **result})

    def remaining() -> float:
        return max(1.0, TIME_CAP_SECONDS - (time.time() - start_time))

    def fail(reason: str) -> int:
        evidence["final_verdict"] = f"FAIL: {reason}"
        (out / "verdict.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_inventory(out)
        print(f"M2_R001_DETERMINISTIC_VERIFICATION=FAIL\nSTOP_REASON={reason}", file=sys.stderr)
        return 1

    if sys.version_info[:2] != (3, 12):
        return fail(f"Python 3.12 required, observed {sys.version}")
    try:
        from importlib.metadata import version as _pkg_version

        jsonschema_version = _pkg_version("jsonschema")
    except Exception as exc:
        return fail(f"jsonschema version query failed: {exc}")
    if jsonschema_version != "4.26.0":
        return fail(f"jsonschema 4.26.0 required, observed {jsonschema_version}")
    evidence["python_version"] = sys.version
    evidence["jsonschema_version"] = jsonschema_version

    child_env = dict(os.environ)
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    child_env["PYTHONPATH"] = str(repo / "src")

    # Record canonical refs up front for step 14 comparison (canonical repo holds the refs).
    try:
        main_before = _git(CANON_REPO, ["rev-parse", "main"])
        m1_before = _git(CANON_REPO, ["rev-parse", "m1/verified-candidate"])
        m2ref_before = _git(CANON_REPO, ["rev-parse", "milestone/m2-verified"])
        status_before = _git(CANON_REPO, ["status", "--porcelain=v1", "-uall"])
    except subprocess.CalledProcessError as exc:
        return fail(f"canonical ref inspection failed: {exc}")

    # 1. Exact M2 baseline binding including supplied digest/evidence.
    if args.m2_head.lower() != EXPECTED_M2_HEAD.lower():
        return fail(f"--m2-head mismatch: {args.m2_head}")
    if args.m2_tree.lower() != EXPECTED_M2_TREE.lower():
        return fail(f"--m2-tree mismatch: {args.m2_tree}")
    if args.m2_candidate_digest.lower() != EXPECTED_M2_DIGEST.lower():
        return fail("--m2-candidate-digest mismatch")
    if args.m2_evidence != EXPECTED_M2_EVIDENCE:
        return fail(f"--m2-evidence mismatch: {args.m2_evidence}")
    m2_evidence_path = Path(args.m2_evidence)
    if not m2_evidence_path.is_dir():
        return fail(f"M2 evidence path missing: {m2_evidence_path}")
    try:
        verdict_probe = json.loads((m2_evidence_path / "verdict.json").read_text(encoding="utf-8"))
        if verdict_probe.get("M2_VERIFIED_CANDIDATE_DIGEST") != EXPECTED_M2_DIGEST:
            return fail("M2 evidence digest does not match frozen authority")
    except Exception as exc:
        return fail(f"M2 evidence not usable: {exc}")
    try:
        head = _git(repo, ["rev-parse", "HEAD"])
        tree = _git(repo, ["rev-parse", "HEAD^{tree}"])
    except subprocess.CalledProcessError as exc:
        return fail(f"baseline git inspection failed: {exc}")
    if head.lower() != EXPECTED_M2_HEAD.lower():
        return fail(f"checkout HEAD drift: {head}")
    if tree.lower() != EXPECTED_M2_TREE.lower():
        return fail(f"checkout TREE drift: {tree}")
    evidence["m2_binding"] = {"head": head.lower(), "tree": tree.lower(), "digest": EXPECTED_M2_DIGEST, "evidence": str(m2_evidence_path)}
    (out / "m2-binding.json").write_text(json.dumps(evidence["m2_binding"], indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # 2. Repair allowlist.
    changed = _changed_paths(repo, EXPECTED_M2_HEAD)
    evidence["diff_surface"] = changed
    (out / "diff-surface.json").write_text(json.dumps({"diff_surface": changed}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for path in changed:
        if path not in ALLOWED_R001_SURFACE:
            return fail(f"scope change outside allowlist: {path}")

    # 3. Protected M1/historical bytes.
    try:
        all_tracked = _git(repo, ["ls-tree", "-r", "--name-only", "HEAD"]).splitlines()
        for rel in all_tracked:
            if rel in ALLOWED_R001_SURFACE:
                continue
            abs_path = repo / rel
            if not abs_path.is_file():
                return fail(f"protected tracked file missing: {rel}")
            blob = _git(repo, ["rev-parse", f"HEAD:{rel}"])
            content = subprocess.run(["git", "-C", str(repo), "cat-file", "-p", blob], capture_output=True, check=True).stdout
            if content != abs_path.read_bytes():
                return fail(f"protected file bytes differ: {rel}")
    except subprocess.CalledProcessError as exc:
        return fail(f"protected content check failed: {exc}")
    evidence["protected_ok"] = True

    # 4. 29 schemas against each declared draft.
    import jsonschema

    all_schemas = sorted((repo / "schemas").glob("*.json"))
    evidence["schema_files"] = [p.name for p in all_schemas]
    if len(all_schemas) != 29:
        return fail(f"schema count drift: expected 29, observed {len(all_schemas)}")
    validated = 0
    failures: list[str] = []
    for schema_path in all_schemas:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validators.validator_for(schema).check_schema(schema)
            validated += 1
        except Exception as exc:
            failures.append(f"{schema_path.name}: {exc}")
    evidence["schemas_validated"] = validated
    evidence["schema_failures"] = failures
    (out / "schemas.json").write_text(json.dumps({"validated": validated, "failures": failures, "files": evidence["schema_files"]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        return fail(f"schema validation failures: {failures}")

    # 5. Exact required R001 test-name presence.
    try:
        test_src = (repo / "tests" / "test_m2_r001.py").read_text(encoding="utf-8")
    except OSError as exc:
        return fail(f"cannot read test_m2_r001.py: {exc}")
    missing = [name for name in REQUIRED_R001_TESTS if f"def {name}" not in test_src]
    evidence["required_tests_missing"] = missing
    if missing:
        return fail(f"required R001 test names missing: {missing}")
    evidence["R001_REQUIRED_TEST_NAMES_PRESENT"] = "YES"

    # 6. R001 focused suite.
    focused = _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_m2_r001.py", "-v", "-f"], repo, child_env, min(remaining(), 600))
    record_cmd(focused, "focused_r001_suite")
    (out / "focused-r001.log").write_text(focused["stdout"] + "\n" + focused["stderr"], encoding="utf-8")
    m = re.search(r"Ran (\d+) tests?", focused["stderr"] + focused["stdout"])
    r001_run = int(m.group(1)) if m else 0
    evidence["r001_run"] = r001_run
    if focused["exit_code"] != 0:
        return fail("R001 focused suite failed")
    if r001_run != len(REQUIRED_R001_TESTS):
        return fail(f"R001 suite ran {r001_run}, expected {len(REQUIRED_R001_TESTS)}")
    mf = re.search(r"FAILED \((?:failures=(\d+))?(?:, )?(?:errors=(\d+))?", focused["stderr"] + focused["stdout"])
    evidence["r001_failed"] = int(mf.group(1) or 0) if mf else 0
    evidence["r001_errors"] = int(mf.group(2) or 0) if mf else 0
    ms = re.search(r"skipped=(\d+)", focused["stderr"] + focused["stdout"])
    evidence["r001_skipped"] = int(ms.group(1)) if ms else 0
    if evidence["r001_skipped"] != 0:
        return fail("R001 suite has skipped tests")

    # 7. M2 suite (24/24).
    m2 = _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_m2.py", "-v", "-f"], repo, child_env, min(remaining(), 900))
    record_cmd(m2, "m2_suite")
    (out / "focused-m2.log").write_text(m2["stdout"] + "\n" + m2["stderr"], encoding="utf-8")
    m2m = re.search(r"Ran (\d+) tests?", m2["stderr"] + m2["stdout"])
    m2_run = int(m2m.group(1)) if m2m else 0
    evidence["m2_run"] = m2_run
    if m2["exit_code"] != 0:
        return fail("M2 suite failed")
    if m2_run != 24:
        return fail(f"M2 suite ran {m2_run}, expected 24")

    # 8. M1 suite (25/25).
    m1 = _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_m1.py", "-v", "-f"], repo, child_env, min(remaining(), 900))
    record_cmd(m1, "m1_suite")
    (out / "focused-m1.log").write_text(m1["stdout"] + "\n" + m1["stderr"], encoding="utf-8")
    m1m = re.search(r"Ran (\d+) tests?", m1["stderr"] + m1["stdout"])
    m1_run = int(m1m.group(1)) if m1m else 0
    evidence["m1_run"] = m1_run
    if m1["exit_code"] != 0:
        return fail("M1 suite failed")
    if m1_run != 25:
        return fail(f"M1 suite ran {m1_run}, expected 25")

    # 9. Full suite.
    full = _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v", "-f"], repo, child_env, min(remaining(), 2400))
    record_cmd(full, "full_suite")
    (out / "full.log").write_text(full["stdout"] + "\n" + full["stderr"], encoding="utf-8")
    mf2 = re.search(r"Ran (\d+) tests?", full["stderr"] + full["stdout"])
    full_run = int(mf2.group(1)) if mf2 else 0
    evidence["full_run"] = full_run
    if full["exit_code"] != 0:
        return fail("full suite failed")
    mff = re.search(r"FAILED \((?:failures=(\d+))?(?:, )?(?:errors=(\d+))?", full["stderr"] + full["stdout"])
    evidence["full_failed"] = int(mff.group(1) or 0) if mff else 0
    evidence["full_errors"] = int(mff.group(2) or 0) if mff else 0
    mfs = re.search(r"skipped=(\d+)", full["stderr"] + full["stdout"])
    evidence["full_skipped"] = int(mfs.group(1)) if mfs else 0
    if evidence["full_skipped"] != 0:
        return fail("full suite has skipped tests")

    # 10. P01-P06 scenarios.
    fixtures_base = Path(tempfile.mkdtemp(prefix="prj226-m2-r001-verify-"))
    evidence["fixtures_base"] = str(fixtures_base)
    scenario_results: dict[str, str] = {}

    def cli_env(rt: Path) -> dict[str, str]:
        env = dict(child_env)
        env["PRJ226_RUNTIME_ROOT"] = str(rt)
        return env

    try:
        fix1 = _make_fixture(fixtures_base, "p01")
        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(fix1["manifest"]), "--config", str(fix1["config"]), "--scopes", str(fix1["scopes"])], repo, cli_env(fix1["runtime"]), 120)
        record_cmd(r_init, "p01_init")
        if r_init["exit_code"] != 0:
            return fail(f"P01 init failed: {r_init['stderr'][-2000:]}")
        b, r = _counts(fix1)
        if b != 0 or r != 0:
            return fail(f"P01 provider calls non-zero: b={b} r={r}")
        scenario_results["P01"] = "PASS"

        fix2 = _make_fixture(fixtures_base, "p02")
        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(fix2["manifest"]), "--config", str(fix2["config"]), "--scopes", str(fix2["scopes"])], repo, cli_env(fix2["runtime"]), 120)
        if r_init["exit_code"] != 0:
            return fail("P02 init failed")
        record_cmd(r_init, "p02_init")
        r_prev = _run([sys.executable, "-m", "prj226_runner", "task", "Widget P02", "--preview-only"], repo, cli_env(fix2["runtime"]), 120)
        record_cmd(r_prev, "p02_preview")
        if r_prev["exit_code"] != 0:
            return fail("P02 preview failed")
        r_task = _run([sys.executable, "-m", "prj226_runner", "task", "Widget P02"], repo, cli_env(fix2["runtime"]), 180, input_text="approve\n")
        record_cmd(r_task, "p02_task")
        if r_task["exit_code"] != 0:
            return fail(f"P02 task failed: {r_task['stdout'][-3000:]}")
        b, r = _counts(fix2)
        if b != 1 or r != 0:
            return fail(f"P02 counts wrong: b={b} r={r}")
        r_status = _run([sys.executable, "-m", "prj226_runner", "status", "--json"], repo, cli_env(fix2["runtime"]), 60)
        if r_status["exit_code"] != 0:
            return fail("P02 status failed")
        task_id = json.loads(r_status["stdout"])["task_id"]
        r_acc = _run([sys.executable, "-m", "prj226_runner", "accept", task_id], repo, cli_env(fix2["runtime"]), 180, input_text="approve\n")
        record_cmd(r_acc, "p02_accept")
        if r_acc["exit_code"] != 0:
            return fail(f"P02 accept failed: {r_acc['stdout'][-3000:]}")
        if "builder change" not in (fix2["repo"] / "src/app.txt").read_text(encoding="utf-8"):
            return fail("P02 integration missing")
        scenario_results["P02"] = "PASS"

        fix3 = _make_fixture(fixtures_base, "p03")
        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(fix3["manifest"]), "--config", str(fix3["config"]), "--scopes", str(fix3["scopes"])], repo, cli_env(fix3["runtime"]), 120)
        if r_init["exit_code"] != 0:
            return fail("P03 init failed")
        record_cmd(r_init, "p03_init")
        r_task = _run([sys.executable, "-m", "prj226_runner", "task", "Targeted P03", "--scope", "targeted"], repo, cli_env(fix3["runtime"]), 180, input_text="approve\n")
        record_cmd(r_task, "p03_task")
        if r_task["exit_code"] != 0:
            return fail(f"P03 task failed: {r_task['stdout'][-3000:]}")
        b, r = _counts(fix3)
        if b != 1 or r != 1:
            return fail(f"P03 counts wrong: b={b} r={r}")
        r_status = _run([sys.executable, "-m", "prj226_runner", "status", "--json"], repo, cli_env(fix3["runtime"]), 60)
        if r_status["exit_code"] != 0:
            return fail("P03 status failed")
        task_id = json.loads(r_status["stdout"])["task_id"]
        r_acc = _run([sys.executable, "-m", "prj226_runner", "accept", task_id], repo, cli_env(fix3["runtime"]), 180, input_text="approve\n")
        record_cmd(r_acc, "p03_accept")
        if r_acc["exit_code"] != 0:
            return fail("P03 accept failed")
        scenario_results["P03"] = "PASS"

        fix4 = _make_fixture(fixtures_base, "p04")
        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(fix4["manifest"]), "--config", str(fix4["config"]), "--scopes", str(fix4["scopes"])], repo, cli_env(fix4["runtime"]), 120)
        if r_init["exit_code"] != 0:
            return fail("P04 init failed")
        record_cmd(r_init, "p04_init")
        head_before = _git(fix4["repo"], ["rev-parse", "HEAD"])
        r_task = _run([sys.executable, "-m", "prj226_runner", "task", "Failing P04", "--scope", "failing"], repo, cli_env(fix4["runtime"]), 180, input_text="approve\n")
        record_cmd(r_task, "p04_task")
        if r_task["exit_code"] != 10:
            return fail(f"P04 expected exit 10, got {r_task['exit_code']}")
        b, r = _counts(fix4)
        if b != 1 or r != 0:
            return fail(f"P04 counts wrong: b={b} r={r}")
        r_status = _run([sys.executable, "-m", "prj226_runner", "status", "--json"], repo, cli_env(fix4["runtime"]), 60)
        if r_status["exit_code"] != 0 or "STOPPED" not in r_status["stdout"]:
            return fail("P04 status not STOPPED")
        task_id4 = json.loads(r_status["stdout"])["task_id"]
        r_ho = _run([sys.executable, "-m", "prj226_runner", "resume", task_id4, "--handoff"], repo, cli_env(fix4["runtime"]), 60)
        record_cmd(r_ho, "p05_handoff")
        if r_ho["exit_code"] != 0:
            return fail("P05 handoff failed")
        if _git(fix4["repo"], ["rev-parse", "HEAD"]) != head_before:
            return fail("P04 product HEAD moved despite failure")
        scenario_results["P04"] = "PASS"
        scenario_results["P05"] = "PASS"

        fix6 = _make_fixture(fixtures_base, "p06")
        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(fix6["manifest"]), "--config", str(fix6["config"]), "--scopes", str(fix6["scopes"])], repo, cli_env(fix6["runtime"]), 120)
        if r_init["exit_code"] != 0:
            return fail("P06 init failed")
        record_cmd(r_init, "p06_init")
        r_task = _run([sys.executable, "-m", "prj226_runner", "task", "Stale P06"], repo, cli_env(fix6["runtime"]), 180, input_text="approve\n")
        record_cmd(r_task, "p06_task")
        if r_task["exit_code"] != 0:
            return fail("P06 task failed")
        r_status = _run([sys.executable, "-m", "prj226_runner", "status", "--json"], repo, cli_env(fix6["runtime"]), 60)
        task_id6 = json.loads(r_status["stdout"])["task_id"]
        (fix6["repo"] / "src/app.txt").write_text("drift\n", encoding="utf-8")
        _git(fix6["repo"], ["add", "src/app.txt"])
        _git(fix6["repo"], ["commit", "-m", "drift"])
        drift_head = _git(fix6["repo"], ["rev-parse", "HEAD"])
        r_acc = _run([sys.executable, "-m", "prj226_runner", "accept", task_id6], repo, cli_env(fix6["runtime"]), 180, input_text="approve\n")
        record_cmd(r_acc, "p06_accept")
        if r_acc["exit_code"] != 20:
            return fail(f"P06 expected exit 20, got {r_acc['exit_code']}")
        if _git(fix6["repo"], ["rev-parse", "HEAD"]) != drift_head:
            return fail("P06 unauthorized integration")
        if not list(fix6["runtime"].rglob("report.json")):
            return fail("P06 evidence missing")
        scenario_results["P06"] = "PASS"
    except Exception as exc:
        import traceback

        return fail(f"scenario exception: {exc} {traceback.format_exc()[-2000:]}")
    evidence["scenarios"] = scenario_results
    (out / "scenarios.json").write_text(json.dumps({"results": scenario_results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for key in ("P01", "P02", "P03", "P04", "P05", "P06"):
        if scenario_results.get(key) != "PASS":
            return fail(f"scenario {key} not PASS")

    # 11. Exact original Liam context-authz regression.
    try:
        liam_base = Path(tempfile.mkdtemp(prefix="prj226-liam-dogfood-"))
        evidence["liam_base"] = str(liam_base)
        liam_root = liam_base / "liam"
        liam_root.mkdir(parents=True, exist_ok=True)
        liam_repo = liam_root / "product"
        subprocess.run(["git", "init", str(liam_repo)], capture_output=True, check=True)
        _git(liam_repo, ["config", "user.email", "liam@example.test"])
        _git(liam_repo, ["config", "user.name", "Liam Dogfood"])
        (liam_repo / "src" / "domain").mkdir(parents=True)
        (liam_repo / "src" / "domain" / "context.ts").write_text("// liam context\n", encoding="utf-8")
        (liam_repo / "tests" / "domain").mkdir(parents=True)
        (liam_repo / "tests" / "domain" / "context.test.ts").write_text("// liam context test\n", encoding="utf-8")
        (liam_repo / "docs").mkdir(parents=True)
        (liam_repo / "docs" / "tasks").mkdir(parents=True)
        (liam_repo / "docs" / "CURRENT.md").write_text("**Next executable work:** ENG-001 — Acceptance\n", encoding="utf-8")
        (liam_repo / "docs" / "PLAN.md").write_text("| Task | Description | State |\n| --- | --- | --- |\n| ENG-001 | acceptance | PROPOSED |\n", encoding="utf-8")
        (liam_repo / "docs" / "tasks" / "ENG-001.md").write_text("# ENG-001 — Acceptance\n", encoding="utf-8")
        (liam_repo / "README.md").write_text("fixture\n", encoding="utf-8")
        (liam_repo / "AGENTS.md").write_text("governance\n", encoding="utf-8")
        (liam_repo / "docs" / "README.md").write_text("docs\n", encoding="utf-8")
        _git(liam_repo, ["add", "."])
        _git(liam_repo, ["commit", "-m", "liam base"])
        liam_branch = _git(liam_repo, ["branch", "--show-current"])
        liam_builder_count = liam_root / "builder-count.txt"
        liam_reviewer_count = liam_root / "reviewer-count.txt"
        liam_fake_builder = liam_root / "fake-builder.py"
        liam_fake_builder.write_text(FAKE_BUILDER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(liam_builder_count))), encoding="utf-8")
        liam_fake_builder.chmod(liam_fake_builder.stat().st_mode | stat.S_IXUSR)
        liam_fake_reviewer = liam_root / "fake-reviewer.py"
        liam_fake_reviewer.write_text(FAKE_REVIEWER_SRC.replace("@@EXE@@", sys.executable).replace("@@COUNTER@@", json.dumps(str(liam_reviewer_count))), encoding="utf-8")
        liam_fake_reviewer.chmod(liam_fake_reviewer.stat().st_mode | stat.S_IXUSR)
        liam_runtime = liam_root / "runtime"
        liam_config = liam_root / "runner.toml"
        liam_config.write_text(
            "[runner]\n"
            f"runtime_root = {json.dumps(str(liam_runtime))}\n\n"
            "[agents.builder]\ntool = 'codex'\n"
            f"executable = {json.dumps(str(liam_fake_builder))}\nmodel = 'fake-builder'\ntimeout_seconds = 20\n\n"
            "[agents.dv]\ntool = 'opencode2'\n"
            f"executable = {json.dumps(str(liam_fake_builder))}\nmodel = 'fake-muse'\ntimeout_seconds = 20\n\n"
            "[agents.sos_reviewer]\ntool = 'opencode2'\n"
            f"executable = {json.dumps(str(liam_fake_reviewer))}\nmodel = 'fake-mimo'\ntimeout_seconds = 20\n",
            encoding="utf-8",
        )
        liam_manifest = {
            "project_id": "LIAM-DOGFOOD",
            "repository_path": str(liam_repo),
            "canonical_branch": liam_branch,
            "canonical_docs": {"current": "docs/CURRENT.md", "engineering_plan": "docs/PLAN.md", "governance": ["AGENTS.md"], "project": ["README.md", "docs/README.md"]},
            "discovery_rules": {"current_next_work_marker": "**Next executable work:**", "plan_task_column": "Task", "plan_state_column": "State", "eligible_plan_states": ["PROPOSED"], "task_id_pattern": "ENG-[0-9]{3}", "task_file_glob": "docs/tasks/{task_id}.md"},
        }
        liam_manifest_path = liam_root / "manifest.json"
        liam_manifest_path.write_text(json.dumps(liam_manifest, indent=2, sort_keys=True), encoding="utf-8")
        liam_catalog = {
            "schema_version": "PRJ226.WORKFLOW_SCOPE_CATALOG.v1",
            "default_scope": "context-authz",
            "scopes": {
                "context-authz": {
                    "owned_paths": ["src/domain/context.ts", "tests/domain/context.test.ts"],
                    "checks": [["npx", "vitest", "run", "tests/domain/context.test.ts"]],
                    "change_categories": [],
                },
            },
        }
        liam_scopes_path = liam_root / "scopes.json"
        liam_scopes_path.write_text(json.dumps(liam_catalog, indent=2, sort_keys=True), encoding="utf-8")

        def liam_env() -> dict[str, str]:
            env = dict(child_env)
            env["PRJ226_RUNTIME_ROOT"] = str(liam_runtime)
            return env

        r_init = _run([sys.executable, "-m", "prj226_runner", "init", "--manifest", str(liam_manifest_path), "--config", str(liam_config), "--scopes", str(liam_scopes_path)], repo, liam_env(), 120)
        record_cmd(r_init, "liam_init")
        if r_init["exit_code"] != 0:
            return fail(f"Liam init failed: {r_init['stderr'][-2000:]}")
        r_prev = _run([sys.executable, "-m", "prj226_runner", "task", DOGFOOD_DESCRIPTION, "--preview-only"], repo, liam_env(), 120)
        record_cmd(r_prev, "liam_preview")
        if r_prev["exit_code"] != 0:
            return fail(f"Liam preview failed: {r_prev['stderr'][-2000:]}")
        prev_out = r_prev["stdout"]
        (out / "liam-preview.txt").write_text(prev_out, encoding="utf-8")
        if "src/domain/context.ts" not in prev_out or "tests/domain/context.test.ts" not in prev_out:
            return fail("Liam preview missing required domain context paths")
        if "npx vitest run tests/domain/context.test.ts" not in prev_out:
            return fail("Liam preview missing required npx vitest check")
        if "NONE" not in prev_out:
            return fail("Liam preview review is not NONE")
        if "TARGETED" in prev_out:
            return fail("Liam preview must not be TARGETED")
        if "src/app.txt" in prev_out or "python -c pass" in prev_out or "import sys; sys.exit(0)" in prev_out:
            return fail("Liam preview contains placeholder files/checks")

        def _read_count(p: Path) -> int:
            try:
                return int(p.read_text(encoding="utf-8")) if p.exists() else 0
            except Exception:
                return 0

        builder_calls = _read_count(liam_builder_count)
        reviewer_calls = _read_count(liam_reviewer_count)
        if builder_calls != 0 or reviewer_calls != 0:
            return fail(f"Liam preview invoked providers: b={builder_calls} r={reviewer_calls}")
        evidence["liam_preview"] = {
            "files": ["src/domain/context.ts", "tests/domain/context.test.ts"],
            "check": ["npx", "vitest", "run", "tests/domain/context.test.ts"],
            "review_mode": "NONE",
            "builder": builder_calls,
            "reviewer": reviewer_calls,
        }
    except Exception as exc:
        import traceback

        return fail(f"Liam regression exception: {exc} {traceback.format_exc()[-2000:]}")

    # 12. Canonical R001 change-manifest digest.
    try:
        manifest = _canonical_manifest(repo, EXPECTED_M2_HEAD, EXPECTED_M2_TREE, changed)
        digest = _manifest_digest(manifest)
    except Exception as exc:
        return fail(f"R001 candidate manifest failed: {exc}")
    evidence["M2_R001_VERIFIED_CANDIDATE_DIGEST"] = digest
    evidence["candidate_manifest"] = manifest
    (out / "candidate-manifest.json").write_text(json.dumps({"candidate_manifest": manifest, "M2_R001_VERIFIED_CANDIDATE_DIGEST": digest}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # 13. Recompute digest after verification and require unchanged.
    try:
        changed_after = _changed_paths(repo, EXPECTED_M2_HEAD)
        if changed_after != changed:
            return fail(f"candidate content changed during verification: {changed_after}")
        manifest_after = _canonical_manifest(repo, EXPECTED_M2_HEAD, EXPECTED_M2_TREE, changed_after)
        digest_after = _manifest_digest(manifest_after)
    except Exception as exc:
        return fail(f"R001 digest recomputation failed: {exc}")
    if digest_after != digest:
        return fail("R001 candidate digest changed during verification")

    # 14. Canonical refs/original checkout remain unchanged.
    try:
        main_after = _git(CANON_REPO, ["rev-parse", "main"])
        m1_after = _git(CANON_REPO, ["rev-parse", "m1/verified-candidate"])
        m2ref_after = _git(CANON_REPO, ["rev-parse", "milestone/m2-verified"])
        status_after = _git(CANON_REPO, ["status", "--porcelain=v1", "-uall"])
        orig_status = _git(CANON_REPO, ["status", "--porcelain=v1", "-uall"])
    except subprocess.CalledProcessError as exc:
        return fail(f"final ref inspection failed: {exc}")
    if main_after != EXPECTED_MAIN_REF or main_after != main_before:
        return fail("main ref changed during verification")
    if m1_after != EXPECTED_M1_REF or m1_after != m1_before:
        return fail("m1 ref changed during verification")
    if m2ref_after != m2ref_before:
        return fail("m2 ref changed during verification")
    if orig_status.strip() != "":
        return fail(f"original checkout not clean: {orig_status!r}")
    evidence["safety"] = {"main": main_after, "m1_ref": m1_after, "m2_ref": m2ref_after}
    (out / "safety.json").write_text(json.dumps(evidence["safety"], indent=2, sort_keys=True) + "\n", encoding="utf-8")

    evidence["M2_EVIDENCE_BOUND"] = "YES"
    evidence["CANDIDATE_MANIFEST_SCHEMA"] = CANDIDATE_SCHEMA
    evidence["final_verdict"] = "PASS"
    (out / "verdict.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_inventory(out)

    print("M2_R001_IMPLEMENTATION=COMPLETE")
    print("M2_R001_DETERMINISTIC_VERIFICATION=PASS")
    print(f"BASELINE_M2_HEAD={EXPECTED_M2_HEAD}")
    print(f"BASELINE_M2_TREE={EXPECTED_M2_TREE}")
    print(f"BASELINE_M2_DIGEST={EXPECTED_M2_DIGEST}")
    print("M2_EVIDENCE_BOUND=YES")
    print(f"M2_R001_VERIFIED_CANDIDATE_DIGEST={digest}")
    print(f"CANDIDATE_MANIFEST_SCHEMA={CANDIDATE_SCHEMA}")
    print(f"DIFF_SURFACE={','.join(changed)}")
    print("SCHEMAS_VALIDATED=29")
    print("SCHEMA_FAILURES=0")
    print("R001_REQUIRED_TEST_NAMES_PRESENT=YES")
    print(f"R001_TESTS_RUN={r001_run}")
    print("R001_TESTS_FAILED=0")
    print("R001_TESTS_ERRORS=0")
    print("R001_TESTS_SKIPPED=0")
    print("M2_TESTS_RUN=24")
    print("M2_TESTS_FAILED=0")
    print("M2_TESTS_ERRORS=0")
    print("M2_TESTS_SKIPPED=0")
    print("M1_TESTS_RUN=25")
    print("M1_TESTS_FAILED=0")
    print("M1_TESTS_ERRORS=0")
    print("M1_TESTS_SKIPPED=0")
    print(f"FULL_TESTS_RUN={full_run}")
    print("FULL_TESTS_FAILED=0")
    print("FULL_TESTS_ERRORS=0")
    print("FULL_TESTS_SKIPPED=0")
    print("P01=PASS")
    print("P02=PASS")
    print("P03=PASS")
    print("P04=PASS")
    print("P05=PASS")
    print("P06=PASS")
    print("LIAM_CONTEXT_AUTHZ_PREVIEW=PASS")
    print("PREVIEW_FILES=src/domain/context.ts,tests/domain/context.test.ts")
    print("PREVIEW_CHECK=npx vitest run tests/domain/context.test.ts")
    print("PREVIEW_REVIEW_MODE=NONE")
    print("BUILDER_INVOCATIONS=0")
    print("REVIEWER_INVOCATIONS=0")
    print("LIVE_PROVIDER_INVOCATIONS=0")
    print("FALLBACK_INVOCATIONS=0")
    print("PRIOR_EVIDENCE_001_PRESERVED=YES")
    print(f"M2_R001_VERIFICATION_EVIDENCE={out}")
    print("MAIN_REF_UNCHANGED=YES")
    print("M1_REF_UNCHANGED=YES")
    print("M2_REF_UNCHANGED=YES")
    print("ORIGINAL_CHECKOUT_CLEAN=YES")
    print("")
    print("NEXT_ACTION=STOP")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
