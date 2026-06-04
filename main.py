#!/usr/bin/env python3
"""Single-command entry point for local project operations."""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
PYTHON_TESTS = ROOT / "tests" / "python"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

# A "check" is (label, callable -> exit_code). The callable runs the underlying
# work and returns a process-style exit code (0 == ok). Keeping checks as small
# closures lets `audit` and `test` share one runner with consistent reporting.
Check = Tuple[str, Callable[[], int]]

# ANSI colours are only emitted when stdout is an interactive TTY, so piping the
# output into logs or CI stays clean and grep-friendly.
_COLOR = sys.stdout.isatty()
_GREEN = "\033[32m" if _COLOR else ""
_RED = "\033[31m" if _COLOR else ""
_YELLOW = "\033[33m" if _COLOR else ""
_DIM = "\033[2m" if _COLOR else ""
_RESET = "\033[0m" if _COLOR else ""


def run_script(script: Path, args: List[str]) -> int:
    if not script.exists():
        print(f"missing script: {script}")
        return 127
    return subprocess.run(
        [sys.executable, str(script), *args], cwd=str(ROOT), check=False
    ).returncode


def run_probe(args: argparse.Namespace) -> int:
    from core.readiness import build_project_state, emit_json, emit_text

    state = build_project_state(
        root=ROOT,
        config_path=Path(args.config),
        cert_path=Path(args.cert),
        key_path=Path(args.key),
        skip_trust=args.skip_trust,
        skip_runtime=args.skip_runtime,
    )
    payload = emit_json(state)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    print(payload if args.json or not sys.stdout.isatty() else emit_text(state))
    return 2 if state.overall == "fail" else 0


def _script_check(label: str, script_name: str, args: Optional[List[str]] = None) -> Check:
    script_args = list(args or [])

    def _run() -> int:
        return run_script(SCRIPTS / script_name, script_args)

    return (label, _run)


def _python_test_check(label: str, script_name: str, args: Optional[List[str]] = None) -> Check:
    script_args = list(args or [])

    def _run() -> int:
        return run_script(PYTHON_TESTS / script_name, script_args)

    return (label, _run)


def run_checks(checks: List[Check], *, fail_fast: bool, title: str) -> int:
    """Run a list of checks, printing a uniform status line and final summary.

    When ``fail_fast`` is False every check runs so the user sees the full set of
    problems in one pass instead of fixing-and-rerunning repeatedly. The overall
    exit code is the first non-zero status encountered.
    """
    print(f"{title} ({len(checks)} checks)")
    print("=" * 72)

    overall = 0
    failures: List[str] = []
    start_all = time.monotonic()
    width = max((len(label) for label, _ in checks), default=0)

    for index, (label, func) in enumerate(checks, start=1):
        prefix = f"[{index:>2}/{len(checks)}] {label.ljust(width)}"
        print(f"{_DIM}{prefix} ...{_RESET}", flush=True)
        start = time.monotonic()
        code = func()
        elapsed = time.monotonic() - start
        if code == 0:
            print(f"{_GREEN}  PASS{_RESET} {label} {_DIM}({elapsed:.2f}s){_RESET}")
        else:
            print(f"{_RED}  FAIL{_RESET} {label} {_DIM}({elapsed:.2f}s, exit {code}){_RESET}")
            failures.append(label)
            if overall == 0:
                overall = code
            if fail_fast:
                break

    total = time.monotonic() - start_all
    print("=" * 72)
    if overall == 0:
        print(f"{_GREEN}All {len(checks)} checks passed{_RESET} {_DIM}({total:.2f}s){_RESET}")
    else:
        print(
            f"{_RED}{len(failures)} of {len(checks)} checks failed{_RESET} "
            f"{_DIM}({total:.2f}s){_RESET}: " + ", ".join(failures)
        )
    return overall


def build_audit_checks(config: str, extra_validate_args: List[str]) -> List[Check]:
    config_arg = str(Path(config))
    return [
        _script_check("validate config", "validate_config.py", [config_arg, *extra_validate_args]),
        _script_check("route intent sync", "route_intent_sync.py", [config_arg]),
        _script_check("route graph verify", "route_graph_verify.py", [config_arg]),
        _script_check("route rule lint", "route_rule_linter.py", [config_arg, "--quiet"]),
        _python_test_check("route policy tests", "route_policy_tests.py"),
        _script_check("metadata", "validate_metadata.py"),
        _script_check("provider dossiers", "provider_dossier_validate.py"),
        _script_check("provider policy", "provider_policy_validator.py"),
        _python_test_check("provider policy tests", "provider_policy_validator_tests.py"),
        _python_test_check("failure classifier tests", "failure_classifier_tests.py"),
        _python_test_check("strategy engine tests", "strategy_engine_test.py"),
        _python_test_check("trust broker tests", "trust_broker_test.py"),
        _python_test_check("ja3 pool validate tests", "ja3_pool_validate_test.py"),
        _python_test_check("version utils tests", "version_utils_test.py"),
        _python_test_check("key at rest tests", "key_at_rest_test.py"),
        _python_test_check("preflight gate tests", "preflight_gate_test.py"),
        _python_test_check("cdp client tests", "cdp_client_test.py"),
        _python_test_check("lab evidence tests", "lab_evidence_tests.py"),
        _python_test_check("path scorer tests", "path_scorer_tests.py"),
        _python_test_check("rust core tests", "rust_core_tests.py"),
        _script_check("transport experiments", "transport_experiment_validate.py"),
        _script_check("transport profiles", "transport_profile_validate.py"),
        _python_test_check("repository structure", "repository_structure_tests.py"),
    ]


def _compile_scripts_check() -> int:
    import py_compile

    errors = 0
    for path in sorted(SCRIPTS.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:  # pragma: no cover - exercised on bad input
            errors += 1
            print(exc)
    return 1 if errors else 0


def build_test_checks(config: str, *, require_rust: bool) -> List[Check]:
    """Full local check suite mirroring the CI `validate` workflow.

    Network- and external-binary-dependent steps (live DNS, Xray runtime test)
    are intentionally excluded so this stays fast, deterministic, and runnable
    offline. Pass ``require_rust`` to fail (instead of skip) when cargo is absent.
    """
    config_arg = str(Path(config))
    rust_args = ["--required"] if require_rust else []
    checks: List[Check] = [
        ("compile python scripts", _compile_scripts_check),
        _python_test_check("rust core checks", "rust_core_tests.py", rust_args),
        _script_check("validate config", "validate_config.py", [config_arg]),
        _script_check("generate profiles", "generate_profiles.py", ["--base", config_arg]),
    ]

    def _profiles_in_sync() -> int:
        proc = subprocess.run(
            ["git", "diff", "--exit-code", "--", "Xray-config/MITM-DomainFronting.*.json"],
            cwd=str(ROOT),
            check=False,
        )
        if proc.returncode != 0:
            print(
                "generated profile configs are out of sync; "
                "run `python scripts/generate_profiles.py` and commit the result"
            )
        return proc.returncode

    checks.extend(
        [
            ("generated profiles in sync", _profiles_in_sync),
            _script_check(
                "preflight (static)",
                "preflight.py",
                ["--config", config_arg, "--no-dns", "--skip-cert", "--skip-runtime"],
            ),
            _script_check("metadata", "validate_metadata.py"),
            _python_test_check("repository structure", "repository_structure_tests.py"),
            _script_check("geodata lock", "geodata_pin.py", ["--verify"]),
            _python_test_check("route policy tests", "route_policy_tests.py"),
            _script_check("route graph verify", "route_graph_verify.py", [config_arg]),
            _script_check("route rule lint", "route_rule_linter.py", [config_arg, "--quiet"]),
            _script_check("route intent sync", "route_intent_sync.py", [config_arg]),
            _python_test_check("protocol policy tests", "protocol_policy_tests.py"),
            _script_check("transport profiles", "transport_profile_validate.py"),
            _script_check("protocol smoke", "protocol_smoke.py", ["--scenario", "udp443-policy"]),
            _script_check("provider dossiers", "provider_dossier_validate.py"),
            _script_check("provider policy", "provider_policy_validator.py"),
            _python_test_check("provider policy tests", "provider_policy_validator_tests.py"),
            _python_test_check("failure classifier tests", "failure_classifier_tests.py"),
        _python_test_check("strategy engine tests", "strategy_engine_test.py"),
        _python_test_check("trust broker tests", "trust_broker_test.py"),
        _python_test_check("ja3 pool validate tests", "ja3_pool_validate_test.py"),
        _python_test_check("version utils tests", "version_utils_test.py"),
        _python_test_check("key at rest tests", "key_at_rest_test.py"),
        _python_test_check("preflight gate tests", "preflight_gate_test.py"),
        _python_test_check("cdp client tests", "cdp_client_test.py"),
        _python_test_check("lab evidence tests", "lab_evidence_tests.py"),
            _python_test_check("path scorer tests", "path_scorer_tests.py"),
            _python_test_check("health policy tests", "health_policy_tests.py"),
            _python_test_check("readiness state tests", "readiness_tests.py"),
            _python_test_check("verified session tests", "verified_session_tests.py"),
            _python_test_check("release artifact tests", "release_artifact_tests.py"),
            _python_test_check("gui readiness bridge tests", "gui_readiness_tests.py"),
            _python_test_check("dns lab harness tests", "dns_lab_harness_tests.py"),
            _script_check("transport experiments", "transport_experiment_validate.py"),
            _script_check("config-src validate", "config_src_validate.py", ["--run-steps"]),
            _script_check(
                "config build sync",
                "build_config.py",
                ["--check-runtime-sync", "--generate-profiles", "--check-profile-sync"],
            ),
            _python_test_check("config-src merge tests", "config_src_merge_test.py"),
            _python_test_check("browser probe semantics", "browser_probe_semantics_test.py"),
            _script_check("gui self-test", "gui.py", ["--self-test"]),
            _script_check("secret scan", "secret_scan.py"),
        ]
    )
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mitm",
        description=(
            "MITM-DomainFronting local operations.\n\n"
            "A toolkit for running and validating the local TLS MITM "
            "domain-fronting proxy: bootstrap the environment, launch the "
            "desktop control center, audit configuration, and run the full "
            "offline CI-mirroring check suite."
        ),
        epilog=(
            "Typical workflow:\n"
            "  python main.py init        # one-time: create venv + optional tooling\n"
            "  python main.py audit       # fast static config/route/governance checks\n"
            "  python main.py test        # full offline suite (mirrors CI)\n"
            "  python main.py gui         # launch the desktop control center\n"
            "  python main.py probe       # shared local readiness state\n"
            "  python main.py verified-session # save a redacted runtime evidence bundle\n"
            "  python main.py release-check # release readiness gate\n"
            "  python main.py trust       # advisory trust-store setup instructions\n\n"
            "Tips:\n"
            "  * 'audit --keep-going' reports every problem in one pass.\n"
            "  * 'test --fail-fast' stops at the first failing check for tight loops.\n"
            "  * 'test --require-rust' turns a missing cargo toolchain into a failure\n"
            "    instead of a skip (use in CI where Rust must be present).\n"
            "  * Unknown flags after a subcommand are forwarded to the underlying tool."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="<command>",
        title="commands",
    )
    sub.add_parser("init", help="create a local virtual environment and install optional tooling")
    sub.add_parser("gui", help="launch the desktop control center")
    audit_parser = sub.add_parser(
        "audit", help="run static config, metadata, route, and governance checks"
    )
    audit_parser.add_argument(
        "--config", default="Xray-config/MITM-DomainFronting.json", help="config to validate"
    )
    audit_parser.add_argument(
        "--keep-going",
        action="store_true",
        help="run every check even after a failure (report all problems at once)",
    )
    test_parser = sub.add_parser(
        "test", help="run the full local check suite mirroring CI (offline, deterministic)"
    )
    test_parser.add_argument(
        "--config", default="Xray-config/MITM-DomainFronting.json", help="config to validate"
    )
    test_parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop at the first failing check instead of running the whole suite",
    )
    test_parser.add_argument(
        "--require-rust",
        action="store_true",
        help="fail (instead of skip) when the Rust toolchain (cargo) is unavailable",
    )
    probe_parser = sub.add_parser("probe", help="emit the shared local readiness state")
    probe_parser.add_argument("--config", default="Xray-config/MITM-DomainFronting.json", help="config to inspect")
    probe_parser.add_argument("--cert", default="Xray-config/mycert.crt", help="local CA certificate to inspect")
    probe_parser.add_argument("--key", default="Xray-config/mycert.key", help="local CA private key to inspect")
    probe_parser.add_argument("--skip-trust", action="store_true", help="skip local trust-store matching")
    probe_parser.add_argument("--skip-runtime", action="store_true", help="skip live listener/process checks")
    probe_parser.add_argument("--json", action="store_true", help="emit JSON even in an interactive terminal")
    probe_parser.add_argument("--json-out", type=Path, default=None, help="optional file path to save probe JSON")
    sub.add_parser("preflight", help="run local preflight checks")
    sub.add_parser("trust", help="print advisory trust-store setup instructions")
    sub.add_parser("release-check", help="run release readiness checks")
    sub.add_parser(
        "verified-session",
        help="run a verified runtime session and save a redacted evidence bundle",
    )
    args, unknown = parser.parse_known_args()

    if args.command == "init":
        return run_script(ROOT / "bootstrap.py", unknown)
    if args.command == "gui":
        return run_script(SCRIPTS / "gui.py", unknown)
    if args.command == "probe":
        if unknown:
            print("unrecognized probe arguments: " + " ".join(unknown))
            return 2
        return run_probe(args)
    if args.command == "preflight":
        return run_script(SCRIPTS / "preflight.py", unknown)
    if args.command == "trust":
        return run_script(SCRIPTS / "trust_assistant.py", unknown)
    if args.command == "release-check":
        return run_script(SCRIPTS / "release_check.py", unknown)
    if args.command == "verified-session":
        return run_script(SCRIPTS / "verified_session.py", unknown)
    if args.command == "audit":
        checks = build_audit_checks(args.config, unknown)
        return run_checks(checks, fail_fast=not args.keep_going, title="Static audit")
    if args.command == "test":
        # Note: enforcement of --require-rust lives in the "rust core checks"
        # step (tests/python/rust_core_tests.py exits non-zero when cargo is absent), so it is
        # reported in the uniform summary like every other check. We deliberately
        # avoid printing a separate out-of-band warning here that would look like
        # a parse-time failure before any check has run.
        checks = build_test_checks(args.config, require_rust=args.require_rust)
        return run_checks(checks, fail_fast=args.fail_fast, title="Full local check suite")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
