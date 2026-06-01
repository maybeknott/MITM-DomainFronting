#!/usr/bin/env python3
"""Single-command entry point for local project operations."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"


def run_script(script: Path, args: list[str]) -> int:
    if not script.exists():
        print(f"missing script: {script}")
        return 127
    return subprocess.run([sys.executable, str(script), *args], cwd=str(ROOT), check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="MITM-DomainFronting local operations")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a local virtual environment and install optional tooling")
    sub.add_parser("gui", help="launch the desktop control center")
    audit_parser = sub.add_parser("audit", help="run static config, metadata, route, and governance checks")
    audit_parser.add_argument("--config", default="Xray-config/MITM-DomainFronting.json", help="config to validate")
    sub.add_parser("probe", help="run the local redacted health probe")
    sub.add_parser("preflight", help="run local preflight checks")
    sub.add_parser("trust", help="print advisory trust-store setup instructions")
    args, unknown = parser.parse_known_args()

    if args.command == "init":
        return run_script(ROOT / "bootstrap.py", unknown)
    if args.command == "gui":
        return run_script(SCRIPTS / "gui.py", unknown)
    if args.command == "probe":
        return run_script(SCRIPTS / "health_probe.py", unknown)
    if args.command == "preflight":
        return run_script(SCRIPTS / "preflight.py", unknown)
    if args.command == "trust":
        return run_script(SCRIPTS / "trust_assistant.py", unknown)
    if args.command == "audit":
        config_arg = str(Path(args.config))
        checks = [
            (SCRIPTS / "validate_config.py", [config_arg]),
            (SCRIPTS / "route_intent_sync.py", [config_arg]),
            (SCRIPTS / "route_graph_verify.py", [config_arg]),
            (SCRIPTS / "route_rule_linter.py", [config_arg, "--quiet"]),
            (SCRIPTS / "route_policy_tests.py", []),
            (SCRIPTS / "validate_metadata.py", []),
            (SCRIPTS / "provider_dossier_validate.py", []),
            (SCRIPTS / "provider_policy_validator.py", []),
            (SCRIPTS / "provider_policy_validator_tests.py", []),
            (SCRIPTS / "failure_classifier_tests.py", []),
            (SCRIPTS / "path_scorer_tests.py", []),
            (SCRIPTS / "transport_experiment_validate.py", []),
            (SCRIPTS / "transport_profile_validate.py", []),
            (SCRIPTS / "repository_structure_tests.py", []),
        ]
        for script, script_args in checks:
            code = run_script(script, [*script_args, *unknown] if script.name == "validate_config.py" else script_args)
            if code != 0:
                return code
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
