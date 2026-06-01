#!/usr/bin/env python3
"""
Transport Experiment Configuration Validator
Enforces strict architectural boundaries, security configurations, and validation rules
for proposed configurations using Python standard library components exclusively.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ALLOWED_CATEGORIES = {"config-profile", "diagnostic-probe"}
ALLOWED_STATUSES = {"experimental", "staged", "deprecated"}
ALLOWED_PLATFORMS = {"windows", "macos", "linux", "android"}
MANDATORY_FIELDS = [
    "id",
    "category",
    "status",
    "owner",
    "config_target",
    "platforms",
    "elevated_privileges",
    "raw_sockets",
    "kernel_hooks",
    "payload_logging",
    "default_enabled",
    "failure_policy",
    "rollback",
    "evidence_required",
    "non_goals",
]


def validate_experiment_structure(entry: dict, repo_root: Path) -> list[str]:
    """Perform deep structural audit against an isolated manifest entry dictionary."""
    errors: list[str] = []
    entry_id = entry.get("id", "unidentified-specification")

    for field in MANDATORY_FIELDS:
        if field not in entry:
            errors.append(f"[{entry_id}] Missing mandatory schema key: '{field}'")

    if errors:
        return errors

    if entry["category"] not in ALLOWED_CATEGORIES:
        errors.append(f"[{entry_id}] Unauthorized category '{entry['category']}'. Allowed: {ALLOWED_CATEGORIES}")
    if entry["status"] not in ALLOWED_STATUSES:
        errors.append(f"[{entry_id}] Unauthorized status '{entry['status']}'. Allowed: {ALLOWED_STATUSES}")

    if not isinstance(entry["platforms"], list) or not entry["platforms"]:
        errors.append(f"[{entry_id}] 'platforms' array must be non-empty.")
    else:
        for platform in entry["platforms"]:
            if platform not in ALLOWED_PLATFORMS:
                errors.append(f"[{entry_id}] Unsupported target platform identifier: '{platform}'")

    if entry["elevated_privileges"] or entry["raw_sockets"] or entry["kernel_hooks"]:
        errors.append(
            f"[{entry_id}] Security Failure: Elevated capabilities, raw sockets, or kernel hooks are strictly prohibited."
        )

    if entry["payload_logging"]:
        errors.append(f"[{entry_id}] Security Failure: Active payload logging must never be enabled inside this repository.")

    if entry["default_enabled"]:
        errors.append(
            f"[{entry_id}] Compliance Failure: Experimental structures must default to disabled states (`default_enabled`: false)."
        )

    if not str(entry["rollback"]).strip():
        errors.append(f"[{entry_id}] Compliance Failure: Rollback procedure documentation cannot be empty.")

    if not isinstance(entry["non_goals"], list) or len(entry["non_goals"]) == 0:
        errors.append(f"[{entry_id}] Governance Failure: Core engineering non-goals must be explicitly detailed.")

    config_target_path = repo_root / entry["config_target"]
    if not config_target_path.exists():
        errors.append(f"[{entry_id}] Target Configuration Error: File target missing at path: '{entry['config_target']}'")

    return errors


def main() -> None:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parent.parent
    manifest_file = repo_root / "configs" / "transport-experiments.json"

    print(f"[+] Launching preflight structural verification: {manifest_file.name}")

    if not manifest_file.exists():
        print(f"[-] Execution Error: Target manifest file is absent at path: {manifest_file}")
        sys.exit(1)

    try:
        with open(manifest_file, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except json.JSONDecodeError as exc:
        print(f"[-] Syntax Error: Target file violates standard RFC JSON styling rules: {exc}")
        sys.exit(1)

    if payload.get("schema_version") != 1:
        print(f"[-] Specification Error: Unsupported manifest layout schema version: {payload.get('schema_version')}")
        sys.exit(1)

    experiments = payload.get("experiments", [])
    collected_violations: list[str] = []

    for item in experiments:
        if not isinstance(item, dict):
            collected_violations.append("[unknown] experiment entry must be an object")
            continue
        collected_violations.extend(validate_experiment_structure(item, repo_root))

    if collected_violations:
        print(f"\n[-] Guardrail Validation Failure: {len(collected_violations)} rule exceptions identified:")
        for violation in collected_violations:
            print(f"    - {violation}")
        sys.exit(1)

    print("[+] Verification Completed Successfully: All configurations conform to project guardrails.")
    sys.exit(0)


if __name__ == "__main__":
    main()
