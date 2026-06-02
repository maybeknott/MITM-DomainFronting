#!/usr/bin/env python3
"""Local release readiness gate for configs, tests, docs, and artifacts."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TESTS = ROOT / "tests" / "python"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from verify_release_artifact import verify_zip  # noqa: E402


def run_command(label: str, args: list[str], *, timeout: int = 180) -> dict[str, object]:
    try:
        proc = subprocess.run(
            args,
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "id": label,
            "status": "fail",
            "exit_code": 124,
            "command": args,
            "output_tail": (exc.stdout or exc.stderr or "timed out")[-4000:] if isinstance(exc.stdout or exc.stderr or "", str) else "timed out",
        }
    except FileNotFoundError as exc:
        return {
            "id": label,
            "status": "fail",
            "exit_code": 127,
            "command": args,
            "output_tail": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "id": label,
            "status": "fail",
            "exit_code": 1,
            "command": args,
            "output_tail": str(exc),
        }
    return {
        "id": label,
        "status": "pass" if proc.returncode == 0 else "fail",
        "exit_code": proc.returncode,
        "command": args,
        "output_tail": (proc.stdout or "")[-4000:],
    }


def require_file(rel: str) -> dict[str, object]:
    path = ROOT / rel
    return {
        "id": f"file:{rel}",
        "status": "pass" if path.exists() else "fail",
        "path": rel,
        "summary": "present" if path.exists() else "missing",
    }


def release_checks() -> list[tuple[str, Callable[[], dict[str, object]]]]:
    py = sys.executable
    config = "Xray-config/MITM-DomainFronting.json"
    return [
        ("config-src validates", lambda: run_command("config-src validates", [py, "scripts/config_src_validate.py", "--run-steps"], timeout=240)),
        (
            "runtime config syncs",
            lambda: run_command(
                "runtime config syncs",
                [py, "scripts/build_config.py", "--check-runtime-sync", "--generate-profiles", "--check-profile-sync"],
                timeout=240,
            ),
        ),
        ("route graph passes", lambda: run_command("route graph passes", [py, "scripts/route_graph_verify.py", config])),
        ("route linter passes", lambda: run_command("route linter passes", [py, "scripts/route_rule_linter.py", config, "--quiet"])),
        ("provider policies pass", lambda: run_command("provider policies pass", [py, "scripts/provider_policy_validator.py"])),
        ("provider tests pass", lambda: run_command("provider tests pass", [py, "tests/python/provider_policy_validator_tests.py"])),
        ("secret scan passes", lambda: run_command("secret scan passes", [py, "scripts/secret_scan.py"])),
        ("GUI self-test passes", lambda: run_command("GUI self-test passes", [py, "scripts/gui.py", "--self-test"])),
        ("README present", lambda: require_file("README.md")),
        ("Farsi quick start present", lambda: require_file("docs/fa/quick-start.md")),
        ("maintainer map present", lambda: require_file("docs/reference/maintainer-map.md")),
        ("generated files guide present", lambda: require_file("docs/reference/generated-files.md")),
        ("Xray executable present", lambda: require_file("xray/xray.exe")),
        ("geoip.dat present", lambda: require_file("xray/geoip.dat")),
        ("geosite.dat present", lambda: require_file("xray/geosite.dat")),
        ("primary config present", lambda: require_file(config)),
        ("strict profile present", lambda: require_file("Xray-config/MITM-DomainFronting.strict.json")),
        ("balanced profile present", lambda: require_file("Xray-config/MITM-DomainFronting.balanced.json")),
        ("compatibility profile present", lambda: require_file("Xray-config/MITM-DomainFronting.compatibility.json")),
        ("debug profile present", lambda: require_file("Xray-config/MITM-DomainFronting.debug.json")),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run release readiness checks")
    parser.add_argument("--zip", type=Path, help="optional release ZIP to verify")
    parser.add_argument("--checksum", type=Path, help="optional .sha256 for --zip")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    results: list[dict[str, object]] = []
    for label, check in release_checks():
        result = check()
        result.setdefault("id", label)
        results.append(result)
        if not args.json:
            print(f"{result['status'].upper():4} {label}")
    if args.zip:
        artifact = verify_zip(args.zip, args.checksum)
        results.append({"id": "release artifact ZIP", **artifact})
        if not args.json:
            print(f"{artifact['status'].upper():4} release artifact ZIP")

    blockers = [item for item in results if item.get("status") == "fail"]
    report = {
        "status": "fail" if blockers else "pass",
        "root": str(ROOT),
        "checks": results,
        "blockers": [item.get("id", "unknown") for item in blockers],
    }
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif blockers:
        print("\nRelease readiness blockers:")
        for blocker in blockers:
            print(f"- {blocker.get('id')}")
    else:
        print("\nRelease readiness passed.")
    return 2 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
