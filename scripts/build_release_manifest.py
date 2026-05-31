#!/usr/bin/env python3
"""Build checksums and a lightweight validation-report.json for a release."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_config_remarks(config: Path) -> Optional[str]:
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
        remarks = data.get("remarks")
        return remarks if isinstance(remarks, str) else None
    except Exception:
        return None


def run_git(root: Path, args: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(
            ["git", *args],
            cwd=str(root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    if p.returncode != 0:
        return None
    return p.stdout.strip()


def git_metadata(root: Path) -> Dict[str, object]:
    status = run_git(root, ["status", "--porcelain"])
    return {
        "commit": run_git(root, ["rev-parse", "HEAD"]),
        "branch": run_git(root, ["branch", "--show-current"]),
        "is_dirty": bool(status),
        "dirty_entries": status.splitlines()[:50] if status else [],
    }


def command_result(cmd: List[str], cwd: Path) -> Dict[str, object]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        return {"status": "not_run", "reason": f"{cmd[0]} not found"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "not_run", "reason": str(exc)}
    return {
        "status": "pass" if p.returncode == 0 else "fail",
        "returncode": p.returncode,
        "stdout": p.stdout.strip()[-2000:],
        "stderr": p.stderr.strip()[-2000:],
    }


def tracked_command(root: Path, script_name: str, *args: str) -> Dict[str, object]:
    script = Path(__file__).resolve().parent / script_name
    if not script.exists():
        return {"status": "not_run", "reason": f"{script_name} not found"}
    return command_result([sys.executable, str(script), *args], root)


def run_validate(config: Path) -> Dict[str, object]:
    script = Path(__file__).resolve().parent / "validate_config.py"
    if not script.exists():
        return {"status": "not_run", "reason": "validate_config.py not found"}
    p = subprocess.run([sys.executable, str(script), str(config)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    try:
        parsed = json.loads(p.stdout)
    except Exception:
        parsed = {"raw_stdout": p.stdout[-2000:], "raw_stderr": p.stderr[-2000:]}
    return {"status": "pass" if p.returncode == 0 else "fail", "returncode": p.returncode, "report": parsed}


def geodata_metadata(root: Path) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    for name in ("geosite.dat", "geoip.dat"):
        matches = sorted(path for path in root.rglob(name) if ".git" not in path.parts)
        if not matches:
            entries.append({"name": name, "status": "not_found", "note": "record runtime package hash if geodata is supplied by client"})
            continue
        for path in matches:
            rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
            entries.append({"name": name, "status": "found", "path": rel, "sha256": sha256_file(path)})
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description="Build release validation manifest")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--out", type=Path, default=Path("validation-report.json"))
    parser.add_argument("--checksums", type=Path, default=Path("checksums.txt"))
    parser.add_argument("--include", action="append", default=[], help="extra file to checksum; repeatable")
    parser.add_argument("--xray-bin", default="xray", help="Xray binary for optional version and config-test evidence")
    parser.add_argument("--skip-xray-test", action="store_true", help="do not attempt xray run -test")
    args = parser.parse_args()

    root = args.root.resolve()
    config = (root / args.config).resolve() if not args.config.is_absolute() else args.config
    files = [config]
    default_candidates = [
        root / "Xray-config" / "certificate_generator.bat",
        root / "Xray-config" / "certificate_generator.sh",
        root / "README.md",
        root / "SUPPORT_MATRIX.md",
        root / "KNOWN_ISSUES.md",
        root / "CHANGELOG.md",
        root / "SECURITY.md",
        root / "PRIVACY.md",
        root / "THREAT_MODEL.md",
        root / ".github" / "workflows" / "validate.yml",
    ]
    files.extend([p for p in default_candidates if p.exists()])
    files.extend([(root / p).resolve() for p in map(Path, args.include)])
    files = [p for p in files if p.exists()]

    checksum_lines: List[str] = []
    file_entries: List[Dict[str, str]] = []
    for path in sorted(set(files)):
        digest = sha256_file(path)
        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        checksum_lines.append(f"{digest}  {rel}")
        file_entries.append({"path": rel, "sha256": digest})

    (root / args.checksums).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    xray_version = command_result([args.xray_bin, "version"], root)
    xray_config_test = (
        {"status": "not_run", "reason": "--skip-xray-test was set"}
        if args.skip_xray_test
        else command_result([args.xray_bin, "run", "-test", "-config", str(config)], root)
    )

    report = {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generated_by": "scripts/build_release_manifest.py",
        "repository": git_metadata(root),
        "config": {
            "path": str(config.relative_to(root)) if config.exists() and config.is_relative_to(root) else str(config),
            "exists": config.exists(),
            "sha256": sha256_file(config) if config.exists() else None,
            "remarks": load_config_remarks(config) if config.exists() else None,
        },
        "validation": run_validate(config) if config.exists() else {"status": "fail", "reason": "config missing"},
        "metadata_validation": tracked_command(root, "validate_metadata.py"),
        "route_policy_tests": tracked_command(root, "route_policy_tests.py"),
        "secret_scan": tracked_command(root, "secret_scan.py"),
        "xray": {
            "binary": args.xray_bin,
            "version": xray_version,
            "config_test": xray_config_test,
        },
        "geodata": geodata_metadata(root),
        "files": file_entries,
        "notes": [
            "Review warnings before publishing.",
            "Attach checksums.txt and this validation report to the release.",
            "Do not include mycert.key or user-local mycert.crt in release artifacts.",
            "A dirty repository can be acceptable for draft evidence, but final release evidence should be generated from a clean commit.",
        ],
    }
    (root / args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / args.out), "checksums": str(root / args.checksums)}, indent=2))
    return 0 if report["validation"].get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
