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


def main() -> int:
    parser = argparse.ArgumentParser(description="Build release validation manifest")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--out", type=Path, default=Path("validation-report.json"))
    parser.add_argument("--checksums", type=Path, default=Path("checksums.txt"))
    parser.add_argument("--include", action="append", default=[], help="extra file to checksum; repeatable")
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

    report = {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generated_by": "scripts/build_release_manifest.py",
        "config": {
            "path": str(config.relative_to(root)) if config.exists() and config.is_relative_to(root) else str(config),
            "exists": config.exists(),
            "sha256": sha256_file(config) if config.exists() else None,
            "remarks": load_config_remarks(config) if config.exists() else None,
        },
        "validation": run_validate(config) if config.exists() else {"status": "fail", "reason": "config missing"},
        "files": file_entries,
        "notes": [
            "Review warnings before publishing.",
            "Attach checksums.txt and this validation report to the release.",
            "Do not include mycert.key or user-local mycert.crt in release artifacts.",
        ],
    }
    (root / args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / args.out), "checksums": str(root / args.checksums)}, indent=2))
    return 0 if report["validation"].get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
