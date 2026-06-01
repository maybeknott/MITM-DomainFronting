#!/usr/bin/env python3
"""Build phase-1 compiled config artifact from config-src manifest."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config-src" / "manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build validated config artifact from config-src manifest")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    validate = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "config_src_validate.py"), "--manifest", str(args.manifest), "--run-steps"],
        cwd=str(args.root),
        check=False,
    )
    if validate.returncode != 0:
        return validate.returncode

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    primary = args.root / manifest["primary_source"]
    output = args.root / manifest["compiled_output"]
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(primary, output)
    print(json.dumps({"compiled_output": str(output), "source": str(primary)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
