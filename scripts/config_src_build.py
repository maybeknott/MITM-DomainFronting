#!/usr/bin/env python3
"""Build compiled config artifacts from the config-src manifest."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config-src" / "manifest.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_src_merge import compile_config, validate_fragments  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build validated config artifact from config-src manifest")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--check-runtime-sync",
        action="store_true",
        help="fail if the compiled config differs from runtime_import_target",
    )
    parser.add_argument(
        "--generate-profiles",
        action="store_true",
        help="generate profile configs from the compiled config into the compiled output directory",
    )
    parser.add_argument(
        "--check-profile-sync",
        action="store_true",
        help="fail if generated profile configs differ from manifest generated_profiles",
    )
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
    fragment_rels = [str(rel) for rel in manifest.get("fragments", [])]
    fragment_errors = validate_fragments(args.root, fragment_rels)
    if fragment_errors:
        for error in fragment_errors:
            print(error)
        return 2

    fragment_paths = [args.root / rel for rel in fragment_rels]
    output = args.root / manifest["compiled_output"]
    output.parent.mkdir(parents=True, exist_ok=True)
    if fragment_paths:
        compiled = compile_config(primary, fragment_paths)
        output.write_text(json.dumps(compiled, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"compiled_output": str(output), "source": str(primary), "fragments": len(fragment_paths)}, indent=2))
    else:
        compiled = json.loads(primary.read_text(encoding="utf-8"))
        shutil.copy2(primary, output)
        print(json.dumps({"compiled_output": str(output), "source": str(primary), "fragments": 0}, indent=2))
    if args.check_runtime_sync:
        runtime = args.root / manifest["runtime_import_target"]
        runtime_config = json.loads(runtime.read_text(encoding="utf-8"))
        if compiled != runtime_config:
            print(f"compiled config differs from runtime target: {runtime}")
            return 2
    generated_profile_paths: List[Path] = []
    if args.generate_profiles or args.check_profile_sync:
        profile_proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_profiles.py"),
                "--base",
                str(output),
                "--out-dir",
                str(output.parent),
            ],
            cwd=str(args.root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if profile_proc.returncode != 0:
            print(profile_proc.stdout)
            return profile_proc.returncode
        generated_profile_paths = [Path(line.strip()) for line in profile_proc.stdout.splitlines() if line.strip()]
        print(json.dumps({"generated_profiles": [str(path) for path in generated_profile_paths]}, indent=2))
        evasion_proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_evasion_profiles.py")],
            cwd=str(args.root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if evasion_proc.returncode != 0:
            print(evasion_proc.stdout)
            return evasion_proc.returncode
        print(json.dumps({"evasion_lab_profiles": "regenerated"}, indent=2))
        evasion_rels = manifest.get("generated_evasion_lab_profiles", [])
        missing_evasion = [rel for rel in evasion_rels if not (args.root / rel).is_file()]
        if missing_evasion:
            print(f"evasion lab profiles missing after generate: {missing_evasion}")
            return 2
    if args.check_profile_sync:
        expected_profiles = [args.root / rel for rel in manifest.get("generated_profiles", [])]
        if len(generated_profile_paths) != len(expected_profiles):
            print("generated profile count differs from manifest generated_profiles")
            return 2
        for generated, expected in zip(sorted(generated_profile_paths), sorted(expected_profiles)):
            generated_data = json.loads((args.root / generated if not generated.is_absolute() else generated).read_text(encoding="utf-8"))
            expected_data = json.loads(expected.read_text(encoding="utf-8"))
            if generated_data != expected_data:
                print(f"generated profile differs from tracked target: {expected}")
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
