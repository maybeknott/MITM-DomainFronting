#!/usr/bin/env python3
"""Validate config-src manifest and build pipeline boundaries."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config-src" / "manifest.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_src_merge import compile_config, validate_fragments  # noqa: E402
STEP_COMMANDS = {
    "validate_config": [sys.executable, "scripts/validate_config.py"],
    "route_intent_sync": [sys.executable, "scripts/route_intent_sync.py"],
    "route_policy_tests": [sys.executable, "scripts/route_policy_tests.py"],
    "transport_experiment_validate": [sys.executable, "scripts/transport_experiment_validate.py"],
}


def load_manifest(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")
    return data


def validate_manifest(manifest: Dict[str, Any], root: Path) -> List[str]:
    errors: List[str] = []
    if manifest.get("schema_version") not in {1, 2}:
        errors.append("schema_version must be 1 or 2")
    for key in ("runtime_import_target", "compiled_output", "primary_source"):
        value = manifest.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"missing or invalid {key}")
    primary = root / str(manifest.get("primary_source", ""))
    if not primary.exists():
        errors.append(f"primary_source missing: {primary}")
    runtime = root / str(manifest.get("runtime_import_target", ""))
    if not runtime.exists():
        errors.append(f"runtime_import_target missing: {runtime}")
    fragments = manifest.get("fragments")
    if fragments is None or not isinstance(fragments, list):
        errors.append("fragments must be an array")
    elif fragments:
        errors.extend(validate_fragments(root, [str(item) for item in fragments]))
    steps = manifest.get("validation_steps")
    if not isinstance(steps, list) or not steps:
        errors.append("validation_steps must be a non-empty array")
    else:
        for step in steps:
            if step != "config_src_runtime_sync" and step not in STEP_COMMANDS:
                errors.append(f"unknown validation step: {step}")
    source_components = manifest.get("source_components", [])
    if source_components is not None:
        if not isinstance(source_components, list):
            errors.append("source_components must be an array when present")
        else:
            for rel in source_components:
                if not isinstance(rel, str) or not rel.strip():
                    errors.append("source_components entries must be non-empty strings")
                    continue
                if not (root / rel).exists():
                    errors.append(f"source component missing: {rel}")
    return errors


def runtime_sync_errors(manifest: Dict[str, Any], root: Path) -> List[str]:
    primary = root / str(manifest["primary_source"])
    runtime = root / str(manifest["runtime_import_target"])
    fragment_paths = [root / str(rel) for rel in manifest.get("fragments", [])]
    try:
        compiled = compile_config(primary, fragment_paths)
        runtime_config = json.loads(runtime.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"config_src_runtime_sync failed to load source/runtime: {exc}"]
    if compiled != runtime_config:
        return [
            "config_src_runtime_sync failed: compiled config-src output differs from "
            f"{manifest['runtime_import_target']}"
        ]
    return []


def run_steps(manifest: Dict[str, Any], root: Path) -> List[str]:
    errors: List[str] = []
    primary = root / str(manifest["primary_source"])
    for step in manifest.get("validation_steps", []):
        if step == "config_src_runtime_sync":
            errors.extend(runtime_sync_errors(manifest, root))
            continue
        cmd = list(STEP_COMMANDS.get(str(step), []))
        if not cmd:
            continue
        if step == "validate_config":
            cmd.append(str(primary))
        elif step == "route_intent_sync":
            cmd.append(str(primary))
        proc = subprocess.run(cmd, cwd=str(root), text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            detail = (proc.stdout or proc.stderr or "").strip()[-500:]
            errors.append(f"{step} failed: {detail or proc.returncode}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate config-src manifest and optional build steps")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--run-steps", action="store_true", help="also execute manifest validation_steps")
    args = parser.parse_args()

    if not args.manifest.exists():
        print(f"manifest missing: {args.manifest}")
        return 2

    manifest = load_manifest(args.manifest)
    errors = validate_manifest(manifest, args.root)
    if args.run_steps:
        errors.extend(run_steps(manifest, args.root))

    if errors:
        for error in errors:
            print(error)
        return 2
    print("config-src validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
