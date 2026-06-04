#!/usr/bin/env python3
"""One-shot lab automation: evasion profiles, JA3 attach validation, evidence bundle."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def run_step(label: str, cmd: List[str], *, timeout: float = 120.0) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"step": label, "status": "fail", "error": f"timeout after {timeout}s"}
    return {
        "step": label,
        "status": "pass" if proc.returncode == 0 else "fail",
        "returncode": proc.returncode,
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-1000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare lab artifacts (evasion profiles + evidence bundle)")
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--allow-warn", action="store_true", help="accept warn-level lab evidence overall")
    parser.add_argument("--skip-evidence", action="store_true")
    args = parser.parse_args()

    py = sys.executable
    steps: List[Dict[str, Any]] = []

    steps.append(
        run_step(
            "generate_evasion_profiles",
            [py, str(ROOT / "scripts" / "generate_evasion_profiles.py")],
        )
    )
    steps.append(
        run_step(
            "ja3_pool_attach_smoke",
            [py, str(ROOT / "scripts" / "protocol_smoke.py"), "--scenario", "ja3-pool-attach"],
        )
    )
    steps.append(
        run_step(
            "ebpf_smoke",
            [py, str(ROOT / "scripts" / "protocol_smoke.py"), "--scenario", "ebpf-xdp-loader"],
        )
    )

    if not args.skip_evidence:
        evidence_args = [
            py,
            str(ROOT / "scripts" / "lab_evidence_run.py"),
            "--json-out",
            str(args.json_out or ROOT / "lab-evidence.bundle.json"),
        ]
        if args.allow_warn:
            evidence_args.append("--allow-warn")
        steps.append(run_step("lab_evidence_run", evidence_args, timeout=300.0))
        bundle_path = args.json_out or ROOT / "lab-evidence.bundle.json"
        if bundle_path.is_file():
            validate_args = [py, str(ROOT / "scripts" / "lab_evidence_validate.py"), str(bundle_path)]
            if args.allow_warn:
                validate_args.append("--allow-warn")
            steps.append(run_step("lab_evidence_validate", validate_args))

    overall = "pass" if all(step.get("status") == "pass" for step in steps) else "warn"
    payload = {"overall": overall, "steps": steps}
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    print(text)
    return 0 if overall == "pass" or args.allow_warn else 1


if __name__ == "__main__":
    raise SystemExit(main())
