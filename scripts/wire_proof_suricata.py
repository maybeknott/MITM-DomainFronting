#!/usr/bin/env python3
"""Suricata / PCAP wire-proof harness for active DPI lab validation (Track A/D).

Structure validation runs in CI; wire-measured proof requires operator-supplied PCAP
captured while Suricata (or Snort) blocks plaintext SNI and the tunnel still
establishes with fragment/evasion profiles active.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config-src" / "lab" / "wire-proof-manifest.json"
RULES = ROOT / "config-src" / "lab" / "suricata-sni-block.rules"


def load_manifest(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


def status_report(scenario: str, status: str, detail: Dict[str, Any]) -> int:
    payload = {"scenario": scenario, "status": status, **detail}
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if status == "pass" else 1


def validate_lab_artifacts(root: Path) -> Dict[str, Any]:
    manifest_path = root / MANIFEST.relative_to(ROOT)
    rules_path = root / RULES.relative_to(ROOT)
    checks: Dict[str, Any] = {
        "manifest_present": manifest_path.is_file(),
        "rules_present": rules_path.is_file(),
        "manifest": {},
        "rules_line_count": 0,
    }
    if rules_path.is_file():
        checks["rules_line_count"] = sum(1 for line in rules_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#"))
    if manifest_path.is_file():
        manifest = load_manifest(manifest_path)
        checks["manifest"] = {
            "schema_version": manifest.get("schema_version"),
            "required_tshark_fields": manifest.get("required_tshark_fields"),
            "dpi_block_rule_sid": manifest.get("dpi_block_rule_sid"),
        }
    return checks


def analyze_pcap(pcap: Path, *, tshark: str) -> Dict[str, Any]:
    fields = ["tls.handshake.ja3_hash", "tls.handshake.extensions_server_name", "frame.number"]
    cmd = [
        tshark,
        "-r",
        str(pcap),
        "-Y",
        "tls.handshake.type == 1",
        "-T",
        "fields",
        "-E",
        "separator=|",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    ja3_values: List[str] = []
    sni_values: List[str] = []
    if proc.returncode == 0 and proc.stdout:
        for line in proc.stdout.splitlines():
            parts = line.split("|")
            if parts and parts[0].strip():
                ja3_values.append(parts[0].strip())
            if len(parts) > 1 and parts[1].strip():
                sni_values.append(parts[1].strip())
    return {
        "pcap": str(pcap),
        "tshark_rc": proc.returncode,
        "ja3_unique": sorted(set(ja3_values)),
        "sni_unique": sorted(set(sni_values)),
        "client_hello_frames": len(ja3_values) + len(sni_values),
        "tshark_stderr": (proc.stderr or "").strip()[-500:],
    }


def run_suricata_rules_check(pcap: Path, rules: Path) -> Dict[str, Any]:
    suricata = shutil.which("suricata")
    if not suricata:
        return {"suricata_available": False, "note": "suricata not in PATH — skip IDS replay"}
    cmd = [
        suricata,
        "-r",
        str(pcap),
        "-S",
        str(rules),
        "-k",
        "none",
        "--runmode",
        "single",
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return {
        "suricata_available": True,
        "returncode": proc.returncode,
        "stdout_tail": (proc.stdout or "").strip()[-1000:],
        "stderr_tail": (proc.stderr or "").strip()[-1000:],
    }


def wire_proof(
    root: Path,
    *,
    pcap: Optional[Path],
    require_wire: bool,
) -> Dict[str, Any]:
    checks = validate_lab_artifacts(root)
    detail: Dict[str, Any] = {"lab_artifacts": checks, "wire_measured": False}

    if not checks["manifest_present"] or not checks["rules_present"]:
        detail["error"] = "missing lab manifest or Suricata rules"
        return detail

    if pcap is None or not pcap.is_file():
        detail["pcap_status"] = "not_supplied"
        if require_wire:
            detail["error"] = "wire proof requires --pcap with lab capture"
        return detail

    tshark = shutil.which("tshark")
    if not tshark:
        detail["error"] = "tshark not in PATH"
        return detail

    detail["pcap_analysis"] = analyze_pcap(pcap, tshark=tshark)
    detail["suricata_replay"] = run_suricata_rules_check(pcap, root / RULES.relative_to(ROOT))
    ja3_unique = detail["pcap_analysis"].get("ja3_unique") or []
    detail["wire_measured"] = bool(ja3_unique) or bool(detail["pcap_analysis"].get("sni_unique"))
    return detail


def main() -> int:
    parser = argparse.ArgumentParser(description="Suricata/PCAP wire proof harness")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--pcap", type=Path, default=None, help="operator lab capture")
    parser.add_argument("--require-wire", action="store_true", help="fail unless PCAP yields TLS fields")
    parser.add_argument(
        "--scenario",
        choices=["structure", "wire-proof"],
        default="structure",
        help="structure=CI lab files; wire-proof=analyze --pcap when provided",
    )
    args = parser.parse_args()

    if args.scenario == "structure":
        checks = validate_lab_artifacts(args.root)
        ok = checks["manifest_present"] and checks["rules_present"] and checks["rules_line_count"] > 0
        return status_report(
            "suricata-wire-proof-structure",
            "pass" if ok else "fail",
            checks,
        )

    detail = wire_proof(args.root, pcap=args.pcap, require_wire=args.require_wire)
    if detail.get("error"):
        status = "fail" if args.require_wire else "warn"
        return status_report("suricata-wire-proof", status, detail)
    if detail.get("wire_measured"):
        return status_report("suricata-wire-proof", "pass", detail)
    return status_report("suricata-wire-proof", "warn", detail)


if __name__ == "__main__":
    raise SystemExit(main())
