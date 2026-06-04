#!/usr/bin/env python3
"""Live eBPF/XDP production loader (Track D — explicit operator consent).

Programs:
  telemetry   — ingress packet counter (pass-through)
  containment — fail-secure XDP_DROP when supervisor_alive=0 (ADR-0003)

Does not replace Xray as the data plane. Writes loader state to
.local-state/ebpf-xdp-loader.json for Rust harness / lab evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = {
    "telemetry": {
        "object": ROOT / "tools" / "ebpf" / "ingress_telemetry.o",
        "pin": "/sys/fs/bpf/mitm_ingress_telemetry",
    },
    "containment": {
        "object": ROOT / "tools" / "ebpf" / "containment_xdp.o",
        "pin": "/sys/fs/bpf/mitm_containment_xdp",
        "map_pins": {
            "supervisor_alive": "/sys/fs/bpf/mitm_supervisor_alive",
            "containment_mode": "/sys/fs/bpf/mitm_containment_mode",
            "authorized_sockets_map": "/sys/fs/bpf/mitm_authorized_sockets",
        },
    },
}
DEFAULT_STATE = ROOT / ".local-state" / "ebpf-xdp-loader.json"
CONSENT_ENV = "MITM_EBPF_CONSENT"


def _consent_granted() -> bool:
    return os.environ.get(CONSENT_ENV, "").strip() in ("1", "true", "yes", "on")


def _run(cmd: List[str], timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)


def load_xdp_program(
    interface: str,
    *,
    program: str,
    object_path: Path,
    pin_path: str,
    dry_run: bool = False,
    force_simulate: bool = False,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "interface": interface,
        "program": program,
        "object": str(object_path),
        "pin": pin_path,
        "platform": platform.system(),
        "consent_env": CONSENT_ENV,
        "consent_granted": _consent_granted(),
        "mode": "rejected",
        "attached": False,
        "errors": [],
    }

    if not _consent_granted():
        result["errors"].append(f"{CONSENT_ENV} must be set to 1 for live kernel attach")
        return result

    if dry_run:
        result["mode"] = "dry_run"
        result["note"] = "consent granted; kernel attach skipped (dry-run)"
        return result

    if force_simulate:
        result["mode"] = "simulated_attach"
        result["attached"] = True
        result["note"] = "consent granted; kernel attach skipped (simulate)"
        if program == "containment":
            result["supervisor_alive"] = True
            result["containment_mode"] = 1
        return result

    if platform.system().lower() != "linux":
        result["mode"] = "unsupported_platform"
        result["errors"].append("live XDP attach requires Linux")
        return result

    if not interface.strip():
        result["mode"] = "missing_interface"
        result["errors"].append("interface name required (e.g. eth0)")
        return result

    if not object_path.is_file():
        result["mode"] = "missing_object"
        result["errors"].append(f"BPF object not found: {object_path} — run: make -C tools/ebpf")
        return result

    bpftool = shutil.which("bpftool")
    if not bpftool:
        result["mode"] = "missing_bpftool"
        result["errors"].append("bpftool not in PATH")
        return result

    load_proc = _run([bpftool, "prog", "load", str(object_path), pin_path])
    if load_proc.returncode != 0:
        result["mode"] = "bpftool_load_failed"
        result["errors"].append((load_proc.stderr or load_proc.stdout or "bpftool load failed").strip())
        return result

    attach_proc = _run(
        [bpftool, "net", "attach", "xdp", "pinned", pin_path, "dev", interface.strip()]
    )
    if attach_proc.returncode != 0:
        result["mode"] = "xdp_attach_failed"
        result["errors"].append((attach_proc.stderr or attach_proc.stdout or "xdp attach failed").strip())
        return result

    map_pins = PROGRAMS.get(program, {}).get("map_pins", {})
    for map_name, map_pin in map_pins.items():
        _run([bpftool, "map", "pin", "name", map_name, map_pin])

    result["mode"] = "kernel_attached"
    result["attached"] = True
    result["bpftool_pin"] = pin_path
    if program == "containment":
        sys.path.insert(0, str(ROOT / "scripts"))
        from core.ebpf_containment import mark_supervisor_alive  # noqa: WPS433

        mark_supervisor_alive()
        result["supervisor_alive"] = True
    return result


def write_state(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def detach_all(interface: str) -> None:
    bpftool = shutil.which("bpftool")
    if bpftool and interface.strip() and _consent_granted():
        _run([bpftool, "net", "detach", "xdp", "dev", interface.strip()])
    for spec in PROGRAMS.values():
        pin = Path(spec["pin"])
        if pin.exists():
            pin.unlink(missing_ok=True)
        for map_pin in spec.get("map_pins", {}).values():
            map_path = Path(map_pin)
            if map_path.exists():
                map_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Load Track D eBPF/XDP programs (consent required)")
    parser.add_argument("--interface", default=os.environ.get("MITM_STREAM_XDP_IFACE", ""))
    parser.add_argument(
        "--program",
        choices=sorted(PROGRAMS),
        default=os.environ.get("MITM_EBPF_PROGRAM", "telemetry"),
    )
    parser.add_argument("--state-out", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--detach", action="store_true")
    args = parser.parse_args()

    if args.detach:
        sys.path.insert(0, str(ROOT / "scripts"))
        from core.ebpf_containment import on_supervisor_stop  # noqa: WPS433

        on_supervisor_stop(args.interface)
        detach_all(args.interface)
        print(json.dumps({"detached": True, "interface": args.interface}, indent=2))
        return 0

    spec = PROGRAMS[args.program]
    payload = load_xdp_program(
        args.interface.strip(),
        program=args.program,
        object_path=Path(spec["object"]),
        pin_path=str(spec["pin"]),
        dry_run=args.dry_run,
        force_simulate=args.simulate,
    )
    payload["loaded_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    payload["loaded_by"] = "scripts/ebpf_xdp_loader.py"
    write_state(args.state_out, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    if payload.get("attached"):
        return 0
    if args.simulate and payload.get("consent_granted"):
        return 0
    return 1 if payload.get("errors") else 2


if __name__ == "__main__":
    raise SystemExit(main())
