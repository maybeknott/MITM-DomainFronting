#!/usr/bin/env python3
"""Track D eBPF containment helpers — supervisor alive flag and map lifecycle."""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = ROOT / ".local-state" / "ebpf-xdp-loader.json"
CONSENT_ENV = "MITM_EBPF_CONSENT"
CONTAINMENT_ENV = "MITM_EBPF_CONTAINMENT"
PIN_CONTAINMENT = "/sys/fs/bpf/mitm_containment_xdp"
MAP_SUPERVISOR_ALIVE = "/sys/fs/bpf/mitm_supervisor_alive"
MAP_CONTAINMENT_MODE = "/sys/fs/bpf/mitm_containment_mode"
MAP_AUTHORIZED_SOCKETS = "/sys/fs/bpf/mitm_authorized_sockets"


def consent_granted() -> bool:
    return os.environ.get(CONSENT_ENV, "").strip() in ("1", "true", "yes", "on")


def containment_enabled() -> bool:
    return os.environ.get(CONTAINMENT_ENV, "").strip() in ("1", "true", "yes", "on")


def _run(cmd: List[str], timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.is_file():
        return {}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def write_state(patch: Dict[str, Any]) -> None:
    state = load_state()
    state.update(patch)
    state["updated_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _bpftool_map_update_u32(map_path: str, value: int) -> bool:
    bpftool = shutil.which("bpftool")
    if not bpftool or not Path(map_path).exists():
        return False
    hex_value = value.to_bytes(4, "little").hex()
    proc = _run([bpftool, "map", "update", "pinned", map_path, "key", "0", "0", "0", "0", "value", hex_value])
    return proc.returncode == 0


def _bpftool_map_clear_hash(map_path: str) -> bool:
    bpftool = shutil.which("bpftool")
    if not bpftool or not Path(map_path).exists():
        return False
    proc = _run([bpftool, "map", "delete", "pinned", map_path, "key", "0", "0", "0", "0", "0", "0", "0", "0"])
    return proc.returncode in (0, 255)


def mark_supervisor_alive(*, simulate: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {"supervisor_alive": True, "simulate": simulate}
    if simulate or platform.system().lower() != "linux" or not consent_granted():
        write_state({"supervisor_alive": True, "containment_enforced": not simulate})
        return result
    _bpftool_map_update_u32(MAP_SUPERVISOR_ALIVE, 1)
    _bpftool_map_update_u32(MAP_CONTAINMENT_MODE, 1)
    write_state({"supervisor_alive": True, "containment_enforced": True})
    return result


def mark_supervisor_dead(*, simulate: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {"supervisor_alive": False, "simulate": simulate}
    if simulate or platform.system().lower() != "linux" or not consent_granted():
        write_state({"supervisor_alive": False, "containment_enforced": False})
        return result
    _bpftool_map_update_u32(MAP_SUPERVISOR_ALIVE, 0)
    _bpftool_map_clear_hash(MAP_AUTHORIZED_SOCKETS)
    write_state({"supervisor_alive": False, "containment_enforced": True})
    return result


def authorize_socket_cookie(cookie: int, *, simulate: bool = False) -> Dict[str, Any]:
    payload = {"cookie": cookie, "authorized": True, "simulate": simulate}
    if simulate or platform.system().lower() != "linux" or not consent_granted():
        write_state({"last_authorized_cookie": cookie})
        return payload
    bpftool = shutil.which("bpftool")
    if not bpftool or not Path(MAP_AUTHORIZED_SOCKETS).exists():
        payload["error"] = "authorized_sockets_map not pinned"
        return payload
    key = int(cookie).to_bytes(8, "little").hex()
    value = (1).to_bytes(4, "little").hex()
    proc = _run([bpftool, "map", "update", "pinned", MAP_AUTHORIZED_SOCKETS, "key", *key, "value", value])
    payload["bpftool_rc"] = proc.returncode
    return payload


def detach_containment(interface: str) -> None:
    if not consent_granted() or not interface.strip():
        return
    bpftool = shutil.which("bpftool")
    if bpftool:
        _run([bpftool, "net", "detach", "xdp", "dev", interface.strip()])
    for pin in (PIN_CONTAINMENT, MAP_SUPERVISOR_ALIVE, MAP_CONTAINMENT_MODE, MAP_AUTHORIZED_SOCKETS):
        path = Path(pin)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
    if STATE_PATH.exists():
        STATE_PATH.unlink(missing_ok=True)


def on_supervisor_start() -> None:
    if containment_enabled() and consent_granted():
        mark_supervisor_alive(simulate=platform.system().lower() != "linux")


def on_supervisor_stop(interface: Optional[str] = None) -> None:
    iface = (interface or os.environ.get("MITM_STREAM_XDP_IFACE") or "").strip()
    mark_supervisor_dead(simulate=platform.system().lower() != "linux")
    if iface and consent_granted():
        detach_containment(iface)
