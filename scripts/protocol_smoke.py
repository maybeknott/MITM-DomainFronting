#!/usr/bin/env python3
"""Small standard-library protocol smoke probes for release evidence."""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from transport_profile_validate import EXPECTED_PROFILE_POLICIES, catchall_rule, first_udp443_rule, load_config


def status_report(scenario: str, status: str, detail: Dict[str, object]) -> int:
    payload = {"scenario": scenario, "status": status, **detail}
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if status == "pass" else 1


def tcp_connect(host: str, port: int, timeout: float) -> int:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = int((time.time() - start) * 1000)
            return status_report("tcp-connect", "pass", {"host": host, "port": port, "elapsed_ms": elapsed_ms})
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("tcp-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def ipv6_connect(host: str, port: int, timeout: float) -> int:
    start = time.time()
    try:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM)
        if not infos:
            return status_report("ipv6-connect", "warn", {"host": host, "port": port, "error": "no IPv6 addresses"})
        last_error = None
        for family, socktype, proto, _, sockaddr in infos:
            try:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(timeout)
                    sock.connect(sockaddr)
                    elapsed_ms = int((time.time() - start) * 1000)
                    return status_report("ipv6-connect", "pass", {"host": host, "port": port, "address": sockaddr[0], "elapsed_ms": elapsed_ms})
            except OSError as exc:
                last_error = str(exc)
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("ipv6-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": last_error})
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("ipv6-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def tls_alpn(host: str, port: int, protocols: List[str], timeout: float, scenario: str) -> int:
    start = time.time()
    context = ssl.create_default_context()
    context.set_alpn_protocols(protocols)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                selected = tls.selected_alpn_protocol()
                elapsed_ms = int((time.time() - start) * 1000)
                status = "pass" if selected in protocols else "warn"
                return status_report(
                    scenario,
                    status,
                    {"host": host, "port": port, "requested_alpn": protocols, "selected_alpn": selected, "elapsed_ms": elapsed_ms},
                )
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report(scenario, "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def websocket_handshake(host: str, port: int, path: str, timeout: float, tls: bool) -> int:
    start = time.time()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        with raw:
            conn = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
            with conn:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("ascii")
                conn.sendall(request)
                response = conn.recv(512).decode("iso-8859-1", errors="replace")
        elapsed_ms = int((time.time() - start) * 1000)
        status = "pass" if " 101 " in response.splitlines()[0:1][0] else "warn"
        return status_report(
            "websocket-handshake",
            status,
            {"host": host, "port": port, "path": path, "tls": tls, "elapsed_ms": elapsed_ms, "status_line": response.splitlines()[0] if response else ""},
        )
    except (OSError, IndexError) as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("websocket-handshake", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def fragment_policy(root: Path) -> int:
    fragment = root / "config-src" / "fragments" / "tls-fragment-overlay.json"
    if not fragment.exists():
        return status_report("fragment-policy", "fail", {"error": "missing tls-fragment-overlay.json"})
    data = json.loads(fragment.read_text(encoding="utf-8"))
    outbounds = data.get("outbounds") if isinstance(data.get("outbounds"), list) else []
    fragment_hits = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
        fragment_cfg = sockopt.get("fragment") if isinstance(sockopt.get("fragment"), dict) else {}
        if fragment_cfg.get("packets") == "tlshello":
            fragment_hits += 1
    status = "pass" if fragment_hits else "fail"
    return status_report("fragment-policy", status, {"fragment_outbounds": fragment_hits})


def reality_stub(root: Path) -> int:
    stub = root / "config-src" / "fragments" / "reality-outbound-stub.json"
    if not stub.exists():
        return status_report("reality-stub", "fail", {"error": "missing reality-outbound-stub.json"})
    data = json.loads(stub.read_text(encoding="utf-8"))
    outbounds = data.get("outbounds") if isinstance(data.get("outbounds"), list) else []
    reality_hits = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        if stream.get("security") == "reality":
            reality_hits += 1
    status = "pass" if reality_hits else "fail"
    return status_report("reality-stub", status, {"reality_outbounds": reality_hits})


def fakedns_policy(root: Path) -> int:
    fragment = root / "config-src" / "fragments" / "fakedns-19818-trap.json"
    base = root / "Xray-config" / "MITM-DomainFronting.json"
    checks: dict[str, object] = {"fragment_present": fragment.exists(), "runtime_fakedns": False, "ip_pool": ""}
    if base.exists():
        data = json.loads(base.read_text(encoding="utf-8"))
        servers = data.get("dns", {}).get("servers", []) if isinstance(data.get("dns"), dict) else []
        checks["runtime_fakedns"] = any(isinstance(item, dict) and item.get("address") == "fakedns" for item in servers)
    if fragment.exists():
        frag = json.loads(fragment.read_text(encoding="utf-8"))
        pool = frag.get("dns", {}).get("fakedns", {}) if isinstance(frag.get("dns"), dict) else {}
        if isinstance(pool, dict):
            checks["ip_pool"] = pool.get("ipPool", "")
    status = "pass" if checks["fragment_present"] and checks["runtime_fakedns"] and checks["ip_pool"] == "198.18.0.0/15" else "warn"
    return status_report("fakedns-policy", status, checks)


def tun_stub(root: Path) -> int:
    fragment = root / "config-src" / "fragments" / "tun-inbound-stub.json"
    checks: dict[str, object] = {"fragment_present": fragment.exists(), "tun_tag": "", "tun_protocol": ""}
    if fragment.exists():
        frag = json.loads(fragment.read_text(encoding="utf-8"))
        inbounds = frag.get("inbounds", []) if isinstance(frag.get("inbounds"), list) else []
        for inbound in inbounds:
            if isinstance(inbound, dict) and str(inbound.get("protocol", "")).lower() == "tun":
                checks["tun_tag"] = inbound.get("tag", "")
                checks["tun_protocol"] = inbound.get("protocol", "")
                break
    status = "pass" if checks["fragment_present"] and checks["tun_protocol"] == "tun" else "warn"
    return status_report("tun-stub", status, checks)


def ttl_spin_policy(root: Path) -> int:
    doc = root / "docs" / "reference" / "track-d-ttl-spin-lab.md"
    fragment = root / "config-src" / "fragments" / "tls-fragment-overlay.json"
    checks: dict[str, object] = {
        "lab_doc_present": doc.exists(),
        "fragment_present": fragment.exists(),
        "note": "TTL spin is lab-only; validate with pcap/TTL inspection outside CI",
    }
    status = "pass" if checks["lab_doc_present"] and checks["fragment_present"] else "warn"
    return status_report("ttl-spin-policy", status, checks)


def firewall_checklist(root: Path) -> int:
    doc = root / "docs" / "tun-operational-notes.md"
    checks: dict[str, object] = {
        "doc_present": doc.exists(),
        "wfp_section": False,
        "nftables_section": False,
        "stun_block_example": False,
    }
    if doc.exists():
        text = doc.read_text(encoding="utf-8")
        checks["wfp_section"] = "Windows (WFP)" in text or "WFP" in text
        checks["nftables_section"] = "nftables" in text
        checks["stun_block_example"] = "3478" in text
    status = (
        "pass"
        if all(checks[key] for key in ("doc_present", "wfp_section", "nftables_section", "stun_block_example"))
        else "warn"
    )
    return status_report("firewall-checklist", status, checks)


def ebpf_xdp_loader_policy(root: Path) -> int:
    loader = root / "scripts" / "ebpf_xdp_loader.py"
    bpf_src = root / "tools" / "ebpf" / "ingress_telemetry.bpf.c"
    containment_src = root / "tools" / "ebpf" / "containment_xdp.bpf.c"
    adr = root / "docs" / "reference" / "track-d-ebpf-helper-adr.md"
    checks: dict[str, object] = {
        "loader_script_present": loader.exists(),
        "bpf_source_present": bpf_src.exists(),
        "containment_source_present": containment_src.exists(),
        "ebpf_containment_module_present": (root / "scripts" / "core" / "ebpf_containment.py").exists(),
        "adr_present": adr.exists(),
        "simulate_attach_rc": None,
        "containment_simulate_rc": None,
    }
    env = {**__import__("os").environ, "MITM_EBPF_CONSENT": "1"}
    if loader.exists():
        for program, key in (("telemetry", "simulate_attach_rc"), ("containment", "containment_simulate_rc")):
            proc = subprocess.run(
                [sys.executable, str(loader), "--simulate", "--interface", "eth0", "--program", program],
                cwd=str(root),
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            checks[key] = proc.returncode
            if proc.stdout.strip():
                try:
                    checks[f"{program}_simulate_report"] = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    checks[f"{program}_stdout"] = proc.stdout.strip()[-500:]
    telemetry = checks.get("telemetry_simulate_report") if isinstance(checks.get("telemetry_simulate_report"), dict) else {}
    containment = checks.get("containment_simulate_report") if isinstance(checks.get("containment_simulate_report"), dict) else {}
    simulate_ok = (
        checks.get("simulate_attach_rc") == 0
        and telemetry.get("mode") == "simulated_attach"
        and telemetry.get("attached") is True
        and checks.get("containment_simulate_rc") == 0
        and containment.get("mode") == "simulated_attach"
        and containment.get("supervisor_alive") is True
    )
    required = (
        "loader_script_present",
        "bpf_source_present",
        "containment_source_present",
        "ebpf_containment_module_present",
        "adr_present",
    )
    status = "pass" if all(checks.get(k) for k in required) and simulate_ok else "warn"
    return status_report("ebpf-xdp-loader", status, checks)


def ebpf_containment_policy(root: Path) -> int:
    module = root / "scripts" / "core" / "ebpf_containment.py"
    checks: dict[str, object] = {"module_present": module.exists()}
    if module.exists():
        sys.path.insert(0, str(root / "scripts"))
        from core.ebpf_containment import mark_supervisor_alive, mark_supervisor_dead  # noqa: WPS433

        alive = mark_supervisor_alive(simulate=True)
        dead = mark_supervisor_dead(simulate=True)
        checks["mark_alive"] = alive
        checks["mark_dead"] = dead
        state_path = root / ".local-state" / "ebpf-xdp-loader.json"
        checks["state_written"] = state_path.is_file()
    status = "pass" if checks.get("module_present") and checks.get("state_written") else "warn"
    return status_report("ebpf-containment-policy", status, checks)


def suricata_wire_proof_structure(root: Path) -> int:
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "wire_proof_suricata.py"), "--scenario", "structure"],
        cwd=str(root),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return status_report(
            "suricata-wire-proof",
            "fail",
            {"returncode": proc.returncode, "stdout": (proc.stdout or "")[-500:], "stderr": (proc.stderr or "")[-500:]},
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return status_report("suricata-wire-proof", "fail", {"error": "invalid JSON from wire_proof_suricata.py"})
    return status_report("suricata-wire-proof", str(report.get("status", "warn")), report)


OPERATING_PROFILES = ("strict", "balanced", "compatibility", "debug")


def ja3_pool_attach_policy(root: Path) -> int:
    sys.path.insert(0, str(root / "scripts"))
    from core.ja3_pool_attach import validate_all_profiles_have_pool_metadata  # noqa: WPS433

    errors = validate_all_profiles_have_pool_metadata(root / "Xray-config", OPERATING_PROFILES)
    status = "pass" if not errors else "fail"
    return status_report("ja3-pool-attach", status, {"errors": errors, "profiles_checked": list(OPERATING_PROFILES)})


def evasion_lab_profiles(root: Path) -> int:
    fragments = {
        "tls-fragment": root / "config-src" / "fragments" / "tls-fragment-overlay.json",
        "reality-stub": root / "config-src" / "fragments" / "reality-outbound-stub.json",
        "tun-stub": root / "config-src" / "fragments" / "tun-inbound-stub.json",
    }
    profiles = root / "configs" / "profiles.yml"
    checks: dict[str, object] = {
        "fragments_present": all(path.exists() for path in fragments.values()),
        "profiles_yml_present": profiles.exists(),
        "optional_lab_labels": [],
        "fragment_merge_ok": False,
    }
    if profiles.exists():
        text = profiles.read_text(encoding="utf-8")
        for label in (
            "evasion-fragment",
            "evasion-reality-stub",
            "evasion-tun-stub",
            "evasion-fakedns",
            "evasion-high-stealth",
        ):
            if label in text:
                checks["optional_lab_labels"].append(label)
    base = root / "Xray-config" / "MITM-DomainFronting.json"
    fragment = fragments["tls-fragment"]
    if base.exists() and fragment.exists():
        sys.path.insert(0, str(root / "scripts"))
        try:
            from config_src_merge import compile_config  # noqa: WPS433

            compiled = compile_config(base, [fragment])
            outbounds = compiled.get("outbounds", []) if isinstance(compiled.get("outbounds"), list) else []
            for outbound in outbounds:
                if not isinstance(outbound, dict):
                    continue
                stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
                sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
                fragment_cfg = sockopt.get("fragment") if isinstance(sockopt.get("fragment"), dict) else {}
                if fragment_cfg.get("packets") == "tlshello":
                    checks["fragment_merge_ok"] = True
                    break
        except Exception as exc:  # noqa: BLE001
            checks["merge_error"] = str(exc)
    labels = checks["optional_lab_labels"]
    high_stealth = (root / "Xray-config" / "MITM-DomainFronting.evasion-high-stealth.json").is_file()
    checks["evasion_high_stealth_generated"] = high_stealth
    status = (
        "pass"
        if checks["fragments_present"] and len(labels) >= 5 and checks["fragment_merge_ok"]
        else "warn"
    )
    return status_report("evasion-lab-profiles", status, checks)


def udp443_policy(config_dir: Path) -> int:
    checks: List[Dict[str, object]] = []
    for profile, expected in EXPECTED_PROFILE_POLICIES.items():
        path = config_dir / f"MITM-DomainFronting.{profile}.json"
        config = load_config(path)
        udp = first_udp443_rule(config)
        catchall = catchall_rule(config)
        checks.append({
            "profile": profile,
            "udp443": udp.get("outboundTag") if udp else None,
            "expected_udp443": expected["udp"],
            "catchall": catchall.get("outboundTag") if catchall else None,
            "expected_catchall": expected["catchall"],
            "status": "pass"
            if udp and catchall and udp.get("outboundTag") == expected["udp"] and catchall.get("outboundTag") == expected["catchall"]
            else "fail",
        })
    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return status_report("udp443-policy", status, {"checks": checks})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run protocol smoke probes and emit redacted JSON")
    parser.add_argument(
        "--scenario",
        choices=[
            "tcp-connect",
            "websocket-handshake",
            "grpc-alpn",
            "http2-alpn",
            "ipv6-connect",
            "udp443-policy",
            "fragment-policy",
            "reality-stub",
            "fakedns-policy",
            "tun-stub",
            "ttl-spin-policy",
            "firewall-checklist",
            "evasion-lab-profiles",
            "ebpf-xdp-loader",
            "ebpf-containment-policy",
            "suricata-wire-proof",
            "ja3-pool-attach",
        ],
        required=True,
    )
    parser.add_argument("--host", default="example.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--plain", action="store_true", help="use plain TCP for websocket-handshake")
    parser.add_argument("--config-dir", type=Path, default=Path("Xray-config"))
    args = parser.parse_args()

    if args.scenario == "tcp-connect":
        return tcp_connect(args.host, args.port, args.timeout)
    if args.scenario == "websocket-handshake":
        return websocket_handshake(args.host, args.port, args.path, args.timeout, tls=not args.plain)
    if args.scenario == "grpc-alpn":
        return tls_alpn(args.host, args.port, ["h2"], args.timeout, "grpc-alpn")
    if args.scenario == "http2-alpn":
        return tls_alpn(args.host, args.port, ["h2", "http/1.1"], args.timeout, "http2-alpn")
    if args.scenario == "ipv6-connect":
        return ipv6_connect(args.host, args.port, args.timeout)
    if args.scenario == "fragment-policy":
        return fragment_policy(Path("."))
    if args.scenario == "reality-stub":
        return reality_stub(Path("."))
    if args.scenario == "fakedns-policy":
        return fakedns_policy(Path("."))
    if args.scenario == "tun-stub":
        return tun_stub(Path("."))
    if args.scenario == "ttl-spin-policy":
        return ttl_spin_policy(Path("."))
    if args.scenario == "firewall-checklist":
        return firewall_checklist(Path("."))
    if args.scenario == "evasion-lab-profiles":
        return evasion_lab_profiles(Path("."))
    if args.scenario == "ebpf-xdp-loader":
        return ebpf_xdp_loader_policy(Path("."))
    if args.scenario == "ebpf-containment-policy":
        return ebpf_containment_policy(Path("."))
    if args.scenario == "suricata-wire-proof":
        return suricata_wire_proof_structure(Path("."))
    if args.scenario == "ja3-pool-attach":
        return ja3_pool_attach_policy(Path("."))
    return udp443_policy(args.config_dir)


if __name__ == "__main__":
    raise SystemExit(main())
