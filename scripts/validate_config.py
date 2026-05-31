#!/usr/bin/env python3
"""
Validate an Xray JSON config for the MITM-DomainFronting single-config workflow.

This script performs static checks only. It does not run traffic, inspect payloads,
read cookies, or send diagnostics anywhere.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

LOOPBACK_NAMES = {"127.0.0.1", "::1", "localhost"}
REQUIRED_INBOUND_TAGS = {"mixed-in", "tls-decrypt-h11", "tls-decrypt-h211"}
REQUIRED_PORTS = {10808, 11666, 11777}


def load_json(path: Path) -> Tuple[Dict[str, Any] | None, List[Dict[str, str]]]:
    checks: List[Dict[str, str]] = []
    if not path.exists():
        return None, [{"id": "config_exists", "status": "fail", "detail": f"missing: {path}"}]
    try:
        return json.loads(path.read_text(encoding="utf-8")), [
            {"id": "config_json", "status": "pass", "detail": "valid JSON"}
        ]
    except Exception as exc:  # noqa: BLE001
        return None, [{"id": "config_json", "status": "fail", "detail": str(exc)}]


def tag_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        tag = item.get("tag")
        if isinstance(tag, str):
            counts[tag] = counts.get(tag, 0) + 1
    return counts


def has_catchall_ip(rule: Dict[str, Any]) -> bool:
    ips = rule.get("ip", [])
    return isinstance(ips, list) and "0.0.0.0/0" in ips and "::/0" in ips


def has_final_block(rule: Dict[str, Any]) -> bool:
    return rule.get("outboundTag") == "block" and str(rule.get("port")) == "0-65535"


def inbound_listen_status(inbound: Dict[str, Any]) -> Tuple[str, str]:
    tag = inbound.get("tag", "<untagged>")
    port = inbound.get("port")
    listen = inbound.get("listen")
    settings_ip = None
    if isinstance(inbound.get("settings"), dict):
        settings_ip = inbound["settings"].get("ip")

    if listen in LOOPBACK_NAMES:
        return "pass", f"{tag}:{port} explicitly listens on {listen}"
    if listen is None and settings_ip in LOOPBACK_NAMES:
        return "warn", f"{tag}:{port} has settings.ip={settings_ip} but no top-level listen; add listen: 127.0.0.1"
    if listen is None:
        return "warn", f"{tag}:{port} has no explicit listen; add listen: 127.0.0.1"
    return "fail", f"{tag}:{port} listens on non-loopback value {listen!r}"


def validate_config(config: Dict[str, Any]) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    inbounds = config.get("inbounds", [])
    outbounds = config.get("outbounds", [])
    routing = config.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []

    if not isinstance(inbounds, list):
        checks.append({"id": "inbounds_type", "status": "fail", "detail": "inbounds must be a list"})
        inbounds = []
    if not isinstance(outbounds, list):
        checks.append({"id": "outbounds_type", "status": "fail", "detail": "outbounds must be a list"})
        outbounds = []
    if not isinstance(rules, list):
        checks.append({"id": "routing_rules_type", "status": "fail", "detail": "routing.rules must be a list"})
        rules = []

    inbound_tags = {item.get("tag") for item in inbounds if isinstance(item.get("tag"), str)}
    outbound_tags = {item.get("tag") for item in outbounds if isinstance(item.get("tag"), str)}
    dns = config.get("dns")
    dns_server_tags = set()
    if isinstance(dns, dict) and isinstance(dns.get("servers"), list):
        dns_server_tags = {
            item.get("tag")
            for item in dns["servers"]
            if isinstance(item, dict) and isinstance(item.get("tag"), str)
        }
    route_source_tags = inbound_tags | dns_server_tags

    missing_inbounds = sorted(REQUIRED_INBOUND_TAGS - inbound_tags)
    checks.append({
        "id": "required_inbound_tags",
        "status": "pass" if not missing_inbounds else "fail",
        "detail": "all required inbounds present" if not missing_inbounds else f"missing: {', '.join(missing_inbounds)}",
    })

    ports = {item.get("port") for item in inbounds if isinstance(item.get("port"), int)}
    missing_ports = sorted(REQUIRED_PORTS - ports)
    checks.append({
        "id": "required_ports",
        "status": "pass" if not missing_ports else "fail",
        "detail": "10808, 11666, 11777 present" if not missing_ports else f"missing ports: {missing_ports}",
    })

    for kind, items in (("inbound", inbounds), ("outbound", outbounds)):
        duplicates = sorted(tag for tag, count in tag_counts(items).items() if count > 1)
        checks.append({
            "id": f"duplicate_{kind}_tags",
            "status": "pass" if not duplicates else "fail",
            "detail": "none" if not duplicates else ", ".join(duplicates),
        })

    for inbound in inbounds:
        if inbound.get("port") in REQUIRED_PORTS or inbound.get("tag") in REQUIRED_INBOUND_TAGS:
            status, detail = inbound_listen_status(inbound)
            checks.append({"id": f"loopback_{inbound.get('tag', inbound.get('port'))}", "status": status, "detail": detail})

    missing_rule_tags = []
    missing_out_refs = []
    missing_in_refs = []
    dns_port_rule = False
    tcp443_redirect_rule = False
    catchall_direct = False
    final_block = False

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            checks.append({"id": f"rule_{idx}_type", "status": "fail", "detail": "rule must be object"})
            continue
        if "ruleTag" not in rule:
            missing_rule_tags.append(str(idx))
        out_tag = rule.get("outboundTag")
        if isinstance(out_tag, str) and out_tag not in outbound_tags:
            missing_out_refs.append(f"rule[{idx}] -> {out_tag}")
        inbound_ref = rule.get("inboundTag")
        if isinstance(inbound_ref, list):
            for tag in inbound_ref:
                if tag not in route_source_tags:
                    missing_in_refs.append(f"rule[{idx}] -> {tag}")
        if str(rule.get("port")) == "53":
            dns_port_rule = True
        if str(rule.get("port")) == "443" and rule.get("network") == "tcp" and isinstance(out_tag, str) and out_tag.startswith("redirect-out"):
            tcp443_redirect_rule = True
        if rule.get("outboundTag") == "direct" and has_catchall_ip(rule):
            catchall_direct = True
        if has_final_block(rule):
            final_block = True

    checks.append({
        "id": "rule_tags",
        "status": "pass" if not missing_rule_tags else "warn",
        "detail": "all rules tagged" if not missing_rule_tags else f"missing ruleTag at indexes: {', '.join(missing_rule_tags)}",
    })
    checks.append({
        "id": "route_outbound_references",
        "status": "pass" if not missing_out_refs else "fail",
        "detail": "all route outboundTag values exist" if not missing_out_refs else "; ".join(missing_out_refs),
    })
    checks.append({
        "id": "route_inbound_references",
        "status": "pass" if not missing_in_refs else "fail",
        "detail": "all route inboundTag values exist as inbound or DNS server tags" if not missing_in_refs else "; ".join(missing_in_refs),
    })
    checks.append({"id": "dns_port_53_rule", "status": "pass" if dns_port_rule else "warn", "detail": "port 53 rule present" if dns_port_rule else "no explicit port 53 rule found"})
    checks.append({"id": "tcp443_redirect_rule", "status": "pass" if tcp443_redirect_rule else "warn", "detail": "TCP/443 redirect rule present" if tcp443_redirect_rule else "no TCP/443 redirect rule found"})
    checks.append({"id": "direct_global_catchall", "status": "pass" if catchall_direct else "warn", "detail": "direct 0.0.0.0/0 and ::/0 catch-all present" if catchall_direct else "no direct global catch-all found"})
    checks.append({"id": "final_block", "status": "pass" if final_block else "warn", "detail": "final block port 0-65535 present" if final_block else "no final block rule found"})

    if isinstance(dns, dict):
        servers = dns.get("servers", [])
        checks.append({"id": "dns_servers", "status": "pass" if isinstance(servers, list) and servers else "warn", "detail": f"{len(servers) if isinstance(servers, list) else 0} DNS servers configured"})
        checks.append({"id": "dns_server_tags", "status": "pass" if dns_server_tags else "info", "detail": ", ".join(sorted(dns_server_tags)) if dns_server_tags else "no tagged DNS servers"})
        checks.append({"id": "dns_serve_stale", "status": "pass" if dns.get("serveStale") is True else "info", "detail": f"serveStale={dns.get('serveStale')!r}"})
        has_fakedns = any(isinstance(s, dict) and s.get("address") == "fakedns" for s in servers) if isinstance(servers, list) else False
        checks.append({"id": "dns_fakedns", "status": "pass" if has_fakedns else "info", "detail": "FakeDNS configured" if has_fakedns else "FakeDNS not configured"})
    else:
        checks.append({"id": "dns_config", "status": "warn", "detail": "no dns object found"})

    return checks


def summarize(checks: List[Dict[str, str]]) -> str:
    statuses = {c.get("status") for c in checks}
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MITM-DomainFronting Xray config structure")
    parser.add_argument("config", type=Path)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    config, checks = load_json(args.config)
    if config is not None:
        checks.extend(validate_config(config))
    report = {"overall": summarize(checks), "config": str(args.config), "checks": checks}
    output = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_out:
        args.json_out.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 2 if report["overall"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
