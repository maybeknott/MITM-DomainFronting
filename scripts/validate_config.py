#!/usr/bin/env python3
"""
Validate an Xray JSON config for the MITM-DomainFronting single-config workflow.

This script performs static checks only. It does not run traffic, inspect payloads,
read cookies, or send diagnostics anywhere.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

LOOPBACK_NAMES = {"127.0.0.1", "::1", "localhost"}
REQUIRED_INBOUND_TAGS = {"mixed-in", "tls-decrypt-h11", "tls-decrypt-h211"}
REQUIRED_PORTS = {10808, 11666, 11777}
EXPECTED_RULE_ORDER_BASE = [
    "r010_block_ads",
    "r020_repack_dns_cloudflare",
    "r025_repack_dns_google",
    "r030_dns_port53",
    "r040_direct_private_regional",
    "r100_repack_googlevideo_h11",
    "r110_block_unmatched_h11",
    "r120_repack_google_h2",
    "r130_repack_fastly_h2",
    "r140_repack_meta_h2",
    "r150_repack_fastly_ip_h2",
    "r160_block_unmatched_h2",
    "r200_redirect_googlevideo_tcp443_h11",
    "r210_redirect_group_tcp443_h2",
    "r300_block_static_bad_ranges",
    "r310_direct_private_regional_ip",
    "r320_redirect_fastly_ip_tcp443_h2",
    "r900_direct_global_catchall",
    "r999_block_final",
]
EXPECTED_RULE_ORDER_WITH_DIRECT_UDP = [
    *EXPECTED_RULE_ORDER_BASE[:5],
    "r050_direct_quic_udp443",
    *EXPECTED_RULE_ORDER_BASE[5:],
]
EXPECTED_RULE_ORDER_WITH_BLOCK_UDP = [
    *EXPECTED_RULE_ORDER_BASE[:5],
    "r050_block_quic_udp443",
    *EXPECTED_RULE_ORDER_BASE[5:],
]
EXPECTED_RULE_ORDER_STRICT = [
    *EXPECTED_RULE_ORDER_BASE[:5],
    "r050_block_quic_udp443",
    *EXPECTED_RULE_ORDER_BASE[5:-2],
    "r900_block_global_catchall",
    "r999_block_final",
]
KNOWN_STATIC_CIDRS = {"10.10.34.0/24", "2001:4188:2:600::/64"}
GLOBAL_CATCHALL_CIDRS = {"0.0.0.0/0", "::/0"}
RULE_TAG_RE = re.compile(r"^r\d{3}_[a-z0-9_]+$")


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


def infer_profile(config: Dict[str, Any]) -> str:
    remarks = str(config.get("remarks", "")).lower()
    for profile in ("strict", "balanced", "compatibility", "debug"):
        if remarks.endswith("_" + profile) or profile in remarks.split("_"):
            return profile
    return "base"


def tag_to_port(items: List[Dict[str, Any]]) -> Dict[str, int]:
    ports: Dict[str, int] = {}
    for item in items:
        tag = item.get("tag")
        port = item.get("port")
        if isinstance(tag, str) and isinstance(port, int):
            ports[tag] = port
    return ports


def parse_loopback_redirect(value: Any) -> Tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    if ":" not in value:
        return None
    host, port_text = value.rsplit(":", 1)
    if host not in LOOPBACK_NAMES:
        return None
    try:
        return host, int(port_text)
    except ValueError:
        return None


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
    profile = infer_profile(config)
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
    inbound_ports_by_tag = tag_to_port(inbounds)
    redirect_targets: Dict[str, int] = {}
    bad_redirects: List[str] = []
    for outbound in outbounds:
        tag = outbound.get("tag")
        settings = outbound.get("settings")
        redirect = settings.get("redirect") if isinstance(settings, dict) else None
        if not isinstance(tag, str) or not tag.startswith("redirect-out"):
            continue
        parsed = parse_loopback_redirect(redirect)
        if parsed is None:
            bad_redirects.append(f"{tag} -> {redirect!r}")
        else:
            redirect_targets[tag] = parsed[1]
    dns_repack_outbounds = {
        item.get("tag")
        for item in outbounds
        if isinstance(item.get("tag"), str) and str(item.get("tag")).startswith("tls-repack-dns")
    }
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
    required_tag_ports = {
        item.get("tag"): item.get("port")
        for item in inbounds
        if item.get("tag") in REQUIRED_INBOUND_TAGS and isinstance(item.get("port"), int)
    }
    default_ports_present = not missing_ports
    required_tags_have_ports = set(required_tag_ports) == REQUIRED_INBOUND_TAGS
    checks.append({
        "id": "required_ports",
        "status": "pass" if default_ports_present else "warn" if required_tags_have_ports else "fail",
        "detail": "10808, 11666, 11777 present"
        if default_ports_present
        else "required local inbounds use non-default ports: " + ", ".join(f"{tag}={port}" for tag, port in sorted(required_tag_ports.items()))
        if required_tags_have_ports
        else f"missing ports: {missing_ports}",
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
    malformed_rule_tags = []
    rule_tags = []
    missing_out_refs = []
    missing_in_refs = []
    redirect_rule_mismatches = []
    unexpected_static_cidrs = []
    dns_port_rule = False
    tcp443_redirect_rule = False
    catchall_direct = False
    catchall_block = False
    udp443_policy = False
    final_block = False

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            checks.append({"id": f"rule_{idx}_type", "status": "fail", "detail": "rule must be object"})
            continue
        rule_tag = rule.get("ruleTag")
        if not isinstance(rule_tag, str) or not rule_tag:
            missing_rule_tags.append(str(idx))
        else:
            rule_tags.append(rule_tag)
            if not RULE_TAG_RE.match(rule_tag):
                malformed_rule_tags.append(f"rule[{idx}] -> {rule_tag}")
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
            expected_inbound = "tls-decrypt-h11" if out_tag == "redirect-out-h11" else "tls-decrypt-h211"
            expected_port = inbound_ports_by_tag.get(expected_inbound)
            redirect_port = redirect_targets.get(out_tag)
            if expected_port is not None and redirect_port != expected_port:
                redirect_rule_mismatches.append(f"rule[{idx}] {out_tag} redirects to {redirect_port}, expected {expected_port}")
        if rule.get("outboundTag") == "direct" and has_catchall_ip(rule):
            catchall_direct = True
        if rule.get("outboundTag") == "block" and has_catchall_ip(rule):
            catchall_block = True
        if str(rule.get("port")) == "443" and rule.get("network") == "udp":
            udp443_policy = True
        if has_final_block(rule):
            final_block = True
        ips = rule.get("ip")
        if isinstance(ips, list):
            literal_cidrs = {
                str(ip)
                for ip in ips
                if "/" in str(ip) and not str(ip).startswith("geoip:") and str(ip) not in GLOBAL_CATCHALL_CIDRS
            }
            if literal_cidrs and rule_tag != "r300_block_static_bad_ranges":
                unexpected_static_cidrs.extend(sorted(literal_cidrs - KNOWN_STATIC_CIDRS))
            elif literal_cidrs:
                unexpected_static_cidrs.extend(sorted(literal_cidrs - KNOWN_STATIC_CIDRS))

    checks.append({
        "id": "rule_tags",
        "status": "pass" if not missing_rule_tags else "warn",
        "detail": "all rules tagged" if not missing_rule_tags else f"missing ruleTag at indexes: {', '.join(missing_rule_tags)}",
    })
    duplicate_rule_tags = sorted(tag for tag, count in tag_counts([{"tag": t} for t in rule_tags]).items() if count > 1)
    checks.append({
        "id": "duplicate_rule_tags",
        "status": "pass" if not duplicate_rule_tags else "fail",
        "detail": "none" if not duplicate_rule_tags else ", ".join(duplicate_rule_tags),
    })
    checks.append({
        "id": "rule_tag_format",
        "status": "pass" if not malformed_rule_tags else "warn",
        "detail": "all ruleTag values match rNNN_name" if not malformed_rule_tags else "; ".join(malformed_rule_tags),
    })
    expected_orders = {
        "base": [EXPECTED_RULE_ORDER_BASE],
        "balanced": [EXPECTED_RULE_ORDER_WITH_DIRECT_UDP],
        "compatibility": [EXPECTED_RULE_ORDER_WITH_DIRECT_UDP],
        "debug": [EXPECTED_RULE_ORDER_WITH_BLOCK_UDP],
        "strict": [EXPECTED_RULE_ORDER_STRICT],
    }
    route_order_ok = rule_tags in expected_orders.get(profile, [EXPECTED_RULE_ORDER_BASE])
    checks.append({
        "id": "route_order",
        "status": "pass" if route_order_ok else "warn",
        "detail": f"route order matches documented {profile} ruleTag order" if route_order_ok else "ruleTag order differs from docs; review routing-correctness.md",
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
    required_dns_server_tags = {"no-filter-dns-cloudflare", "no-filter-dns-google"}
    required_dns_repack_outbounds = {"tls-repack-dns-cloudflare", "tls-repack-dns-google"}
    missing_dns_server_tags = sorted(required_dns_server_tags - dns_server_tags)
    missing_dns_repack_outbounds = sorted(required_dns_repack_outbounds - dns_repack_outbounds)
    checks.append({
        "id": "dns_fallback_server_tags",
        "status": "pass" if not missing_dns_server_tags else "warn",
        "detail": "Cloudflare and Google DNS fallback server tags present" if not missing_dns_server_tags else "missing: " + ", ".join(missing_dns_server_tags),
    })
    checks.append({
        "id": "dns_fallback_outbounds",
        "status": "pass" if not missing_dns_repack_outbounds else "warn",
        "detail": "Cloudflare and Google DNS repack outbounds present" if not missing_dns_repack_outbounds else "missing: " + ", ".join(missing_dns_repack_outbounds),
    })
    checks.append({"id": "dns_port_53_rule", "status": "pass" if dns_port_rule else "warn", "detail": "port 53 rule present" if dns_port_rule else "no explicit port 53 rule found"})
    checks.append({"id": "tcp443_redirect_rule", "status": "pass" if tcp443_redirect_rule else "warn", "detail": "TCP/443 redirect rule present" if tcp443_redirect_rule else "no TCP/443 redirect rule found"})
    checks.append({"id": "redirect_outbounds", "status": "pass" if not bad_redirects else "fail", "detail": "redirect outbounds target loopback ports" if not bad_redirects else "; ".join(bad_redirects)})
    checks.append({"id": "redirect_target_ports", "status": "pass" if not redirect_rule_mismatches else "fail", "detail": "redirect rules target their matching local tunnel ports" if not redirect_rule_mismatches else "; ".join(redirect_rule_mismatches)})
    checks.append({"id": "static_cidr_rationale", "status": "pass" if not unexpected_static_cidrs else "warn", "detail": "only documented static CIDRs are present" if not unexpected_static_cidrs else "review undocumented static CIDRs: " + ", ".join(unexpected_static_cidrs)})
    checks.append({"id": "udp443_policy", "status": "pass" if udp443_policy or profile == "base" else "warn", "detail": "explicit UDP/443 profile policy present" if udp443_policy else "base config has no explicit UDP/443 policy; profile configs should"})
    if profile == "strict":
        checks.append({"id": "strict_global_catchall", "status": "pass" if catchall_block else "fail", "detail": "strict profile blocks global catch-all" if catchall_block else "strict profile must block global catch-all"})
    else:
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
