# Lab Evidence Checklist

## Purpose

Collect real-environment evidence beyond static CI validation: DNS harness scenarios,
FakeDNS recovery, protocol structure probes, and redacted bundles suitable for release
notes or support escalation.

Use this when collecting **real-environment** evidence beyond static CI validation.

## Automated local bundle

```bash
python scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
python scripts/lab_evidence_validate.py lab-evidence.bundle.json
# CI / desktop without full lab network:
python scripts/lab_evidence_run.py --allow-warn --json-out lab-evidence.bundle.json
python scripts/lab_evidence_validate.py --allow-warn lab-evidence.bundle.json
```

This runs:

- DNS harness scenarios (including `fake-dns-lab` and `captive-portal`)
- `fakedns_recovery_check.py`
- Protocol structure probes via `protocol_smoke.py`:
  - `udp443-policy`, `reality-stub`, `fragment-policy`, `fakedns-policy`
  - `tun-stub`, `ttl-spin-policy`, `firewall-checklist`, `evasion-lab-profiles`

Review and redact before attaching to issues or release evidence.

## Scenario matrix

| Scenario | Environment needed | Pass signal |
|---|---|---|
| resolver-timeout | Unreachable primary resolver or lab firewall | Fallback resolver returns answers |
| fallback-order | Multiple resolvers | First success order recorded |
| dns-hijack | Two resolvers with different answers | Suspicious difference flagged |
| fake-dns-lab | Local loopback only | Controlled wrong IP `203.0.113.99` confirmed |
| split-dns | Private hostname + public resolvers | External answers on private name flagged |
| nat64-dns64 | IPv6-only or DNS64 network | `network_classification` not `unknown` |
| captive-portal | Hotel/airport Wi-Fi | HTTP 204 from connectivity check |
| fakedns recovery | Xray stopped after FakeDNS use | Recovery steps documented |
| reality-stub | None (structure probe) | Fragment merges; REALITY stub validates |
| fragment-policy | None (structure probe) | TLS fragment overlay present in merged config |
| tun-stub | None (structure probe) | TUN inbound stub validates |
| firewall-checklist | None (doc probe) | WFP/nftables checklist referenced |
| evasion-lab-profiles | None (merge probe) | Optional lab profiles compile |

## Release attach list

- [ ] `lab-evidence.bundle.json` from target platform
- [ ] `validation-report.json` from clean commit
- [ ] `release-geodata-lock.json` after `geodata_pin.py --write-lock`
- [ ] Browser smoke output when claiming browser support
- [ ] Provider dossier `last_tested` updated for changed routes
- [ ] Optional: PCAP + `tshark` JA3 series when claiming wire-measured evasion (03 §4.1)

## Not automated here

- Certificate pinning inside independent Android apps
- Provider CDN drift in every region
- Long-running QUIC leakage under mixed network conditions
- Suricata/Snort bypass proof under active DPI block (operator lab — 03 §4.1)

Record those manually in issue templates or [`release-evidence.md`](release-evidence.md).

## Related documents

| Document | Topic |
|---|---|
| [`dns-resilience.md`](dns-resilience.md) | DNS harness commands |
| [`release-evidence.md`](release-evidence.md) | Release validation bundle |
| [`fakedns-recovery.md`](fakedns-recovery.md) | FakeDNS recovery procedure |
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Static preflight checks |
| [`reference/03-issues-risks-validation.md`](reference/03-issues-risks-validation.md) | Closure register §4 |
