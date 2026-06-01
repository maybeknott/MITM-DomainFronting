# Lab Evidence Checklist

Use this when collecting **real-environment** evidence beyond static CI validation.

## Automated local bundle

```bash
python scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
```

This runs DNS harness scenarios (including `fake-dns-lab` and `captive-portal`) plus `fakedns_recovery_check.py`. Review and redact before attaching to issues or release evidence.

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

## Maintainer release attach list

- [ ] `lab-evidence.bundle.json` from target platform
- [ ] `validation-report.json` from clean commit
- [ ] `release-geodata-lock.json` after `geodata_pin.py --write-lock`
- [ ] Browser smoke output when claiming browser support
- [ ] Provider dossier `last_tested` updated for changed routes

## Not automated here

- Certificate pinning inside independent Android apps
- Provider CDN drift in every region
- Long-running QUIC leakage under mixed network conditions

Record those manually in issue templates or [`release-evidence.md`](release-evidence.md).
