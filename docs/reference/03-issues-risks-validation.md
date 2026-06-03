# Issues, Risks & Validation

## Purpose

Operational known issues, prioritized risks, open engineering gaps, assumptions,
unknowns, and verification gates for MITM-DomainFronting.

**Terminology:** [00-engineering-handbook.md](00-engineering-handbook.md) §0.  
**Delivery tracks:** [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md) §4.  
**Policy:** [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md).

## Document map

| Section | Contents |
|---|---|
| **§1** | Known issues (CERT, DNS, PROTO, PROV, OPSEC) with diagnostics |
| **§2** | Risk register |
| **§3** | Verification gates and lab checks |
| **§4** | Open engineering items |
| **§5** | Assumptions and unknowns |
| **§6** | Reviewer gates |

---

## 1. Operational known issues

Each row is actionable. **Track** maps to delivery tracks in doc `01` §4.

### 1.1 Certificate and trust

| ID | Symptom | Likely cause | Diagnostic steps | Workaround | Track |
|---|---|---|---|---|---|
| CERT-001 | Browser shows privacy / certificate error | Local CA not installed, wrong CA, or hostname mismatch | `py -3 scripts/mitm_trust.py status --json`; compare SHA-256 to `mycert.crt` | Reinstall per `docs/ca-install-guide.md`; confirm proxy `127.0.0.1:10808` | — |
| CERT-002 | Worked previously, fails after days/weeks | MITM certificate expired or rotated | Check `notAfter` on `Xray-config/mycert.crt` | Run certificate generator; reinstall trust | — |
| CERT-003 | Browser works; native app fails | App uses certificate pinning or ignores user trust store | Compare browser vs app for same URL | Mark app unsupported | — |
| CERT-004 | System trust store shows project CA | Operator used OS-wide install | `Get-ChildItem Cert:\LocalMachine\Root\` | `docs/ca-remove-guide.md`; prefer profile-scoped trust | D |
| CERT-005 | `mycert.key` readable on disk | DPAPI wrap not implemented | Inspect ACL on `Xray-config/mycert.key` | Restrict ACL; Track D key wrap | D |

### 1.2 DNS

| ID | Symptom | Likely cause | Diagnostic steps | Workaround | Track |
|---|---|---|---|---|---|
| DNS-001 | Lookup times out | Resolver slow/unreachable; missing fallback | `py -3 scripts/check_dns.py` | Enable fallback in `configs/dns-profiles.yml` | — |
| DNS-002 | Internet broken after stopping Xray | FakeDNS stale mappings | `docs/fakedns-recovery.md` | Flush caches before reporting bug | D |
| DNS-003 | Internal LAN hostnames fail | Split-horizon DNS | Compare system vs Xray resolver | Route private domains locally | — |
| DNS-004 | App connects by raw IP, bypasses proxy | No FakeDNS trap | tcpdump during app use | High Stealth + `198.18.0.0/15` FakeDNS | D |

### 1.3 Protocols

| ID | Symptom | Likely cause | Diagnostic steps | Workaround | Track |
|---|---|---|---|---|---|
| PROTO-001 | HTML loads; video/WebRTC fails | QUIC or media CDN not via Xray | `docs/protocol-coverage.md` | Route rules; document QUIC limits | B |
| PROTO-002 | Chromium works; Firefox fails | Firefox trust or proxy differs | Import CA; verify proxy | `docs/ca-install-guide.md` Firefox section | — |
| PROTO-003 | Mobile differs from Wi‑Fi | IPv6, NAT64, carrier DNS | Record ISP, APN, IPv6 | Add network context to probe | B |
| PROTO-004 | WebRTC leak shows public IP | STUN UDP/3478 bypasses SOCKS | Leak test + `tcpdump udp port 3478` | High Stealth TUN + firewall | D/B |
| PROTO-005 | DPI flags static TLS fingerprint | Single `fingerprint: chrome` on repack | PCAP; `tshark … tls.handshake.ja3_hash` | JA3 template pools + strategy (A/B) | A/B |

### 1.4 CDN / providers

| ID | Symptom | Likely cause | Diagnostic steps | Workaround | Track |
|---|---|---|---|---|---|
| PROV-001 | One provider front stops working | CDN policy, SNI block, IP drift | `docs/provider-status.md` | Update provider YAML; rebuild config | — |
| PROV-002 | Failure limited to one ISP/region | GeoDNS or regional block | Traceroute, DNS from failing network | Alternate outbound tag; document in provider status | B |

### 1.5 OPSEC

| ID | Symptom | Likely cause | Diagnostic steps | Workaround | Track |
|---|---|---|---|---|---|
| OPSEC-001 | Activity history on disk | GUI writes `.local-state/gui-telemetry.jsonl` | Monitor file size | Clear Activity; Track D OPSEC cap | D |
| OPSEC-002 | ETW shows Xray process tree | ProcessSupervisor spawn chain | Sysmon during Start Core | Default tradeoff; see threat model | D |
| OPSEC-003 | UI implies measured JA3 without oracle | Oracle URL not configured (ADR-0004) | Check probe output | Separate "configured" vs "measured" | C |

---

## 2. Risk register

| Priority | Risk | Mitigation track | Validation |
|---|---|---|---|
| P1 | Static TLS / JA3 fingerprint | A + B: REALITY, fragment, template pools | PCAP JA3 series across sessions |
| P1 | Plaintext `mycert.key` | D: DPAPI / keychain | ACL check; secret scan in CI |
| P1 | Proxy / WebRTC / DNS leaks | D TUN + firewall; B probe labels | STUN checklist; `tcpdump udp 3478` |
| P2 | Host forensic artifacts | D OPSEC mode (cap, clear-on-exit) | File monitor during GUI session |
| P2 | Xray schema drift on upgrade | Version-lock in doc `01` §6 | `build_config.py --check-runtime-sync` |
| P3 | Xray supply chain | `verify_release_artifact.py`, pinned releases | Release checklist |

---

## 3. Verification gates

### 3.1 Repository health

```bash
py -3 main.py test
py -3 tests/python/repository_structure_tests.py
py -3 tests/python/sni_camouflage_tests.py
py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts/core/sni_camouflage.py Xray-config/MITM-DomainFronting.json
cargo test --locked
cargo fmt --check
cargo clippy --locked -- -D warnings
```

### 3.2 Engineering checklists

Implementation checklist: [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md) Part III §5.

Layer verification (data / control / protocol): Part III §8.

### 3.3 High Stealth lab gates (Track D)

| Gate | Method |
|---|---|
| No system CA in profile-scoped mode | `Get-ChildItem Cert:\LocalMachine\Root\` |
| No WebRTC STUN leak | Browser leak test + `tcpdump udp port 3478` |
| JA3 rotation across sessions | `tshark -r capture.pcap -T fields -e tls.handshake.ja3_hash` |
| TLS record fragmentation | Wireshark: ClientHello in multiple records |
| Fail-closed on supervisor exit | Kill GUI; confirm `xray.exe` gone; connectivity fails |

---

## 4. Open engineering items

| Item | Status | Notes |
|---|---|---|
| Xray binary verification | Closed | `scripts/verify_release_artifact.py` |
| CA install path documented | Closed | `scripts/mitm_trust.py`, ADR-0002 |
| DPAPI wrap for `mycert.key` | Open | Track D |
| JA3 oracle in GUI | Open | ADR-0004 |
| REALITY + TLS fragment in config-src | Open | Track A |
| `scripts/core/strategy_engine.py` | Open | Track B |
| OPSEC telemetry mode | Open | Track D |
| Optional eBPF helper | Open | Track D; separate from Rust fixture |

---

## 5. Assumptions and unknowns

### 5.1 Assumptions

| Assumption | Validation |
|---|---|
| User-controlled local operation | README, loopback listeners |
| Per-user `mycert.*` secrets | Certificate lifecycle docs |
| Single primary Xray JSON workflow | `Xray-config/MITM-DomainFronting.json` |
| Browser MITM more reliable than arbitrary apps | Platform trust behavior |
| CDN routing changes externally | `docs/provider-status.md` |
| Xray is sole live data plane | ProcessSupervisor spawns Xray only |
| Rust crate validates only | ADR-0007; empty `Cargo.toml` deps |

### 5.2 Unknowns

| Unknown | Reduce uncertainty |
|---|---|
| Client import UI versions | Record in release notes |
| Xray default bind address | Explicit `listen` + preflight |
| Geosite/GeoIP on user device | Publish hashes in release lock |
| Provider success by ISP/region | Provider status + issue templates |
| HTTP/3 / QUIC per browser | `docs/protocol-coverage.md` |
| ECH support | Compatibility matrix |
| App certificate pinning | Compatibility labels |
| Captive portal interference | `docs/firewall-and-network-testing.md` |
| FakeDNS stale cache frequency | `docs/fakedns-recovery.md` |
| DPAPI on all Windows SKUs | Track D platform matrix |

---

## 6. Reviewer gates

See [docs/reviewer-checklist.md](../reviewer-checklist.md). Minimum before merge:

- Config JSON valid; tags resolve; no private keys committed
- FakeDNS recovery and DNS fallback documented
- QUIC/WebRTC limits in protocol coverage
- Policy edits in `docs/reference/*.md` only
- `py -3 tests/python/repository_structure_tests.py` passes

---

## 7. Related documents

- [00-engineering-handbook.md](00-engineering-handbook.md)
- [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md)
- [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md)
- [../../THREAT_MODEL.md](../../THREAT_MODEL.md)
