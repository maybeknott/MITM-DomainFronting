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
| **§2.1** | FMEA (shipped components) |
| **§3** | Verification gates and lab checks |
| **§3.1** | CI pipeline stages |
| **§3.5** | OPSEC telemetry and build artifacts |
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

## 2.1 Failure mode and effects analysis (FMEA)

Formal FMEA for **shipped** subsystems only. Risk Priority Number: **RPN = SEV × LIK × DET**
(severity, likelihood, detection — each 1–10). Targets use **SHALL** in `01` / `02`; open work in §4.

| ID | Component | Failure mode | SEV | LIK | DET | RPN | Tier | Mitigation |
|---|---|---|:---:|:---:|:---:|:---:|---|---|
| F-01 | ProcessSupervisor | Parent exit leaves Xray orphan | 8 | 3 | 2 | 48 | SHIPPED | Job Object (Win); `killpg` (Linux) `[TM-08]` |
| F-02 | GUI telemetry | `.local-state/gui-telemetry.jsonl` IoC | 7 | 6 | 3 | 126 | TARGET | OPSEC RAM mode (C5 / §4); see OPSEC-001 |
| F-03 | Trust / CDP | System-wide CA or stale profile trust | 9 | 4 | 4 | 144 | TARGET | Profile-scoped CDP (D5) `[TM-09]` |
| F-04 | Static JA3 / uTLS | Single fingerprint across sessions | 9 | 6 | 5 | 270 | POLICY | Pool JSON + Xray uTLS (A4–A5) `[TM-06]` |
| F-05 | Route / config | Loop or wrong outbound tag | 8 | 4 | 3 | 96 | SHIPPED | Linter + validate_config `[TM-05]` |
| F-06 | Rust fixture misuse | `ingress_xdp_gateway` wired as live egress | 10 | 2 | 2 | 40 | REJECTED | ADR-0007/0008; code review `[TM-10]` |

**Not in FMEA (TARGET / not shipped):** live eBPF verifier failure, WFP rule drift, DPAPI unwrap —
track under §4 when implemented.

---

## 3. Verification gates

### 3.0 CI pipeline stages (POLICY)

```text
config-src change → Stage 1 Schema → Stage 2 Offline Rust → Stage 3 Lab PCAP (release)
```

| Stage | Command | Proves |
|---|---|---|
| **1 — Schema** | `py -3 scripts/config_src_validate.py --run-steps` | Fragments merge; routes lint `[TM-05]` |
| **1 — Schema** | `py -3 scripts/core/route_rule_linter.py` (via validate chain) | No loop hazards |
| **2 — Offline** | `cargo test --locked` | JA3/ALPN/H2 models; fixture bounds `[TM-06]` |
| **2 — Offline** | `py -3 tests/python/rust_core_tests.py` | Python↔Rust contract |
| **3 — Lab** | `py -3 scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json` | Release evidence bundle |
| **3 — Wire (manual)** | PCAP + `tshark` (below) | Fragment / JA3 on wire `[TM-07]` |

**Aggregate gate:** `py -3 main.py test` runs the repository health subset.

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

**Wire-level examples (lab — adjust capture path):**

```bash
# Distinct JA3 hashes across sessions (when pools enabled)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.ja3_hash | sort -u

# TLS carried across multiple TCP segments when fragment profile active
tshark -r capture.pcap -Y "tls && tcp" -T fields -e frame.number -e ip.len
```

Expected: multiple JA3 values when pool rotation is configured; multi-segment ClientHello when
`streamSettings.sockopt.fragment` is present in the active Xray profile (Track A — TARGET until A3 ships).

### 3.4 Compliance checklist (bounded rigor)

| Check | Tier | Status |
|---|---|---|
| Xray sole live egress documented | POLICY | SHIPPED |
| Route linter before release | POLICY | SHIPPED |
| `cargo test --locked` in CI | POLICY | SHIPPED |
| JA3 pool JSON ↔ offline hash cross-check in CI | SHIPPED | `ja3_pool_validate.py` + `src/ja3.rs` pool test |
| OPSEC RAM telemetry (no jsonl) | SHIPPED | GUI OPSEC toggle (`gui_preferences.py`) |
| WFP / nftables fail-closed docs tested | TARGET | Open — D3 |
| Optional eBPF helper (not Rust fixture) | TARGET | Open — D7 |

### 3.5 OPSEC telemetry and build artifacts (POLICY / TARGET)

| Control | Tier | Requirement |
|---|---|---|
| GUI activity log | SHIPPED | Writes `.local-state/gui-telemetry.jsonl` — see OPSEC-001 |
| OPSEC RAM-only telemetry | TARGET | Operator-toggle; no jsonl append (T-02, C5) |
| failure_classifier | SHIPPED | In-memory only — no default disk log |
| PyInstaller staging dirs | POLICY | `build/`, `dist/`, `build/pyinstaller-runs/` gitignored (T-03) |
| Lab bundle validation | SHIPPED | `py -3 scripts/lab_evidence_validate.py lab-evidence.bundle.json` |

**Validation (lab bundle):**

```bash
py -3 scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
py -3 scripts/lab_evidence_validate.py lab-evidence.bundle.json
```

---

## 4. Open engineering items

| Item | Status | Notes |
|---|---|---|
| Xray binary verification | Closed | `scripts/verify_release_artifact.py` |
| CA install path documented | Closed | `scripts/mitm_trust.py`, ADR-0002 |
| DPAPI wrap for `mycert.key` | Partial | `mitm_trust restrict-key` + `key_at_rest.py` (ACL only; DPAPI reserved) |
| JA3 oracle in GUI | Open | ADR-0004 |
| REALITY + TLS fragment in config-src | Open | Track A |
| `scripts/core/strategy_engine.py` | Partial | Wired to `decision_report.py` via `strategy_profiles.py`; GUI hot-swap open |
| `scripts/core/trust_broker.py` | Partial | Profile-scoped launch + GUI action; CDP cert import open |
| Config fragment merge semantics | Closed | `scripts/config_src_merge.py` + `tests/python/config_src_merge_test.py` |
| OPSEC telemetry mode | Shipped | GUI RAM-only toggle — T-02 |
| Optional eBPF helper | Open | Track D; separate from Rust fixture |
| **T-01** JA3 pool JSON ↔ `ja3.rs` CI cross-check | Shipped | `ja3_pool_validate.py` manifest step |
| **T-02** OPSEC RAM-only GUI telemetry | Shipped | `scripts/gui.py` + `gui_preferences.py` |
| **T-03** Build artifact hygiene in docs | Open | Track C — `build/`, `dist/` excluded |

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
