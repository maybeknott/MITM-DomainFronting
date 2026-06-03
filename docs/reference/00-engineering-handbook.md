# Engineering Handbook — Documentation Index

## Purpose

Single entry point for architecture, policy, delivery, evasion engineering, and
operational documentation for MITM-DomainFronting.

**Maintainers edit Markdown directly** under `docs/reference/` and `docs/`. There is
no doc generator.

## Documentation standards

| Rule | Detail |
|---|---|
| **Self-contained** | Each doc opens with Purpose; states scope and exclusions |
| **Concrete commands** | Copy-pasteable paths from repository root |
| **Single source of truth** | Policy in `docs/reference/02-*.md`; procedures in `docs/*.md` |
| **Name the live owner** | State whether **Xray**, **Python**, or **Rust (validation)** owns behavior |
| **Minimal cross-refs** | One link to the canonical doc per topic |

## Bounded tiered rigor (RFC 2119)

Normative language in `docs/reference/` uses [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keywords.
Every **MUST** / **MUST NOT** is tagged with an implementation **tier** and, where applicable, a
threat traceability ID from [THREAT_MODEL.md](../../THREAT_MODEL.md) § Traceability IDs.

| Tier | Keywords | Meaning |
|---|---|---|
| **SHIPPED** | MUST, MUST NOT | True in the current baseline; cite path + validation command |
| **POLICY** | MUST, MUST NOT | Architectural boundary (applies now and to future code) |
| **TARGET** | SHALL, SHOULD | Track A/B/C/D roadmap; open item in `03` §4 |
| **REJECTED** | MUST NOT | Forbidden pattern; see `01` §7 and `02` ADR-0007/0008 |

**Traceability tag format:** `[Mitigates: TM-NN — short title]`

### Component boundary matrix

```text
+-----------------------------------------------------------------------------------+
| Layer              | Language / artifact        | Tier     | Live egress?        |
+--------------------+---------------------------+----------+---------------------+
| Live data plane    | xray/xray.exe (Go)        | SHIPPED  | YES — sole path     |
| Control plane      | Python (scripts/, GUI)    | SHIPPED  | NO                  |
| Validation harness | Rust (mitm_stream_core)   | SHIPPED  | NO (lab/CI only)    |
+-----------------------------------------------------------------------------------+
```

**Interaction rules (POLICY):**

- Python **MUST** launch and supervise Xray; it **MUST NOT** terminate or rewrite live TLS bytes.
- Rust **MAY** parse configs and ClientHello fixtures offline; it **MUST NOT** be wired as inline
  production egress (ADR-0007). `[Mitigates: TM-10 — Parallel Rust data plane]`
- Cross-layer integration is **config-and-evidence** (JSON, tests, PCAP), not in-band byte handoff.

**Primary deployment target:** Windows operator UX (GUI + ProcessSupervisor). Linux and Android
use the same Xray config model; platform-specific containment is **TARGET** Track D — see
`01` §2.7.

### Subsystem ownership (paths)

| Domain | Paths | Tier | Live egress? |
|---|---|---|---|
| Live data plane | `xray/`, `Xray-config/*.json`, `providers/*.yml` | SHIPPED | Yes — sole path |
| Control plane | `main.py`, `bootstrap.py`, `scripts/gui.py`, `scripts/build_config.py`, `scripts/core/process_supervisor.py` | SHIPPED | No |
| Validation harness | `src/`, `Cargo.toml`, `tests/python/rust_core_tests.py` | SHIPPED | No (CI / lab) |

**Rust harness note (POLICY):** `mitm_stream_core` and `src/main.rs` use synchronous
`std::thread` accept loops for the **optional** loopback lab binary — not a Tokio production
data plane. Do **not** document Tokio `spawn_blocking` budgets or volatile `cert_cache.rs`
zeroization as **SHIPPED**; key material today is `Xray-config/mycert.key` on disk (see `03`
CERT-005, Track D DPAPI).

**Telemetry (POLICY / TARGET):** `scripts/core/failure_classifier.py` is in-memory only
(SHIPPED). GUI activity history writes `.local-state/gui-telemetry.jsonl` (SHIPPED behavior;
TARGET OPSEC RAM mode — `03` §5, T-02).

## 0. Terminology (read first)

This handbook spells out acronyms on first use in each document; this section is the
authoritative glossary.

| Term | Expansion | Meaning in this repository |
|---|---|---|
| **ADR** | Architecture Decision Record | Numbered policy decision (0001–0010) in `02-decisions-evasion-engineering.md` Part I |
| **A-ION** | Asymmetric overlay integration (external consumer name) | Downstream system that consumes named Xray profiles and version-locked config bundles |
| **ALPN** | Application-Layer Protocol Negotiation | TLS extension selecting HTTP/1.1 vs HTTP/2; modeled in Rust, emitted by Xray |
| **CA** | Certificate Authority | Local MITM root generated as `mycert.crt` / `mycert.key` under `Xray-config/` |
| **CDP** | Chrome DevTools Protocol | WebSocket API to control Chromium; preferred ephemeral-trust path (Track D) |
| **CDN** | Content Delivery Network | Front domain provider (Cloudflare, Fastly, Google, Meta routes in config) |
| **DPI** | Deep Packet Inspection | Middlebox that inspects TLS ClientHello / SNI / JA3 fingerprints |
| **DPAPI** | Data Protection API (Windows) | OS API to encrypt `mycert.key` at rest (Track D, not shipped) |
| **eBPF** | extended Berkeley Packet Filter | Kernel bytecode for XDP packet programs (Track D optional, not in Rust crate today) |
| **ECH** | Encrypted Client Hello | TLS extension encrypting ClientHello; compatibility matrix item |
| **EDR** | Endpoint Detection and Response | Host security product that flags hooking / covert cert patching |
| **ETW** | Event Tracing for Windows | OS facility that logs process creation (ProcessSupervisor spawn visibility) |
| **GUI** | Graphical User Interface | `scripts/gui.py` Control Center |
| **H2** | HTTP/2 | Multiplexed HTTP version; SETTINGS order modeled in `h2_coalescing.rs` |
| **IoC** | Indicator of Compromise | Forensic artifact (e.g. machine-wide CA in CryptoAPI store) |
| **JA3** | TLS client fingerprint hash | MD5 of ClientHello fields; parsed offline in `ja3.rs`, emitted live by Xray uTLS |
| **Job Object** | Windows process group | Kernel object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (0x2000) in ProcessSupervisor |
| **MITM** | Man-in-the-Middle | Local TLS termination on `tls-decrypt-*` inbounds, re-encryption on repack outbounds |
| **NAT64** | IPv6↔IPv4 translation | Mobile network path that can change routing behavior |
| **NSS** | Network Security Services | Firefox crypto stack storing trust in profile `cert9.db` |
| **OPSEC** | Operational Security | Minimizing local forensic surface (telemetry caps, profile-scoped trust) |
| **PCAP** | Packet capture | Wireshark/tcpdump capture for JA3 / fragment validation |
| **REALITY** | Xray TLS camouflage transport | VLESS + REALITY settings masquerading as a real site (Track A) |
| **RFC 2544** | Benchmark address space | `198.18.0.0/15` used by FakeDNS trap design (Track D) |
| **SNI** | Server Name Indication | TLS extension carrying hostname; camouflage `serverName` on repack outbounds |
| **SOCKS5** | Socket proxy protocol | What Xray mixed-in port 10808 speaks to browsers |
| **STUN** | Session Traversal Utilities for NAT | WebRTC UDP/3478 leak class when only HTTP proxy is set |
| **TUN** | Network tunnel interface | OS virtual NIC capturing all IP traffic (High Stealth Track D) |
| **uTLS** | Universal TLS (Go library) | Xray fingerprint mimicry via `tlsSettings.fingerprint` |
| **WFP** | Windows Filtering Platform | Host firewall API for fail-closed egress rules (Track D) |
| **XDP** | eXpress Data Path | Early kernel hook for packet drop/shaping before TCP stack (Track D) |
| **Xray-core** | Go proxy runtime | Sole live data plane binary (`xray/xray.exe`) |

### Delivery track names

| Track | Full name | Priority |
|---|---|---|
| **Track A** | Xray-native evasion profiles | P0 — REALITY, TLS record fragment, JA3 pool artifacts |
| **Track B** | Strategy and probe automation | P1 — `strategy_engine.py`, classifier labels, profile hot-swap |
| **Track C** | Operator user experience | P1–P2 — GUI honesty, preflight, OPSEC mode toggles |
| **Track D** | High Stealth containment | P2 — TUN, firewall, FakeDNS, CDP trust, DPAPI, optional eBPF |

## Read order

| # | Document | Use when |
|---|---|---|
| 1 | [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md) | Runtime graph, components, workflow, Tracks A–D task breakdown, completed work, out-of-scope |
| 2 | [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md) | Architecture Decision Records 0001–0010, evasion map, survivability specs, JSON targets, governance checklist |
| 3 | [03-issues-risks-validation.md](03-issues-risks-validation.md) | Known issues, risk register, verification gates, assumptions |

## Topic → document map

| Topic | Section |
|---|---|
| Xray vs Rust boundary | 01 §2, 02 ADR-0001/0007/0008 |
| ProcessSupervisor / fail-closed | 01 §3, 02 ADR-0003 |
| Trust / CA / CDP | 02 ADR-0002, Part III §1 |
| JA3 / uTLS pools | 02 ADR-0004, Part III §3 |
| TUN / XDP / FakeDNS 198.18 | 02 ADR-0003, Part III §2 |
| REALITY / fragment profiles | 01 Track A, doc 02 Part III §4 |
| Implementation checklist | doc 02 Part III §5 |
| Strategy engine | 01 Track B |
| GUI / progressive disclosure | 01 Track C, ADR-0006 |
| Assumptions / unknowns | 03 §5 |
| Layer verification | doc 02 Part III §8 |
| Bounded rigor / RFC 2119 | 00 § Bounded tiered rigor |
| FMEA / CI stages | 03 §2.1, §3.0 |
| Threat traceability (TM-*) | [THREAT_MODEL.md](../../THREAT_MODEL.md) § Traceability IDs |

## Operational guides (day-to-day)

Certificate, DNS, protocol, platform, release, and GUI guides live under `docs/`.
Each guide opens with **Purpose** and ends with **Related documents** where helpful.

| Area | Path | Summary |
|---|---|---|
| **Handbook index** | [00-engineering-handbook.md](00-engineering-handbook.md) | This file — glossary, read order, validation commands |
| **Maintainer map** | [maintainer-map.md](maintainer-map.md) | Code ownership and which test guards each area |
| **Repository layout** | [../repository-structure.md](../repository-structure.md) | Directory contract and where artifacts belong |
| **Threat model** | [../../THREAT_MODEL.md](../../THREAT_MODEL.md) | Adversary assumptions and trust boundaries |
| **SNI camouflage** | [../sni-camouflage.md](../sni-camouflage.md) | Camouflage `serverName` wire format on repack outbounds |
| **Chromium / browsers** | [../chromium-integration.md](../chromium-integration.md) | Diagnostics vs stealth paths, profile-scoped trust |
| **CA lifecycle** | [../ca-install-guide.md](../ca-install-guide.md), [../ca-remove-guide.md](../ca-remove-guide.md), [../ca-verify-guide.md](../ca-verify-guide.md) | Install, remove, verify local MITM CA |
| **Certificate ops** | [../certificate-lifecycle.md](../certificate-lifecycle.md) | Rotation, expiry, compromise recovery |
| **DNS** | [../dns-resilience.md](../dns-resilience.md), [../dns-profiles.md](../dns-profiles.md), [../fakedns-recovery.md](../fakedns-recovery.md) | Resolver profiles and FakeDNS cache recovery |
| **Routing** | [../routing-correctness.md](../routing-correctness.md) | Loopback deadlock rules and route invariants |
| **Protocols** | [../protocol-coverage.md](../protocol-coverage.md), [../transport-profiles.md](../transport-profiles.md) | QUIC, WebRTC, ALPN coverage limits |
| **Providers** | [../provider-status.md](../provider-status.md) | CDN drift register and evidence levels |
| **TUN / High Stealth** | [../tun-operational-notes.md](../tun-operational-notes.md) | TUN inbound, firewall fail-closed checklist |
| **GUI** | [../gui.md](../gui.md) | Control Center screens and workflows |
| **Preflight / diagnostics** | [../preflight-and-diagnostics.md](../preflight-and-diagnostics.md) | Preflight gates and probe commands |
| **Local telemetry** | [../local-telemetry.md](../local-telemetry.md) | GUI activity history scope and OPSEC |
| **Rust validation crate** | [../rust-stream-core-baseline.md](../rust-stream-core-baseline.md) | What `mitm_stream_core` is and is not |
| **Release** | [../release-engineering.md](../release-engineering.md), [../release-evidence.md](../release-evidence.md), [../lab-evidence-checklist.md](../lab-evidence-checklist.md), [../final-verdict-template.md](../final-verdict-template.md), [../evidence-map.md](../evidence-map.md) | Build, sign, evidence hashes, lab scenarios |
| **Platform guides** | [../windows-guide.md](../windows-guide.md), [../linux-guide.md](../linux-guide.md), [../macos-guide.md](../macos-guide.md), [../android-guide.md](../android-guide.md), [../android-trust-model.md](../android-trust-model.md), [../platform-compatibility.md](../platform-compatibility.md), [../uninstall.md](../uninstall.md) | OS-specific operator steps and compatibility matrix |
| **Governance / review** | [../reviewer-checklist.md](../reviewer-checklist.md), [../transport-extension-governance.md](../transport-extension-governance.md), [../listener-binding.md](../listener-binding.md), [../firewall-and-network-testing.md](../firewall-and-network-testing.md) | Review gates, transport experiments, binding safety |
| **Strategy / profiles** | [../decision-engine.md](../decision-engine.md), [../operating-profiles.md](../operating-profiles.md), [../relay-and-metrics-policy.md](../relay-and-metrics-policy.md), [../transport-profiles.md](../transport-profiles.md) | Decision reports, relay/metrics policy |
| **Farsi quick start** | [../fa/quick-start.md](../fa/quick-start.md) | Persian-language operator intro |
| **Generated artifacts** | [generated-files.md](generated-files.md) | Which outputs are committed vs gitignored |

## Validation commands

```bash
py -3 main.py test
py -3 tests/python/repository_structure_tests.py
py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts/core/sni_camouflage.py Xray-config/MITM-DomainFronting.json
cargo test --locked
```
