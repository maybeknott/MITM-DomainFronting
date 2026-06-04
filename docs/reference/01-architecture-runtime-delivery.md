# Architecture, Runtime & Delivery

## Purpose

Engineering reference for repository structure, the production runtime graph (Xray
data plane vs Python control plane vs Rust validation), delivery sequencing, and
anti-censorship track boundaries. Read the handbook glossary first if acronyms are unfamiliar.

Terminology (ADR, DPI, JA3, TUN, etc.): [00-engineering-handbook.md](00-engineering-handbook.md) §0.

---

## 1. Executive summary

| Layer | Runtime role | Ships bytes to internet? |
|---|---|---|
| **Xray-core** (`xray/xray.exe`) | TLS MITM, repack, domain fronting, optional TUN | **Yes** — sole live data plane |
| **Python** (`scripts/`, `main.py`, GUI) | Preflight, config build, probes, ProcessSupervisor | No — control plane only |
| **Rust** (`mitm_stream_core`, `cargo test`) | ClientHello parse, JA3/ALPN/H2 models, regression harness | **No** — validation / offline harness |

Some third-party descriptions of this project show Rust as live NIC-facing egress with
eBPF or uTLS — **that does not match this repository**. Boundaries: doc `02` ADR-0007/0008 and
[03-issues-risks-validation.md](03-issues-risks-validation.md).

---

## 2. Production data path

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  Client (browser / app)                                                  │
│    │ explicit proxy or TUN (Track D)                                     │
│    ▼                                                                     │
│  Xray mixed-in :10808  ──►  tls-decrypt-*  ──►  tls-repack-*            │
│    │                              │                    │                 │
│    │                              │                    └── camouflage SNI │
│    │                              └── local MITM cert (profile / system)  │
│    └──► fronted CDN / REALITY target (Track A)                           │
└─────────────────────────────────────────────────────────────────────────┘

Control plane (parallel, not in hot path):
  main.py / GUI → build_config.py → Xray-config/*.json
               → validate_config.py, probes, failure_classifier (in-memory)
               → ProcessSupervisor → spawns xray.exe only
               → cargo test (CI / dev — optional loopback harness)
```

### 2.1 Config compile pipeline

```text
config-src/          YAML fragments, templates, provider pins
    │
    ▼
scripts/build_config.py
    │
    ├──► Xray-config/MITM-DomainFronting.json   (runtime)
    ├──► configs/profiles.yml                   (GUI / CLI labels)
    └──► sync checks (--check-runtime-sync, --check-profile-sync)
```

### 2.2 GUI path (Windows default)

```text
scripts/gui.py
  → ProcessSupervisor (Job Object 0x2000 kill-on-close)
  → xray/xray.exe -c Xray-config/MITM-DomainFronting.json
  → .local-state/gui-telemetry.jsonl (forensic surface — OPSEC mode planned)
```

### 2.3 Single points of failure (SPOF)

| SPOF | Symptom if broken | Mitigation today | Track |
|---|---|---|---|
| **Trust anchor** (`mycert.crt` / profile trust) | Browser TLS errors; apps with pinning fail closed | `scripts/mitm_trust.py status`; CA guides; explicit install consent | D (CDP profile) |
| **Xray child process** | All proxied traffic stops | `ProcessSupervisor` restart; Job Object kill-on-close | C (supervisor UX) |
| **Generated config** (`Xray-config/*.json`) | Xray refuses start or routes wrong | `build_config.py --check-runtime-sync`; `validate_config.py` | — |
| **Provider front domain** | One CDN path dead; others may work | `providers/*.yml`; `docs/provider-status.md`; strategy failover | B |

During Xray restart windows, browsers may briefly expose default routing (no proxy) unless
High Stealth TUN + firewall fail-closed is enabled (Track D).

### 2.4 Client request lifecycle (production)

```text
[Browser/app]
    |  ClientHello + HTTP(S) over SOCKS/HTTP proxy
    v
[127.0.0.1:10808 mixed-in]  (Xray — live data plane)
    |  route match → tls-decrypt-* inbound
    v
[Local MITM terminate]  (mycert-signed leaf cert)
    |  plaintext HTTP inside process
    v
[tls-repack-* outbound]  (camouflage serverName + uTLS fingerprint)
    v
[CDN edge / REALITY target]  → origin
```

**Control plane (parallel):** `preflight.py` → `build_config.py` → `cargo test` (optional)
→ `ProcessSupervisor` spawns `xray.exe` only. Rust `mitm_stream_core` does **not** sit
inline on this arrow unless the optional loopback harness is run manually for lab work.

### 2.5 Config delivery state machine (SHIPPED)

The path from `config-src/` to a running Xray process **MUST** follow this sequence.
Failure at lint **MUST** block treating the config as release-ready. `[Mitigates: TM-05]`

```text
INIT → LOAD_FRAGMENTS → LINT → MERGE → DISPATCH → RUNNING
         │                │
         │                └── HALT (linter/validator failure — do not ship)
         └── build_config.py reads config-src/
```

| State | Owner | Action |
|---|---|---|
| **INIT** | Operator / CI | Repository checkout; optional `bootstrap.py` |
| **LOAD_FRAGMENTS** | `scripts/build_config.py` | Merge `config-src/` → `Xray-config/MITM-DomainFronting.json` |
| **LINT** | `validate_config.py`, `route_rule_linter.py`, `config_src_validate.py` | Schema, routes, provider targets |
| **MERGE** | `build_config.py` | Profile labels; pool attachment when Track A/B land |
| **DISPATCH** | `ProcessSupervisor` / operator | `xray run -config …` or GUI Start Core |
| **RUNNING** | Xray | Live data plane only |

**Validation (POLICY):**

```bash
py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts/validate_config.py Xray-config/MITM-DomainFronting.json
py -3 scripts/config_src_validate.py --run-steps
```

### 2.6 ProcessSupervisor lifecycle (SHIPPED)

Supervisor states for the Xray child (simplified):

```text
IDLE → SPAWNING → RUNNING → STOPPING → IDLE
```

| Transition | Windows (SHIPPED) | Linux (SHIPPED) |
|---|---|---|
| Spawn | Child assigned to Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (0x2000) | Process group; teardown via `killpg` |
| Stop / parent exit | `TerminateJobObject` + taskkill tree | SIGTERM/SIGKILL to process group |

`[Mitigates: TM-08]`

**Validation:** Start Core from GUI → kill GUI process → confirm `xray.exe` is not listening on
`:10808`.

### 2.7 Platform containment phases

| Phase | Tier | Mechanism | Leak class |
|---|---|---|---|
| **1 — Explicit proxy** | SHIPPED | Browser/app → `127.0.0.1:10808` (Xray mixed-in) | WebRTC, system DNS, QUIC may bypass `[Mitigates: TM-02]` |
| **2 — TUN + host firewall** | TARGET (D) | Xray TUN + WFP (Windows) / nftables (Linux) | Reduces bypass when documented rules applied |
| **2 — Profile trust** | TARGET (D) | CDP / isolated profile; no `LocalMachine\Root` by default | System CA IoC `[Mitigates: TM-09]` |
| **3 — FakeDNS trap** | TARGET (D) | Xray FakeDNS `198.18.0.0/15` | Raw-IP / system resolver bypass `[Mitigates: TM-04]` |
| **4 — Optional eBPF helper** | TARGET (D) | Out-of-tree or Xray-core — **not** Rust fixture loader | Kernel containment lab only |

**Windows note (POLICY):** ETW process-creation visibility from supervisor/browser attach is an
**accepted tradeoff** on the reference platform — not claimed invisible. See `03` OPSEC-002.

**Reject (POLICY):** Promote `src/ingress_xdp_gateway.rs` to live `libbpf` egress — see `01` §7.

### 2.8 Loopback wire ingress (SHIPPED)

Production browsers and apps reach Xray via the **mixed inbound** on loopback:

| Listener | Address | Tier | Notes |
|---|---|---|---|
| Mixed (SOCKS + HTTP) | `127.0.0.1:10808` | SHIPPED | Primary ingress — `config-src/base.json`, `configs/browser-integration.json` |

There is **no** separate `:10809` listener in the shipped primary config. Additional inbounds
are profile-specific generated JSON only.

```text
[Browser / app] --SOCKS/HTTP--> 127.0.0.1:10808 (Xray mixed-in)
                                      |
                                      v
                               tls-decrypt / tls-repack --> CDN front
```

`[Mitigates: TM-01]` — listeners MUST stay loopback unless explicitly documented and consented.

---

## 3. Component inventory

### 3.1 Python control plane

| Module | Path | Responsibility | Production |
|---|---|---|---|
| CLI entry | `main.py` | test, build, probe orchestration | Yes |
| GUI | `scripts/gui.py` | One-button connect, profile picker | Yes |
| Config builder | `scripts/build_config.py` | Fragment merge, profile sync | Yes |
| Validator | `scripts/validate_config.py` | Schema / outbound checks | Yes |
| Supervisor | `scripts/core/process_supervisor.py` | Xray lifecycle, Windows Job Object | Yes |
| SNI inspector | `scripts/core/sni_camouflage.py` | Assert camouflage on repack outbounds | Yes |
| Failure labels | `scripts/core/failure_classifier.py` | In-memory probe taxonomy | Yes |
| Strategy (skeleton) | `scripts/core/strategy_engine.py` | O(1) pool / profile rotation | Track B — wire to build_config open |
| Trust broker (scaffold) | `scripts/core/trust_broker.py` | Profile-scoped Chromium launch; CDP flow open | Track D |
| Preflight | `scripts/core/platform_capability_check.py` | Capability / env checks | Partial |

**Not in tree:** Python does **not** spawn `mitm_stream_core` as a production
forwarder at init.

### 3.2 Rust validation crate (`mitm_stream_core`)

| Module | Purpose | Live egress? |
|---|---|---|
| `parser.rs` | ClientHello field extraction | No |
| `ja3.rs` | JA3 string / hash (parse only) | No |
| `alpn_policy.rs` | ALPN expectation model | No |
| `h2_coalescing.rs` | H2 SETTINGS / coalescing regression | No |
| `tls_orchestrator.rs` | Policy routing model | No |
| `tls_orchestrator_backend.rs` | Backend selection model | No |
| `scheduler.rs` | Circuit / selection with ScoreBreakdown | No |
| `regression_harness.rs` | Order-sensitive TLS/H2 checks | No |
| `ingress_xdp_gateway.rs` | **Mock/fixture** — documents XDP shapes | **No** — not loaded eBPF |
| `ingress_android_tun.rs` | TUN ingress model (harness) | No |

`Cargo.toml`: **`[dependencies]` is empty** — no `libbpf`, `tokio`, `rustls`, uTLS.

### 3.3 Xray runtime

| Artifact | Role |
|---|---|
| `xray/xray.exe` | Pinned binary (see `config-src` / docs) |
| `Xray-config/MITM-DomainFronting.json` | Generated runtime config |
| Outbounds `tls-repack-*` | uTLS fingerprint + camouflage SNI (shipped) |

---

## 4. Delivery tracks — granular task breakdown

Status legend: `[x]` shipped · `[~]` partial · `[ ]` not started · `[—]` rejected wrong site

### Track A — Xray-native evasion (P0)

**Goal:** REALITY, TLS record fragmentation, static JA3 pool attachment via
config — all emitted by Xray uTLS, validated offline by Rust.

| ID | Task | Deliverable | Validate |
|---|---|---|---|
| A1 | [x] Camouflage SNI on all repack outbounds | `scripts/core/sni_camouflage.py` + tests | `py -3 tests/python/sni_camouflage_tests.py` |
| A2 | [~] REALITY outbound profile fragment | `config-src/fragments/reality-outbound-stub.json` | `protocol_smoke.py --scenario reality-stub` |
| A3 | [~] TLS `fragment` block on tlshello | `config-src/fragments/tls-fragment-overlay.json` | `protocol_smoke.py --scenario fragment-policy` |
| A4 | [x] JA3 pool artifact directory | `config-src/templates/ja3-pools/*.json` | `ja3_pool_validate.py` + `cargo test ja3_pool` |
| A5 | [~] build_config attaches pool id to profile | `ja3_pool_validate.py` in manifest | CI green; runtime attach still optional |
| A6 | [~] protocol_smoke REALITY + fragment scenarios | `scripts/protocol_smoke.py` | Config-structure probes (not live handshake) |
| A7 | [ ] Pin Xray schema to version in docs | `docs/reference/01` + config-src header | Manual diff on Xray upgrade |

**Dependencies:** None (blocks Track B pool rotation semantics).

**Reject:** Implementing A3/A7 in `ingress_xdp_gateway.rs` or raw `send()` in Rust.

---

### Track B — Strategy & probe automation (P1)

**Goal:** Session-scoped profile/pool selection, structured probe reports, optional
JSON export — without persistent covert logging.

| ID | Task | Deliverable | Validate |
|---|---|---|---|
| B1 | [x] `strategy_engine.py` skeleton | `scripts/core/strategy_engine.py` | `strategy_engine_test.py` |
| B2 | [x] O(1) pool index `session & (size-1)` | API + docs in 02 §3.3 | `strategy_engine_test.py` |
| B3 | [~] Wire engine to build_config profile names | `strategy_profiles.py` + GUI apply | Profile switch + optional core restart |
| B4 | [x] Probe orchestration CLI | `main.py probe --json-out` | Opt-in file only |
| B5 | [x] failure_classifier labels for WebRTC/DNS leak | `derive_strategy_labels()` | `failure_classifier_tests.py` |
| B6 | [x] decision_report opt-in export | `scripts/decision_report.py` | `--json-out` + strategy block |

**Dependencies:** A4–A5 (pool artifacts).

---

### Track C — GUI / operator UX (P1–P2)

**Goal:** Consent-first profiles, measured-vs-claimed JA3 honesty, preflight surfacing.

| ID | Task | Deliverable | Validate |
|---|---|---|---|
| C1 | [~] Profile picker + connect | `scripts/gui.py` | Manual |
| C2 | [~] Preflight panel (capabilities, Xray pin) | GUI health tab | Run Full Preflight + live pin labels |
| C3 | [x] JA3 display: "expected" vs "measured (oracle URL)" | GUI readiness + `ja3_evidence.py` | No fake "measured" |
| C4 | [~] REALITY / fragment profile labels | `configs/profiles.yml` optional_lab_profiles | `generate_evasion_profiles.py` |
| C5 | [x] OPSEC mode: telemetry cap / clear-on-exit | GUI RAM-only toggle + `gui_preferences.py` | No jsonl append in OPSEC mode |

**Dependencies:** A2–A3 for profile labels.

---

### Track D — High Stealth containment (P2)

**Goal:** TUN fail-closed, FakeDNS 198.18.0.0/15, ephemeral trust, optional eBPF
**outside** validation crate.

| ID | Task | Deliverable | Validate |
|---|---|---|---|
| D1 | [x] ProcessSupervisor kill-on-close | `process_supervisor.py` | Kill GUI → Xray dies |
| D2 | [ ] TUN inbound profile | `config-src/tun-*.yml` | `tun-operational-notes.md` |
| D3 | [ ] Host firewall checklist (WFP / nftables) | `docs/tun-operational-notes.md` | Leak test Xray down |
| D4 | [~] FakeDNS 198.18.0.0/15 | `config-src/fragments/fakedns-19818-trap.json` | `protocol_smoke.py --scenario fakedns-policy` |
| D5 | [~] `trust_broker.py` profile-scoped launch | `scripts/core/trust_broker.py` + GUI | CDP steps documented; auto-import open |
| D6 | [~] DPAPI wrap `mycert.key` | `key_at_rest.py` + `mitm_trust restrict-key` | ACL tighten shipped; DPAPI reserved |
| D7 | [ ] Track D decision record for optional eBPF helper | `track-d/` or new ADR section in 02 | bpftool lab |
| D8 | [ ] TTL spin / ghost segments | Xray-core or eBPF | Suricata lab |
| D9 | [ ] Android TUN harness LeakSanitizer | `ingress_android_tun.rs` tests | CI optional |

**Phasing (mandatory):** explicit proxy (shipped) → TUN + firewall → FakeDNS → eBPF.

**Reject:** Promote `ingress_xdp_gateway.rs` to production `libbpf` loader.

**Appendix — platform containment (Track D, TARGET):**

| OS | Mechanism | Mitigates |
|---|---|---|
| Windows (reference) | Job Object kill-on-close; WFP fail-closed (D3); DPAPI for `mycert.key` (D6); CDP profile trust (D5) | TM-08, TM-09; ETW visibility **accepted** (OPSEC-002) |
| Linux | nftables redirect; network namespace optional; FakeDNS 198.18/15 via Xray (D4) | TM-03, TM-04 |
| Android | VPN/TUN via `VpnService`; model in `ingress_android_tun.rs` (harness) | Non-root app limits — `docs/android-trust-model.md` |

Live kernel shaping **MUST NOT** ship from `ingress_xdp_gateway.rs` (REJECTED-01). Optional
Linux eBPF **SHALL** be an out-of-tree helper or Xray-core change (D7) with consent + new ADR text.

### Track status matrix (bounded rigor)

| Track | Tier | Wire owner | Notes |
|---|---|---|---|
| **A** — Xray profiles (REALITY, fragment, pools) | SHIPPED: camouflage SNI · TARGET: REALITY, fragment, pools | Xray uTLS | See §4 Track A tasks A2–A4 |
| **B** — Strategy / probes | PARTIAL | Python selects → Xray config | `strategy_engine.py` skeleton shipped; build_config wiring open |
| **C** — GUI / UX | SHIPPED partial | Python | Profile picker; OPSEC mode TARGET |
| **D** — Containment | TARGET (D1 SHIPPED) | Xray TUN + OS firewall + optional helper | eBPF **not** Rust fixture |

---

## 5. Completed baseline (reference)

| Area | Evidence |
|---|---|
| Xray-only live path | ADR-0001, GUI supervisor |
| SNI camouflage layer | 5 repack outbounds, 12/12 tests |
| Rust regression harness | H2 SETTINGS order, extension order, scheduler jitter |
| Repository structure pins | `repository_structure_tests.py` |
| ProcessSupervisor without psutil | Source review |
| failure_classifier in-memory only | No `open(..., 'a')` |

---

## 6. Version & sync chain

When bumping Xray-core or downstream asymmetric-overlay consumers (A-ION integration), rev in lockstep:

```text
Xray pin ↔ config-src ↔ build_config.py ↔ Xray-config/*.json
  ↔ validate_config.py ↔ ja3-pools ↔ regression_harness
  ↔ strategy_engine (B) ↔ eBPF schema (D)
```

---

## 7. Out of scope / wrong implementation sites

| Proposal | Why rejected | Accepted alternative |
|---|---|---|
| Rust NIC forwarder | Duplicates Xray; empty deps | Xray outbounds + Rust validate |
| mmap `cert9.db` patch | Covert, fragile | CDP trust broker (D5) |
| LD_PRELOAD / DLL hook | Hostile rewrite | Documented browser flags |
| Persistent classifier logs | Forensic leak | In-memory + opt-in export |
| On-the-fly JA3 shuffle in Rust | Latency + wrong layer | Pre-computed pools (A4) |

Full routing: [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md) ADR-0010.

---

## 8. Related

- Decisions & specs: [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md)
- Issues & validation: [03-issues-risks-validation.md](03-issues-risks-validation.md)
- Index: [00-engineering-handbook.md](00-engineering-handbook.md)
