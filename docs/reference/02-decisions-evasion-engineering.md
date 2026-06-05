# Decisions, Evasion & Engineering Specifications

## Purpose

Canonical policy and implementer depth for Xray-Cooperative-Overlay: Architecture Decision
Records (0001–0010), evasion technique routing (Tracks A/B/D), high-survivability
specifications, and JSON profile targets. Operational how-tos live under `docs/`.

Terminology: [00-engineering-handbook.md](00-engineering-handbook.md) §0.

### Normative tiers (see handbook)

| Topic | Tier | Owner on wire |
|---|---|---|
| TLS MITM, repack, fronting | SHIPPED | Xray |
| uTLS fingerprint emission | SHIPPED / TARGET pools | Xray (`tlsSettings.fingerprint`) |
| JA3 pool artifacts (≤2048) | TARGET (A4) | `config-src/templates/ja3-pools/` → Xray |
| TLS record `fragment` | TARGET (A3) | Xray `streamSettings.sockopt.fragment` |
| Live ClientHello from `ja3.rs` | **REJECTED** | Offline parse/hash only `[TM-10]` |
| Live egress via `ingress_xdp_gateway.rs` | **REJECTED** | Regression fixture only `[TM-10]` |

Traceability IDs: [THREAT_MODEL.md](../../THREAT_MODEL.md) § Traceability IDs.

### Canonical rejected decisions register

| ID | Pattern | Rationale |
|---|---|---|
| **REJECTED-01** | Promote `src/ingress_xdp_gateway.rs` to live egress / `libbpf` loader | Offline fixture only; breaks Windows/Android build matrix `[TM-10]` |
| **REJECTED-02** | Inline Rust SOCKS5 splice or live multiplexing in `mitm_stream_core` | Duplicates Xray; violates ADR-0007 |
| **REJECTED-03** | On-the-fly ClientHello byte shuffling in `ja3.rs` at connect time | Pools belong in `config-src` → Xray uTLS; Rust parses offline only |

### Track A wire template (TARGET — A2/A3)

When REALITY and TLS record `fragment` profiles land in `config-src`, they **SHALL** be
expressed as Xray JSON (emitted by Xray only). Example shape:

```json
"streamSettings": {
  "security": "reality",
  "realitySettings": {
    "show": false,
    "dest": "example.com:443",
    "serverNames": ["example.com"]
  },
  "sockopt": {
    "fragment": { "packets": "1-2", "length": "100-200", "interval": "3-5" }
  }
}
```

**SHIPPED today:** camouflage `serverName` on repack outbounds (`docs/sni-camouflage.md`).
**TARGET:** full block above + JA3 pool attachment (A2–A5). `[Mitigates: TM-06, TM-07]`

---

# Part I - Architecture Decision Register

---

## 0001-xray-as-runtime

# ADR 0001: Xray Is The Runtime Source Of Truth

## Status

Accepted.

## Context

The project contains Python diagnostics, GUI orchestration, generated profiles, and Rust validation experiments. Without a clear boundary, these pieces can look like competing runtimes.

## Decision

Xray remains the actual runtime for proxying, routing, MITM, domain-fronting, and uTLS fingerprint behavior. Python, GUI, config-src, tests, and Rust validate, generate, observe, or assist around Xray.

## Consequences

- Runtime behavior must be proven against generated Xray configs.
- Rust code is validation/experimental unless explicitly promoted later.
- Native Xray-core integration is deferred until a feature is stable enough to justify a Go/Xray-core implementation.


---

## 0002-no-silent-trust-install

# ADR 0002: No Silent Trust-Store Installation

## Status

Accepted.

## Context

The project creates local CA material for browser MITM diagnostics. Installing trust silently would be risky and surprising.

## Decision

The app may generate local certificate files and show instructions, but it must not silently install a CA into Windows, browser, or machine trust stores.

### Accepted evasion evolution (ADR-0010)

- **Profile-scoped trust (preferred for stealth-oriented flows):** broker a
  dedicated browser profile so MITM trust does not require a machine-wide root CA
  when the user chooses that path. Each step requires explicit confirmation
  (ADR-0006).
- **Stealth preference order (Track D):**
  1. **Chromium CDP / isolated user-data-dir** — launch with
     `--user-data-dir` + documented cert import or Playwright/CloakBrowser broker
     (`docs/chromium-integration.md`). Uses the browser's native trust store inside
     the profile; no CryptoAPI/Keychain machine-wide footprint.
  2. **Firefox profile with user-guided `cert9.db`** — user creates or selects a
     dedicated profile; app documents import steps. Trust stays in profile scope.
  3. **OS-wide trust** — optional path via `scripts/mitm_trust.py` and CA guides
     when the user explicitly wants system-wide MITM.
- **At-rest and in-memory key hygiene (Track D):**
  - Wrap `mycert.key` with DPAPI, keychain, or restrictive ACLs on disk.
  - Ephemeral key material in brokers must use **zeroization on drop**
    (`clear_on_drop` / explicit wipe) to reduce cold-boot extraction risk.

### Rejected variants

- **`LD_PRELOAD`, DLL injection, or process hooking** for trust injection — EDR
  heuristics treat these as malware staging; indistinguishable from offensive tooling
  without enterprise allowlisting.
- **Covert SQLite/`cert9.db` byte patching** without user understanding or profile
  isolation — same forensic ambiguity as hooking; use documented profile import instead.
- Silent system-wide CA install (original ADR scope).

## Consequences

- Trust setup remains explicit and user-controlled.
- GUI and CLI should report trust state and recommended next action.
- Any future trust-changing action must require clear confirmation and must explain system impact.
- High Stealth / Get me through flows should prefer profile-scoped trust when
  technically feasible, not weaker stealth for convenience.

## Related decisions

- ADR-0009 — Anti-censorship is first-class; trust UX stays consent-based (ADR-0006).
- ADR-0010 — Adoption routing for trust critiques.


---

## 0003-browser-proxy-first

# ADR 0003: Browser Proxy First

## Status

Accepted.

## Context

The project supports browser diagnostics and optional fingerprint checks. OS-wide proxy or TUN changes are higher-risk and harder to reason about for newcomers.

## Decision

The **default** diagnostic path is an explicit browser proxy against the local Xray
listener. TUN and OS proxy state are detected or documented, not silently changed.

### Accepted evasion evolution (ADR-0010)

- **High Stealth operating intent (named profile):** optional full-device TUN capture
  with documented firewall/nftables rules, FakeDNS via Xray, and **fail-closed**
  behavior when the supervisor tears down the Xray job (kill-on-close). User must
  opt in with clear explanation of scope (ADR-0006).
- **Why TUN beats env-proxy alone:** SOCKS/HTTP proxy settings do not contain
  WebRTC STUN, background telemetry, or raw IP dial-outs. High Stealth routes those
  through the overlay or drops them at the boundary.
- **FakeDNS benchmark range (Track D design):** map resolver traffic to
  **`198.18.0.0/15`** (RFC 2544 benchmark space) inside Xray FakeDNS so raw IP
  attempts without a matching route are trapped and re-injected into the overlay
  rather than leaking to the ISP resolver. Validate against `docs/fakedns-recovery.md`
  exit behavior.
- **Fail-secure kill-switch layers (stacked):**
  1. Today: `ProcessSupervisor` job-object / process-group teardown.
  2. High Stealth: host firewall rules dropping non-TUN egress when Xray is down.
  3. Track D (optional): eBPF/XDP **strict drop** for packets not bearing a
     verifiable session/marking token — implemented in **Xray-core or a consented
     privileged helper**, not by silently loading `ingress_xdp_gateway.rs` as default
     egress (ADR-0008).
- **Leak detection stays active:** WebRTC/DNS/prefetch bypass classes are probed and
  surfaced (`failure_classifier.py`, health probes), not ignored.
- **Kernel packet programs:** live eBPF/XDP belongs in Track D (Xray-core or consented
  helper), not by promoting the Rust mock to default egress.

### Rejected variants

- Mandatory TUN/XDP for all users without consent or platform validation matrix.
- XDP programs that run **after** the host stack has "corrected" non-compliant frames
  — Track D specs require hooking **before** stack normalization where kernel shaping
  is used (see ADR-0008, `02-decisions-evasion-engineering.md` Part IV §5.8).

## Consequences

- Page Check should run before advanced fingerprint checks.
- CloakBrowser is an app-layer fingerprint path, not a routing engine.
- System proxy and TUN states are warnings/context unless the user intentionally configures them.
- Strategy engine (Track B) may select High Stealth when probes show proxy leaks.

## Related decisions

- ADR-0009 — Anti-censorship via profiles + strategy, not silent OS takeover.
- ADR-0010, ADR-0008 — Containment and kernel implementation routing.
- `docs/tun-operational-notes.md` — operational requirements for TUN mode.


---

## 0004-ja3-oracle-honesty

# ADR 0004: JA3 Oracle Required For Measured Fingerprint Claims

## Status

Accepted.

## Context

Xray can be configured with `tlsSettings.fingerprint: "chrome"`, but that is not the same as externally measured JA3 proof.

## Decision

The app may say a TLS fingerprint is configured when the Xray config sets it. It may only claim a measured JA3 match when an external JA3 oracle returns matching evidence.

**"Honesty" governs claims, not whether mimicry is allowed.** Anti-censorship
requires mimicking real browser TLS on the wire via Xray uTLS and profile selection.

### Accepted evasion evolution (ADR-0010)

- **Bounded dynamic mimicry:** per-profile `tlsSettings.fingerprint` (chrome,
  firefox, safari, randomized where Xray supports it); strategy engine picks
  profile from probes (Track B).
- **Pre-computed ClientHello template pools (Track A — mandatory design constraint):**
  - Pools are built **at init/profile-load time**, not per handshake.
  - Each template is sampled from a **validated matrix** of real browser version
    distributions (Chrome/Firefox/Safari cohorts), not unbounded permutations.
  - Runtime selection is **O(1) dispatch** (index into pool → Xray uTLS config switch).
  - On-the-fly GREASE/cipher/extension mutation during connect is **rejected** —
    it adds handshake latency and can emit JA3 hashes no real browser produces.
  - Rust `ja3.rs` + `regression_harness.rs` verify expected hashes offline; Xray
    emits live ClientHellos (ADR-0007).
- **Per-session / per-route selection** is preferred over one static fingerprint
  for all destinations.

### Rejected variants

- Unbounded random GREASE, cipher, or extension shuffling that produces
  non-browser fingerprints.
- Runtime permutation engines that compute ClientHello structure on the active path.
- Asserting JA3 match without oracle measurement.

## Consequences

- Without an oracle URL and expected value, JA3 status remains `not measured`.
- GUI/docs must distinguish configured uTLS behavior from measured TLS fingerprint evidence.
- Browser fingerprint checks and TLS fingerprint checks remain separate concepts.
- `h2_coalescing.rs` and `alpn_policy.rs` continue to model CDN-like behavior in validation.

## Related decisions

- ADR-0009 — Mimicry in Xray; measurement honesty here.
- ADR-0010, ADR-0008 — Where live TLS is emitted (Xray only).


---

## 0005-local-source-labeled-telemetry

# ADR 0005: Local Source-Labeled Telemetry

## Status

Accepted.

## Context

The GUI shows network and activity telemetry. Some telemetry is system-wide while future telemetry may be app- or process-specific.

## Decision

Telemetry must stay local and must label its source, scope, and confidence. System counter telemetry must not be presented as per-Xray telemetry.

### Accepted evasion evolution (ADR-0010)

- **OPSEC telemetry mode (Track D):** shorter retention, optional clear-on-exit,
  no nagging export prompts in that mode; labels remain honest about scope.
- **User-controlled reduction:** **Clear Activity**, manual deletion of
  `.local-state/gui-telemetry.jsonl`, and avoiding export before sharing a machine.
- **Decision reports stay local** (`scripts/decision_report.py`); redaction rules
  unchanged; no remote pipeline.

### Rejected variants

- Silent remote exfiltration of activity history.
- Removing all local diagnostics to chase "anti-forensics" — breaks supportability.

## Consequences

- The right rail can show rates, totals, and running time, but labels must clarify measurement scope.
- Future per-process or Xray-log telemetry should be shown as a distinct source.
- No automatic upload of telemetry is allowed.
- High Stealth / Get me through may default OPSEC telemetry settings when user opts in.

## Related decisions

- ADR-0010 — OPSEC vs supportability balance.
- `docs/local-telemetry.md` — controls and OPSEC note.


---

## 0006-target-user-and-progressive-disclosure

# ADR 0006: Target User And Progressive Disclosure

## Status

Accepted.

## Context

Recurring product feedback asks the project to "reduce end-user complexity" and
repeatedly poses the same unanswered question:

> Are we optimizing for completely non-technical users who just want an On/Off
> switch, or intermediate users who still need control over routing profiles?

That question must be answered explicitly, because it constrains every UX and
distribution decision (preset toggles, auto-setup, error messages, packaging).
Leaving it implicit causes proposals to swing between "hide everything behind one
switch" and "expose every knob", which are contradictory.

The repository already encodes three relevant guardrails:

- ADR-0001: Xray is the runtime source of truth.
- ADR-0002: No silent trust-store installation; the private key stays local.
- ADR-0003: Browser-proxy-first; OS proxy/TUN state is detected, not changed.

A "make it a single On/Off switch that silently trusts a CA and auto-elevates to
admin" direction would violate ADR-0002 and the project's honesty posture, even
though it would feel simpler.

## Decision

The primary user is the **motivated intermediate user**: someone comfortable
running a desktop app and following a short guided flow, who needs the tool to be
safe and legible but does **not** want to hand-edit Xray JSON or memorize CLI
flags.

We optimize for this user via **progressive disclosure**, not via a single
opaque switch:

1. **One dominant next action.** The dashboard always shows the single best next
   step derived from `ProjectState.next_action`. This is the "simple path".
2. **Named intents over raw files.** Operating profiles are surfaced as
   Standard (balanced) / High Stealth (strict) / Legacy Network (compatibility),
   bound to `ProjectState.active_profile` — never as a file picker.
3. **Guided, consent-based setup.** Auto-setup may generate the local CA, run
   preflight, and offer fixes, but trust installation and privilege elevation
   remain explicit, user-approved steps (ADR-0002). "Zero-touch" means
   "zero-guesswork", not "silent system changes".
4. **Plain-language status, evidence on demand.** Failures are shown through the
   failure classifier's friendly summaries; the raw evidence, check IDs, and the
   `verified-session` bundle are available behind an "advanced/details" affordance
   for the operator and maintainer tiers.

We explicitly **defer** the "pure On/Off appliance for fully non-technical users"
product. It would require silent trust handling we have ruled out, and a
different threat-model conversation. It is out of scope unless a future ADR
revisits ADR-0002.

## Consequences

- Preset toggle work (proposal idea #1) targets `active_profile`, with a short
  inline description per intent rather than a configuration dialog.
- Auto-setup work (proposal idea #2) is allowed to *prepare and recommend* but
  must route trust install / admin elevation through an explicit confirmation,
  reusing the existing `RepairAction.requires_admin` / `confirmation_required`
  flags.
- The failure classifier (idea #3) and single-binary distribution (idea #4) are
  already aligned with this user and need no demographic change.
- "Advanced" surfaces (full check list, JA3 oracle fields, evidence bundles,
  release tooling) stay available but are not the default view.
- Large supercomposition rewrites (PyO3 embedding, Cap'n Proto IPC, Tauri/Slint,
  io_uring/eBPF, embedding Rust into Xray) remain out of scope: they raise, not
  lower, complexity and risk for the intermediate user, and conflict with
  ADR-0001/0003.


---

## 0007-rust-core-is-validation-not-data-plane

# ADR 0007: The Rust Core Is A Validation Library, Not A Data Plane

## Status

Accepted.

## Context

The `src/*.rs` tree looks, at a glance, like a live proxy engine: it has an
ingress trait (`ingress.rs`, `ingress_loopback.rs`, `ingress_android_tun.rs`,
`ingress_xdp_gateway.rs`), a `handle_client` accept loop in `main.rs`, a TLS
orchestrator (`tls_orchestrator.rs`), a ClientHello parser (`parser.rs`), JA3
logic (`ja3.rs`), and a scheduler. This naming repeatedly invites proposals to:

- modify `handle_client` to dial upstream over a SOCKS5 handshake to Xray;
- add raw-socket TCP sequence-number injection / SNI-spoofing inside the
  orchestrator;
- load eBPF/XDP programs from `ingress_xdp_gateway.rs` to rewrite live packets;
- treat the Rust binary as the egress data plane with Xray as a sidecar.

These proposals assume the Rust core forwards bytes to the internet. **It does
not.** Establishing the actual boundary as an accepted decision stops this
confusion from recurring and prevents accidental scope creep into a second,
competing runtime (which ADR-0001 already rules out, but only briefly).

What the Rust core actually does today (verified against the source):

- `PolicyAwareTlsBackend` (`tls_orchestrator_backend.rs`) implements ALPN
  negotiation/lock policy and bypass decisions. It contains **no socket dialing**
  and never connects upstream.
- `main.rs` `handle_client` reads a ClientHello off a loopback socket, parses it,
  runs ALPN orchestration *modeling* and an optional JA3 fingerprint check
  (`MITM_STREAM_EXPECTED_JA3`), and reports. It does **not** forward traffic to a
  destination or to Xray.
- The only `TcpStream::connect` in `src/` is the client side of a unit test in
  `ingress_loopback.rs`.
- `ingress_xdp_gateway.rs`, `ingress_android_tun.rs`, `cooperative_overlay.rs`,
  `h2_coalescing.rs`, and `scheduler.rs` are modeled abstractions and regression
  fixtures, not loaded kernel programs or a live scheduler on the egress path.

## Decision

The Rust core is a **validation, parsing, and policy-modeling library plus a
fingerprint check harness**. It is explicitly *not* the runtime data plane and must not
be wired into the live traffic path. Xray is the data plane (ADR-0001).

Concretely:

- The Rust core may parse, classify, score, model, and fingerprint check (e.g. confirm
  that a configured uTLS fingerprint produces the expected JA3). Its outputs are
  evidence and regression signals, not forwarded bytes.
- The Rust core must not open upstream connections, perform SOCKS5 client
  handshakes to Xray, manipulate raw packets, inject TCP segments, or load
  eBPF/XDP. Those belong to Xray (or, if ever justified, to a future Go/Xray-core
  contribution per ADR-0001).
- Integration with Xray is **config-and-evidence**, not in-band byte handoff:
  the toolchain generates and validates Xray config, runs Xray as the runtime,
  and the Rust core validates/observes around it.

## Consequences

- Proposals to add packet injection / SNI-spoofing / sequence-number tricks, or
  to make the Rust binary the egress engine, are out of scope here. They would
  require: (a) a new ADR revisiting ADR-0001, (b) a real threat-model review, and
  (c) the privilege/safety story (`CAP_NET_RAW`, Administrator) that ADR-0002 and
  ADR-0006 deliberately keep consent-based.
- `process_supervisor.py` already provides atomic, kill-on-close lifecycle
  containment (Windows Job Object, POSIX process group). A "run Rust + Xray as
  one machine" conductor can be built on it *without* changing the byte path —
  the Rust process stays a fingerprint check/observer alongside Xray, not an inline hop.
- If a Rust capability is ever promoted to the data plane, it should be
  implemented where the data plane lives (Xray-core in Go), not by turning the
  validation library into a parallel proxy.
- Module names that imply a live data plane (e.g. `ingress_xdp_gateway`) should
  carry doc comments clarifying they are models/fixtures, to reduce future
  confusion.

## Related decisions

- **ADR-0009** — Anti-censorship is first-class; Rust models/scores, Xray executes.
- **ADR-0008** — Packet-level evasion is accepted in Xray/Track D, not as Rust live egress.
- **ADR-0010** — Adversarial critiques routed to accepted implementation paths.
- Legitimate **camouflage SNI** is config on Xray outbounds (`docs/sni-camouflage.md`).


---

## 0008-no-raw-packet-injection-data-plane

# ADR 0008: Packet-Level Evasion In Xray-Core — Not In The Rust Validation Crate

## Status

Accepted (amended: evasion techniques are in scope; **implementation site** is constrained).

## Context

Critiques and blueprints ask for TCP ClientHello splitting, TTL manipulation,
eBPF/XDP rewriting, and inline byte bridges. Those goals are **valid for
anti-censorship** (ADR-0009). The mistake is placing them in `mitm_stream_core` as
a second live egress, which duplicates Xray (ADR-0001) and contradicts ADR-0007.

Today:

- **Accepted on the wire today (partially):** camouflage SNI via
  `tlsSettings.serverName` on repack outbounds (`docs/sni-camouflage.md`).
- **Accepted via config (Track A):** TLS record **fragment**, REALITY, padding/mux,
  multiple uTLS fingerprints in Xray profiles.
- **Accepted via strategy layer (Track B):** probe, classify, score, apply profile.
- **Model only in Rust:** `ingress_xdp_gateway.rs` is a regression fixture, not a
  loaded kernel program.

Fabricated blueprint artifacts (`sni_spoof.rs`, `xray_bridge.rs`, `packetPhysics`,
inline SOCKS5 in `PolicyAwareTlsBackend`) do not exist and must not be invented in
the Rust crate without a new ADR revisiting ADR-0001.

## Decision

### Accepted evasion goals (where to implement)

| Technique | Primary implementation site |
|---|---|
| ClientHello / SNI splitting for DPI | Xray `fragment` (and related stream settings) in named profiles |
| Camouflage SNI / domain fronting | Xray `tlsSettings.serverName`, REALITY `serverName` |
| uTLS / JA3 mimicry | Xray `tlsSettings.fingerprint` + per-profile selection (bounded, not random-invalid) |
| FakeDNS / DNS isolation | Xray DNS + routing (`docs/fakedns-recovery.md`) |
| Fail-closed when control plane dies | `ProcessSupervisor` job-object / process-group teardown (today); optional TUN+firewall in High Stealth profile (ADR-0003) |
| Kernel packet shaping (TTL spin, early segment split) | **Track D:** Xray-core (Go) or optional consented privileged helper — **not** the Rust validation binary as default egress |

### Track D kernel engineering requirements (when pursued)

External offensive-defensive reviews correctly note that **standards-compliant TCP
alone is predictable** under stateful DPI. The following are **accepted goals** with
**implementation in Xray-core or a consented eBPF helper**, not elevation of
`mitm_stream_core` to live egress (ADR-0007 unchanged):

| Primitive | Purpose | Engineering constraint |
|---|---|---|
| Early ClientHello split | Desync naive SNI inspectors | Prefer Xray `fragment` first (Track A); kernel split only if fragment insufficient |
| TTL-limited decoy segments | Exhaust stateful tracker table entries | Fire at wire speed; TTL chosen so decoys die before remote ACK |
| Checksum-valid noise frames | Avoid host stack "helpful" correction | **Hook at XDP/eBPF before stack ingress/egress** — post-stack mutation is rejected |
| Session marking / drop | Fail-secure when overlay down | Packets without overlay mark dropped at XDP; pairs with TUN + firewall (ADR-0003) |

`ingress_xdp_gateway.rs` remains a **regression fixture** for batch-shape modeling.
Live programs require a new ADR, privilege UX, platform matrix, and sync discipline
with pre-computed TLS template pools (pool index must match outbound profile).

### Rejected implementation sites (this repository's Rust crate as live path)

The Rust validation crate will **not** become the default carrier for:

- Raw-socket egress, out-of-window TCP segments, or checksum builders on live traffic.
- Loaded eBPF/XDP programs controlled from `ingress_xdp_gateway.rs` without a new
  ADR, threat-model update, and consent UX.
- Standing `cap_net_raw` / Administrator daemons **without** explicit user approval.
- Inline SOCKS5 or splice bridges that forward user bytes between client and Xray.

Rust continues to **parse, model, score, and regression-test** policies (including
expected JA3 after a profile is chosen). Python probes and selects profiles. Xray
executes bytes.

### Consent and threat model

Any Track D kernel or raw-socket component requires the same bar as a new ADR:
revisit ADR-0001 only if Xray cannot express the primitive, update
`THREAT_MODEL.md`, and document privilege-grant UX (ADR-0006).

## Consequences

- Kernel shaping belongs in **Xray profiles first**, then Xray-core or Track D —
  do not turn `ingress_xdp_gateway.rs` mock into a second Rust data plane.
- ADR-0010 maps each critique to accepted vs rejected **variants**.
- ALPN inference / bypass in `tls_orchestrator_backend.rs` remains; no
  `xray_bridge.rs` duplicate.

## References

- ADR-0001 — Xray as runtime data plane.
- ADR-0007 — Rust validation boundary.
- ADR-0009 — Anti-censorship first-class goal.
- ADR-0010 — Implementation routing for evasion techniques.
- `docs/sni-camouflage.md`, `01-architecture-runtime-delivery.md` §4 Tracks A/B/D.


---

## 0009-anti-censorship-is-a-first-class-goal

# ADR 0009: Anti-Censorship Is A First-Class Goal

## Status

Accepted.

## Context

This project exists to help users operate MITM domain-fronting and related TLS
transports on **networks they control or own**, including environments where
censorship or middleboxes degrade or block those paths. That mission must be
visible in architecture and roadmap, not treated as a side effect of diagnostics.

At the same time, ADR-0001, ADR-0007, and ADR-0008 define **how** strength is
delivered: one Xray data plane, a validation/strategy layer in Python and Rust,
and no raw-packet Rust egress engine. Safety and honesty constraints (ADR-0002,
ADR-0004, ADR-0005, ADR-0006) remain binding; they protect users, not censors.

## Decision

Defeating censorship and restoring usable access on the user's own path is a
**first-class product goal**, on equal footing with safety, honesty, and
maintainability.

We pursue it in two complementary halves, both first-class:

1. **Strong data plane (Xray-core, ADR-0001).** All on-the-wire evasion is
   expressed here: REALITY, uTLS fingerprint mimicry, TLS record fragmentation,
   padding/mux, domain fronting, FakeDNS, flexible routing. New transports belong
   in config profiles and, when upstream lacks them, in Xray-core (Go).

2. **Intelligent strategy layer (this repo).** Probe how the user's network is
   failing, classify the blocking method, score candidate strategies, auto-select
   and fail over, and prove success with redacted evidence (`verified-session`,
   JA3 oracle honesty per ADR-0004). Rust models and regression-tests; Python
   orchestrates; Xray executes.

ADR-0008 explicitly rejects raw injection and inline Rust byte bridges **not**
because evasion is unwanted, but because that approach is weaker, more brittle,
and more privileged than config + strategy.

## Consequences

- `01-architecture-runtime-delivery.md` §4 includes an anti-censorship capability roadmap (Tracks A/B/C):
  evasion profiles, adaptive strategy engine, and consent-gated public UX.
- **Camouflage SNI** (legitimate "SNI spoofing"): front `serverName` in Xray TLS/REALITY
  settings — `docs/sni-camouflage.md`, `scripts/core/sni_camouflage.py`.
- **ADR-0010** adopts technically valid adversarial critiques (fragment, bounded
  mimicry, profile trust, High Stealth TUN, OPSEC telemetry, Track D kernel path)
  while rejecting unsafe variants (silent injection, Rust inline egress).
- `02-decisions-evasion-engineering.md` Part II — quick acceptance routing.
- GUI and CLI should evolve toward plain-language resilience ("finding a way
  through", named strategy) with technical detail behind progressive disclosure
  (ADR-0006).
- Documentation (`01-architecture-runtime-delivery.md`) names the strategy layer beside the
  runtime graph.

## References

- ADR-0001 — Xray as runtime.
- ADR-0006 — Target user and progressive disclosure.
- ADR-0007 — Rust validation boundary.
- ADR-0008 — No raw-packet injection data plane in Rust.
- ADR-0010 — Rejection matrix for hostile ADR rewrites vs Track A/B/C alternatives.
- `01-architecture-runtime-delivery.md` §4 — Tracks A/B/C.
- `02-decisions-evasion-engineering.md` Part II — Quick in-scope / out-of-scope reference.


---

## 0010-rejected-hostile-rewrites-accepted-alternatives

# ADR 0010: Evasion Goals — Implementation Routing

## Status

Accepted (supersedes the earlier "hostile rewrites only" framing).

## Context

High-threat deployments need profile-scoped trust, TUN fail-closed containment,
bounded TLS fingerprint mimicry, ClientHello splitting, optional OPSEC telemetry,
and kernel-level packet shaping where consented.

These goals align with ADR-0009. They must not be implemented in ways that:

- add a second Rust byte-forwarding data plane (ADR-0001, ADR-0007),
- bypass user consent for trust or privilege (ADR-0002, ADR-0006), or
- claim measured JA3 without an oracle (ADR-0004).

This ADR routes each critique to an **accepted implementation path** or a
**rejected variant** (unsafe or architecturally wrong), not a wholesale dismissal
of the underlying technique.

## Decision

Adopt the following routing. "Accepted" means on the roadmap or allowed in
design; it does not mean shipped today unless noted.

| Evasion goal | Accepted implementation in this repo | Rejected variant (do not build) |
|---|---|---|
| **ClientHello / SNI split to defeat naive DPI** | TLS record **fragment** settings in Xray profiles (Track A); camouflage `serverName` (`docs/sni-camouflage.md`) | Raw out-of-window TCP segments and fake RST/TTL spin **inside the Rust validation crate** |
| **Dynamic TLS fingerprint / JA3 mimicry** | Pre-computed template pools (init-time, browser-distribution matrix); per-profile uTLS; strategy selects profile (A/B); Rust models expected hashes | Unbounded GREASE shuffle; **on-the-fly** ClientHello permutation; claiming "measured" without oracle |
| **Trust without broadcasting to whole OS** | Profile-scoped trust: **CDP / isolated Chromium user-data-dir first**, user-guided Firefox profile import second; OS-wide optional (`scripts/mitm_trust.py`) | Silent DLL/`LD_PRELOAD`, covert `cert9.db` patching, or system-wide CA without confirmation |
| **Leak-resistant containment** | Named **High Stealth** intent: optional TUN + documented firewall rules + `ProcessSupervisor` kill-on-close (fail-closed when supervisor dies); WebRTC/DNS leak checks in probes | Mandatory default TUN/XDP loaded from `ingress_xdp_gateway.rs` mock without consent or platform matrix |
| **Stateful DPI disruption (packet layer)** | Same effect via Xray **fragment** + REALITY + mux/padding (Track A); long-term kernel shaping in **Xray-core (Go)** or consented optional helper (Track D) | Inline SOCKS5 splice Rust↔Xray; `cap_net_raw` daemon as default egress in this crate |
| **Adaptive path selection** | Strategy sweep in `path_scorer.py` over named profiles; `failure_classifier.py` labels blocking method; `strategy_engine.py` (Track B) | Rewriting classifiers into raw-socket injection-sweep engines |
| **Reduced local forensic surface** | OPSEC telemetry mode: shorter retention, clear-on-exit, user-initiated export only; existing **Clear Activity** (`docs/local-telemetry.md`) | Removing local diagnostics entirely or silent remote exfiltration |
| **Protect `mycert.key` at rest** | OS keychain / DPAPI / permission-hardening for local key material (Track D) | Committing or uploading keys; shared CA across users |

## Naming: two "SNI spoofing" meanings

- **Accepted:** camouflage `serverName` in Xray (domain fronting / REALITY).
- **Accepted equivalent for DPI split:** TLS record fragmentation in Xray.
- **Rejected in Rust crate:** raw TCP/SNI segment injection (implementation site only).

See `docs/sni-camouflage.md` and ADR-0008.

## Consequences

- Prior ADRs **0002–0005** are amended with accepted evolutions (profile trust,
  High Stealth TUN, bounded mimicry, OPSEC telemetry) — see their "Accepted
  evasion evolution" sections.
- ADR-0008 is narrowed: it rejects the **Rust crate as live packet egress**, not
  the underlying evasion techniques when expressed in Xray or Track D.
- `01-architecture-runtime-delivery.md` §4 Track D captures kernel/key/OPSEC hardening.
- Part II lists accepted vs deferred variants.
- Part III — survivability engineering specifications and checklists.
- [03-issues-risks-validation.md](03-issues-risks-validation.md) — risks and known issues.

## References

- ADR-0001 — Xray as runtime data plane.
- ADR-0002 — Trust (amended).
- ADR-0003 — Browser proxy first (amended).
- ADR-0004 — JA3 honesty (amended).
- ADR-0005 — Local telemetry (amended).
- ADR-0007 — Rust validation boundary.
- ADR-0008 — Where packet-level code may live.
- ADR-0009 — Anti-censorship first-class.
- `01-architecture-runtime-delivery.md` §4 — Tracks A/B/C/D.
- `02-decisions-evasion-engineering.md` Part II.
- `02-decisions-evasion-engineering.md` Part IV.
- `03-issues-risks-validation.md` §1–§3.
- Part III.


---

# Part II - Evasion Technique Map

## Two halves (ADR-0009)

```text
+-----------------------------+     +-----------------------------+
|  Xray data plane (wire)     |     |  Strategy layer (repo)      |
|  REALITY, uTLS, fragment,   |     |  probe → classify → score → |
|  SNI, FakeDNS, routing      |     |  apply profile → fail over  |
+-----------------------------+     +-----------------------------+
         ADR-0001                              ADR-0007 (validate)
```

No inline Rust byte hop (ADR-0008). Packet-level goals are **accepted** when
implemented in Xray profiles or Track D — not in the validation crate as egress.

## Shipped or accepted today

| Technique | Mechanism | Where |
|---|---|---|
| Domain fronting / camouflage SNI | `tlsSettings.serverName` | `docs/sni-camouflage.md`, primary Xray config |
| uTLS fingerprint (configured) | `fingerprint: chrome` | Xray outbounds |
| ALPN / bypass modeling | `tls_orchestrator*.rs` | Rust validation |
| JA3 fingerprint check | `MITM_STREAM_EXPECTED_JA3` | `src/ja3.rs` |
| FakeDNS / DNS routing | Xray DNS + routes | `docs/fakedns-recovery.md` |
| Fail-closed on supervisor exit | Job object / process group | `scripts/core/process_supervisor.py` |
| Path / failure probing | Staged probes | `failure_classifier.py` |
| SNI config inspection | Read-only | `scripts/core/sni_camouflage.py` |

## Accepted — delivery Tracks A/B/C/D (not yet all built)

| Track | Technique | Notes |
|---|---|---|
| **A** | REALITY profile | Highest-value Xray addition |
| **A** | TLS record **fragment** (ClientHello split) | Accepted equivalent to raw TCP split for DPI |
| **A** | Padding/mux, multi-uTLS fingerprints | Bounded mimicry (ADR-0004) |
| **B** | Blocking classifier + strategy engine | Evolves `path_scorer` to strategy sweep |
| **B** | Per-network strategy memory | `.local-state/`, redacted |
| **C** | "Get me through" one button | Consent-gated trust/elevation only |
| **D** | Profile-scoped browser trust | ADR-0002 evolution |
| **D** | High Stealth TUN + firewall kill-switch | ADR-0003 evolution, user opt-in |
| **D** | OPSEC telemetry mode | ADR-0005 evolution |
| **D** | `mycert.key` DPAPI / keychain | Track D |
| **D** | Kernel packet shaping (eBPF/XDP) | Xray-core or consented helper — **not** Rust mock as default egress |

## Rejected variants only (unsafe or wrong site)

| Variant | Why |
|---|---|
| Silent DLL/`LD_PRELOAD` trust | No consent; EDR signal |
| Rust inline SOCKS5 splice | Second data plane |
| Unbounded random ClientHello in Rust | Non-browser fingerprints |
| Mandatory TUN for everyone | ADR-0003 default stays browser-proxy-first |
| Remote telemetry upload | ADR-0005 |
| Claiming measured JA3 without oracle | ADR-0004 |

## Critique → acceptance quick map

| Blueprint asks for | Accepted path |
|---|---|
| TCP split / DPI desync | Xray `fragment` (A), then kernel in Xray-core (D) |
| Dynamic JA3 | uTLS per profile + template pools (A/B) |
| Ephemeral trust | Profile-scoped browser trust with consent (D) |
| TUN kill-switch | High Stealth profile (D) |
| Anti-forensics logs | OPSEC mode + Clear Activity (D) |
| `ingress_xdp_gateway` live | Track D in Go/consented helper, not Rust validation egress |

## Related reading

- `02-decisions-evasion-engineering.md` Part IV — workflow, JSON specs, findings, remediation
- `02-decisions-evasion-engineering.md` Part I ADR-0010 — full routing table
- `02-decisions-evasion-engineering.md` Part I ADR-0008 — implementation site boundary
- `01-architecture-runtime-delivery.md` — runtime + strategy diagrams
- `01-architecture-runtime-delivery.md` §4 — Tracks A/B/C/D

---

# Part III — High-Survivability Engineering Specification

Deep specs for Tracks A/B/D: ephemeral trust, TUN/XDP containment, JA3 pools,
TLS record fragmentation. Rejected variants: Part I ADR-0010.

## 0. Production graph (do not invert)

```text
Live path:  app → Xray mixed-in :10808 → tls-decrypt-* → tls-repack-* → CDN
Control:    Python (ProcessSupervisor, build_config, probes, GUI)
Validation: Rust (parse, JA3 hash, regression_harness) — NOT default egress
```

Wire traffic always flows through **Xray**. Specs that name `src/ja3.rs` or
`ingress_xdp_gateway.rs` for egress mean **offline validation or fixtures** unless
Track D ships a **separate, consented** privileged component under a new ADR.

### 0.1 Design tension — compliance defaults vs high-threat OPSEC

| Default posture | High-threat cost | Planned evolution (Tracks A/B/D) |
|---|---|---|
| Persistent GUI telemetry | Disk forensic surface | OPSEC mode: cap, clear-on-exit |
| System-wide CA | Trust-store IoC | CDP + isolated `--user-data-dir` (Track D) |
| SOCKS5 / env proxy only | WebRTC STUN + DNS prefetch leaks | TUN + firewall + FakeDNS 198.18 (Track D) |
| Static JA3 / honesty rules | Single fingerprint cluster | Pre-computed pools + strategy (A/B) |
| Rust validation-only | No in-crate TCP split/TTL | Xray profiles + optional kernel helper (D) |

**Rule:** adopt evasion goals via ADR-0010 routing; reject wrong sites (Rust live
forwarder, covert NSS mmap, silent hooking).

---

## 1. ADR-0002 — Ephemeral trust virtualization

### 1.0 Problem statement

**Legacy stance:** install MITM root CA via platform tools (`certutil -addstore`, macOS
`security add-trusted-cert`) with explicit user confirmation.

| Risk | Mechanism |
|---|---|
| Persistent IoC | Windows: `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates`; Linux/macOS system trust DB |
| EDR alarm (rejected bypass) | `LD_PRELOAD`, `VirtualAllocEx` / `CreateRemoteThread`, `PAGE_EXECUTE_READWRITE` — malware-equivalent |

**Elevated decision:** targeted, isolated application context — **not** global store mutation.

### 1.1 Accepted architecture

```text
+------------------------------------------------------------------+
| HOST OS — system trust stores UNTOUCHED (profile-scoped mode)     |
|  CryptoAPI / Keychain / NSS system DB → no MITM root IoC          |
+------------------------------------------------------------------+
| EPHEMERAL APP CONTEXT (Track D)                                   |
|  Chromium: --user-data-dir + --remote-debugging-port              |
|       → CDP Network domain / cert override in isolated profile    |
|  Firefox:  dedicated profile + user-guided cert import            |
|  Keys:     DPAPI/keychain for mycert.key; zeroize in brokers      |
+------------------------------------------------------------------+

System trust stores (CryptoAPI / Keychain) → UNTOUCHED in profile-scoped mode
Chromium → isolated --user-data-dir + CDP broker (Python)
Firefox  → dedicated profile + user-guided cert import (documented)
Optional → OS-wide via scripts/mitm_trust.py (explicit consent only)
Keys     → DPAPI/keychain for mycert.key (Track D); zeroize in brokers
```

### 1.2 Chromium CDP broker (Track D — implement in Python)

**Owner:** `scripts/browser_diagnostics.py` / new `scripts/core/trust_broker.py`
(not `src/main.rs` — Rust harness does not launch browsers today).

Launch template (adjust paths per OS):

```bash
chrome.exe --remote-debugging-port=9222 \
  --user-data-dir=%LOCALAPPDATA%\MITM-DF\ephemeral-profile \
  --disable-background-networking \
  --proxy-server=socks5://127.0.0.1:10808
```

CDP workflow (Track D):

1. Connect WebSocket to `http://127.0.0.1:9222/json/version`.
2. Enable `Network` domain.
3. Apply certificate override for MITM CA **inside the isolated profile** via
   documented CDP / profile import — target: trust limited to proxy loopback use.
4. On session end: close browser; optionally delete ephemeral profile dir (user opt-in).

**CDP target flow (owner = Python broker, not Rust harness):**

```text
[Target app] --subprocess--> [Chromium + isolated user-data-dir]
                                    |
                                    v
                         Ephemeral remote-debugging-port :9222
                                    |
                                    v
                         CDP Network.* / cert override (in-profile only)
                                    |
                                    v
                         Broker memory buffers — zeroize on session close
                         System CryptoAPI / Keychain — UNTOUCHED
```

**Implementation site:** CDP trust is implemented in `scripts/core/trust_broker.py`
(Track D), not `src/main.rs` (Rust harness does not launch browsers).

**Validation:**

```powershell
Get-ChildItem Cert:\LocalMachine\Root\ | Where-Object { $_.Subject -match "MITM" }
# Expect: zero entries in profile-scoped mode
py -3 scripts/mitm_trust.py status --json
```

### 1.3 Firefox / NSS (Track D)

**Accepted:** User creates/selects profile; GUI documents import of `mycert.crt`.

**Rejected variant (do not ship):** Covert `mmap` + `INSERT INTO nssPublic` without
user understanding — EDR-equivalent to malware staging.

**Do not ship** — covert NSS surgery sample (reference only):

```python
# REJECTED — covert NSS surgery; use documented profile import instead
import mmap, sqlite3
def inject_ephemeral_ca_to_nss(profile_path, ca_der_bytes):
    with open(f"{profile_path}/cert9.db", "r+b") as f:
        mm = mmap.mmap(f.fileno(), 0)
        conn = sqlite3.connect(f"{profile_path}/cert9.db")
        conn.execute("INSERT OR REPLACE INTO nssPublic VALUES (?, ?, ?, ?)",
                     (b'ephemeral_ca', 3, ca_der_bytes, b'CT,C,C'))
        conn.commit(); conn.close(); mm.close()
```

**Refinement:** prefer CDP or user-guided profile import over
DLL/`LD_PRELOAD` hooking — same behavioral signature as malware staging.

### 1.4 Volatile key zeroization (Track D)

**Owner:** Trust broker + optional hardening in `src/cert_cache.rs` **model** for
tests; production keys live in `Xray-config/mycert.key` until DPAPI wrap ships.

Use the `zeroize` crate (preferred over hand-rolled volatile loops):

```rust
use zeroize::Zeroize;

pub struct EphemeralKeyMaterial {
    key_payload: Vec<u8>,
}

impl Drop for EphemeralKeyMaterial {
    fn drop(&mut self) {
        self.key_payload.zeroize();
    }
}
```

**Validation:** Lab-only cold-boot / memory imaging on broker process; not a CI gate.

Hand-rolled volatile zeroization in `cert_cache.rs` is **reference only** — prefer
`zeroize` crate in the production broker.

```rust
// REFERENCE ONLY — use zeroize crate in production broker code
pub struct SecureKeyPair { pub key_payload: Vec<u8>, }
impl Drop for SecureKeyPair {
    #[inline(always)]
    fn drop(&mut self) {
        let dest_ptr = self.key_payload.as_mut_ptr();
        for i in 0..self.key_payload.len() {
            unsafe { std::ptr::write_volatile(dest_ptr.add(i), 0x00); }
        }
    }
}
```

Volatility / cold-boot sweeps: CA key buffers zeroed after broker exit; system trust
stores unchanged in profile-scoped mode.

### 1.5 Legacy vs elevated — decision table

| Topic | Legacy (compliance) | Elevated (survivability) | Repo implementation site |
|---|---|---|---|
| Trust install | System-wide root + dialogs | Ephemeral profile / CDP | Track D `trust_broker.py` |
| NSS | N/A | Covert `cert9.db` mmap | **Rejected** |
| Key at rest | Plaintext `mycert.key` | DPAPI / keychain + zeroize | Track D |
| OS-wide optional | N/A | Explicit `mitm_trust.py install` | Shipped with consent |

### 1.6 Files

| Action | File |
|---|---|
| Profile-scoped trust UX | `scripts/mitm_trust.py`, `docs/chromium-integration.md` |
| CDP broker | `scripts/core/trust_broker.py` + `cdp_client.py` (shipped) |
| DPAPI wrap | **New** Track D module + ADR amendment |
| Zeroize pattern | Broker + optional `src/cert_cache.rs` tests |

---

## 2. ADR-0003 — Fail-secure transport containment

### 2.0 Problem statement

**Legacy stance:** route apps via `http_proxy`, `all_proxy`, browser SOCKS settings.

| Leak class | Mechanism | Probe / mitigation |
|---|---|---|
| WebRTC STUN | UDP/3478 outside proxy stack | Browser leak test; `tcpdump udp port 3478`; Track D TUN |
| DNS prefetch | System resolver UDP/53 before click | FakeDNS 198.18 + Xray routing; Track D kernel trap |
| Background updates | Raw IP dials bypass env proxy | High Stealth firewall fail-closed |

**Elevated decision:** kernel-level fail-secure containment loop (phased — see §2.1).

### 2.1 Phased containment (mandatory order)

| Phase | Mechanism | Site | Status |
|---|---|---|---|
| 1 | Browser explicit proxy + QUIC policy | Xray + browser flags | Shipped (default) |
| 2 | High Stealth TUN + host firewall fail-closed | Xray TUN + WFP/nftables docs | Track D |
| 3 | FakeDNS `198.18.0.0/15` | Xray DNS config | Track D design |
| 4 | eBPF socket-cookie / `XDP_DROP` | Consented helper or Xray-core | Track D ADR |

**Do not skip phase 1→2** by loading kernel programs from `ingress_xdp_gateway.rs`
(Rust fixture only — no `libbpf` in tree).

### 2.2 Userspace containment (Track D — ship before eBPF)

1. Enable Xray TUN inbound (`docs/tun-operational-notes.md`).
2. Document firewall: drop all non-TUN egress when Xray PID absent.
3. `ProcessSupervisor` kill-on-close (shipped) + post-teardown connectivity probe.
4. Xray FakeDNS + routing for benchmark range; recovery per `docs/fakedns-recovery.md`.

### 2.3 eBPF reference design (Track D ADR — not default Rust egress)

High-threat deployments need fail-secure containment instead of voluntary proxy env vars:
**kernel-level eBPF/XDP fail-secure containment loop**:

```text
Outbound packet stream
        |
        v
 [XDP ingress/egress hook]
        |
        +--> authorized_sockets_map lookup (socket cookie)
        |         |
        |         +-- token present --> allow toward loopback / TUN
        |         +-- missing       --> XDP_DROP (hard block)
        |
        v
Supervisor crash --> map cleared --> fail-closed drop (no leak window)
```

**Note:** `src/ingress_xdp_gateway.rs` does **not** compile or load
this program today — it is a **Rust regression fixture**. Live eBPF belongs in Track D
ADR / Xray-core / consented out-of-tree helper.

Reference XDP filter (implement out-of-tree):

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
} authorized_sockets_map SEC(".maps");

SEC("xdp")
int containment_ingress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        __u64 sk_cookie = bpf_get_socket_cookie(ctx);
        __u32 *auth = bpf_map_lookup_elem(&authorized_sockets_map, &sk_cookie);
        if (!auth) return XDP_DROP;
    }
    return XDP_PASS;
}
```

Kernel DNS trap (phase 4 reference) — synthetic `198.18.0.0/15` replies; prefer Xray
FakeDNS until TUN is stable. Recovery: `docs/fakedns-recovery.md`.

**FakeDNS kernel trap (phase 4 reference):**

```text
+------------------------------------------------------------------+
| DNS QUERY KERNEL TRAP (Track D — eBPF reference)                  |
|  [App] --> outbound UDP/53                                        |
|              |                                                    |
|              v                                                    |
|       [eBPF packet interceptor]                                   |
|              |                                                    |
|              +--> map domain -> 198.18.0.0/15 + cache in kernel   |
|              v                                                    |
|       [synthetic DNS reply in-kernel]                             |
|              v                                                    |
|  [App] <-- virtual IP (no real-world resolver query)              |
+------------------------------------------------------------------+
```

Supervisor crash → authorization map cleared → XDP filter drops subsequent outbound
from uncontained sockets (fail-secure).

**Validation:**

```bash
# After Track D eBPF ships (lab only)
bpftool map dump name authorized_sockets_map
tcpdump -i eth0 udp port 3478   # WebRTC STUN — expect zero leak in High Stealth
```

### 2.4 Files

| Action | File |
|---|---|
| TUN + firewall checklist | `docs/tun-operational-notes.md`, `configs/tun-profiles.yml` |
| Leak probes | `scripts/core/failure_classifier.py` (labels), Track B |
| XDP fixture (regression only) | `src/ingress_xdp_gateway.rs` |
| Live eBPF | **Future** Track D ADR + out-of-tree or Xray-core |

---

## 3. ADR-0004 — Pre-computed handshake pools (bounded polymorphism)

### 3.0 Problem statement

**Legacy stance:** stable JA3 / consistent TLS extensions for interoperability (“oracle honesty”).

| Risk | Mechanism |
|---|---|
| Signature clustering | One ClientHello profile → many unrelated CDN targets = tunnel classification |
| On-the-fly mutation | Runtime GREASE/cipher shuffle adds latency + timing fingerprint |

**Elevated decision:** **pre-computed** pools at init/profile-load; **O(1)** selection at
connect — speed is mandatory; runtime byte-shuffling is rejected.

**Do not implement in `ja3.rs` (wrong site):**

```text
[Inbound TLS event] → ja3.rs runtime engine → raw socket uTLS emit   ← REJECTED
```

**Correct-site diagram:**

```text
[Build / profile load] → config-src/templates/ja3-pools/*.json (≤2048 templates)
[Connect]              → strategy_engine O(1) index → Xray uTLS profile switch
[CI / lab]             → regression_harness + MITM_STREAM_EXPECTED_JA3 per template id
```

### 3.1 Design constraints (non-negotiable)

1. **No on-the-fly** GREASE/cipher shuffle at connect time.
2. Pool built at **init / profile compile**, not per connection in Tokio.
3. Templates sampled from **real browser cohorts** (Chrome/Firefox/Safari versions).
4. **Live ClientHello emission:** Xray uTLS — not `src/ja3.rs`.
5. **Offline JA3:** Rust validates each template id (`regression_harness.rs`).

### 3.2 Pool architecture (live site = Xray)

```text
STATIC REGISTRY (build / profile-load time)
  config-src/templates/ja3-pools/*.json  — up to 2048 validated templates
  cohort masks: Chrome / Firefox / Safari version matrices

RUNTIME SELECTION (Track B — O(1))
  session_counter & (pool_size - 1)  →  named Xray profile / tlsSettings.fingerprint
  Xray uTLS emits ClientHello on wire

OFFLINE VALIDATION (Rust — not wire)
  regression_harness + MITM_STREAM_EXPECTED_JA3 per template id
```

### 3.3 Build pipeline (Track A + B)

```text
1. Offline harvest (lab): PCAP → ClientHello bytes → JA3 string
2. Filter: must match known browser JA3 distribution (reject "alien" templates)
3. Store: config-src/templates/ja3-pools/<browser>-<version>.json (git)
4. build_config.py: attach pool id + tlsSettings.fingerprint to outbound profile
5. cargo test: MITM_STREAM_EXPECTED_JA3 per template id
6. strategy_engine: session_index & (pool_size-1) → profile/pool_id (Track B)
```

**Rejected:** `HANDSHAKE_MUTATION_POOL` as `once_cell::Lazy` in `ja3.rs` with
`acquire_handshake_bytes()` → raw socket / uTLS in Rust validation binary.

**Do not merge** — wrong-site pool code in `mitm_stream_core`:

```rust
// REJECTED in mitm_stream_core — pools live in config-src + Xray uTLS
pub static HANDSHAKE_MUTATION_POOL: Lazy<Vec<PreComputedHandshake>> = Lazy::new(|| {
    let mut pool = Vec::with_capacity(2048);
    for _ in 0..2048 {
        pool.push(generate_realistic_browser_handshake_matrix());
    }
    pool
});

fn generate_realistic_browser_handshake_matrix() -> PreComputedHandshake {
    // Offline lab tool only — NOT ja3.rs wire emit
    let mut rng = rand::thread_rng();
    let grease_1 = [((rng.next_u32() & 0x0F) << 4 | 0x0A) as u8, 0x1A];
    let mut handshake = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    // append_standard_chrome_cipher_matrix, append_rfc8701_grease_extensions, etc.
    PreComputedHandshake {
        raw_bytes: handshake,
        matching_ja3: "771,4865-4866-4867,0-23-65281,10-11,0".to_string(),
    }
}

#[inline(always)]
pub fn acquire_handshake_bytes(session_index: usize) -> &'static [u8] {
    let target_index = session_index & 0x07FF;
    &HANDSHAKE_MUTATION_POOL[target_index].raw_bytes
}
```

**Evaluation refinement:** polymorphism must sample **real browser cohorts** (Chrome /
Firefox / Safari version matrices). Unbounded random GREASE produces “alien” JA3 hashes
no real browser emits.

Bounded matrix generation (offline lab tool — not `ja3.rs` wire path):

```text
PCAP harvest → filter to known browser JA3 distribution → store template bytes + id
GREASE/padding variants only within cohort mask → reject outliers in regression_harness
```

### 3.4 O(1) selection (strategy layer)

```python
# scripts/core/strategy_engine.py (shipped)
def pool_index(session_counter: int, pool_size: int) -> int:
    return session_counter & (pool_size - 1)  # pool_size power of two, e.g. 2048
```

Xray receives a **named profile** already bound to template subset — no per-packet
Rust dispatch.

### 3.5 Validation

```bash
tshark -r stream.pcap -T fields -e tls.handshake.ja3_hash
py -3 scripts/core/sni_camouflage.py Xray-config/Xray-Cooperative-Overlay.json
cargo test ja3 regression_harness --locked
```

Latency gate (lab): connect p99 within ~2ms of native Chrome for same RTT path.

---

## 4. ADR-0007 / 0008 — Stateful packet manipulation

### 4.0 Problem statement

**Legacy stance:** delegate packet construction to OS TCP stack (`std::net::TcpStream`) —
fully RFC-compliant, predictable to stateful DPI.

| Censor technique | Effect on passive proxy |
|---|---|
| Plaintext SNI match in first ClientHello | Injected TCP RST |
| Contiguous ClientHello inspection | Structural fingerprinting |

**Elevated decision:** adversarial traffic shaping — split records, TTL-limited decoys —
**pre-stack** where kernel shaping is used (ADR-0008).

```text
ADVERSARIAL TRAFFIC SHAPING (Track A + D)

  ClientHello buffer
        |
        +--> [Splitter] --> part 1 (e.g. first TLS record bytes) --> send
        |                   part 2 (remainder) --> delay --> send
        |
        +--> [TTL spin]   --> decoy segment (TTL expires at DPI, not at CDN)
        |                   genuine segment (normal TTL) --> origin
```

### 4.1 Mandatory first step — Xray TLS record fragment (Track A)

Equivalent to split-at-byte-2 + delay without `libc::send` / `MSG_OOB`
in this repo:

```json
"fragment": {
  "packets": "tlshello",
  "length": "100-200",
  "interval": "10-20"
}
```

Pin exact schema to Xray-core version; add `protocol_smoke.py` scenario when landed.

Raw socket split (**rejected in this crate**):

```rust
// REJECTED — use Xray streamSettings.fragment instead
pub unsafe fn execute_adversarial_tcp_split(socket_fd: i32, payload: &[u8]) -> Result<(), i32> {
    send(socket_fd, payload.as_ptr() as *const _, 2, MSG_OOB);
    std::thread::sleep(Duration::from_millis(3));
    send(socket_fd, payload.as_ptr().add(2) as *const _, payload.len() - 2, 0);
    Ok(())
}
```

Camouflage SNI on repack outbounds (`providers/fastly.yml` etc.) complements split:
outer `serverName` is front domain; logical Host carried inside decrypted HTTP routing.

### 4.2 Track D — TTL spin / ghost segments

Reference behavior (Track D):

- Decoy TCP segment, invalid checksum or junk payload.
- TTL expires after censor DPI, before CDN edge.
- Genuine stream uses normal TTL.

**Site:** Xray-core kernel module or consented eBPF helper — **not**
`execute_adversarial_tcp_split()` in `mitm_stream_core`.

```text
WIRE-LEVEL PACKET TRANSIT (Track D reference)

  [Host]
     |-- decoy segment (TTL=8)  --> [DPI trap] corrupt / drop state
     |-- genuine stream (TTL=64) -> [DPI] passes --> [CDN / origin]
```

`src/ingress_xdp_gateway.rs` may **model** batch shapes for regression tests only.

**Evaluation refinement:** operate mutations via eBPF/XDP **before** the host stack
normalizes frames — otherwise the kernel “fixes” invalid segments (ADR-0008).

### 4.3 Validation

- Suricata/Snort SNI rule on lab bridge — tunnel establishes under block rule when
  fragment profile active.
- Wireshark: ClientHello spans multiple TLS records / TCP segments.

---

## 5. High Stealth implementation checklist

Use during Track A/B/D work. `[ ]` = not shipped; `[~]` = partial; `[x]` = shipped.

```text
=================================================================================================
                    HIGH STEALTH IMPLEMENTATION CHECKLIST (BASELINE CLOSED)
=================================================================================================

1. EPHEMERAL TRUST VIRTUALIZATION [ADR-0002]
   [x] Document no silent OS-wide CA in High Stealth default (ADR-0002).
   [x] CDP assist opens profile certificate settings (`trust_broker.py`, `cdp_client.py`).
   [x] DPAPI wrap for `mycert.key` (`key_at_rest.py`, `mitm_trust wrap-key`).
   [x] Reject covert mmap `cert9.db` patching (policy — ADR-0002, code review).

2. FAIL-SECURE CONTAINMENT [ADR-0003]
   [x] ProcessSupervisor kill-on-close (shipped).
   [x] TUN lab fragment + WFP/nftables checklist (`tun-operational-notes.md`).
   [x] FakeDNS 198.18 fragment + recovery docs.
   [x] Live eBPF/XDP production loader (`ebpf_xdp_loader.py`, consent gate).

3. PRE-COMPUTED HANDSHAKE POOLS [ADR-0004]
   [x] Static pool artifacts + CI cross-check (`ja3_pool_validate.py`).
   [x] O(1) selection via strategy layer → Xray profile.
   [x] GUI Apply Recommended + optional auto-apply after decision report.

4. STATEFUL PACKET MANIPULATION [ADR-0007 / ADR-0008]
   [x] TLS fragment + REALITY lab fragments + protocol_smoke probes.
   [x] TTL spin lab ADR + smoke probe (structure only).
   [x] Suricata/PCAP wire proof harness (`wire_proof_suricata.py`; wire capture = operator lab).
=================================================================================================
```

Move trust, containment, and signature management into **volatile memory + kernel
space (Track D)** and **Xray profiles (Track A)** — not a second Rust forwarder in
`mitm_stream_core`.

## 9. Implementation-readiness closure register

This section turns the reference-track ideas into concrete engineering closure
criteria. It is intentionally scoped to Xray profiles, Python control-plane
automation, Rust offline validation, and consent-based local operation.

| Track item | Owner | Concrete artifact | Required tests | Ship gate | Non-negotiable boundary |
|---|---|---|---|---|---|
| Profile-scoped trust | Python control plane | `scripts/core/trust_broker.py`, browser guide update | unit test for command generation; manual profile trust validation | no system CA entry in profile-scoped mode | no silent CA install, no DLL/LD_PRELOAD, no covert `cert9.db` patch |
| Config fragment semantics | Python build pipeline | `scripts/config_src_merge.py` explicit list strategies | `tests/python/config_src_merge_test.py` | generated config matches runtime target | no implicit route-rule shadowing through blind list append |
| Strategy selection | Python strategy layer | `scripts/core/strategy_engine.py` | deterministic pool-index vectors; labels-to-profile tests | decision report includes reason and confidence | no packet manipulation or live TLS emission in Python |
| JA3 pool readiness | config-src + Rust validation | `config-src/templates/ja3-pools/*.json` plus expected hashes | Rust JA3 harness per template ID | oracle evidence marks measured vs configured | no on-connect random ClientHello mutation |
| TLS fragment profile | Xray profile | config-src fragment bound to named profile | PCAP shows multi-record ClientHello | `protocol_smoke.py` scenario passes | do not implement raw split in Rust validation crate |
| OPSEC telemetry mode | GUI/control plane | bounded retention, clear-on-exit option | file-monitor test; GUI self-test | `.local-state` growth capped in OPSEC mode | no remote telemetry upload |
| Key-at-rest hardening | OS crypto helper | DPAPI/keychain wrapper with consent | ACL/permission test; secret scan | key never included in package/release | no shared CA, no upload |

### 9.1 Definition of done for a Track A/B/D pull request

Every pull request that claims Track A/B/D progress must include:

1. the affected ADR row and traceability ID;
2. exact files changed;
3. a validation command runnable from repository root;
4. a negative test proving the rejected implementation site remains rejected;
5. evidence classification: `configured`, `locally verified`, or `wire measured`;
6. rollback behavior if the profile or helper fails.

### 9.2 Evidence vocabulary

| Word | Meaning |
|---|---|
| `configured` | Config contains the setting, but no runtime or packet evidence has been collected. |
| `locally verified` | Local validator or harness proved structure/contract. |
| `wire measured` | PCAP/oracle/lab evidence observed the behavior on the wire. |
| `unsupported` | Known platform/browser/provider limitation. |
| `rejected` | Violates an accepted ADR boundary. |

Pull requests must not describe configured behavior as wire measured without a
captured artifact or oracle result.

### 5.1 Ephemeral trust (ADR-0002) — Track D

| Status | Item | Implementation target |
|---|---|---|
| [x] | No silent OS-wide CA in High Stealth default | `scripts/mitm_trust.py`, GUI consent, ADR-0002 |
| [x] | CDP/isolated Chromium profile broker | `scripts/core/trust_broker.py` + `cdp_client.py` |
| [x] | Documented Firefox profile import path | `docs/chromium-integration.md` |
| [x] | Reject covert mmap `cert9.db` patching | ADR-0002, code review |
| [x] | DPAPI/keychain for `mycert.key` at rest | `key_at_rest.py`, `mitm_trust wrap-key` |

### 5.2 Fail-secure containment (ADR-0003) — Track D

| Status | Item | Implementation target |
|---|---|---|
| [x] | ProcessSupervisor kill-on-close | `scripts/core/process_supervisor.py` |
| [x] | High Stealth TUN + firewall fail-closed (lab baseline) | TUN stub + `docs/tun-operational-notes.md` |
| [x] | FakeDNS `198.18.0.0/15` lab fragment | `config-src/fragments/fakedns-19818-trap.json` |
| [x] | WebRTC/DNS leak probe labels | `failure_classifier.py`, Track B |
| [x] | eBPF cookie map + XDP_DROP (containment loader) | `containment_xdp.bpf.c`, `ebpf_xdp_loader.py --program containment`, `ebpf_containment.py` |
| [x] | Env-proxy as **default** (not only path) | ADR-0003 |

### 5.3 Pre-computed pools (ADR-0004) — Track A/B

| Status | Item | Implementation target |
|---|---|---|
| [x] | Static `fingerprint: chrome` on repack outbounds | `Xray-config/` |
| [x] | Offline template pool artifacts | `config-src/templates/ja3-pools/` |
| [x] | Pool CI validation + profile fingerprint selection | `ja3_pool_validate.py`, `configs/profiles.yml` |
| [x] | regression_harness per template id | `src/regression_harness.rs` |
| [x] | strategy_engine O(1) pool selection + GUI apply | `scripts/core/strategy_engine.py`, `apply_strategy_profile.py` |
| [x] | Reject on-the-fly shuffle in Rust egress | ADR-0004, ADR-0007 |

### 5.4 Packet manipulation (ADR-0007/8) — Track A/D

| Status | Item | Implementation target |
|---|---|---|
| [x] | Camouflage SNI on repack outbounds | `scripts/core/sni_camouflage.py` |
| [x] | TLS record `fragment` lab fragment | `config-src/fragments/tls-fragment-overlay.json` |
| [x] | REALITY outbound lab fragment | `config-src/fragments/reality-outbound-stub.json` |
| [x] | TTL spin / ghost segments (lab ADR + probe) | `track-d-ttl-spin-lab.md`, `protocol_smoke.py` |
| [x] | Rust mock ≠ live XDP egress | `src/ingress_xdp_gateway.rs` header |

---

## 6. Version-lock chain (A-ION / overlay consumers)

When this toolchain feeds an asymmetric overlay, rev together:

```text
Xray-core pin ↔ config-src ↔ build_config.py ↔ Xray-config/*.json
  ↔ validate_config.py ↔ ja3-pool artifacts ↔ regression_harness
  ↔ eBPF map schema (Track D) ↔ strategy_engine state
```

---

## 7. ADR implementation matrix

| ADR / topic | Default posture | High-threat target | Implementation site |
|---|---|---|---|
| **0002 Trust** | System-wide CA + confirmation dialogs | Ephemeral profile / CDP; zeroize broker keys | `trust_broker.py`, `docs/chromium-integration.md`, Track D DPAPI |
| **0003 Boundaries** | SOCKS5 env vars; warn on leak | TUN + firewall fail-closed + optional XDP cookie map | Xray TUN, `tun-operational-notes.md`, Track D eBPF ADR |
| **0004 Handshakes** | Static predictable JA3 | 2048-template pools; O(1) profile switch | `config-src/templates/ja3-pools/`, Xray uTLS, `strategy_engine.py` |
| **0005 Logging** | Detailed local diagnostics | OPSEC mode: volatile-first, clear-on-exit | `scripts/gui.py` telemetry; **keep** `local-telemetry.md` |
| **0007/0008 Data plane** | OS stack only; Rust validates | TLS record fragment + TTL spin at XDP/Xray | Xray `fragment` (A); eBPF helper (D) — **not** mock gateway as P0 |
| **0009 Goal** | Compliance proxy | Asymmetric cloaking via profiles A/B/D | ADR-0010 routing |

### 7.1 Synthesis

| ADR block | Verdict | Refinement |
|---|---|---|
| **0002 Ephemeral trust** | OPSEC upgrade vs system CA | Prefer **CDP + isolated profile** over DLL/`LD_PRELOAD`; mmap NSS **rejected** |
| **0003 XDP containment** | Only acceptable high-threat boundary | Phase userspace TUN/firewall **before** eBPF; map cleared on supervisor death |
| **0004 JA3 polymorphism** | Static JA3 is critical gap | **Bounded** cohort masks; **pre-compute** at build — never on-the-fly in hot path |
| **0007/0008 Packet engineering** | Active split/TTL beats passive proxy | Hook **pre-stack**; first ship Xray `fragment`; sync pool indices with strategy state |
| **A-ION / overlay consumers** | Blueprint isolates host, weaponizes egress | Version-lock chain §6; rev Xray pin + pool artifacts + eBPF schema together |

**Operational shift:** from default local proxy to asymmetric cloaking via Tracks A/B/D
**without** adding a second Rust byte forwarder.

---

## 8. Layer verification checklists (by engine layer)

Granular gates for implementation and lab validation.

Legend: **Shipped** · **Future research** = 03 §4.1 · **N/A** = model/fixture only · **Reject** = wrong site

### 8.1 Data plane and kernel ingress (`src/` + live Xray)

| # | Checklist item | Status | Correct target / note |
|---|---|---|---|
| 1 | Loopback drops packets without crypto token | **N/A** | `ingress_loopback.rs` uses normal `TcpListener::accept`; containment = Xray/TUN (D) |
| 2 | eBPF ring buffer uses lockless bounds under load | **Track D** | No live ring in `ingress_xdp_gateway.rs` — fixture only |
| 3 | XDP fail-secure kill-switch on user-space panic | **Shipped** | `containment_xdp.bpf.c` + `mark_supervisor_dead()` → `XDP_DROP` |
| 4 | FakeDNS maps only to `198.18.0.0/15` | **Track D** | `docs/fakedns-recovery.md` + Xray DNS config — not Rust `src/` |
| 5 | JNI / Android TUN leak-free across GC | **Harness** | `ingress_android_tun.rs` model; Valgrind/LSAN when Android path ships |
| 6 | Live TLS MITM + repack on wire | **Shipped (Xray)** | `tls-decrypt-*` / `tls-repack-*` — not Rust orchestrator |
| 7 | TLS record `fragment` splits ClientHello | **Track A** | Xray `streamSettings.fragment` — validate with PCAP |
| 8 | REALITY outbound profile present | **Track A** | `config-src/fragments/` — `sni_camouflage.py` requires `serverName` |

**Lab commands:**

```bash
cargo test ingress_xdp_gateway ingress_android_tun --locked
tshark -r capture.pcap -T fields -e tls.handshake.ja3_hash
py -3 scripts/core/sni_camouflage.py Xray-config/Xray-Cooperative-Overlay.json
```

### 8.2 Control plane and automation (`scripts/`)

| # | Checklist item | Status | Correct target / note |
|---|---|---|---|
| 1 | `failure_classifier.py` does not append disk logs | **Shipped** | In-memory `ProbeResult` only — grep confirms no `open(..., 'a')` |
| 2 | `decision_report.py` writes only when `--json-out` passed | **Shipped** | CLI opt-in; not GUI default |
| 3 | GUI telemetry stays under `.local-state/` | **Shipped** | See `docs/local-telemetry.md`; OPSEC cap/clear-on-exit = Track D |
| 4 | `ProcessSupervisor` cleans child tree on exit | **Shipped** | Job Object `0x2000`; POSIX `killpg` |
| 5 | `platform_capability_check.py` checks admin / capability hints | **Shipped** | Includes `ebpf` section (bpftool, BPF sources, consent env vars) |
| 6 | `build_config.py` output parseable and sync-checked | **Shipped** | `--check-runtime-sync --check-profile-sync` |
| 7 | Config secrets not committed | **Shipped** | `mycert.key` gitignored; release ZIP scan |
| 8 | Forensic disk sweep after GUI session | **Track D** | `grep`/FS monitor — expect jsonl only if user ran GUI; Clear Activity |

**Lab commands:**

```powershell
py -3 scripts/core/failure_classifier.py --help
Get-ChildItem .local-state\
py -3 scripts/build_config.py --check-runtime-sync
```

### 8.3 Protocol mutation layer (JA3 / TLS / H2 models)

| # | Checklist item | Status | Correct target / note |
|---|---|---|---|
| 1 | Pre-computed pools — no connect-time shuffle | **Shipped** | Pools in `config-src/templates/`; Xray emits live; CI validates |
| 2 | `ja3.rs` validates parsed ClientHello hashes offline | **Shipped** | Does **not** send uTLS/raw sockets (`Cargo.toml` deps empty) |
| 3 | `regression_harness.rs` checks extension order + H2 SETTINGS id:value | **Shipped** | CI gate via `cargo test` |
| 4 | `tls_orchestrator*.rs` ALPN policy — no socket I/O | **Shipped** | Policy model only |
| 5 | `h2_coalescing.rs` stream-limit logic | **Model** | Live H2 multiplexing is **Xray** outbound |
| 6 | Bounded mimicry — browser cohort masks only | **Shipped** | Pool builder + `ja3_pool_validate.py` rejects outliers |
| 7 | Measured vs configured JA3 claims honest | **Shipped** | ADR-0004; GUI **Run JA3 Oracle** + `ja3-evidence.json` |
| 8 | ALPN policy forces H2/H3 on wire | **Model** | `alpn_policy.rs` — live ALPN = Xray repack |
| 9 | Cooperative overlay strict sequence on wire | **N/A** | `cooperative_overlay.rs` — regression only |

**Lab commands:**

```bash
cargo test ja3 regression_harness h2_coalescing --locked
MITM_STREAM_EXPECTED_JA3=<md5> cargo run --bin mitm_stream_core  # harness fingerprint check
tshark -r stream.pcap -T fields -e ssl.handshake.ciphersuite
```

### 8.4 High Stealth lab gates (Track D — when shipped)

| Gate | Command / tool | Pass criteria |
|---|---|---|
| No system CA in profile-scoped mode | `Get-ChildItem Cert:\LocalMachine\Root\` | Zero MITM project subjects |
| CDP profile isolated | Inspect `--user-data-dir` path | Ephemeral dir; optional delete on exit |
| No WebRTC STUN leak | Browser leak test + `tcpdump udp port 3478` | Zero egress outside TUN |
| eBPF map fail-closed | `bpftool map dump name authorized_sockets_map` | Empty after supervisor kill |
| TLS fragmentation active | Wireshark | ClientHello spans multiple records/segments |
| Supervisor fail-closed | Kill GUI process | `xray.exe` terminated; connectivity probe fails |

---

# Part IV — Workflow, components, and technique depth

## 1. Executive summary

`Xray-Cooperative-Overlay` is a **control plane + validation layer** wrapped around
**Xray as the sole live data plane** (ADR-0001). Python orchestrates lifecycle,
preflight, health probes, and config compilation; Rust models TLS/routing policy
offline; Xray performs MITM, domain fronting, uTLS, and repack on the wire.

That split is deliberate: stability, testability, and a single byte path. Evasion
strength is **not** rejected — it is routed to:

- **Track A:** validated Xray profiles (REALITY, TLS record fragment, mux/padding, multi-uTLS).
- **Track B:** adaptive strategy engine (probe → classify → score → apply profile).
- **Track C:** consent-gated “Get me through” UX.
- **Track D:** stealth hardening (profile trust, High Stealth TUN, OPSEC telemetry, key wrap, optional kernel shaping in Xray-core).

What stays out of the Rust crate as **live egress**: inline SOCKS5 splice, default
`cap_net_raw` daemon, promoting `ingress_xdp_gateway.rs` mock to production without
ADR (ADR-0008).

## 2. End-to-end workflow (concrete)

```text
1. Preflight / readiness
   scripts/preflight.py, scripts/validate_config.py, main.py probe
   scripts/core/readiness.py → ProjectState

2. Config synthesis
   config-src/base.json + routes/dns/providers YAML
   scripts/build_config.py --check-runtime-sync --generate-profiles
   → Xray-config/Xray-Cooperative-Overlay.json (+ *.strict|balanced|…)

3. Offline validation (Rust)
   cargo test (parser, ja3, tls_orchestrator, regression_harness, scheduler)
   optional: MITM_STREAM_EXPECTED_JA3 fingerprint check via src/main.rs harness

4. Runtime spawn
   GUI/CLI → scripts/core/process_supervisor.py → xray/xray.exe -c …
   Windows: Job Object + JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000)
   POSIX: new session / process group → SIGTERM on teardown

5. Data path
   Browser/app → 127.0.0.1:10808 (mixed-in)
   → route rules → tls-decrypt-* :11666–11999
   → tls-repack-* outbounds (camouflage serverName + uTLS fingerprint)
```

**Validation commands (maintainer):**

```bash
py -3 main.py test
py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts/core/sni_camouflage.py Xray-config/Xray-Cooperative-Overlay.json
cargo test --locked
```

## 3. Component inventory

| Component | Language | Live path? | Role | Key files |
|---|---|---|---|---|
| Xray runtime | Go (binary) | **Yes** | Proxy, MITM, routing, uTLS, repack | `xray/xray`, `Xray-config/*.json` |
| ProcessSupervisor | Python | Control | Spawn/kill Xray; fail-closed on job close | `scripts/core/process_supervisor.py` |
| Readiness / probe | Python | Control | Shared ProjectState, next action | `scripts/core/readiness.py`, `main.py probe` |
| Failure classifier | Python | Probe | Staged DNS/TCP/TLS classification | `scripts/core/failure_classifier.py` |
| Path scorer | Python | Advisory | Score probe reports / paths | `scripts/path_scorer.py` |
| SNI camouflage inspector | Python | Read-only | Validate front `serverName` bindings | `scripts/core/sni_camouflage.py` |
| mitm_stream_core | Rust | **No** (harness) | Parse/model JA3, ALPN, ingress fixtures | `src/*.rs` |
| ingress_xdp_gateway | Rust | **Mock only** | Batch buffer regression fixture | `src/ingress_xdp_gateway.rs` |
| Config compiler | Python | Build | Merge config-src → Xray-config | `scripts/build_config.py`, `config-src/` |

## 4. Rust modules — what they actually do

| Module | Purpose | On wire? |
|---|---|---|
| `parser.rs` | ClientHello parse (ciphers, extensions, ALPN) | No |
| `ja3.rs` | JA3 string/hash + optional expected-hash check | No |
| `tls_orchestrator_backend.rs` | ALPN negotiate/commit/bypass **policy** | No sockets |
| `regression_harness.rs` | Profile vs observation mismatch reports | No |
| `ingress_loopback.rs` | Loopback ingress **test** (`TcpStream::connect` only in tests) | Test only |
| `ingress_xdp_gateway.rs` | XDP-shaped **fixture**; docstring states not loaded eBPF | No |
| `ingress_android_tun.rs` | TUN ingress **model** when feature enabled | No (model) |
| `h2_coalescing.rs`, `scheduler.rs` | Routing/coalescing **models** for regression | No |

**Note:** `PolicyAwareTlsBackend` does not dial upstream or perform
SOCKS5. Env wiring for inference lives in `src/main.rs`
(`MITM_STREAM_UPSTREAM_ALPN`, `MITM_STREAM_ALLOW_POLICY_INFERENCE`).

## 5. Accepted evasion techniques (implementation depth)

### 5.1 Camouflage SNI (shipped)

Front TLS SNI differs from logical destination — domain fronting at the TLS layer.

**Shipped bindings** (inspect with `py -3 scripts/core/sni_camouflage.py`):

| Outbound tag | serverName |
|---|---|
| `tls-repack-dns-cloudflare` | `www.microsoft.com` |
| `tls-repack-dns-google` | `www.google.com` |
| `tls-repack-google` | `www.google.com` |
| `tls-repack-fastly` | `github.githubassets.com` |
| `tls-repack-meta` | `www.microsoft.com` |

Config shape:

```json
"streamSettings": {
  "security": "tls",
  "tlsSettings": {
    "serverName": "www.google.com",
    "fingerprint": "chrome",
    "alpn": ["h2", "http/1.1"]
  }
}
```

See `docs/sni-camouflage.md`.

### 5.2 TLS record fragmentation (Track A — not yet in primary config)

**Accepted equivalent** to raw TCP ClientHello splitting for naive DPI: Xray
stream `fragment` settings split TLS records before they hit the kernel stack —
no `SOCK_RAW` in this repo.

**Target profile fragment** (to be added under `config-src/fragments/` or a
named evasion profile, then validated by `config_src_validate.py` + smoke):

```json
"streamSettings": {
  "security": "tls",
  "tlsSettings": {
    "serverName": "www.google.com",
    "fingerprint": "chrome"
  },
  "sockopt": {
    "dialerProxy": ""
  },
  "fragment": {
    "packets": "tlshello",
    "length": "100-200",
    "interval": "10-20"
  }
}
```

Exact field names and enums must match the pinned Xray-core version; add a
`protocol_smoke.py` scenario when the profile lands.

### 5.3 REALITY outbound (Track A — highest priority gap)

**Target shape** (server keys documented out-of-band; profile validated, not hard-coded secrets):

```json
{
  "tag": "reality-front-out",
  "protocol": "vless",
  "settings": { "vnext": [{ "address": "…", "port": 443, "users": [{ "id": "…", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "serverName": "www.microsoft.com",
      "fingerprint": "chrome",
      "publicKey": "<server-public-key>",
      "shortId": "<short-id>"
    }
  }
}
```

`scripts/core/sni_camouflage.py` treats REALITY `serverName` as **required** (error if missing).

### 5.4 Bounded TLS mimicry (Tracks A/B)

- **Configured:** `tlsSettings.fingerprint` per outbound (today: mostly `chrome`).
- **Planned:** profile sets `{chrome, firefox, safari, randomized}` selectable by
  strategy engine; Rust `ja3.rs` regression-tests **expected** hash per profile
  (`MITM_STREAM_EXPECTED_JA3`), does not emit live ClientHellos.
- **Rejected variant:** unbounded GREASE/extension shuffle producing non-browser JA3.
- **Claims (ADR-0004):** “configured” vs “measured” — oracle required for measured.

Pre-computed template pools: build offline, validate in
`regression_harness.rs`, select at runtime via Xray config switch — not
on-the-fly mutation in the Rust binary (latency + invalid fingerprint risk).

### 5.5 High Stealth containment (Track D)

**Default (ADR-0003):** browser explicit proxy to `127.0.0.1:10808`.

**Accepted evolution — High Stealth intent:**

1. User opts in (ADR-0006) after leak warnings.
2. Enable Xray TUN inbound per `docs/tun-operational-notes.md` + `configs/tun-profiles.yml`.
3. Document platform firewall rules (Windows Filtering Platform / nftables) so
   traffic outside TUN drops when Xray is down.
4. Rely on `ProcessSupervisor` kill-on-close today; extend with explicit
   “connectivity check” probe after supervisor exit.

**Leak probes to extend in Track B** (`failure_classifier.py` labels):

| Class | Symptom | Probe idea |
|---|---|---|
| WebRTC STUN | Public IP outside proxy | Browser diagnostics / manual checklist |
| DNS bypass | System resolver hits ISP | Port 53 + DoH policy in profile |
| QUIC/UDP443 | Non-proxied UDP | `protocol_smoke.py --scenario udp443-policy` |

### 5.6 Profile-scoped trust (Track D)

**Accepted (with consent):** launch brokered Chromium/Firefox with an isolated
user profile that trusts `mycert.crt` without machine-wide root store — see
`docs/chromium-integration.md`.

**Rejected:** silent DLL injection / `LD_PRELOAD` without user understanding.

### 5.7 OPSEC telemetry (Track D)

**Accepted:** GUI **Clear Activity**, optional future “minimal retention” mode
(clear `.local-state/gui-telemetry.jsonl` on exit). Labels stay honest (ADR-0005).

**Rejected:** remove all local diagnostics or silent upload.

### 5.8 Kernel packet shaping (Track D — long-term)

TTL-limited decoy segments and early TCP splits belong in **Xray-core (Go)** or
a **consented** privileged helper — not by turning `ingress_xdp_gateway.rs` into
live egress in this crate without a new ADR.

Rust mock exists so regression tests can reason about batch ingress shapes without
loading `libbpf`.

## 6. ProcessSupervisor — technical detail

**Windows** (`scripts/core/process_supervisor.py`):

- `CreateJobObjectW` → `SetInformationJobObject` with
  `JobObjectExtendedLimitInformation` and `LimitFlags = 0x2000`
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
- Child assigned via `AssignProcessToJobObject`.
- When the supervisor closes the job handle or process, the kernel terminates the
  Xray tree — **fail-closed** for GUI-launched cores.

**POSIX:** `start_new_session=True`; teardown uses `killpg(SIGTERM)` then `SIGKILL`.

**Known tradeoff:** `subprocess.Popen` + Job Objects produce
ETW-visible process trees on Windows. This is accepted for the default path;
Track D may document lower-visibility spawn patterns only with explicit user
consent and platform review — not silent substitution.

## 7. Strategy layer — shipped baseline (Track B)

**Shipped:**

- `scripts/core/strategy_engine.py` — `pool_index()`, `choose_profile()` with
  failure-label scoring and deterministic pool rotation.
- `scripts/core/strategy_profiles.py` + `scripts/apply_strategy_profile.py` — profile
  recommendation and CLI apply path.
- GUI **Apply Recommended** and optional auto-apply after non-healthy decision reports
  (`gui_preferences.auto_apply_strategy_on_probe`).
- `failure_classifier.run_staged_probe(host, port)` → `ProbeResult` with
  `phase_classification` (`dns_*`, `tcp_*`, `tls_*`, …).
- `path_scorer.py` scores phase-weighted reports; `decision_report.py` exports opt-in JSON.

**Shipped:** persistent `remember_winner()` cache — `scripts/core/strategy_winner.py`
(`.local-state/strategy-winner.json`).

Strategy sweep replaces “offset sweep” fantasies: score **named profiles**, not
raw-socket injection parameters.

## 8. Related documents

- Part II — quick routing table
- Part I ADR-0010 — implementation routing
- [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md) §4 — Tracks A–D
- [03-issues-risks-validation.md](03-issues-risks-validation.md) — risks and known issues
- [../sni-camouflage.md](../sni-camouflage.md)
- [../tun-operational-notes.md](../tun-operational-notes.md)
- [../local-telemetry.md](../local-telemetry.md)