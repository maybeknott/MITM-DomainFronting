# Roadmap And Gap Tracker

This file tracks product coherence work that should remain visible between releases.

## Mission: stronger, smarter, easier anti-censorship

Per ADR-0009, defeating censorship and restoring open access is a **first-class
product goal**, on equal footing with safety and honesty. The architecture pursues
this in two complementary halves, both first-class:

- **A strong data plane (Xray-core, ADR-0001).** All on-the-wire evasion is
  expressed here: REALITY, uTLS fingerprint mimicry, TLS record fragmentation,
  padding/mux, domain fronting, FakeDNS, flexible routing. New evasion techniques
  are added as config-pipeline profiles or (if genuinely missing upstream)
  contributed to Xray-core in Go.
- **An intelligent strategy layer (this repo's Python + Rust).** Its job is to
  make that data plane self-healing: probe how *the user's own* network is
  blocking, classify the method, score candidate strategies, auto-select the one
  most likely to punch through, fail over automatically, and prove it worked with
  evidence. The Rust core models/validates/scores; Python orchestrates/probes;
  Xray executes.

The hard limits we keep are the ones that protect users, not censors: no silent CA
trust (ADR-0002), no silent privilege elevation (ADR-0006), local-only
source-labeled telemetry (ADR-0005), honest measurement (ADR-0004), single runtime
data plane (ADR-0001). None of these weaken evasion.

## Completed

- Shared `ProjectState`, `CheckResult`, and `RepairAction` readiness layer.
- `main.py probe` emits shared readiness state.
- GUI dashboard consumes readiness state for next action, safety banner, and status cards.
- Unsafe external listener detection is visible in CLI and GUI.
- Python regression tests moved to `tests/python/`.
- Release ZIP verifier added and wired into the GUI release workflow.
- Maintainer map and ADRs added.
- JA3 echo-oracle measurement wired into the stock-Chromium diagnostics probe
  (`--ja3-oracle` / `--expected-ja3`); result lands honestly in
  `fingerprint_validation` and stays `not_measured` without an oracle.
- `verified-session` evidence bundle command added
  (`py -3 main.py verified-session`) that composes the shared readiness state,
  an optional page check, and an optional JA3 oracle into one redacted
  `runtime-evidence.json` (config/profile hashes, listener/trust/cert evidence,
  PID dropped, root redacted).

## Target user

Per ADR-0006, the project optimizes for the **motivated intermediate user** via
progressive disclosure: one dominant next action up front, named intents instead
of raw files, consent-based setup (no silent trust install / no silent admin
elevation), and advanced surfaces available on demand. The "pure On/Off
appliance for fully non-technical users" is explicitly deferred because it would
require silent trust handling ruled out by ADR-0002.

## Anti-censorship capability roadmap (ADR-0009)

Three tracks. Each item must keep the data-plane boundary (ADR-0007/0008): evasion
is config + strategy, never raw packet surgery in the Rust crate.

### Track A — Evasion catalog (data-plane profiles)

Expand `config-src` / `configs` evasion profiles, each validated by
`scripts/config_src_validate.py` + route/structure tests, each with a named
operating profile and a smoke check.

- **Camouflage SNI ("SNI spoofing")** — the legitimate data-plane technique of
  presenting a front `serverName` that differs from the real target, defeating
  SNI-based DPI without raw packets or privileges. *Done (foundation):*
  documented in `docs/sni-camouflage.md`, inspected/validated by
  `scripts/core/sni_camouflage.py` (+ `tests/python/sni_camouflage_tests.py`); the
  shipped config already fronts via `tlsSettings.serverName`. *Next:* surface
  per-front selection in the strategy engine (Track B) and add REALITY
  `serverName` in a REALITY profile (below).
- **REALITY outbound profile** (`vless` + `reality`, server-side keys documented):
  the current strongest TLS-camouflage transport. Today the pipeline has uTLS
  `fingerprint: chrome`, ALPN control, and FakeDNS but **no REALITY profile** —
  this is the highest-value addition.
- **TLS record fragmentation** outbound (`fragment` settings: packets/length/
  interval) to split the ClientHello/SNI across segments and defeat naive SNI DPI
  without any raw sockets.
- **Padding / mux profile** to blur packet-size and timing fingerprints.
- **Multiple uTLS fingerprints** (chrome / firefox / safari / randomized) selectable
  per profile, not hard-coded to chrome.
- **ECH-readiness**: track Xray ECH support and add a profile + a `not_available`
  honest status until upstream lands it.

### Track B — Intelligent, adaptive strategy engine

Make strategy selection automatic and evidence-driven instead of manual.

- **Blocking-method classifier**: extend `scripts/core/failure_classifier.py` to
  label the user's path as RST-injection / SNI-filtering / timeout-drop /
  DNS-poisoning / TLS-alert, from real probe results (not hard-coded WinSock
  codes only).
- **Path scorer over real strategies**: evolve `scripts/path_scorer.py` so the
  offset-sweep concept becomes a *strategy sweep* (direct / fragment / REALITY /
  fronting / DNS-mode) scored by success, latency, and jitter against the user's
  own canary endpoints.
- **Auto-select + auto-failover**: a strategy engine (`scripts/core/strategy_engine.py`,
  new) that picks the best-scoring profile, switches Xray config via the existing
  generator, and re-probes/fails over when a strategy degrades. Rust may *model*
  and regression-test the selection logic; Xray applies it.
- **Strategy memory**: cache the winning strategy per network fingerprint locally
  (under `.local-state/`, redacted, ADR-0005) so reconnects are instant.

### Track C — Public-friendly, one-button experience (ADR-0009 + ADR-0006)

Strength must reach non-technical users without lying about consent.

- **"Connect / Get me through" one button**: runs setup checks, auto-selects the
  best strategy (Track B), and connects — escalating to the user *only* for the
  two things we never do silently: trust-store install and privilege elevation
  (ADR-0002/0006), each behind a clear, one-tap consent prompt.
- **Plain-language status**: "Finding a way through… Connected via REALITY /
  Fragmentation" instead of raw profile names, with the technical detail behind a
  details affordance.
- **Resilience proof on demand**: the one button can emit the `verified-session`
  bundle so a user (or helper) can confirm it really worked.

## Next (anchored to ADR-0006 progressive disclosure)

- Surface operating profiles as named intents (Standard / High Stealth / Legacy
  Network) bound to `ProjectState.active_profile` — a toggle with inline
  descriptions, never a file picker.
- Make auto-setup *prepare and recommend* CA + preflight in one flow, while
  routing trust install / admin elevation through explicit confirmation
  (reusing `RepairAction.requires_admin` / `confirmation_required`).
- Extract more of `scripts/gui.py` (currently ~5.5k lines) into focused GUI
  modules **under `scripts/`** (e.g. `scripts/core/` or a `scripts/gui/` package),
  keeping `scripts/gui.py` as the pinned entrypoint. The layout stays inside
  `scripts/` per `docs/repository-structure.md`; a separate top-level `app/gui/`
  tree is intentionally not adopted (it would break
  `tests/python/repository_structure_tests.py`, which pins `scripts/gui.py`).
- Add a guided trust checklist panel backed by shared readiness fields.
- Surface JA3 oracle fields and `verified-session` in the GUI (CLI path done).
- Add `verified-session` evidence output to release notes.
- Consolidate CA docs into a single certificate reference, and DNS/profile/
  protocol docs into a single network-model reference. **Note:** update
  `docs/repository-structure.md` and `tests/python/repository_structure_tests.py`
  in the same change — those pin the current per-topic doc paths, so a merge that
  only deletes the old docs would break the structure test.
- Add JSON schemas for `configs/`, `providers/`, and `config-src/`.

## Out of scope (deliberate)

- Single On/Off appliance with silent CA trust / auto-elevation (conflicts with
  ADR-0002; revisit only via a new ADR).
- Supercomposition rewrites: PyO3 interpreter embedding, Cap'n Proto / shared-
  memory IPC, Tauri/Slint UI migration, io_uring/eBPF kernel-bypass, embedding
  the Rust core inside Xray. These raise complexity/risk and conflict with
  ADR-0001 (Xray as runtime) and ADR-0003 (browser-proxy-first). Track as
  research, not roadmap.
- Raw-packet evasion data plane: TCP sequence-number / out-of-window injection,
  SNI/decoy-frame spoofing, eBPF/XDP packet rewriting, or a `cap_net_raw` Rust
  daemon / inline SOCKS5 bridge that makes the Rust core carry live traffic.
  Rejected by ADR-0008 (also ADR-0001/0007) **not** because evasion is unwanted
  but because it is the weak, brittle, privileged way to get it; the strong path
  is Track A/B above. Revisit only via a new ADR with a fresh threat-model and
  privilege/consent review, implementing any such primitive in Xray-core (Go).
- Top-level repo restructure into `app/gui/` + `tools/` and merging the per-topic
  `docs/` files into new `docs/reference/*.md` as a single big move. The intended
  layout is `docs/repository-structure.md`, enforced by
  `tests/python/repository_structure_tests.py`. Structure changes are welcome but
  must be incremental *with* matching updates to that doc and test in the same
  change, not a wholesale move that drops contract-pinned paths. Note that the
  bulk of the broader UX/evidence/release roadmap (shared `ProjectState`,
  unsafe-listener banner, `verified-session`, `release-check`, artifact verifier,
  source-labeled telemetry, tests under `tests/python/`, ADRs/maintainer map) is
  **already implemented** — see "Completed" and `docs/repository-structure.md`.

## Open Gaps

| Gap | Desired Outcome | Current Status |
|---|---|---|
| Per-process telemetry | Show app-owned Xray counters separately from system counters | System counters are labeled; per-process telemetry not implemented |
| JA3 oracle workflow | User enters oracle URL and expected hash; app records measured result | CLI + probe wiring done (`--ja3-oracle`); GUI flow still pending |
| Verified runtime session | One command saves redacted runtime evidence | Done via `py -3 main.py verified-session` |
| Docs consolidation | Fewer first-contact docs, stronger reference docs | Started with Farsi quick start, ADRs, maintainer map |
| GUI modularization | `scripts/gui.py` becomes a small entrypoint | Started with `scripts/core/gui_readiness.py` |
| Camouflage SNI ("SNI spoofing") | Front serverName != real target, validated and honestly documented | Foundation done: `docs/sni-camouflage.md` + `scripts/core/sni_camouflage.py` + tests; shipped config already fronts (Track A) |
| REALITY evasion profile | Strongest TLS-camouflage transport available as a named profile | Not present; highest-value evasion addition (Track A) |
| TLS fragmentation profile | SNI/ClientHello split to defeat naive DPI, no raw sockets | Not present (Track A) |
| Adaptive strategy engine | Auto-probe, classify blocking, score + select + fail over strategies | `path_scorer.py` + `failure_classifier.py` exist as building blocks; engine not built (Track B) |
| One-button public connect | Non-technical users get "Get me through" with consent-gated trust/elevation | Dashboard is state-driven; one-button auto-strategy flow pending (Track C) |
