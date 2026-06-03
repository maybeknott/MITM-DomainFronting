# Transport Extension and Configuration Governance

## Purpose

Define in-scope transport work, engineering vocabulary, profile failure isolation, and CI guardrails for transport and profile changes. Proposals outside these boundaries should go to upstream engines or separate privileged components.

This document codifies the technical review matrix, engineering terms, and compliance guardrails governing transport modifications and profile evaluations within this repository.

## 1. Architectural Scopes & Boundaries

To maintain a stable, cross-platform codebase, all proposals must fit explicitly into one of the following two categories. Submissions attempting to introduce out-of-scope behaviors will be automatically rejected.

### In-Scope Tracks

1. **Config Profile:** Creating, tuning, or hardening configuration structures that target established, upstream runtime engines (e.g., `Xray-config/MITM-DomainFronting.json`).
2. **Diagnostic Probe:** Developing standard, user-space tools (e.g., Python validation functions or automated browser instrumentation passes) to verify routing and connection integrity.

### Out-of-Scope Tracks (Declined / External)

1. **Upstream Engine Proposal:** Code that modifies the core execution blocks, state machines, or protocol structures of proxy daemons. These changes must be submitted directly to their respective upstream core engines.
2. **Kernel / Raw Runtime Research:** Low-level networking implementations that require elevated execution permissions (e.g., L3 raw packet construction, OS fingerprint spoofing, or platform-specific eBPF kernel maps).

---

## 2. Technical Glossary

To eliminate ambiguity when evaluating configurations, the project uses the following domain-specific terms within internal code reviews and technical specifications:

* **Entropy Masking:** The design and verification of user-space configurations that randomize byte distributions across transport layers. This hides recognizable metadata structures from pattern-matching and traffic-shaping heuristics.
* **Protocol Fingerprint Alignment:** The mechanical synchronization of downstream client handshake patterns (such as JA4T configurations, TLS Extension sequences, or HTTP/2 frame sizes) with expected target baseline systems to ensure profile consistency.
* **Transport Profile Boundaries:** The explicit user-space configuration limits inside which an engine executes network modifications without altering host system permissions, routing integrity, or platform security baselines.
* **Route Determinism:** Complete path isolation ensuring that network streams exactly match intentional routing boundaries, eliminating accidental cleartext leakage or un-vetted system behavior.

---

## 3. Explicit Failure Isolation Matrix

We do not use automatic "transparent bypass" policies across all transport failures. Falling back to an unencrypted connection when a security layer fails compromises user data without warning.

Instead, failure handling is explicitly bound to our profile classification levels:

* **Strict Profile:** **Fail Closed.** Instantly cuts the local loopback listener. Drops the execution context to prevent cleartext leakage outside the encrypted network layer.
* **Balanced Profile:** **Controlled Failure.** Restricts connections to domains on explicit inclusion lists. Allows unmapped direct endpoints to route over standard connections only when explicitly declared.
* **Compatibility Profile:** **Explicit Fallback.** Direct routing fallback is permitted **only** when explicitly enabled by the user via structural configuration flags, backed by clear local notification logging.

---

## 4. Automated CI Guardrails

Our continuous integration toolchain runs `scripts/transport_experiment_validate.py` on every pull request. A proposal will be blocked immediately if it triggers any of the following conditions:

* Attempts to execute under root/administrative context or requests elevated system privileges (`CAP_NET_RAW`, `CAP_NET_ADMIN`).
* Modifies host platform security boundaries, such as injecting untrusted root certificates into system stores outside the ephemeral browser profile sandbox.
* Opens network access by defaulting to public relay configurations or enabling unsafe open proxies.
* Lacks a defined, verified rollback plan or leaves the repository non-goals array empty.

Manifest entries live in `configs/transport-experiments.json`.

## Related documents

| Document | Topic |
|---|---|
| [`transport-profiles.md`](transport-profiles.md) | Shipped transport expectations |
| [`operating-profiles.md`](operating-profiles.md) | Strict/balanced/compatibility/debug |
| [`protocol-coverage.md`](protocol-coverage.md) | Protocol support matrix |
| [`reference/02-decisions-evasion-engineering.md`](reference/02-decisions-evasion-engineering.md) | Evasion engineering decisions |
