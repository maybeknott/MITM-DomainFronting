# Platform Compatibility

## Purpose

Summarize expected support and constraints per platform and browser class without
adding user-facing configuration branches. Use this matrix when triaging reports,
updating guides, or reviewing release claims.

The default operator path remains: generate local CA → import config → trust certificate → run client.

## Compatibility summary

| Platform | Expected support | Main constraints | Required docs |
|---|---|---|---|
| Windows | Primary supported platform | Certificate trust store, v2rayN path, local ports | Windows guide + CA install/verify |
| Android non-root | Browser-oriented support | User CA limitations, app pinning, HEV TUN behavior | Android guide + app limitation section |
| macOS | Should be supportable but must be tested | Keychain trust settings, firewall, browser trust | macOS guide |
| Linux | Should be supportable but distro-dependent | CA trust path, NetworkManager, browser stores | Linux guide |

## Browser compatibility

| Browser class | Expected behavior | Notes |
|---|---|---|
| Chromium-based desktop | Usually works if CA is trusted by OS/browser | Verify certificate fingerprint |
| Chromium-based Android | Usually best non-root Android path | Some devices vary |
| Firefox desktop | May use its own trust behavior depending on settings | Verify browser store separately |
| Firefox Android | May require third-party CA setting | Document exact steps |
| Browser with ECH/HTTP3 forced | May behave differently | Test and document |

## Android app compatibility

Many Android apps do not trust user-installed CAs, use certificate pinning, use custom trust stores, or rely heavily on QUIC/WebRTC. Those apps may fail even when the browser works. This is a platform/app design limit, not always a config bug.

Classify Android reports as:

```text
android_browser_supported
android_app_unknown
android_app_pinned_or_custom_trust
android_app_udp_heavy
android_app_unsupported_without_app_cooperation
```

## Platform checklist template

Record the filled version of this checklist in release evidence. The project docs should not carry stale one-off platform results.

| Item | Windows | Android | macOS | Linux |
|---|---|---|---|---|
| Xray version tested | record per release | record per release | record per release | record per release |
| Client version tested | record v2rayN | record v2rayNG | record client | record client |
| Browser version tested | record browser | record browser | record browser | record browser |
| CA generation tested | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| CA install tested | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| CA verify tested | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| Local ports checked | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| DNS check passed | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| FakeDNS recovery tested | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| IPv6 tested | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| QUIC behavior documented | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |
| Known unsupported app classes documented | pass/fail/not run | pass/fail/not run | pass/fail/not run | pass/fail/not run |

## Rust backend fallback contract

The Rust stream-core runtime accepts a backend preference but must not fail hard when packet backends are unavailable.

- `MITM_STREAM_BACKEND=loopback`: always available baseline path.
- `MITM_STREAM_BACKEND=android_tun`: requires Android runtime and a valid `MITM_STREAM_ANDROID_TUN_FD`; otherwise fallback to loopback.
- `MITM_STREAM_BACKEND=gateway_xdp`: requires Linux runtime and `MITM_STREAM_XDP_IFACE`; otherwise fallback to loopback.
- `MITM_STREAM_BACKEND=auto`: attempts packet backends opportunistically, then falls back to loopback.

This keeps desktop diagnostics and local orchestration usable even when Android/XDP capability is absent.

## Public Wi-Fi, LAN, and hostile local network assumptions

The method should be treated as a local-only tool. All local listeners should bind to `127.0.0.1` or `::1`. On public Wi-Fi or hostile LANs, a listener bound to `0.0.0.0` or a LAN IP may be reachable by other devices.

Required tests:

- Public Wi-Fi scenario: confirm local ports are not reachable from another device.
- LAN scenario: confirm no LAN address is listening on 10808, 11666, or 11777.
- Hostile local network scenario: confirm firewall blocks inbound traffic and only loopback clients can connect.

## Known limitation language for README

Recommended wording:

```text
This method is mainly browser-oriented. On Android without root, independent apps may fail because they can ignore user-installed CAs, use certificate pinning, or use network stacks that do not follow browser trust settings. A browser working does not guarantee every app will work.
```

## Related documents

| Topic | Document |
|---|---|
| Windows setup | [windows-guide.md](windows-guide.md) |
| Android setup | [android-guide.md](android-guide.md) |
| macOS setup | [macos-guide.md](macos-guide.md) |
| Linux setup | [linux-guide.md](linux-guide.md) |
| CA trust | [ca-install-guide.md](ca-install-guide.md) |
| Support matrix | [../SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md) |
| Issue registry | [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) |
