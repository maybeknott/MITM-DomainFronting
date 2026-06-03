# Android Trust Model

## Purpose

Explain why Android browser success does not imply app success. User-installed CAs, system CAs, app trust policies, and VPN/TUN behavior differ by app; use this model when triaging Android reports.

## Why Android behavior differs

Android separates user-installed CAs, system CAs, app trust policies, and VPN/TUN behavior. A browser may trust a user CA while an independent app may ignore it.

## Practical rule

Browser support is realistic. Arbitrary app support is not guaranteed.

## Compatibility classes

| Class | Expected result | Notes |
|---|---|---|
| Chromium-based browser trusts user CA | Usually works | Best non-root Android path |
| Firefox Android with third-party CA enabled | May work | Requires extra setting |
| App trusts user CAs | May work | App-specific |
| App trusts only system CAs | Usually fails | Not a config bug |
| App pins certificates | Usually fails | Do not try to bypass pinning |
| App uses QUIC/WebRTC heavily | May degrade or fail | UDP-heavy behavior must be tested |
| App uses custom network stack | Unknown | App-specific |

## Issue template language

When reporting Android issues, specify:

- Android version;
- device/vendor;
- v2rayNG version;
- browser or app name;
- whether browser works;
- whether the failing target is an independent app;
- whether HEV TUN is enabled;
- redacted preflight output if available.

## Recommended support wording

For app failures when the browser works:

```text
If the same service works in a browser but fails in the Android app, the app may ignore user CAs, use certificate pinning, use a custom network stack, or use UDP/QUIC/WebRTC paths not handled by the browser-oriented setup. Please test in a supported browser and provide platform details.
```

## Related documents

| Document | Topic |
|---|---|
| [`android-guide.md`](android-guide.md) | v2rayNG setup steps |
| [`platform-compatibility.md`](platform-compatibility.md) | Cross-platform support matrix |
| [`protocol-coverage.md`](protocol-coverage.md) | QUIC/WebRTC expectations |
| [`tun-operational-notes.md`](tun-operational-notes.md) | TUN vs browser proxy on Android |
