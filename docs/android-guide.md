# Android Guide

## Purpose

Set up v2rayNG with a locally generated CA and the primary Xray config on Android. This path targets Chromium-based browsers first; independent apps may ignore user CAs or use certificate pinning.

## Steps

1. Install v2rayNG.
2. Generate `mycert.crt` and `mycert.key` locally on a trusted device or on Android if your workflow supports it.
3. Import both files into v2rayNG asset files if required by the client workflow.
4. Install `mycert.crt` as a user CA in Android settings.
5. Import `MITM-DomainFronting.json`.
6. Enable required TUN/VPN setting in v2rayNG according to the client guide.
7. Test with a Chromium-based browser first.
8. For Firefox Android, enable third-party CA support if needed.

## App limitation

If the browser works but an independent app fails, treat it as an app compatibility issue unless proven otherwise. Many apps do not use the user CA store.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Browser privacy error | CA not installed or wrong CA | Reinstall and verify fingerprint |
| Chrome works, Firefox fails | Firefox CA setting | Enable third-party CA support/import CA |
| Browser works, app fails | app pinning/custom trust | Use browser path or mark unsupported |
| Works on Wi-Fi not mobile | IPv6/NAT64/provider DNS | Add network details and DNS check |
| Internet broken after stop | FakeDNS/VPN cache | Toggle airplane mode and follow FakeDNS recovery |

## Related documents

| Document | Topic |
|---|---|
| [`android-trust-model.md`](android-trust-model.md) | User CA vs app trust behavior |
| [`ca-install-guide.md`](ca-install-guide.md) | Android CA install steps |
| [`tun-operational-notes.md`](tun-operational-notes.md) | TUN/VPN checks on Android |
| [`fakedns-recovery.md`](fakedns-recovery.md) | Network recovery after stop |
