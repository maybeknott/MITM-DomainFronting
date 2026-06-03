# CA Remove Guide

## Purpose

Remove the local test CA from OS and browser trust stores and delete local certificate files when you stop using the method. Complete all steps so stale trust entries do not cause privacy errors or unexpected TLS behavior on normal browsing.

## Step 1: stop the client

Stop v2rayN, v2rayNG, Xray, or any client using the config.

## Step 2: remove proxy/TUN settings

Disable system proxy or TUN/VPN mode in the client.

## Step 3: remove trusted CA

Windows:

1. Open certificate manager.
2. Go to Trusted Root Certification Authorities.
3. Find the certificate matching your `mycert.crt` fingerprint.
4. Delete it.

macOS:

1. Open Keychain Access.
2. Find the certificate.
3. Delete or set trust back to default.

Linux:

Debian/Ubuntu:

```bash
sudo rm -f /usr/local/share/ca-certificates/mitm-domainfronting-mycert.crt
sudo update-ca-certificates --fresh
```

Fedora/RHEL-like:

```bash
sudo rm -f /etc/pki/ca-trust/source/anchors/mitm-domainfronting-mycert.crt
sudo update-ca-trust
```

Android:

1. Open Settings.
2. Go to security certificates / user credentials.
3. Remove the installed user CA.

## Step 4: remove local files

```bash
python scripts/mitm_trust.py remove-local --cert Xray-config/mycert.crt --key Xray-config/mycert.key --yes
```

## Step 5: FakeDNS/network recovery

Follow [`fakedns-recovery.md`](fakedns-recovery.md) to flush stale DNS caches if internet access is broken after disabling the method.

## Related documents

| Document | Topic |
|---|---|
| [`uninstall.md`](uninstall.md) | Disable proxy, remove trust, and recover network |
| [`ca-verify-guide.md`](ca-verify-guide.md) | Confirm removal and fingerprint mismatch |
| [`fakedns-recovery.md`](fakedns-recovery.md) | DNS cache recovery after exit |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Local file and trust lifecycle |
