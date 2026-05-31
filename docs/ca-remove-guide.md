# CA Remove Guide

## Goal

Cleanly remove local certificate files and remove the trusted CA from the OS/browser trust store when no longer using the method.

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

Follow `docs/fakedns-recovery.md` to flush stale DNS caches if internet access is broken after disabling the method.
