# CA Install Guide

## Purpose

Install the locally generated `mycert.crt` so your browser or operating system trusts certificates issued by the local Xray tunnel. Follow the platform steps below, record the SHA-256 fingerprint before installing, and complete verification before troubleshooting routing or DNS.

## Windows: install for current user or local machine

Recommended for most users: install only where needed. Browser-specific trust is preferred when practical.

Basic Windows flow:

1. Double-click `mycert.crt`.
2. Select **Install Certificate**.
3. Select **Current User** or **Local Machine**.
4. Select **Place all certificates in the following store**.
5. Choose **Trusted Root Certification Authorities**.
6. Finish the wizard.
7. Verify fingerprint with [`ca-verify-guide.md`](ca-verify-guide.md).

Before installing, run:

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Record the SHA-256 fingerprint shown by the script. After installing, verify the trusted certificate fingerprint matches this value.

PowerShell fingerprint check:

```powershell
Get-FileHash .\Xray-config\mycert.crt -Algorithm SHA256
```

## macOS

1. Open **Keychain Access**.
2. Drag `mycert.crt` into the login keychain or System keychain.
3. Open the certificate.
4. Expand **Trust**.
5. Set SSL trust according to your intended scope.
6. Verify fingerprint.

## Linux

Linux trust store paths vary by distribution. Common approaches:

Debian/Ubuntu:

```bash
sudo cp Xray-config/mycert.crt /usr/local/share/ca-certificates/mitm-domainfronting-mycert.crt
sudo update-ca-certificates
```

Fedora/RHEL-like:

```bash
sudo cp Xray-config/mycert.crt /etc/pki/ca-trust/source/anchors/mitm-domainfronting-mycert.crt
sudo update-ca-trust
```

Firefox may require importing the certificate into Firefox settings separately depending on configuration.

## Android

1. Copy `mycert.crt` to the device.
2. Open Android settings.
3. Go to security / encryption / credential storage section.
4. Select install from device storage.
5. Choose CA certificate.
6. Select `mycert.crt`.
7. Verify it appears under user certificates.

Android apps may ignore user-installed CAs or use certificate pinning. Browser success does not guarantee app success.

## Verification required

After installation, always run the verify guide. Do not troubleshoot routing before confirming the trusted CA fingerprint is correct.

## Related documents

| Document | Topic |
|---|---|
| [`ca-verify-guide.md`](ca-verify-guide.md) | Fingerprint and trust-store checks |
| [`ca-rotate-guide.md`](ca-rotate-guide.md) | Replacing an expired or mismatched CA |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Status, rotation, and lifecycle states |
| [`android-guide.md`](android-guide.md) | v2rayNG and Android user-CA setup |
