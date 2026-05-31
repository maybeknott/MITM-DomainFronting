# CA Install Guide

## Goal

Install the locally generated `mycert.crt` so the browser or OS trusts certificates issued by the local Xray tunnel.

## Before installing

Run:

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Record the SHA-256 fingerprint shown by the script. After installing, verify the trusted certificate fingerprint matches this value.

## Windows: install for current user or local machine

Recommended for most users: install only where needed. Browser-specific trust is preferred when practical.

Basic Windows flow:

1. Double-click `mycert.crt`.
2. Select **Install Certificate**.
3. Select **Current User** or **Local Machine**.
4. Select **Place all certificates in the following store**.
5. Choose **Trusted Root Certification Authorities**.
6. Finish the wizard.
7. Verify fingerprint with `docs/ca-verify-guide.md`.

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
