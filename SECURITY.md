# Security Policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting if it is enabled for this repository. If it is not available, open a minimal public issue that describes the affected file or behavior without posting private keys, cookies, credentials, request bodies, or full decrypted logs.

## Supported versions

Only the latest release is normally supported unless maintainers state otherwise.

## Sensitive material that must not be posted

- `mycert.key`
- local CA private keys, PEM keys, PKCS#12 bundles, or copied certificate-generation outputs
- full request logs
- cookies
- Authorization headers
- screenshots containing tokens or QR codes
- private account data

## Secret scanning

The repository must not track local CA keys, diagnostics, or release outputs. Local files such as `Xray-config/mycert.key`, `*.pem`, `validation-report.json`, and `checksums.txt` are ignored by git.

Before submitting changes, run:

```bash
python scripts/secret_scan.py
```

The scan only inspects tracked repository files. It fails on private-key-like filenames and PEM private key markers; it does not upload files or inspect traffic.

## Maintainer response

If sensitive material is posted publicly, maintainers should hide/delete it when possible and instruct the user to rotate their local CA.
