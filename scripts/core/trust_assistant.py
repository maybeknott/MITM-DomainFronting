#!/usr/bin/env python3
"""Advisory trust-store setup instructions with no privilege escalation."""
from __future__ import annotations

import argparse
import platform
from pathlib import Path


class TrustAssistant:
    def __init__(self, cert_path: Path) -> None:
        self.cert_path = cert_path
        self.system = platform.system().lower()

    def instruction_manifest(self) -> str:
        resolved = self.cert_path.resolve()
        lines = [
            "=" * 72,
            "Xray-Cooperative-Overlay Trust Assistant",
            "=" * 72,
            f"Certificate: {resolved}",
            "This tool prints instructions only. It does not elevate privileges or modify trust stores.",
            "",
        ]
        if not self.cert_path.exists():
            lines.extend([
                "Status: certificate file is missing.",
                "Create it first with:",
                "  python scripts/mitm_trust.py generate --out-dir Xray-config",
                "",
            ])

        if self.system == "windows":
            lines.extend([
                "Windows machine trust store:",
                "  Run in an elevated Administrator PowerShell:",
                f'  certutil -addstore -f "Root" "{resolved}"',
                "",
                "Windows verification:",
                "  Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*fromMitM*' }",
                "",
                "Firefox may use its own NSS store. Import the certificate in Firefox certificate settings if needed.",
            ])
        elif self.system == "darwin":
            lines.extend([
                "macOS system keychain:",
                "  Run in Terminal; macOS will request administrator approval:",
                f'  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{resolved}"',
                "",
                "macOS verification:",
                "  security find-certificate -c 'fromMitM' /Library/Keychains/System.keychain",
            ])
        elif self.system == "linux":
            lines.extend([
                "Debian/Ubuntu system trust store:",
                f'  sudo cp "{resolved}" /usr/local/share/ca-certificates/xray-cooperative-overlay.crt',
                "  sudo update-ca-certificates",
                "",
                "Linux verification:",
                "  openssl x509 -in /etc/ssl/certs/xray-cooperative-overlay.pem -text -noout",
                "",
                "Firefox may use its own NSS store. Import the certificate in Firefox certificate settings if needed.",
            ])
        else:
            lines.append("Unsupported platform. Import the certificate manually into the intended browser or OS trust store.")
        lines.append("=" * 72)
        return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Print trust-store setup instructions without modifying the system")
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    args = parser.parse_args()
    print(TrustAssistant(args.cert).instruction_manifest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

