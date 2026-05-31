# macOS Guide

## Steps

1. Ensure Xray is available.
2. Run:

```bash
sh Xray-config/certificate_generator.sh Xray-config
```

3. Install `Xray-config/mycert.crt` in Keychain Access.
4. Set trust for the intended scope.
5. Import the Xray config into your client.
6. Run:

```bash
python3 scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

## Checks

- Confirm ports 10808, 11666, 11777 are loopback-only.
- Confirm browser trust matches local certificate fingerprint.
- Confirm firewall does not expose local ports to the LAN.
