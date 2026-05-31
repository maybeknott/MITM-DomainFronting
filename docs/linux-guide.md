# Linux Guide

## Steps

1. Ensure Xray is installed or available in the current directory.
2. Generate local cert/key:

```bash
sh Xray-config/certificate_generator.sh Xray-config
```

3. Install `mycert.crt` into the distro trust store if system trust is desired.
4. Import the config into your client or run Xray directly according to your workflow.
5. Run preflight:

```bash
python3 scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

## Common distro trust commands

Debian/Ubuntu:

```bash
sudo cp Xray-config/mycert.crt /usr/local/share/ca-certificates/mitm-domainfronting-mycert.crt
sudo update-ca-certificates
```

Fedora/RHEL:

```bash
sudo cp Xray-config/mycert.crt /etc/pki/ca-trust/source/anchors/mitm-domainfronting-mycert.crt
sudo update-ca-trust
```

## Checks

```bash
ss -ltnp | grep -E ':10808|:11666|:11777'
```

Expected: loopback-only listeners.
