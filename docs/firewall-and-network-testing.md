# Firewall and Network Testing

## Purpose

Verify that local proxy and decrypt ports bind to loopback only and are not reachable from other devices on public Wi-Fi or LANs. Use these scenarios when validating listener binding and host firewall posture.

Confirm that local ports are not reachable from other devices and that the config behaves reasonably on public Wi-Fi, normal LANs, and hostile local networks.

## Public Wi-Fi scenario

Assumption: other devices on the same Wi-Fi are untrusted.

Test:

1. Connect device A to public Wi-Fi.
2. Start the client.
3. From device A, run preflight.
4. From device B on the same Wi-Fi, attempt to connect to device A on ports 10808, 11666, 11777.
5. Device B should not be able to connect.

Expected result:

- device A listens only on `127.0.0.1`;
- firewall blocks inbound LAN traffic;
- no admin/API endpoint is exposed.

## LAN scenario

Assumption: home/office LAN devices are semi-trusted but should not access local proxy ports.

Test:

1. Start the client.
2. Verify listener binding.
3. Scan from another LAN device only if you own/control the LAN.
4. Confirm ports are closed from the LAN.

## Hostile local network assumption

Assume:

- another device can scan your ports;
- DNS can be manipulated;
- captive portal may hijack HTTP/DNS;
- LAN clients are not trusted.

Required handling:

- loopback-only listeners;
- firewall blocks inbound connections;
- no unauthenticated admin APIs;
- no private keys in logs or issue reports;
- use FakeDNS recovery if network is broken after stopping.

## Firewall guidance

Windows:

- Keep Windows Defender Firewall enabled.
- Do not create inbound allow rules for ports 10808, 11666, or 11777.
- If prompted by Windows firewall, deny public-network inbound access.

macOS:

- Keep firewall enabled if using public networks.
- Do not allow inbound access for unknown Xray/client prompts unless required and understood.

Linux:

Example UFW deny rules:

```bash
sudo ufw deny in to any port 10808 proto tcp
sudo ufw deny in to any port 11666 proto tcp
sudo ufw deny in to any port 11777 proto tcp
```

Loopback local use still works because firewall rules generally target inbound network interfaces, not local loopback.

## Related documents

| Document | Topic |
|---|---|
| [`listener-binding.md`](listener-binding.md) | Required ports and `listen` fields |
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Loopback checks in preflight |
| [`fakedns-recovery.md`](fakedns-recovery.md) | Network recovery after stop |
| [`THREAT_MODEL.md`](../THREAT_MODEL.md) | Untrusted LAN assumptions |
