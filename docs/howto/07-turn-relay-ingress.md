<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 07 TURN Relay Ingress

Previous: [06 Pluggable Transports](06-pluggable-transports.md)
Next: [08 Reference Map](08-reference-map.md)

This is the “WireGuard server behind NAT, but still reachable for inbound
clients” pattern.

The idea is simple:

1. Run a small TURN daemon on a reachable host.
2. Let your `uwgsocks` server allocate a stable relay port there.
3. Point clients at that mapped relay port.

The relay is not just a dumb UDP hose. In WireGuard mode it can:

- pin traffic to the expected hidden server public key
- drop garbage before it hits the real backend
- slow obvious handshake floods before they hit the real backend

## Start A Local TURN Relay

```bash
turn -config ./examples/turn-relay-local.yaml
```

The example file is [`examples/turn-relay-local.yaml`](../../examples/turn-relay-local.yaml):

```yaml
realm: "local-turn.example"
software: "uwgsocks-local-turn"
allocation_ttl: "10m"
nonce_ttl: "10m"

listen:
  relay_ip: "127.0.0.1"

listeners:
  - type: "udp"
    listen: "127.0.0.1:3478"

users:
  - username: "wireguard"
    password: "super-secret-turn-password"
    port: 40000
    permission_behavior: "allow"
    source_networks:
      - "127.0.0.0/8"
    mapped_address: "127.0.0.1:40000"
    wireguard_mode: "server-only"
    wireguard_public_key: "QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI="
```

That binds loopback TURN on `127.0.0.1:3478` and reserves relay port
`127.0.0.1:40000` for username `wireguard`.

## Start The TURN-Backed WireGuard Server

```bash
./uwgsocks --config ./examples/turn-server.yaml
```

The important part is:

```yaml
turn:
  server: 127.0.0.1:3478
  realm: local-turn.example
  username: wireguard
  password: super-secret-turn-password
  no_create_permission: true
  include_wg_public_key: false
```

That means the WireGuard server itself does not need a public UDP socket. It
binds through the TURN allocation.

For normal WireGuard ingress, this is the right shape:

- do not maintain per-client TURN permissions
- let the TURN relay's own policy decide who may hit the mapped relay port
- let the WireGuard-aware guard filter by the hidden server identity

## Start A Client

```bash
./uwgsocks --config ./examples/turn-client.yaml
```

The paired [`examples/turn-client.conf`](../../examples/turn-client.conf) uses:

```ini
Endpoint = 127.0.0.1:40000
```

That endpoint is the TURN relay's mapped port, not the private server host.

## Production Version

In a real deployment:

- run `turn` on a small VPS or public edge box
- keep the private WireGuard server behind NAT
- publish one mapped relay port per server identity
- use `no_create_permission: true` and relay-side policy instead of prelisting
  every client IP
- enable TURN-side WireGuard guarding so the relay can filter inbound traffic
  by the server's public key before it reaches the hidden backend
- let the TURN edge absorb random Internet noise, bad handshakes, and obvious
  abuse instead of spraying every packet at the private WireGuard node

This is the cleanest way to expose a server that cannot port-forward its own
UDP listener.
