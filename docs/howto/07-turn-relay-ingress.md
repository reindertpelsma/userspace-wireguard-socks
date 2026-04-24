<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 07 TURN Relay Ingress

Previous: [06 Mesh Coordination](06-mesh-coordination.md)  
Next: [08 Reference Map](08-reference-map.md)

This is the “my WireGuard server is behind NAT and I still want inbound
connectivity” pattern.

The idea is simple:

1. Run a small TURN daemon on a reachable host.
2. Let your `uwgsocks` server allocate a stable relay port there.
3. Point clients at that mapped relay port.

## Start A Local TURN Relay

```bash
turn -config ./examples/turn-relay-local.yaml
```

That example binds loopback TURN on `127.0.0.1:3478` and reserves relay port
`127.0.0.1:40000` for username `wireguard`.

## Start The TURN-Backed WireGuard Server

```bash
./uwgsocks --config ./examples/turn-server.yaml
```

The key bit is:

```yaml
turn:
  server: 127.0.0.1:3478
  realm: local-turn.example
  username: wireguard
  password: super-secret-turn-password
  permissions:
    - 127.0.0.1
```

That means the WireGuard server itself does not need a public UDP socket. It
binds through the TURN allocation.

For this localhost demo, the explicit permission is intentional: TURN
allocations only accept peer traffic they are permitted to talk to. On one box,
the peer source IP is `127.0.0.1`, so the demo pins that permission directly.

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
- optionally enable TURN-side WireGuard filtering
- when the relay policy is intentionally open, use `no_create_permission: true`
  on TURN transports instead of prelisting every peer source IP

This is the cleanest way to expose a server that cannot port-forward its own
UDP listener.

## Validation Note

The local loopback TURN demo now passes end-to-end in this sandbox after adding
the explicit localhost TURN permission.
