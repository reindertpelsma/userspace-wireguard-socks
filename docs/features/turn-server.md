<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# TURN Integration And Relay Modes

There are two related TURN stories in this repository:

1. `uwgsocks` can use a TURN relay as the outer WireGuard path
2. the `turn/` directory contains the standalone public relay daemon

Most users care about TURN for one reason: make a hidden WireGuard server
reachable when direct UDP port forwarding is not available.

## Using TURN From `uwgsocks`

The preferred modern path is through `transports:`:

```yaml
transports:
  - name: turn-edge
    base: turn
    turn:
      server: turn.example.com:3478
      username: wireguard
      password: secret
      realm: example
      protocol: udp
      no_create_permission: true
```

Then point the peer at that named transport:

```yaml
wireguard:
  peers:
    - public_key: SERVER_PUBLIC_KEY
      endpoint: turn.example.com:3478
      allowed_ips:
        - 0.0.0.0/0
      transport: turn-edge
```

Use TURN when:

- the real server is behind NAT or CGNAT
- the real server sits behind a firewall you do not control
- you want a small public relay box instead of exposing the real server itself

## Standalone TURN Relay

The standalone daemon is documented in more depth at [../../turn/README.md](../../turn/README.md).
The main relay allocation models are:

### Fixed Port Per User

Best for: one hidden WireGuard server per TURN username.

```yaml
users:
  - username: wireguard
    password: secret
    port: 40000
```

### Username-As-Port Range

Best for: “the username selects the relay port” within a shared range.

```yaml
port_ranges:
  - start: 41000
    end: 41099
    password: shared-secret
```

### Per-User Dynamic Port Range

Best for: clients or ephemeral allocations that do not need one permanent port.

```yaml
users:
  - username: batch-worker
    password: secret
    port_range_start: 45000
    port_range_end: 45031
```

## WireGuard Guarding

The TURN relay can understand enough about WireGuard to behave like a safer
public edge in front of a hidden backend.

That matters because a normal public TURN relay would otherwise forward a lot of
garbage at the private server.

Useful relay-side settings:

```yaml
users:
  - username: wireguard
    password: secret
    port: 40000
    wireguard_mode: server-only
    wireguard_public_key: BASE64_SERVER_PUBLIC_KEY
```

From a user perspective, this buys you:

- the relay can pin traffic to the expected hidden server identity
- obviously invalid traffic is dropped at the edge
- abusive handshake floods are rate-limited before they hit the real backend

You do not need to understand the guard internals to use it. The important part
is: turn it on when the relay is protecting a hidden WireGuard server.

## Permissions Versus Relay Policy

For the common “public edge relay in front of one hidden WireGuard server”
pattern, the cleanest setup is usually:

- relay-side `source_networks` plus `permission_behavior` on the `turn` daemon
- `no_create_permission: true` on the hidden `uwgsocks` server
- optional WireGuard guarding on the relay side

That keeps the admission decision at the public edge and lets the hidden server
stay behind one stable mapped relay port without maintaining a static TURN peer
list.

Static `permissions:` on the `uwgsocks` side are still useful when you want the
client allocation itself to pin a narrow peer list. That is more relevant for
mesh or point-to-point TURN usage than for the “publish one hidden WireGuard
server behind a relay” pattern.

`permission_behavior` applies on the relay side:

- `allow`: accept peers from allowed `source_networks` even without explicit
  TURN permissions on the allocation
- `allow-if-no-permissions`: open until the allocation starts creating
  explicit permissions, then fall back to normal TURN permission checks
- `reject-unless-permitted`: require classic TURN permissions

## TURN Over Other Carriers

TURN itself can also ride over:

- UDP
- TCP
- TLS
- DTLS
- HTTP
- HTTPS
- QUIC

That is useful when even TURN needs to hide inside something more firewall
friendly than plain UDP.

## When To Reach For TURN

Use TURN when the real problem is reachability, not selective local routing.

- Need a rootless client proxy without exposing a server: use plain `uwgsocks`.
- Need to publish a hidden server through a small public box: use TURN.
- Need censorship or DPI evasion for a public edge: combine TURN or QUIC with
  the transport modes in [transport-modes.md](transport-modes.md).
