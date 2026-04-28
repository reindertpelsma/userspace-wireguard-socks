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

## WireGuard guard — threat model

The standalone TURN daemon can run with `wireguard_guard.enabled`,
which inspects every packet a TURN client sends and drops
non-WireGuard traffic before it reaches the relay back-end. This
is the load-bearing security feature when you run an open TURN
relay that's intended to carry only WG traffic — without it, any
TURN credential can relay arbitrary UDP to anywhere on your
trusted network.

### What is trusted

- The standalone daemon itself (you operate it).
- The WireGuard server behind the relay (you operate it).

### What is NOT trusted

- TURN clients with valid credentials. Even an authenticated
  client can be malicious — credentials don't imply intent.
- TURN message contents. The TURN protocol itself isn't encrypted;
  any on-path attacker can mangle messages.
- Inbound packet bytes from any source. The guard's parser is the
  primary attack surface — every TURN client can send arbitrary
  bytes that reach `ProcessInbound`.

### What the guard enforces

- Packet length bounds (handshake-init = 148 bytes, handshake-resp
  = 92, cookie-reply = 64, data ≥ 32). Out-of-spec sizes drop.
- mac1 verification on handshake initiation against the server's
  configured public key. Random bytes won't pass.
- Cookie/mac2 verification when the server is overloaded (cookie
  reply path).
- Per-IP handshake rate limiting (default 10/s sustained). Hostile
  IPs trying to flood don't get through.
- Roaming sustained-rate detection — abnormally fast endpoint
  changes from the same session get throttled.
- Session table cap at `max_sessions` (default 1000). Beyond the
  cap, the oldest session is evicted; the table can't grow
  without bound.

### What the guard does NOT do

- Encrypt TURN messages (TURN itself doesn't; TURNS over TLS
  does). An on-path attacker who can MITM the TURN carrier can
  disrupt connections by mangling ICMP or TURN-control messages —
  but they can't decrypt the WG payload, and they can't make the
  guard forward arbitrary traffic.
- Validate the source-IP claim on data packets. WireGuard's own
  cryptographic envelope authenticates the data; the guard relies
  on that.
- Filter the carrier transport (HTTP/QUIC/etc.). Use the carrier's
  own auth + TLS for transport-layer integrity.

### Why the guard makes a public-internet relay safe

The TURN protocol is, by design, an open relay — any
authenticated client can ask it to forward UDP to anywhere on
your trusted network. That's fine when you control every client
(P2P fallback for known users), but for a public ingress relay
fronting a hidden WireGuard server, you'd be handing every TURN
credential a "send arbitrary UDP into the LAN" capability.

The WG-guard inverts this: the relay still accepts arbitrary
TURN clients (the whole point — anyone with credentials can
connect to your hidden WG server), but **only valid WireGuard
traffic destined for one of your configured server keys passes
through**. Random UDP, malformed packets, and floods get dropped
at the parser stage before they reach the WG server.

This is what makes it safe to put the relay's listen port on
0.0.0.0 and publish the URL — the relay is a full ingress server
for the WG protocol, not a generic UDP forwarder.

### Hardening checklist for a public WG-guard relay

- `wireguard_guard.enabled: true` (otherwise it's a free-for-all
  — every authenticated TURN client can relay arbitrary UDP).
- Set `wireguard_guard.public_keys` to exactly the WG server keys
  you intend to ingress; never leave it empty. Random WG bytes
  with the wrong server key fail mac1 verification.
- Set `max_sessions` to bound the session table. Default 1000
  handles thousands of simultaneous WG peers; raise only if you
  have evidence you need more.
- Run the relay in an unprivileged container or systemd unit with
  the smallest capability set. `NoNewPrivileges`, no capabilities
  beyond what binding the listen ports needs.
- Monitor the `Sessions evicted` log line — sustained eviction
  means the cap is too low or someone is flooding (still bounded
  memory, but a flooder is using up the slots fresh peers would
  use).
- TURN credentials themselves can stay loose (or even open, with
  the right `permission_policy` — see "permission policy" below).
  The guard is doing the real work, not the credentials.

The fuzz target `FuzzWireguardGuardProcessInbound` runs in tier-3
release CI for 30 seconds per release, throwing random bytes at
the parser. Local 15-second runs at 20k execs/sec have not
discovered any panics.

## When To Reach For TURN

Use TURN when the real problem is reachability, not selective local routing.

- Need a rootless client proxy without exposing a server: use plain `uwgsocks`.
- Need to publish a hidden server through a small public box: use TURN.
- Need censorship or DPI evasion for a public edge: combine TURN or QUIC with
  the transport modes in [transport-modes.md](transport-modes.md).
