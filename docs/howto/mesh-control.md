<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Mesh Control And Peer Sync

`mesh_control` is the small tunnel-only HTTP control plane used by `uwgsocks`
peers to learn about other peers behind the same server or behind another
`uwgsocks` server.

This feature solves two different problems:

- **Peer sync / multi-server sync**: a second `uwgsocks` server can learn the
  currently active peers, public keys, `AllowedIPs`, and derived pairwise PSKs
  from a first server without copying every peer into static config.
- **Optional direct paths / P2P**: `uwgsocks` peers can learn each other's
  direct UDP-capable endpoints and create child peers for direct WireGuard
  sessions while still keeping the original server peer as the stable parent.

This is not a general public HTTP API. It binds only inside the userspace
WireGuard netstack, similar to `dns_server.listen`.

## What It Does

The mesh control server exposes:

- `/v1/challenge` for authenticated control sessions
- `/v1/peers` for peer discovery and syncing
- `/v1/acls` for distributed ACL state used by direct-path fallback

Discovered peers always include:

- the peer public key
- `AllowedIPs`
- the derived pairwise PSK for that peer pair

The advertised `endpoint` field is more strict:

- it is included only when the peer is currently reachable over a
  **UDP-capable outer transport**
- direct UDP and TURN-over-UDP are eligible
- HTTP/TLS/QUIC-only peers are still syncable, but they are not advertised as
  direct P2P candidates

That means mesh control can still be useful for multi-server synchronization
even when direct P2P is impossible.

## Why It Exists

Standard WireGuard is intentionally minimal. That is good for simplicity, but
it leaves two gaps:

- every peer normally has to be distributed into every other server/client
  config ahead of time
- discovering direct paths between clients usually requires an extra control
  plane

`uwgsocks` keeps the control surface small by exposing only the data another
`uwgsocks` peer needs to synthesize normal WireGuard child peers.

## Minimal Hub Config

```yaml
wireguard:
  private_key: SERVER_PRIVATE_KEY_BASE64
  listen_port: 51820
  addresses: [100.64.80.1/32]
  peers:
    - public_key: CLIENT_A_PUBLIC_KEY
      preshared_key: CLIENT_A_PSK
      allowed_ips: [100.64.80.2/32]
      mesh_enabled: true
      mesh_accept_acls: true
    - public_key: CLIENT_B_PUBLIC_KEY
      preshared_key: CLIENT_B_PSK
      allowed_ips: [100.64.80.3/32]
      mesh_enabled: true
      mesh_accept_acls: true

mesh_control:
  listen: 100.64.80.1:8787

relay:
  enabled: true

acl:
  relay_default: deny
```

The hub is still just a normal WireGuard peer. Mesh control only changes how
other `uwgsocks` peers can learn about currently active peers behind it.

## Minimal Mesh Client

```yaml
wireguard:
  private_key: CLIENT_PRIVATE_KEY_BASE64
  addresses: [100.64.80.2/32]
  peers:
    - public_key: HUB_PUBLIC_KEY
      preshared_key: CLIENT_A_PSK
      endpoint: edge.example.com:51820
      allowed_ips: [100.64.80.1/32, 100.64.80.3/32]
      persistent_keepalive: 25
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      # Omit this flag to accept distributed ACLs by default.
      mesh_disable_acls: false
```

This parent peer remains the stable route. Discovered child peers only become
active when they complete a direct WireGuard session.

## Trust And ACLs

For untrusted peers, direct-path fallback is only allowed when both sides
support the distributed dynamic ACL model.

Relevant peer flags:

- `mesh_enabled`: allow mesh control for that parent peer
- `mesh_disable_acls`: opt out of distributed ACL enforcement
- `mesh_accept_acls`: explicit capability bit; usually derived automatically
- `mesh_trust`:
  - `untrusted`
  - `trusted_always`
  - `trusted_if_dynamic_acls`

Use `mesh_trust` sparingly. It trusts the **WireGuard endpoint
implementation**, not the routed LAN behind it.

## Authentication Model

Mesh control auth is deliberately lightweight because it is expected to run
inside the encrypted WireGuard tunnel, but it still protects against ordinary
host-network probes and leaked control requests.

At a high level:

- the server rotates an ephemeral X25519 challenge key
- the client proves knowledge of its WireGuard static private key
- the server derives the shared secret using:
  - the challenge ephemeral key
  - the client ephemeral key
  - the server static WireGuard private key
  - the peer PSK, when configured
  - the observed source IP binding

That means an off-tunnel rogue HTTP endpoint cannot forge mesh responses just
by replaying the public challenge and the client request body.

## Tagged wg-quick Shortcut

You can opt a parent peer into mesh control from a normal wg-quick file with:

```ini
[Peer]
PublicKey = HUB_PUBLIC_KEY
AllowedIPs = 100.64.80.1/32, 100.64.80.3/32
Endpoint = edge.example.com:51820
#!Control=http://100.64.80.1:8787
```

That maps to:

- `control_url`
- `mesh_enabled: true`

## Operational Notes

- Mesh control is useful even without P2P. The sync path still distributes
  public keys, `AllowedIPs`, and pairwise PSKs.
- Direct P2P depends on both peers having UDP-capable outer transports.
- Standard WireGuard clients do not speak mesh control themselves. They can
  still benefit indirectly when a control plane generates multi-peer configs
  from the synced peer list.
- If you only want a simple rootless client/server, leave `mesh_control.listen`
  empty and omit `control_url`.
