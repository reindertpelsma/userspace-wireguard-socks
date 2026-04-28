<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Mesh Control

`mesh_control` is the small coordination plane that lets `uwgsocks` peers learn
about each other without turning the project into a heavy external control
system.

The practical jobs it does are:

- publish a peer list inside the tunnel
- distribute projected ACL state
- help peers find direct paths when the outer transport supports it
- let more than one server share peer information instead of each relay becoming
  its own island

## Where It Listens

`mesh_control.listen` binds an HTTP server inside the userspace WireGuard
network, not on the host network:

```yaml
mesh_control:
  listen: 100.64.80.1:8787
```

That means only already-connected WireGuard peers can even reach the controller
address in the first place.

## Peer Settings That Matter

On a peer, mesh behavior is driven from the normal peer entry:

```yaml
wireguard:
  peers:
    - public_key: HUB_PUBLIC_KEY
      endpoint: 203.0.113.10:51820
      allowed_ips:
        - 100.64.80.1/32
        - 100.64.80.0/24
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      mesh_accept_acls: true
```

Useful fields:

- `control_url`: where this peer polls for controller data
- `mesh_enabled`: opt into discovery for this parent peer
- `mesh_accept_acls`: say that this peer can enforce distributed ACLs
- `mesh_disable_acls`: opt out of distributed ACL enforcement locally
- `mesh_trust`: how much fallback behavior the relay should allow when direct
  and relayed paths mix
- `mesh_advertise`: explicitly suppress advertising of a peer when needed

## What The Controller Returns

### `/v1/challenge`

Used to start authenticated polling. Returns:

- controller WireGuard public key
- short-lived challenge public key
- token version
- expiry time

### `/v1/peers`

Returns discovered peers that the caller is allowed to learn about. For each
peer, the useful fields are:

- `public_key`
- `endpoint` when the peer is a direct-path candidate
- `allowed_ips`
- `psk`
- `mesh_accept_acls`
- `mesh_trust`

### `/v1/acls`

Returns the projected ACL subset the caller should enforce locally:

- default action
- inbound rules
- outbound rules

## How Authentication Works

From a user point of view, the important fact is simple: only real WireGuard
participants in the mesh can fetch the peer list.

At a high level:

1. the controller publishes a short-lived X25519 challenge key
2. the client builds a bearer token from:
   - an ephemeral X25519 key
   - its real WireGuard identity
   - the controller's challenge key
   - the remote source address
   - the pairwise PSK material, if present
3. the controller verifies that:
   - the caller is a configured mesh-enabled peer
   - the caller's source IP matches that peer's routed address
4. the peer list and ACL payloads are returned encrypted with the derived
   shared secret

Current default token behavior is version `v2`, which binds the auth flow more
tightly to the controller's static WireGuard identity.

## Direct Paths Versus Relay Paths

Mesh control does not replace the stable parent path. It improves on top of it.

The normal sequence is:

1. a peer connects through a known parent or hub
2. it learns about other peers from the controller
3. if both sides have UDP-capable outer transports, they may try a more direct path
4. if that fails, traffic keeps flowing through the stable relay path

So the user-facing promise is not “always peer-to-peer.” It is “stable mesh
first, direct path when possible.”

## Multi-Server Use

You can run more than one relay site and still keep one shared peer inventory.

That is the main operational reason this feature exists: a team can have more
than one reachable server, but peers still discover each other through a common
controller instead of being stranded per site.

## Example

```yaml
mesh_control:
  listen: 100.64.80.1:8787
  active_peer_window_seconds: 120
```

```yaml
wireguard:
  peers:
    - public_key: HUB_PUBLIC_KEY
      control_url: http://100.64.80.1:8787
      mesh_enabled: true
      mesh_accept_acls: true
```

For a runnable walkthrough, see [../howto/05-mesh-coordination.md](../howto/05-mesh-coordination.md).
