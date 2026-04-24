<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 06 Mesh Coordination

Previous: [05 Pluggable Transports](05-pluggable-transports.md)  
Next: [07 TURN Relay Ingress](07-turn-relay-ingress.md)

`mesh_control` is the small coordination plane that turns a set of `uwgsocks`
nodes into one private peer network. It lets peers:

- discover other peers
- learn projected ACL state
- use a stable relayed parent path as the default backbone
- upgrade to a direct peer-to-peer path when both sides can reach each other

## Validate The Hub And Peer Examples

Hub:

```bash
./uwgsocks --config ./examples/mesh-control-hub.yaml --check
```

Peer:

```bash
./uwgsocks --config ./examples/mesh-control-peer.yaml --check
```

In plain terms:

- start with one reachable hub or parent node
- let remote peers join that private network through it
- allow the coordinator to tell peers about each other
- keep traffic on the relayed path when that is the only thing that works
- switch to a more direct path automatically when the network allows it

That gives you one multi-peer overlay without requiring every peer to be
publicly reachable.

## Hub Config

The hub exposes a tunnel-only controller:

```yaml
mesh_control:
  listen: 100.64.80.1:8787
  active_peer_window_seconds: 120
```

## Peer Config

The child peer points back to the parent:

```yaml
control_url: http://100.64.80.1:8787
mesh_enabled: true
```

## What It Buys You

The hub acts like the stable meeting point for your peer network. In a single
server setup, every peer can always fall back to that hub. In a multi-server
setup, you can distribute peers across more than one relay site while still
sharing discovery and projected policy.

When a laptop switches from Wi-Fi to 4G, the parent path stays up as the stable
anchor. If the network later allows a more direct peer-to-peer path,
`uwgsocks` can switch to it. If not, traffic keeps flowing through the relay.

That gives you:

- one private peer network
- stable relay-backed connectivity
- direct-path optimization when possible
- graceful roaming between network changes

## TURN And Mesh

Only UDP-capable outer transports can become direct peer-to-peer paths.
HTTP-only and TLS-only peers can still join the network, receive peer
discovery, and use relay paths, but they are not advertised as direct
connectivity candidates.

That is why TURN matters here too:

- direct UDP when possible
- TURN relay when necessary
- one control plane for both
