<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 04 Firewall And ACLs

Previous: [03 Wrapper Interception](03-wrapper-interception.md)  
Next: [05 Mesh Coordination](05-mesh-coordination.md)

`uwgsocks` has three main policy planes:

- `inbound`: what a WireGuard peer may reach on this machine or behind this node
- `outbound`: what local proxy and socket-api clients may dial through the tunnel
- `relay`: what one peer may reach through another peer when this node is a relay

For most people, `inbound` is the important one first.

## Lock One Peer To One Service

The example file is [`examples/inbound-acls.yaml`](../../examples/inbound-acls.yaml):

```yaml
acl:
  inbound_default: deny
  inbound:
    - action: allow
      source: 100.64.82.2/32
      destination: 100.64.82.1/32
      protocol: tcp
      destination_port: 443
```

That means:

- peer `100.64.82.2` can reach `100.64.82.1:443`
- everything else is denied
- replies still work because the inbound connection already exists

If this node is terminating traffic into the host network, that one rule is the
difference between “this peer can hit exactly one HTTPS service” and “this peer
can wander around my private network.”

Validate the config:

```bash
./uwgsocks --config ./examples/inbound-acls.yaml --check
```

## Relay ACLs For Multi-Peer Routing

Once this node is relaying traffic between peers, use `acl.relay`:

```yaml
relay:
  enabled: true
  conntrack: true

acl:
  relay_default: deny
  relay:
    - action: allow
      source: 100.64.82.2/32
      destination: 100.64.82.3/32
      protocol: tcp
      destination_port: 443
```

That means peer `100.64.82.2` may reach peer `100.64.82.3:443` through this
relay, but no other peer-to-peer traffic is opened.

## Why Conntrack Matters

Relay policy uses a userspace conntrack table so replies and TCP state changes
can pass without turning the relay into a stateless hole punch. That is how you
get “allow one service” instead of “allow everything that looks vaguely related.”

Mesh adds one more layer on top: the relay can distribute projected dynamic ACLs
to peers that enforce them locally, so direct paths and relay fallback still
stay aligned. The deeper mechanics are in
[ACL model](../reference/acls.md) and [Mesh control](../reference/mesh-control.md).

## Runtime Updates

You can replace ACLs live through the API:

```bash
curl -X PUT \
  -H 'Content-Type: application/json' \
  --unix-socket uwgsocks.sock \
  http://localhost/v1/acls
```

For the full rule schema and mesh interaction model, jump to
[08 Reference Map](08-reference-map.md).
