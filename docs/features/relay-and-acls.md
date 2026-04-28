<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# ACL Model

`uwgsocks` does not have one firewall. It has several policy planes that apply
at different points in the data path.

If you are deciding where to put a rule, this is the page to read.

## The Three Main Policy Planes

### `acl.inbound`

Use this for: “What may a WireGuard peer reach on this node or behind this
node?”

Typical examples:

- let one peer reach `100.64.90.1:443`
- deny access to everything else
- allow DNS but deny arbitrary TCP ports

This is the policy that matters most when you are exposing local services or
using transparent inbound routing.

### `acl.outbound`

Use this for: “What may local proxy clients or socket-api users dial through
the tunnel?”

Typical examples:

- allow egress only to one subnet
- block direct access to internal admin ranges
- restrict what a local automation sidecar may reach

### `acl.relay`

Use this for: “What may one WireGuard peer reach through another peer when this
node is acting as a relay?”

Typical examples:

- allow peer A to reach peer B on `tcp/443`
- deny all other east-west traffic
- allow DNS or one service, but not full lateral movement

## Rule Shape

All ACL lists use the same rule object:

```yaml
- action: allow
  source: 100.64.0.2/32
  destination: 100.64.0.10/32
  protocol: tcp
  destination_port: 443
```

Rules are ordered. First match wins. If nothing matches, the corresponding
default decides.

## Relay Conntrack

When `relay.conntrack: true` is enabled, relay rules are stateful. That means:

- the forward direction must match the ACL rule
- replies are then tracked and allowed automatically
- TCP state changes and normal response traffic work without opening a
  stateless hole

For most relay deployments, this is the right mode.

## Mesh And Dynamic ACLs

Mesh control can distribute projected ACL state to peers. The practical point
is simple:

- the relay still enforces its own policy
- clients can also enforce the same projected policy locally
- direct peer paths and relay fallback stay aligned instead of drifting apart

Two peer settings matter here:

- `mesh_accept_acls`: this peer is willing to enforce distributed ACLs
- `mesh_trust`: how much the relay should trust this peer when relay fallback
  and direct paths mix

The useful mental model:

- `untrusted`: default, safest posture
- `trusted_always`: allow broader stateless fallback behavior
- `trusted_if_dynamic_acls`: only loosen fallback behavior when the other side
  is also ACL-capable

That last mode exists for the common “direct path when possible, relay fallback
when needed” deployment without giving up policy entirely.

## Example Layout

Lock one peer to one service on this node:

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

Lock one peer-to-peer path through a relay:

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

## Runtime Updates

ACLs can be replaced live through the runtime API. That is what
`simple-wireguard-server` and other control-plane tools rely on.

Relevant endpoints:

- `PUT /v1/acls`
- `GET /v1/status`

For the exact field names, see [config-reference.md](../reference/config-reference.md).
