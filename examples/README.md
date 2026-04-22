# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC

# Examples

These examples are runnable demonstration patterns, not production configs.
They ship with fixed public demo keys and placeholder secrets so they can be
loaded and tested out of the box. Replace keys, addresses, endpoints, and
tokens before real deployment.

- `client.yaml` / `client.conf`: simple outbound client
- `server.yaml` / `server.conf`: basic server / exit-node shape
- `exit-client.yaml` / `exit-server.yaml`: rootless exit-node pair
- `forwarding.yaml`: local forwards and reverse forwards
- `socksify.yaml`: `uwgwrapper` / proxy-oriented local app routing
- `turn-server.yaml`: legacy TURN transport example
- `mesh-control-hub.yaml`: hub/server with tunnel-only mesh control enabled
- `mesh-control-peer.yaml`: client/peer that learns discovered peers from a parent
- `transport-http-quic.yaml`: multi-transport edge using HTTPS, QUIC, TURN, and fronting knobs
- `relay-acls.yaml`: relay server with explicit relay ACL policy

See also:

- `docs/howto/mesh-control.md`
- `docs/transport-modes.md`
- `docs/config-reference.md`
