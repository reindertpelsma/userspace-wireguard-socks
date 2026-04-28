<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Runtime API reference

`uwgsocks` exposes a management HTTP API on `api.listen` (defaults
empty — set `api.listen: "127.0.0.1:9090"` to enable).

Trust model: **the API is the trusted surface**. Bind to a
loopback or otherwise-firewalled address. Set `api.token` for
non-loopback binds. Token is read dynamically per request —
rotating the token doesn't require a restart.

## Status

```
GET /v1/status
```

Returns engine + per-peer state.

```json
{
    "running": true,
    "listen_port": 51820,
    "active_connections": 12,
    "peers": [
        {
            "public_key": "...",
            "endpoint": "203.0.113.5:51820",
            "allowed_ips": ["100.64.0.5/32"],
            "has_handshake": true,
            "last_handshake_time": "2026-04-28T10:15:00Z",
            "transmit_bytes": 102400,
            "receive_bytes": 51200
        }
    ],
    "dynamic_peers": [...],
    "transports": [...]
}
```

## Peer mutations

```
POST /v1/peers
```
Add a peer. Body: a single peer object matching the YAML `peers[]`
shape. Returns the added peer.

```
DELETE /v1/peers
```
Remove a peer. Body: `{"public_key": "..."}`.

## ACL replacement

```
PUT /v1/acls
```
Body: `{"inbound": [...], "outbound": [...], "relay": [...],
"inbound_default": "allow", "outbound_default": "allow",
"relay_default": "deny"}`. Replaces all three planes atomically.

## WireGuard config replace

```
PUT /v1/wireguard/config
```
Body: a YAML or wg-quick text. Replaces the WG layer's config.

## DNS resolve

```
POST /v1/resolve
```
Body: `{"name": "example.com", "type": "A"}`. Returns DNS records
resolved through the tunnel-side resolver. Aliased at
`/uwg/resolve` for proxy-style access.

## Socket protocol upgrades

```
GET /v1/socket
GET /uwg/socket
```
Switching-protocols upgrade to the documented socket protocol
(see [socket-protocol.md](socket-protocol.md)). Used by language
SDKs and the `uwgwrapper` toolchain.

## Auth

When `api.token` is set, every request needs:
```
Authorization: Bearer <token>
```

Loopback binds (`127.0.0.1` or `::1`) skip auth by default — set
`api.require_auth_on_loopback: true` if you need auth even there.

## Stability

Every endpoint above is in scope for the [v1.0 stability
promise](../../STABILITY.md). New endpoints + new optional fields
on existing endpoints are additive. Removing endpoints or fields is
a major-version bump.
