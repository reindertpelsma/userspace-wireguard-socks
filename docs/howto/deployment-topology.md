<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Deployment Topology Guide

`uwgsocks` is not a single-shape tool. The same binary can act as a client
proxy, a relay hub, a hidden server, or a transparent process interceptor —
often simultaneously. This guide maps the common deployment shapes and
explains which components are active in each.

## Component overview

```
Internet / outer network
      │
      │  UDP · HTTPS/WS · QUIC/WebTransport · TURN
      │
  ┌───▼───────────────────────────────────────────────────┐
  │  WireGuard (userspace)                                 │
  │  ─ standard WireGuard protocol                        │
  │  ─ outer packet travels over a pluggable transport     │
  └───┬───────────────────────────────────────────────────┘
      │  decrypted inner IP packets
  ┌───▼───────────────────────────────────────────────────┐
  │  gVisor netstack (userspace TCP/IP stack)              │
  │  ─ terminates TCP connections, UDP flows               │
  │  ─ exposes them as Go net.Conn / net.PacketConn        │
  └───┬───────────────────────────────────────────────────┘
      │  flows
  ┌───▼───────────────────────────────────────────────────┐
  │  Engine: Routing · ACLs · Relay · Reverse Forwards    │
  │  ─ decides where each flow goes                        │
  │  ─ enforces inbound/outbound/relay ACLs                │
  │  ─ optional traffic shaping per peer                   │
  └───┬───────────────────────────────────────────────────┘
      │
  ┌───┴──────────────────────────────────────────────────────────┐
  │  Entry paths (one or more may be active at the same time)    │
  │                                                              │
  │  SOCKS5 listener       → browser, curl, any SOCKS5 client   │
  │  HTTP proxy listener   → curl --proxy, git, language SDKs   │
  │  Mixed listener        → SOCKS5 and HTTP on the same port   │
  │  Local forwards        → fixed host:port → tunnel:port      │
  │  Reverse forwards      → tunnel-ip:port → host:port         │
  │  Raw socket API        → socket protocol clients            │
  │  fdproxy / uwgwrapper  → transparent Linux process intercept│
  │  Host TUN device       → OS-level traffic (optional)        │
  └──────────────────────────────────────────────────────────────┘
```

`mesh_control` (when enabled) distributes peer lists and ACL projections
across the engine in the background. It does not add a separate data path.

---

## Deployment shapes

### 1. Rootless client proxy

The most common shape. One machine acts as a WireGuard client. Local
apps talk SOCKS5 or HTTP to `uwgsocks`. Traffic that matches WireGuard
`AllowedIPs` goes through the tunnel; everything else falls back directly
(or is rejected, depending on policy).

```
Browser / curl / git
      │
      │  SOCKS5 127.0.0.1:1080
      │  HTTP   127.0.0.1:8082
      ▼
  uwgsocks
      │  WireGuard (UDP or carrier)
      ▼
  Remote server / exit node
```

Relevant config: `proxy.socks5`, `proxy.http`, `proxy.fallback_direct`.
CLI quickstart: `uwgsocks --wg-config client.conf --socks5 127.0.0.1:1080`.

---

### 2. Rootless server / exit node

`uwgsocks` acts as the server that peers connect to. Inbound WireGuard
traffic is routed into the engine and — with `inbound.transparent` and
`host_forward.inbound.enabled` — can reach local host services or be
forwarded back out.

```
WireGuard peer (any transport)
      │
      │  WireGuard protocol
      ▼
  uwgsocks (server)
      │
      ├── host_forward.inbound → local host services (port 80, 443, …)
      ├── reverse_forwards     → host port listeners exposed to peers
      └── dns_server           → DNS inside the tunnel
```

Relevant config: `inbound.transparent`, `host_forward.inbound`,
`reverse_forwards`, `wireguard.listen_port`.
Example: `examples/server.yaml`.

---

### 3. Relay hub (SD-WAN shape)

`uwgsocks` acts as a relay between peers who cannot see each other
directly. The engine forwards L3 packets between peers according to
relay ACLs and optional conntrack state.

```
Peer A ──WireGuard──► uwgsocks (relay hub) ◄──WireGuard── Peer B
                            │
                       relay ACLs
                       conntrack (optional)
```

Relevant config: `relay.enabled`, `relay.conntrack`, `acl.relay`,
`acl.relay_default`. CLI flag: `--relay`.

With `mesh_control` enabled on the hub, peers discover each other and
attempt direct UDP paths. Relay acts as automatic fallback when the
direct path is down.

---

### 4. Hidden server behind a TURN relay

`uwgsocks` server does not need a public IP. It connects outbound to a
TURN relay. Clients reach it through the relay carrier.

```
Client ──TURN/WebSocket──► TURN relay ──TURN/TCP──► uwgsocks (server)
```

The server config uses a `#!TURN=turn+tls://...` directive or
`transports:` YAML. The client config uses the TURN relay as the
WireGuard `Endpoint`.

Relevant docs: `docs/howto/07-turn-relay-ingress.md`,
`docs/features/transports.md`.

---

### 5. Transport-obfuscated edge

When plain UDP is blocked, `uwgsocks` can wrap WireGuard inside:

- **TCP / TLS** — raw stream framing
- **HTTP(S) / WebSocket** — looks like normal HTTPS traffic
- **QUIC / WebTransport** — multiplexed, works through HTTP/3 load balancers
- **TURN over HTTP/HTTPS/QUIC** — TURN itself carried by a web carrier

```
uwgsocks (client) ──HTTPS/WebSocket──► Reverse proxy / CDN ──► uwgsocks (server)
```

Server and client exchange `#!URL=` or `#!TCP=` hints in the wg-quick
config, or use explicit `transports:` YAML. Both endpoints must agree
on the carrier scheme.

Relevant docs: `docs/howto/06-pluggable-transports.md`,
`docs/features/transports.md`.

---

### 6. Process-level tunnel enforcement (Linux)

`uwgwrapper` intercepts Linux processes transparently, without the app
needing SOCKS5/HTTP support. The app's socket calls are redirected to the
`uwgsocks` raw socket API via `fdproxy`.

```
Unmodified Linux app
      │  socket()/connect()/sendmsg() [libc or direct syscall]
      ▼
  uwgwrapper (preload / systrap / ptrace)
      │
      ▼
  fdproxy (socket bridge)
      │  raw socket API protocol
      ▼
  uwgsocks raw socket API (/v1/socket or /uwg/socket)
      │
      ▼
  WireGuard tunnel
```

Mode selection is automatic (`--transport=auto`) or explicit. Modes from
lowest overhead to broadest compatibility:

| Mode | Intercepts |
|---|---|
| `preload` | Dynamic-linked binaries via LD_PRELOAD |
| `systrap` | Direct syscalls from Go / non-libc binaries |
| `systrap-static` | Fully static binaries (zero libc dependency) |
| `systrap-supervised` | Across `execve` boundaries incl. fork+exec |
| `ptrace` | Any binary, maximum compatibility, lowest throughput |

Relevant docs: `docs/howto/03-wrapper-interception.md`,
`docs/features/transparent-wrapper.md`,
`docs/howto/wrapper-modes.md`.

---

### 7. Unix socket bridge

`uwgsocks` can bind forwards and reverse forwards on Unix domain sockets.
This lets local services and tools communicate across the WireGuard tunnel
over `unix://` paths, useful in CI or container environments where
network port allocation is awkward.

```
Local tool → unix:///tmp/uwg.sock (local forward) → tunnel:port
                                                     (or vice-versa via reverse forward)
```

Relevant docs: `docs/howto/09-unix-socket-forwards.md`,
`examples/unix-forwarding.yaml`.

---

### 8. Mesh coordination shape

Multiple `uwgsocks` nodes run with `mesh_control` enabled. A central hub
distributes peer tables and projected ACLs. Nodes attempt direct UDP paths
to each other; the relay hub is the fallback.

```
Node A ──mesh_control──► Hub (uwgsocks with mesh_control.listen)
Node B ──mesh_control──►     │
                             ├── distributes peer lists
                             ├── distributes ACL projections
                             └── acts as relay if direct path is down
```

Relevant docs: `docs/howto/05-mesh-coordination.md`,
`docs/howto/mesh-control.md`, `examples/mesh-control-*.yaml`.

---

## Component activation quick-reference

| Feature | Key config / flag |
|---|---|
| SOCKS5 proxy | `proxy.socks5` / `--socks5` |
| HTTP proxy | `proxy.http` / `--http` |
| Mixed SOCKS5+HTTP | `proxy.mixed` / `--mixed` |
| Local forward | `forwards:` / `--forward` |
| Reverse forward | `reverse_forwards:` / `--reverse-forward` |
| Relay | `relay.enabled` / `--relay` |
| Relay conntrack | `relay.conntrack` / `--relay-conntrack` |
| Inbound transparent | `inbound.transparent` / `--inbound-transparent` |
| Proxy host forwarding | `host_forward.proxy.enabled` / `--proxy-host-forward` |
| Inbound host forwarding | `host_forward.inbound.enabled` / `--inbound-host-forward` |
| Host TUN | `tun.enabled` / `--tun` |
| DNS server | `dns_server.listen` / `--dns-listen` |
| Management API | `api.listen` / `--api-listen` |
| Mesh control | `mesh_control:` (YAML only) |
| Outbound proxy fallback | `proxy.outbound_proxies` / `--outbound-proxy` |
| ACL inbound | `acl.inbound` / `--acl-inbound` |
| ACL outbound | `acl.outbound` / `--acl-outbound` |
| ACL relay | `acl.relay` / `--acl-relay` |
| Traffic shaping | `traffic_shaper:` / `--traffic-upload-bps` |

See `docs/config-reference.md` for the full option reference.
