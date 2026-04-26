<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Security Model

This document describes the trust boundaries `uwgsocks`, `uwgwrapper`,
`uwgfdproxy`, and the standalone `turn` daemon are designed to enforce,
and the deliberate non-goals. Read this before deploying in any
multi-tenant environment, before exposing a listener to the network, or
before mapping how the daemon's permissions interact with your wider
system.

If you are *changing the code* of those daemons, also read
[`docs/internal/security-conventions.md`](../internal/security-conventions.md)
— it covers the per-surface invariants and defense-in-depth conventions
that the architecture below depends on.

The security model is structural — it tells you *what* the project is
trying to protect against and *why* — not a changelog. For audit findings
and patches, see the project's git history.

## Trust boundaries

Every byte the daemon processes comes from a source with a defined trust
level. Surfaces that look similar from outside (HTTP proxy vs admin API,
WireGuard tunnel vs mesh control) have very different trust contracts.

### Untrusted sources

These produce bytes the daemon must treat as adversarial — bounds-checked,
size-capped, panic-free, race-free, and never allowed to execute code.

| Source | Where it enters | Why untrusted |
|---|---|---|
| Outer WireGuard packets (UDP, TCP, TLS, DTLS, HTTP/HTTPS, QUIC, TURN carriers) | `internal/transport/*`, `internal/wgbind/` | Anyone on the network path can send these. |
| Tunneled L4 traffic (TCP, UDP, ICMP) inside the tunnel | `internal/engine/transport.go`, `relay_conntrack.go`, `icmp_*.go` | Any peer can craft any inner packet, including malformed ICMP errors with embedded inner-headers. |
| DNS hostnames being resolved | `internal/engine/socks.go`, the DNS server, `/v1/resolve` | Hostnames come from applications using the proxy or the tunnel. |
| Application data over TCP/UDP through proxies (SOCKS5, HTTP, raw socket API) | `internal/engine/socks.go`, `proxy_protocol.go`, `socket_api.go` | Apps may be malicious or compromised. |
| SOCKS5 / HTTP proxy clients connecting to the daemon | the proxy listeners | The proxy listener is intended for *internal* use (LAN, container, host), not the wide internet. Still: hostile bytes from *internal* attackers are real. |
| Mesh control clients | `internal/engine/mesh_control.go` | Anyone who can handshake on the WireGuard tunnel can hit `/v1/challenge`, `/v1/peers`, `/v1/acls`. |
| `fdproxy` clients arriving at the `uwgsocks` API socket | `internal/engine/socket_api.go` via `fdproxy.go` | The `fdproxy` daemon is per-user, but a corrupted/buggy client still must not be able to crash `uwgsocks`. |
| `wg-quick` `.ini` configs from the network | `internal/config/config.go` (strict variants) | A user can paste a downloaded config into the runtime API. |

### Trusted sources

These have at least one credential check between them and the daemon.

| Source | Defense |
|---|---|
| YAML config (`--config`) | File on disk, supplied by the operator. |
| Runtime admin API (`/v1/*` plus `/uwg/*`) | Bearer token (`api.token`); optionally the `AllowUnauthenticatedUnix` flag declares a Unix socket trusted. |
| Application running under `uwgwrapper` / preload | Same uid as the wrapper, lives inside the wrapper sandbox. |
| `fdproxy` listener as seen by its own preload clients | Per-user Unix socket: `0o600` mode + `0o077` umask + Linux `SO_PEERCRED` check on accept (other uids rejected even if the socket file is somehow readable). |

### Explicit non-goals

Things the daemon deliberately does NOT defend against. These are not
oversights — they are choices that trade ergonomics or scope for
something the typical deployment doesn't need.

- **The HTTP / SOCKS5 proxy listeners are not for the wide-open internet.**
  They are intended for internal/LAN/container use. There is no per-IP
  rate limit on the proxy listeners by design — that trades ergonomics
  for a defense the deployment doesn't need. RCE-class bugs on those
  surfaces are taken extremely seriously; DoS resistance is an explicit
  non-goal. Don't expose `proxy.socks5` or `proxy.http` to a hostile
  network.
- **`uwgwrapper` is Linux-only.** Its preload + ptrace + seccomp paths
  depend on Linux ABI details. Don't assume macOS/BSD portability.
- **The mesh control plane is not a full SD-WAN controller.** It is a
  small, opt-in peer-discovery + ACL-distribution surface. If you want
  centralised policy, fleet management, or audit logging, that lives
  outside the daemon.
- **No anti-fingerprint guarantees on transports.** Transport modes are
  designed to traverse hostile networks, not to be indistinguishable
  from background traffic. If you need the latter, layer something
  that does that explicitly.

## Surfaces and where their defenses live

Each row is one network-reachable surface and the file the load-bearing
defenses live in. If you're auditing the daemon for deployment, this is
the surface enumeration. If you're changing the code, the linked
internal doc tells you what defenses to preserve.

| Surface | Files | Defense reference |
|---|---|---|
| Outer WireGuard transports | `internal/transport/*`, `internal/wgbind/` | [security-conventions.md § transports](../internal/security-conventions.md#outer-wireguard-transports) |
| Tunneled L4 (gVisor netstack inbound) | `internal/engine/transport.go`, `relay_conntrack.go`, `icmp_*.go` | [security-conventions.md § netstack inbound](../internal/security-conventions.md#tunneled-l4-gvisor-netstack-inbound) |
| Mesh control listener | `internal/engine/mesh_control.go` | [security-conventions.md § mesh control](../internal/security-conventions.md#mesh-control) |
| Runtime admin API + `fdproxy` socket-API | `internal/engine/api.go`, `socket_api.go`, `internal/fdproxy/` | [security-conventions.md § admin API + fdproxy](../internal/security-conventions.md#runtime-admin-api--fdproxy-socket-api-client) |
| SOCKS5 / HTTP proxy listeners | `internal/engine/socks.go`, `proxy_protocol.go` | [security-conventions.md § SOCKS/HTTP proxy](../internal/security-conventions.md#socks5--http-proxy-listeners-internal-use) |
| Outbound HTTP CONNECT proxy | `internal/engine/outbound_proxy.go` | [security-conventions.md § outbound CONNECT](../internal/security-conventions.md#outbound-http-connect-proxy-dialer) |
| `uwgwrapper` + preload | `cmd/uwgwrapper/`, `preload/`, `internal/uwgtrace/`, `internal/fdproxy/` | [security-conventions.md § wrapper + preload](../internal/security-conventions.md#uwgwrapper--preload-trust-boundary) |
| `wg-quick` INI parsing | `internal/config/config.go` | [security-conventions.md § wg-quick INI](../internal/security-conventions.md#wg-quick-ini-parsing) |

## Reporting a security issue

Open a GitHub issue *only* for low-severity / informational findings.
For anything that looks like RCE, sandbox escape, or auth bypass, please
email the maintainer directly so a fix can ship before public
disclosure.
