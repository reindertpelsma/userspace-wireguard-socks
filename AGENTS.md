# userspace-wireguard-socks (uwgsocks)

## Repository identity
`uwgsocks` is a rootless userspace WireGuard gateway and relay toolkit. It is
not just a SOCKS proxy and not just a `wireguard-go` wrapper. It combines:

- embedded WireGuard (`wireguard-go`)
- a userspace TCP/IP stack (gVisor netstack)
- proxy/listener/fronting entry points for host applications
- optional host-TUN integration
- alternative WireGuard transports for hostile or awkward networks
- relay / SD-WAN style peer forwarding and ACLs
- a Linux transparent wrapper (`uwgwrapper`)
- a standalone TURN relay server in `turn/`

The project is designed for environments where a kernel VPN, root privileges,
or host routing changes are undesirable or impossible.

Primary real-world roles:

- rootless WireGuard client
- rootless WireGuard server / relay hub
- proxy-aware app tunnel gateway
- transparent Linux app tunnel gateway via preload/ptrace/fdproxy
- transport-obfuscated WireGuard endpoint
- peer-sync / mesh-control assisted multi-peer network
- TURN-backed UDP relay path for WireGuard

## Main binaries
- `uwgsocks`
  - main data-plane binary
  - runs WireGuard, netstack, proxies, ACL engine, relay engine, raw socket API
- `uwgwrapper`
  - Linux-only launcher for transparently routing legacy apps via `uwgsocks`
  - embeds `uwgpreload.so`
  - can use preload-only or ptrace/seccomp-assisted interception
- `uwgfdproxy`
  - helper/manager-side bridge for wrapper paths
- `turn/turn`
  - standalone TURN relay daemon

## What the codebase actually does
### Core tunnel/data-plane
`uwgsocks` terminates or originates WireGuard sessions in userspace and then
routes host-originated traffic into those sessions using gVisor netstack or,
optionally, a host TUN device.

### Entry paths for traffic into the tunnel
- SOCKS5
- HTTP proxy
- local forwards
- reverse forwards
- raw socket API (`/v1/socket`, `/uwg/socket`)
- Linux wrapper path (`uwgwrapper`)
- host TUN mode
- transparent inbound from WireGuard peers to host services

### Exit paths for packets
For each IP packet or socket flow, the engine decides between:
- local tunnel address handling
- reverse forwards
- WireGuard peer `AllowedIPs`
- outbound proxy fallback
- direct host dialing
- relay-to-peer forwarding

The project deliberately prevents leaking traffic destined for local tunnel
subnets onto the host network.

## High-level architecture
1. Config is built from YAML, wg-quick config, `#!` directives, and CLI flags.
2. WireGuard device state is created from normalized config.
3. Transport registry resolves how outer WireGuard packets travel.
4. gVisor netstack or host TUN supplies local IP connectivity.
5. Proxies / forwards / raw socket API / wrapper feed flows into the engine.
6. ACL / relay / routing logic determines where each flow or packet goes.
7. Runtime API can mutate peers, ACLs, forwards, shapers, and some policy
   state without full restart.

## Directory map
- `cmd/uwgsocks/`
  - main CLI entry point
  - utility commands like key generation / config helpers / text status output
- `cmd/uwgwrapper/`
  - Linux wrapper CLI
  - embeds `assets/uwgpreload.so`
- `cmd/uwgfdproxy/`
  - fdproxy helper binary
- `internal/config/`
  - YAML parsing, wg-quick parsing, normalization, `#!` directives,
    transport scheme synthesis
- `internal/engine/`
  - main runtime
  - proxies, forwards, relay, ACLs, socket API, mesh control, DNS server,
    runtime API, traffic shaping, transparent inbound
- `internal/transport/`
  - outer WireGuard transports and listener/client registry
  - UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC/TURN logic
- `internal/tun/`
  - host-TUN manager abstraction
  - Linux/macOS/Windows/FreeBSD/OpenBSD backends
- `internal/wgbind/`
  - bind layer between WireGuard and transport/dialer logic
- `internal/netstackex/`
  - gVisor-related helpers (MSS clamping, tun integration helpers, etc.)
- `internal/uwgtrace/`
  - Linux ptrace/seccomp trace engine for wrapper interception
- `internal/fdproxy/`
  - socket-bridge manager used by wrapper/preload flows
- `preload/`
  - `uwgpreload.c`, the LD_PRELOAD shim for Linux
- `turn/`
  - standalone TURN server implementation, config, CI packaging
- `tests/`
  - integration, malicious/fuzz-style, preload, soak, and helper scripts

## Configuration model
Config comes from multiple layers:
1. YAML runtime config (`--config`)
2. wg-quick config (`--wg-config`, `--wg-inline`, `wireguard.config_file`, etc.)
3. CLI overrides and repeated adds

Important top-level YAML blocks:
- `wireguard`
- `transports`
- `proxy`
- `acl`
- `relay`
- `forwards`
- `reverse_forwards`
- `inbound`
- `dns_server`
- `api`
- `tun`
- `mesh_control`
- legacy convenience `turn`

The authoritative option-by-option reference is:
- `docs/config-reference.md`

The broader behavioral guide is:
- `docs/configuration.md`

## wg-quick `#!` directives
The parser also recognizes transport/control hints embedded in wg-quick comment
lines. These are important because `uwgsocks` client configs often use them to
carry runtime-only transport information that standard WireGuard ignores.

Important directives:
- `#!TURN=<url>`
- `#!URL=<url>`
- `#!Control=<url>`
- `#!TCP`
- `#!TCP=supported`
- `#!TCP=required`
- `#!SkipVerifyTLS=yes`

These live primarily in:
- `internal/config/config.go`
- `internal/config/transport_tags.go`

## Transport system
Supported base transports:
- `udp`
- `tcp`
- `tls`
- `dtls`
- `http`
- `https`
- `quic`
- `turn`

Important semantics:
- UDP is the normal WireGuard transport.
- TCP/TLS/DTLS are stream or datagram wrappers for difficult networks.
- HTTP/HTTPS support:
  - WebSocket framing
  - raw HTTP upgrade framing
- QUIC supports:
  - WebTransport
  - RFC 9220 WebSocket-over-HTTP/3 coexistence on the same listener/path
- TURN supports:
  - UDP/TCP/TLS/DTLS relay
  - HTTP/HTTPS/QUIC carrier modes for TURN itself

Transport config is startup-only. Runtime API updates do not hot-swap transport
listeners or peer transport definitions; those require restart.

Useful docs:
- `docs/transport-modes.md`

## URL / tagged scheme parsing
Peer endpoints and `#!TURN=` / `#!URL=` inputs use split `+` tag parsing.
Examples:
- `udp://`
- `tcp://`
- `tls://`
- `http://` (TURN over HTTP/WebSocket by default)
- `http+raw://`
- `https://`
- `turn+wss://`
- `quic+ws://`

The parser decomposes tags instead of treating every scheme as a hardcoded
opaque string.

## Routing model
Routing order matters and is reused across multiple entry paths.

Rough order:
1. local tunnel addresses
2. reverse forwards
3. peer `AllowedIPs`
4. local tunnel subnet reservation / leak prevention
5. outbound proxy fallback
6. direct host dialing if allowed

This applies to:
- SOCKS5
- HTTP proxy
- connected raw sockets
- fdproxy / wrapper traffic
- transparent inbound
- host TUN mode

Authoritative reference:
- `docs/proxy-routing.md`

## ACL model
There are multiple policy planes:
- outbound ACLs
- inbound ACLs
- relay ACLs
- dynamic mesh ACLs

Relay ACLs are stateful by default via userspace conntrack. Stateless fallback
for roaming/direct/relay transitions is intentionally gated and only permitted
under constrained conditions, including mesh/dynamic ACL capability or explicit
trust mode.

Important facts:
- ACLs are not just proxy ACLs; they affect relay and inbound behavior too.
- Mesh control can distribute projected ACL subsets to clients.
- Runtime API can replace ACL sets live.

## Mesh control / peer sync
This repo now includes an optional tunnel-only mesh control server and client
polling logic. It is not a full separate control plane; it is a small discovery
and ACL sync plane for:
- peer discovery
- direct UDP path attempts
- multi-server peer distribution/sync
- dynamic ACL projection

Important endpoints:
- `/v1/challenge`
- `/v1/peers`
- `/v1/acls`
- `/v1/resolve`
- aliases under `/uwg/...` for proxy-style access

Important mesh properties:
- challenge-based auth uses rotating X25519 challenge state
- current default is token version `v2`
- server accepts old/new versions for compatibility
- peer discovery trims dynamic peers to parent `AllowedIPs`
- dynamic peers never override static peers of the same key
- active direct peer state only affects route preference, not inbound acceptance
- endpoint advertisement is only included for UDP-capable peer transports
- non-UDP-capable peers can still be distributed for secondary-server sync

Mesh docs:
- `docs/howto/mesh-control.md`

## Runtime API
Served on `api.listen` via TCP or Unix socket.

Important endpoints:
- `GET /v1/status`
- `POST /v1/peers`
- `DELETE /v1/peers`
- `PUT /v1/acls`
- `PUT /v1/wireguard/config`
- `POST /v1/resolve`
- socket protocol upgrades on `/v1/socket` and `/uwg/socket`
- DoH-like resolver aliases on `/v1/resolve` and `/uwg/resolve`

The API is designed so `simple-wireguard-server` / `uwgsocks-ui` can manage
`uwgsocks` as a child process.

## Raw socket API
The socket API supports:
- TCP connect
- TCP listen / accept
- UDP sockets
- connected UDP
- ICMP ping-style sockets
- DNS frames
- bind/listen/accept semantics for tunnel-side access

It is used directly by some clients and internally by wrapper/fdproxy paths.

Spec:
- `docs/socket-protocol.md`

## DNS
There are two distinct DNS-related features:
- `dns_server.listen`
  - a DNS server hosted inside the tunnel for peers/clients
- `/v1/resolve` and `/uwg/resolve`
  - DNS-over-HTTP style runtime resolve API

The tunnel-side DNS server is for clients that should resolve through the
WireGuard side. The HTTP resolve API is for tooling/browsers/apps that already
speak HTTP(S) but need tunnel-aware DNS resolution.

## Host TUN
Host TUN is optional. It is implemented in `internal/tun/`.

Supported host-TUN backends currently exist for:
- Linux
- macOS
- Windows
- FreeBSD
- OpenBSD

Manager abstraction includes:
- create/start/stop device
- add/remove local tunnel addresses
- add/remove routes
- DNS configuration hooks
- bypass source-address snapshots for outer dialers

Notes:
- Linux has the strongest future story for policy-routing/fwmark-style bypass,
  but that is not implemented as a public opt-in mode yet.
- FreeBSD/OpenBSD currently rely on route/ifconfig style orchestration.
- DNS automation on BSD is intentionally simple; `tun.dns_resolv_conf` is the
  safest cross-platform explicit mechanism.

Useful docs:
- `docs/howto/host-tun.md`
- `docs/compatibility.md`

## TURN server
The standalone TURN daemon in `turn/` is not an afterthought. It has:
- multiple listener protocols
- relay port policies and dynamic ranges
- optional WireGuard-aware filtering / guard logic
- management API
- container packaging

TURN itself now supports HTTP/HTTPS/QUIC carriers and can be reverse-proxied.

Docs:
- `turn/README.md`

## `uwgwrapper`
`uwgwrapper` is intentionally Linux/Android-oriented.

It depends on Linux-specific pieces:
- `LD_PRELOAD`
- ELF/libc interposition assumptions
- Linux syscall ABI details
- `ptrace`
- `seccomp`
- `/proc`
- fdproxy manager protocol and Linux socket semantics

Do not assume portability to macOS/BSD. `uwgsocks` itself is broadly portable;
`uwgwrapper` is not. Treat wrapper portability as a separate project.

Wrapper modes:
- preload-only
- ptrace-assisted
- seccomp-assisted tracing on supported Linux arches

Key dirs:
- `preload/`
- `internal/uwgtrace/`
- `internal/fdproxy/`
- `cmd/uwgwrapper/`

## Lite build
There is now a `lite` build tag for a reduced feature set intended for
low-attack-surface or lower-footprint deployments.

Current lite behavior:
- keeps core UDP WireGuard runtime
- keeps main proxy/API functionality that is still useful in minimal setups
- excludes or rejects advanced features such as:
  - mesh control
  - traffic shaping
  - TURN
  - advanced transports outside the lite surface

The exact exclusions are enforced by build-tag-specific files and runtime
validation.

CI tests `-tags lite` on major platforms and release workflow publishes
`uwgsocks-lite` artifacts.

## Platform support snapshot
### Strongly supported / repeatedly exercised
- Linux amd64 / arm64
- macOS amd64 / arm64
- Windows amd64 / arm64
- FreeBSD amd64 / arm64
- OpenBSD amd64

### Additional release/build targets
- Linux riscv64
- Linux mips
- Linux mipsle

### Current guidance
- `uwgsocks`: broad cross-platform support
- `turn`: broad cross-platform support
- `uwgwrapper`: Linux/Android only
- 32-bit: not currently documented as supported; do not assume runtime support
  just because a cross-build succeeds

Details:
- `docs/compatibility.md`

## Build and packaging expectations
### Local build
- `bash compile.sh`
  - builds `uwgsocks`
  - builds `uwgwrapper` on Linux when toolchain is present
- `turn/compile.sh`
  - builds standalone TURN

### Installers
The repo now includes:
- `install.sh`
- `install.ps1`
- `install.bat`

Installer supports installing:
- `uwgsocks`
- `uwgsocks-lite`
- `turn`
- `uwgwrapper`
- `uwgkm`

### Containers
GHCR publish paths exist for:
- main `uwgsocks`
- TURN daemon

### Release artifacts
Current release workflows publish:
- `uwgsocks`
- `uwgsocks-lite`
- `uwgwrapper`
- `turn`

across the configured OS/arch matrix in `.github/workflows/release.yml`.

## CI/testing model
This repo is heavily test-driven and relies on a wide mix of test styles.

Important suites:
- `go test ./...`
- malicious cases in `tests/malicious`
- preload/wrapper coverage in `tests/preload`
- soak tests in `tests/soak`
- host-TUN smoke tests behind env flags
- BSD real-host validation has been done manually on real hosts

Useful commands:
```bash
bash compile.sh
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
go test -tags lite ./...
```

Real host-TUN smoke tests are gated by env vars like:
- `UWG_TEST_REAL_TUN=1`
- `UWG_TEST_REAL_TUN_DEFAULT=1`

There is also a helper for emulated exotic-arch runs:
- `tests/test-exotic-arches.sh`

Important nuance:
- `linux/386` lite cross-build currently works
- reliable `linux/386` runtime validation under Docker/QEMU on this Mac did not
  produce a trustworthy signal because the Go runtime/emulation path crashed in
  the emulation layer (`fatal: bad g in signal handler`)
- do not claim 386 runtime support without real 32-bit host validation

## Security / hardening notes that matter when editing
- WebSocket frame parsing has explicit upper bounds; do not reintroduce
  unbounded frame allocations.
- QUIC/WebTransport accept paths are overload-protected; do not block handler
  goroutines on full accept queues.
- SOCKS handshake/request reads are deadline-guarded.
- socket API UDP peer tracking is capped per session.
- runtime API auth reads current token dynamically; avoid startup-only capture.
- mesh auth now binds the client secret to the server static key in `v2`.
- URL transport QUIC and QUIC-WS now intentionally coexist on the same HTTP/3
  socket/path instead of a hidden extra listener port.

## Integration with `simple-wireguard-server`
`uwgsocks-ui` manages `uwgsocks` as a child daemon:
- writes canonical YAML (`uwg_canonical.yaml`)
- starts `uwgsocks --config uwg_canonical.yaml`
- talks over `uwgsocks.sock` or HTTP API
- pushes peer/ACL/runtime updates live
- restarts only when transport-level changes require it

The control plane also generates configs with `#!` directives that standard
WireGuard ignores but `uwgsocks` understands.

## Documentation map
Read these before large behavioral changes:
- `README.md`
- `docs/configuration.md`
- `docs/config-reference.md`
- `docs/transport-modes.md`
- `docs/proxy-routing.md`
- `docs/socket-protocol.md`
- `docs/testing.md`
- `docs/compatibility.md`
- `docs/howto/README.md`
- `docs/howto/host-tun.md`
- `docs/howto/mesh-control.md`
- `turn/README.md`
- `tests/README.md`

## Practical editing advice for future agents
- Prefer changing normalization/validation in `internal/config` before adding
  scattered ad-hoc behavior elsewhere.
- For transport changes, inspect both client and listener paths in
  `internal/transport` and `internal/wgbind`.
- For policy/routing changes, read `docs/proxy-routing.md` first; many subtle
  invariants are intentional.
- For wrapper work, keep Linux-only assumptions explicit rather than pretending
  generic Unix portability.
- For UI/control-plane behavior, remember `simple-wireguard-server` may depend
  on runtime API compatibility and generated config semantics.
