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

### Wrapper modes (post-Phase 2 rename)

Note: the old names `preload-only`, `ptrace-assisted`, `seccomp-assisted-tracing`
have been REPLACED. Do not use them. Current modes (`-transport=<name>`):

- `preload`: pure libc-symbol interposition. Lowest overhead, dynamic-libc
  binaries only, no kernel-trap involvement.
- `systrap`: SIGSYS+seccomp BPF kernel-trap path. Catches direct syscalls that
  bypass libc (Go statically-linked binaries that don't go through libc, etc).
  Phase 1.
- `systrap-static`: like `systrap`, but with a freestanding-runtime preload
  that has zero libc dependency. For static binaries that lack a dynamic
  loader (musl-static, fully-statically-linked Go programs). Phase 2.
- `systrap-supervised`: ptrace-supervised systrap. The ptracer re-arms the
  preload across `execve` boundaries — including dynamic→static and the
  Chromium zygote fork+exec model. Phase 1.5+2 fusion.
- `ptrace`: ptrace-only fallback for hosts where seccomp BPF or RET_TRAP isn't
  available (some containers). Slowest path.
- `auto` (default): probes the host and the target binary, picks the fastest
  viable mode. Cascade order: `systrap-supervised` → `systrap` → `systrap-static`
  → `ptrace` → `preload`. Falls back fast on a static-target × no-ptrace host
  rather than silently mis-routing.
- `ptrace-seccomp`: legacy mode kept for diagnostic comparison. Excluded from
  the auto cascade — never selected unless requested explicitly.

The authoritative perf comparison + host-shape compatibility matrix:
- `docs/howto/wrapper-modes.md`

### Wrapper specifics worth knowing

- The published `cmd/uwgwrapper/assets/uwgpreload.so` is intentionally built
  against `ubuntu:18.04` (glibc 2.17) so it runs on every supported host
  baseline. Do NOT downgrade or remove that base in `.github/workflows/release.yml`.
- musl-arm64 needed an explicit `msghdr`-zero before populating sendmsg fields;
  uninitialized padding caused ENOBUFS. See `preload/core/`.
- The fxlock primitive had a bug in `try_wrlock` where the post-CAS
  reader-slipped-in retry path missed a `FUTEX_WAKE` for parked writers; this
  was fixed and a regression test exists. Do not regress.
- Phase 2's freestanding runtime (`preload/core/freestanding_runtime.c`) is
  the non-libc shim. `build_static.sh` produces the freestanding `.so`.
- `systrap-supervised` validated: dynamic→static execve seamless (incl.
  Chromium full zygote model rendering YouTube under real-internet smoke).
  The Chromium amd64 GH-runner-specific hang is a known continue-on-error
  matrix item; it reproduces in 8s on the self-hosted amd64 runner so it's
  not a blocker.

Key dirs:
- `preload/` (legacy LD_PRELOAD shim) and `preload/core/` (Phase 1+2 sources)
- `internal/uwgtrace/` (ptrace+seccomp engine, supervisor)
- `internal/fdproxy/` (socket bridge to uwgsocks)
- `cmd/uwgwrapper/` (CLI entry, supervisor glue, embedded assets)

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

## CI/testing model — three-tier cadence

This repo deliberately splits tests into three tiers by cost. The split is
load-bearing — do not collapse them, do not move chaos/soak/fuzz into the
fast tier, and do not drop the pre-commit budget:

### Tier 1 — pre-commit hook (≤ 10s wall, target ~5s)

`scripts/precommit.sh`. Symlinkable into `.git/hooks/pre-commit`. Runs:
1. `gofmt -l` on staged `.go` files.
2. `clang-format --dry-run --Werror` on staged `.c` / `.h` files (tolerates
   absence so contributors without clang-format don't get blocked).
3. Doc-link sanity (broken markdown link grep — we've had a few).
4. `go test -short -count=1 -timeout 30s ./...` — fast unit tests only.

Heavy integration tests opt out via `if testing.Short() { t.Skip(...) }`. The
load-bearing helpers that gate this:
- `mustStart` (full WG engine — `internal/engine/integration_test.go`)
- `mustStartMeshEngine` (mesh-control engine — `mesh_control_test.go`)
- `requirePhase1Toolchain`, `requireWrapperToolchain` (preload/wrapper builds)
- `TestLDPreloadManagedTCPUDPConnect`, `TestPreloadDNS` (slow preload tests)

Goal of `-short` mode: "would this catch a typo or a logic regression in code
the dev just wrote?" — NOT "is this test valuable in general?" Be ruthless.
Above the 10s ceiling devs reflexively start using `--no-verify`, defeating
the hook entirely. Pure-logic tests (packet parsers, ACL ordering, SOCKS
codecs, relay conntrack table) STAY in `-short`; anything bringing up a full
engine + WireGuard + netstack SKIPS.

### Tier 2 — `test.yml` per push (minutes)

`go test ./...` and the lite/race/exotic-arch matrix. Runs on every push and
PR. Target: under ~10 minutes per matrix entry. Catches mid-tier regressions
that didn't fire in the fast tier.

### Tier 3 — `release.yml` tag-triggered only (longer)

Chaos / soak / fuzz / multi-glibc / gVisor smoke. ONLY runs on tag pushes.
DO NOT add these steps to `test.yml` — that would slow PR feedback for every
developer push. Current Tier-3 steps:

- Mesh chaos suite — `TestMeshChaosResume_(Foundation|LossyDirectPath|
  AdvertisedEndpointThroughNAT|RelayFailoverOn100PercentDrop)`. UWGS_RUN_MESH_CHAOS=1.
  BLOCKING (no continue-on-error) — a real chaos failure stops the release.
- Wrapper fuzz (wg-quick parser, ACL parser, config parser) ~30s each.
- gVisor smoke — `uwgwrapper preload curl example.com` + `uwgwrapper systrap
  curl example.com` under `runsc do --network=host`. amd64 only initially.
- Phase 2 multi-glibc matrix (Ubuntu 18.04 baseline + musl + arm64).

Useful local commands:
```bash
bash compile.sh
go test -short ./...                                    # tier 1
go test ./...                                           # tier 2
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
go test -tags lite ./...
UWGS_RUN_MESH_CHAOS=1 go test -count=1 -timeout 900s \  # tier 3 (mesh chaos)
  -run 'TestMeshChaosResume_' ./internal/engine/
UWGS_STRESS=1 go test ./internal/engine/                # tier 3 (4-peer mesh)
```

### Mesh chaos infrastructure

`internal/engine/mesh_chaos_proxy_test.go` defines `chaosProxy`: a
single-socket UDP middleman with full-cone NAT semantics. Single-socket is
load-bearing — an earlier two-socket version exposed the upstream-dial
ephemeral port to the recipient, breaking mesh-control endpoint
advertisement (the advertised port wasn't reachable from other peers).
The single socket also lets the same proxy address serve as both "outbound
from local peer" and "inbound to local peer" in the production NAT shape.

Chaos test files (all `//go:build !lite`, gated by `UWGS_RUN_MESH_CHAOS=1`,
`-short`-skipped):
- `mesh_5peer_chaos_test.go` — 5-peer foundation + lossy-direct-path 2-peer.
- `mesh_chaos_advertised_endpoint_test.go` — pins NAT-translation
  invariants: hub learns peer-source = proxy.Addr; mesh-control advertises
  proxy addrs; relay-routed transfers survive 5%/20ms loss on BOTH legs.
- `mesh_chaos_relay_failover_test.go` — 100%-drop on direct path triggers
  `dp.Active=false` → automatic relay failover. Wall ~127s.

### Mesh-control timing gotcha

`MeshControl.ActivePeerWindowSeconds` defaults to 120 — DO NOT lower it for
test convenience. Values < ~120 conflict with wireguard-go's 120s rekey
cadence: `LastHandshakeTime` fluctuates above the window between rekeys, so
the hub intermittently stops advertising peers and clients drop them from
their dynamic-peer table mid-session. 120s is the smallest stable window.

### Other test gates

Real host-TUN smoke tests:
- `UWG_TEST_REAL_TUN=1`
- `UWG_TEST_REAL_TUN_DEFAULT=1`

Helper for emulated exotic-arch runs:
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

## Collaboration model (user preferences)

The repo owner has been explicit about how they want autonomous agents to
work this codebase:

- **Iterate to solid-green batches, then review.** Don't ping per-test or
  per-fix; commit between milestones, push when a coherent batch is green.
- **Tests must be mean and hard.** Production-faithful chaos beats happy-path
  smoke. If a test isn't exercising the real failure mode (e.g. naive
  `dp.Active=false` toggle isn't a faithful "WG path died" simulation),
  flag it and design the harder version.
- **Tier-1 chaos in release.yml is BLOCKING.** No `continue-on-error` on
  real chaos. The escape hatch is: re-run with the step disabled manually
  after confirming it was an environment flake. Don't silence failures
  pre-emptively.
- **Pre-commit budget is hard ≤10s.** ~5s preferred. Above 10s users
  reflexively `--no-verify`. When in doubt, `-short`-skip rather than tune.
- **One commit at a time, push to origin between milestones.** If something
  goes sideways the bisect surface stays small.
- **Multi-kernel QEMU matrix is a separate-branch project** (`kernel-matrix`,
  ~2 days). Don't try to land it on `main` in a single sweep.
- **gVisor matters.** `uwgwrapper` was designed for syscall-restricted
  sandboxes — gVisor is exactly that audience. Smoke step in release.yml
  (amd64 only initially) is the canary.

### Test-host shortcut (faster than CI)

Two real-internet test hosts are available for iterating when CI feedback is
too slow:
- amd64 VPS (see owner for SSH target)
- arm64 VPS (see owner for SSH target)

Use these to repro flake-class issues that need real-network or real-arch
behavior before pushing — especially Chromium-amd64 / chrome-headless-shell
interactions that misbehave on GH runners but reproduce in 8s on the
self-hosted amd64 box.

### Coding-style reminders worth re-stating

- **Don't add helper bloat.** A homegrown `errChainf`+`sprintfTest` to avoid
  importing `fmt` is not the win you think it is — review feedback rejected
  this once already. Just import `fmt`.
- **Avoid `--no-verify`, `--no-gpg-sign`, `--amend` of pushed commits.** All
  three have bitten this repo.
- **No emojis unless requested.** No README/MD files unless requested.
- **Comments earn their keep.** Default to no comment. Add one only when the
  WHY is non-obvious (a hidden constraint, a workaround for a specific
  bug, an invariant that would surprise a reader).
