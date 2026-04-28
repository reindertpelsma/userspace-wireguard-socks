<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Architecture — high-level component map

## Top-level binaries

| Binary | What it does |
|---|---|
| `cmd/uwgsocks/` | the main runtime — WireGuard, netstack, proxies, ACLs, relay engine, raw socket API, runtime API |
| `cmd/uwgwrapper/` | Linux-only transparent app wrapper. Embeds `uwgpreload.so`. Multi-mode (preload, systrap, ptrace). |
| `cmd/uwgfdproxy/` | the fdproxy helper used by the wrapper |
| `turn/` | standalone public TURN relay daemon (separate Go module) |

## Internal packages

```
internal/
  config/       YAML parser, wg-quick parser, #! directive parser, transport-tag URL splitter
  engine/       runtime — proxies, forwards, relay, ACLs, socket API, mesh control, DNS, runtime API, traffic shaping, transparent inbound
  transport/    pluggable outer transports (UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC/TURN). Listener + client paths + carrier framing.
  tun/          host-TUN backends (Linux/macOS/Windows/FreeBSD/OpenBSD)
  wgbind/       binding layer between WG-go and the transport/dialer registry
  netstackex/   gVisor netstack helpers (MSS clamp, tun-integration shims)
  uwgtrace/     Linux ptrace+seccomp tracer used by wrapper modes
  fdproxy/      socket-bridge protocol manager used by wrapper paths
  uwgshared/    shared mmap state used by preload+wrapper+tracer cross-process
  acl/          ACL rule parser + matcher
  socketproto/  /v1/socket and /uwg/socket wire format
  buildcfg/     build-tag-aware config (lite vs full)
  uwgtrace/     ptrace tracer
preload/
  uwgpreload.c    legacy LD_PRELOAD shim (still the production default)
  core/           Phase 1+2: SIGSYS+seccomp, freestanding runtime, futex_rwlock primitive
  shim_libc/      libc-symbol shim layer (Phase 1 dynamic-binary fast path)
```

## Data flow — host-app → tunnel → peer

```
host app
   │  SOCKS5 / HTTP / wrapper-intercept / forward
   ▼
[ internal/engine: SOCKS / HTTP listener, wrapper listener, forward ]
   │  routing decision
   ▼
[ internal/engine: routing — local addr / reverse forward / peer AllowedIPs / outbound proxy / direct dial / relay-to-peer ]
   │
   ▼  (if peer AllowedIPs match)
[ internal/wgbind: select transport for this peer ]
   │
   ▼
[ internal/transport: encrypt + send via UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC/TURN ]
   │
   ▼
peer endpoint
```

The reverse path mirrors this — outer packets arrive on the
transport listener, decrypted by `wireguard-go` (vendored), and
delivered into the gVisor netstack via `internal/netstackex`. From
there they're surfaced through forwards, reverse-forwards, the raw
socket API, or the transparent-inbound path.

## Data flow — wrapper-intercepted Linux app

```
unsuspecting Linux app                  uwgsocks engine
       │                                       │
       │  socket()  → libc symbol shim         │
       │  connect() → SIGSYS handler           │
       │                                       │
       ▼                                       │
  [ preload/uwgpreload.c or preload/core/* ]   │
       │                                       │
       │  /uwg/socket protocol                 │
       └───────────────────────────────────────┤
                                               │
                                  [ internal/engine: socket API ]
                                               │
                                               ▼
                                       (tunnel side; same path
                                        as host-app data flow)
```

The wrapper has multiple interception strategies — see
[../features/transparent-wrapper.md](../features/transparent-wrapper.md).

## Mesh control

`internal/engine/mesh_control.go` implements an optional tunnel-only
peer-discovery + ACL-projection plane:

```
client polls hub: GET /v1/peers → list of peers visible to the hub
                  GET /v1/acls   → projected ACL subset for this client
client populates: e.dynamicPeers map → upsertDynamicPeerDevice (IpcSet to WG-go)
                  e.meshACLsIn / Out → applied alongside static ACLs
                  reconcileDynamicPeerPriority → reorder routing
```

See [../features/mesh-coordination.md](../features/mesh-coordination.md)
for the protocol and trust model.

## Build-tag matrix

| Tag | Effect |
|---|---|
| (default) | full feature set |
| `lite` | excludes mesh-control, traffic shaping, TURN, advanced transports |
| `race` | (used as `!race`) — Go race detector mode; chaos suite gated `!race` |
| `perf` | enables `tests/perf/` workloads (also gated by `UWGS_PERF=1`) |
| `integration` | heavy TURN integration test in `turn/` |

See [testing.md](testing.md) for the full build-tag + env-var
table.

## Where to start when contributing

| You're touching… | Read first |
|---|---|
| YAML keys / config | `internal/config/config.go` + `docs/reference/config-reference.md` |
| Routing decisions | `docs/features/proxies-and-forwards.md` (the order is load-bearing) |
| Adding a new transport | `internal/transport/registry.go` (registration), then your new `*_transport.go` next to its kin |
| ACL changes | `internal/acl/acl.go` + `docs/features/relay-and-acls.md` |
| Wrapper modes | `cmd/uwgwrapper/main.go` (mode dispatch) + `preload/core/*` (Phase 1+2) |
| Mesh-control wire | `internal/engine/mesh_control.go` + `docs/features/mesh-coordination.md` |
| Adding a metric | `internal/engine/metrics.go` + remember to update `docs/operations/observability.md` |
| Adding a config field | put a `// doc comment` above the struct field; `tools/genconfigref` regenerates the reference; pre-commit hook fails if the field has no docstring |
