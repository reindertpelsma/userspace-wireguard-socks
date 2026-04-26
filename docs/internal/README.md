<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Internal documentation

Docs in this directory are for **contributors working on the codebase**
(human or agent). They explain how the daemon is built, the conventions
to follow when changing it, and the load-bearing invariants you can't
see from the call graph.

If you are *deploying* `uwgsocks` rather than changing its code, you
want [`docs/howto/`](../howto/README.md) for guides and
[`docs/reference/`](../reference/) for behavioral references — start
there instead.

## What's in this directory

| Doc | Read this when … |
|---|---|
| [`security-conventions.md`](security-conventions.md) | You're touching any network-reachable surface or any auth/credential code. Lists the per-surface invariants and the defense-in-depth conventions that the architecture depends on. |
| [`lock-map-fdproxy.md`](lock-map-fdproxy.md) | You're changing anything in `internal/fdproxy/` or `preload/`. Maps every mutex, every acquisition site, lock-order rules, and the cross-process / cross-language locking story shared with the preload C code. |

More lock maps will land here as they're written; same shape, one per
package with non-trivial locking (`internal/engine`,
`internal/transport`, `internal/wgbind` are the next planned).

## Project shape (one-page)

`uwgsocks` is a rootless userspace WireGuard gateway and relay toolkit.
The code falls into seven loosely-coupled subsystems:

| Subsystem | Where | What it does |
|---|---|---|
| **Config** | `internal/config/` | YAML + wg-quick INI parsing, `#!` directive handling, Normalize(), defaults. Two parser variants (`MergeWGQuick`, `MergeWGQuickStrict`) for trusted vs hostile inputs. |
| **Transports** | `internal/transport/`, `internal/wgbind/` | Pluggable outer transports for WireGuard packets (UDP/TCP/TLS/DTLS/HTTP/HTTPS/QUIC/TURN, plus carrier modes). The `wgbind` package adapts these to wireguard-go's `conn.Bind` interface. |
| **Engine** | `internal/engine/` | The runtime. WireGuard device + gVisor netstack integration, proxy listeners, ACLs, relay conntrack, mesh control, runtime API, socket protocol, metrics. The biggest package by far. |
| **Netstack glue** | `internal/netstackex/` | Helpers for gVisor: forwarder setup, MSS clamp, packet filter, stats accessor. |
| **Preload + wrapper** | `cmd/uwgwrapper/`, `preload/`, `internal/uwgtrace/`, `internal/fdproxy/` | Linux-only LD_PRELOAD interception + ptrace/seccomp fallback that transparently routes a wrapped app through `uwgsocks`. `uwgfdproxy` is the per-user manager that bridges the wrapped app's file descriptors into the tunnel. |
| **Standalone TURN** | `turn/` | Independent TURN relay daemon. Has its own `go.mod` and its own release pipeline; talks to `uwgsocks` only as a regular TURN server would. |
| **CLI surface** | `cmd/uwgsocks/`, `cmd/uwgfdproxy/`, `cmd/uwgwrapper/` | Thin wrappers around the engine + helpers. `cmd/uwgsocks/api_client.go` is the small admin CLI (status, peers, ACLs, resolve). |

### Subsystem dependency direction

```
config ← engine ← cmd/uwgsocks
        ↑       ↘
   transport ← wgbind
        ↑
  netstackex

fdproxy ← cmd/uwgfdproxy
fdproxy ← preload (via Unix socket protocol; preload is C, not a Go dep)
fdproxy ← cmd/uwgwrapper

turn/   (standalone module)
```

`engine` is at the centre and depends on `config`, `transport`,
`netstackex`, `acl`, `socketproto`, `wgbind`, `tun`, `uwgshared`, and
the standard Go runtime libs. **`engine` does NOT import `fdproxy` or
`preload`** — those are reached only via the socket-API protocol over
HTTP, which keeps the wrapper subsystem genuinely separable.

## Build tags

Two build configurations:

- **Default (full):** every subsystem present. Used for the standard
  release artifacts.
- **`-tags lite`:** drops mesh control, traffic shaping, advanced WG
  transports, the metrics endpoint, and several other surfaces. Used
  for low-footprint / minimal-attack-surface deployments. Lite shaves
  ~32% off the binary and removes ~860 prometheus symbols.

The pattern, when a feature needs to be lite-aware:
- `feature.go` carries `//go:build !lite` and contains the full impl.
- `feature_lite.go` carries `//go:build lite` and contains the stub
  (typically a no-op or an explicit "not supported in lite" error).
- Always-built state (e.g. atomic counters whose call sites are in
  always-built files) lives in `feature_state.go` with no build tag.

`internal/engine/mesh_control{,_lite}.go` and
`internal/engine/metrics{,_lite,_state}.go` are the canonical examples.

## Testing layout

| Suite | What it covers |
|---|---|
| `go test ./...` | Unit + small integration tests inside each package. |
| `tests/malicious/` | Adversarial / regression tests for security fixes. New defenses MUST land with a regression test here. |
| `tests/preload/` | LD_PRELOAD + ptrace + headless-Chrome smoke tests. Slow (~85s) but exercises the wrapper end-to-end. |
| `tests/soak/` | Env-gated long-running soak tests (`UWGS_SOAK=1`). |
| `go test -tags lite ./...` | Same suite under the lite build. CI runs this. |
| `go test -race ./...` | Race detector. CI does not run this on `tests/preload` because of slow. |

The CI matrix builds for linux-amd64, linux-arm64, macos, windows, plus
cross-builds for FreeBSD/OpenBSD on amd64+arm64. Release builds add
linux-mips/mipsle/riscv64 and the musl/glibc split for `uwgwrapper`.

## Where common things live

| Looking for … | Look in … |
|---|---|
| The runtime API handlers | `internal/engine/api.go` |
| The `/v1/socket` raw socket protocol | `internal/engine/socket_api.go`, `internal/socketproto/protocol.go` |
| Routing decisions (local addr / reverse / AllowedIPs / proxy / direct) | `internal/engine/transport.go`, `internal/engine/socks.go`, `proxy_routing.md` reference |
| Mesh peer discovery / dynamic peers | `internal/engine/mesh_control.go` |
| Per-packet ICMP error parsing | `internal/engine/icmp_errors.go`, `relay_conntrack.go` |
| Strict wg-quick parsing | `internal/config/config.go` (`MergeWGQuickStrict`, `mergeWGQuick`) |
| The Prometheus metrics surface | `internal/engine/metrics.go` (full), `metrics_state.go` (always-built atomics), `metrics_lite.go` (stub) |
| The fdproxy lock model | [`lock-map-fdproxy.md`](lock-map-fdproxy.md) |
| The preload C side | `preload/uwgpreload.c`, `preload/shared_state.h` |
| The ptrace / seccomp tracer | `internal/uwgtrace/` (per-arch files) |

## Things that look weird but aren't

A short list of design decisions that surprise contributors. Each has a
load-bearing reason.

- **`addMemberLocked` doesn't mean "caller holds the lock"** — it
  means "this function locks the group's mu". Naming dates from before
  the lock-order rules tightened. See lock-map for the full rules.
- **The preload's shared-state mmap is `PROT_WRITE`** — not a bug.
  The wrapped app is trusted within its own user; a malicious app can
  already do anything the user can do. The threat model is documented
  in [`security-conventions.md`](security-conventions.md).
- **The runtime API and HTTP proxy listeners are separate ports by
  design.** Sharing them was considered and rejected; see git log for
  the discussion. The metrics endpoint is also separate, for the same
  scrape-secret-isolation reason.
- **`#!Control=`, `#!URL=`, `#!TURN=` directives in wg-quick are
  accepted from untrusted sources.** They describe how a peer wants to
  be reached, which is the peer's call. Only `Pre/Post Up/Down` is
  filtered. Spelled out in
  [`security-conventions.md § wg-quick INI`](security-conventions.md#wg-quick-ini-parsing).
- **`MultiTransportBind.acceptLoop` captures `b.closed` at goroutine
  creation rather than reading it from the field.** This is to avoid a
  race when `BindUpdate` (close+reopen) reassigns the field while the
  prior acceptLoop is still draining. See defense-in-depth convention
  #4 in `security-conventions.md`.

## Adding new internal docs

The bar: a doc belongs here if a future contributor (human or AI)
genuinely needs it to make a correct change. Things that don't belong:

- **Operator-facing material** — that goes in `docs/howto/` or
  `docs/reference/`.
- **Changelog / audit history** — git log is authoritative.
- **API reference** — Go doc comments and `go doc` cover this.
- **Anything that goes stale per release** — write a code comment
  next to the thing instead. Long-lived docs should describe
  invariants, not implementation details that move.

When adding a doc, link it from this README's table at the top so it's
discoverable. If two related internal docs exist, cross-link them
explicitly — `lock-map-fdproxy.md` and `security-conventions.md` cross-
link each other; follow the same pattern.
