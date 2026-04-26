<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Security conventions (internal)

This is the developer-facing companion to
[`docs/reference/security-model.md`](../reference/security-model.md). The
reference doc tells operators *what* the daemon defends against; this doc
tells contributors *how those defenses are implemented* and the patterns
to follow when changing them.

If you're adding a new network-reachable surface or modifying an existing
one, read the relevant per-surface section before opening the PR. The
defenses here are not always obvious from the call graph — they depend on
invariants that span multiple files and packages.

## Per-surface defenses

### Outer WireGuard transports

Every transport (UDP, TCP, TLS, DTLS, HTTP/HTTPS WebSocket and raw
upgrade, QUIC including WebTransport, TURN over each of those) terminates
hostile bytes from the public network. Concrete invariants:

- **Frame size caps before allocation.** WebSocket payload length is
  validated against `maxWireGuardPacket` *before* the buffer is
  `make([]byte, payLen)`'d (`internal/transport/websocket.go`). The same
  pattern repeats in `tcp.go`'s `streamSession.ReadPacket`. Do not
  allocate a wire-derived length without a clamp first.
- **Concurrent connection caps.** The TURN HTTP/WebSocket and
  WebTransport carriers cap their `peers` map at 4096 concurrent
  sessions to bound memory and goroutine count under upgrade floods
  (`internal/transport/turn_carriers.go`).
- **HTTP header size caps.** WebSocket / TURN HTTP listeners set
  `MaxHeaderBytes: 32 KiB` instead of Go's 1 MiB default.
- **TURN allocation cap.** The standalone TURN daemon's
  pending-allocation queue has a hard cap (`turn/open_turn_pion.go:
  maxPendingAllocations`).

### Tunneled L4 (gVisor netstack inbound)

Per-packet handlers parse IPv4/IPv6 headers, transport headers (TCP/UDP),
and ICMP error inner packets. Concrete invariants:

- **Header bounds checked at every layer.** `parseRelayPacket` checks
  `len==0`, `parseRelayIPv4Packet` requires `>=20`,
  `parseRelayIPv6Packet` requires `>=40`, `packetPorts` requires `>=4`,
  TCP flags read is gated by `>=14`. ICMP error inner-packet parsing
  reuses these checks.
- **Conntrack table cap.** `relay_conntrack.go` enforces both global
  (`relay.conntrack_max_flows`) and per-peer
  (`relay.conntrack_max_per_peer`) caps so a chatty peer can't fill the
  table. Refusals increment `uwgsocks_conntrack_refusals_total`.
- **Stateless relay fallback is gated.** The conntrack-bypass fallback
  for roaming/direct/relay transitions only runs under specific
  conditions (mesh trust mode or explicit per-peer flag). Keep that
  gate strict; a permissive fallback would let an attacker bypass
  relay ACLs by walking source ports.

### Mesh control

(`/v1/challenge`, `/v1/peers`, `/v1/acls`, `/v1/resolve` aliases.)

The mesh listener is reachable by any peer that successfully handshakes
on the WireGuard tunnel. Defenses:

- **Per-source-IP token bucket** (10 rps, burst 20, max 4096 buckets,
  oldest-evicted) wraps the entire mesh mux. WG peers are not trusted;
  a flooder peer cannot keep the mesh control loop hot or evict
  legitimate peer state. See `meshControlRateLimit` in
  `internal/engine/mesh_control.go`.
- **Challenge / token (v2)** binds the server's static key into the
  auth key (defense in depth against future challenge-ephemeral
  compromise). v1 tokens are no longer accepted.
- **Constant-time secret comparison** for the bearer token and the
  ECDH-derived shared secret (`subtle.ConstantTimeCompare`).
- **Body size caps** on every JSON-decoding handler
  (`io.LimitReader`-wrapped `io.ReadAll`).
- **Dynamic peers never override static peers of the same key.** This
  is a hard invariant; `meshPeerConfig` is the one place that resolves
  the conflict and it always favors the static entry.

### Runtime admin API + `fdproxy` socket-API client

- **`AllowUnauthenticatedUnix` is the operator's explicit declaration**
  that anyone who can `connect(2)` to that socket is trusted with the
  whole admin surface — including `/v1/socket` (which can dial
  anywhere) and `/v1/resolve`. The flag is honored uniformly across
  endpoints; there are no carve-outs.
- **Token comparison is constant-time.**
- **Reading the token is dynamic** (per-request lookup against the live
  config), so rotating the token via the API takes effect immediately.

### SOCKS5 / HTTP proxy listeners (internal use)

- **`proxy.username` is optional.** When unset, only the password is
  validated; clients may present any username (or none). This makes the
  proxy usable as a password-only endpoint for newer integrations.
- **Per-conn UDP cap of 256 sessions, global SOCKS conn cap of 1024.**
  Bounds memory under abusive *internal* clients. The "capped"
  rejection increments `uwgsocks_socks_connections_capped_total`.
- **Handshake deadline (10s)** for SOCKS, request deadline (30s) for
  the request phase, idle timeouts for tunnels.
- **No per-IP rate limit by design** — the surface is internal-use.

### Outbound HTTP CONNECT proxy dialer

- **Fresh additive 10s deadline** around the CONNECT write+read, on
  top of whatever the caller's context deadline is. A nearly-exhausted
  context cannot leave a partial CONNECT line on a keep-alive proxy
  (request-smuggling shape).

### `uwgwrapper` + preload trust boundary

- **Preload is per-user.** The `fdproxy` Unix socket is bound under
  `umask 0o077` so the file is `0o600` from the moment it appears in
  the filesystem (closing the chmod race window) and the server
  enforces `SO_PEERCRED` on accept on Linux. Other uids are rejected
  even if the socket inode is somehow accessible.
- **Within a single user, the wrapped application is trusted.** The
  preload's shared-state region is `PROT_WRITE` mapped — that is by
  design, not a vulnerability. A malicious app can already do anything
  the user can do.
- **The shared mmap rwlocks have no kernel-mediated owner-death
  recovery.** A preload thread that crashes while holding the write
  lock permanently hangs the region. See
  [`lock-map-fdproxy.md`](lock-map-fdproxy.md) for the full picture
  and the planned robust-pthread mitigation.

### `wg-quick` INI parsing

- **Two parser variants:** `MergeWGQuick` (lenient — operator-supplied)
  and `MergeWGQuickStrict` (drops `PreUp`/`PostUp`/`PreDown`/`PostDown`
  silently, used for hostile sources like the runtime API and YAML
  loads with `scripts.allow=false`).
- **Other wg-quick fields and `#!` directives stay accepted by
  design.** `Endpoint`, `AllowedIPs`, `#!Control`, `#!URL`, `#!TURN`,
  `#!SkipVerifyTLS` describe how to talk to a peer or where to find
  dynamic mesh information — that is under the peer's control.
- **Engine-layer guard (`scripts.allow=false`)** is the second line of
  defense even if a hook key somehow slipped through.

## Defense-in-depth conventions

Patterns to follow when adding new code in any of these areas. These are
the conventions that make the per-surface defenses above keep working —
violating one tends to silently re-introduce a bug class we've already
fixed.

1. **Size-cap before allocation.** Validate any wire-derived length
   against an explicit upper bound *before* `make([]byte, n)`. The
   bound should reference a named constant (e.g. `maxWireGuardPacket`,
   `DefaultMaxPayload`).
2. **Constant-time comparison for secrets.** Always
   `subtle.ConstantTimeCompare`; never `==` or `bytes.Equal` for
   token/HMAC/PSK material.
3. **Bound concurrent state.** A new peer/session/connection map needs
   an entry cap and an eviction policy. The mesh control rate-limiter
   map and the TURN carrier `peers` map are the working examples.
4. **Capture, don't read.** Goroutines that outlive a bind/open/close
   cycle should *capture* synchronization channels at creation time,
   not re-read them from a struct field — see
   `internal/transport/bind.go`'s `acceptLoop`.
5. **Lock-order is `s.mu → g.mu`** in the `fdproxy` package. Never the
   reverse (deadlock). Full rules in
   [`lock-map-fdproxy.md`](lock-map-fdproxy.md).
6. **Pre-existing tunables should be `atomic.*` if a test mutates
   them.** The `tunnelDNSTCPDeadline` migration is the working
   example. A package-level `var X = 10 * time.Second` that any test
   rewrites is a data race waiting to happen under `-race`.
7. **Hot-path counters are atomic, scrape-time exposition is
   `prometheus.CounterFunc`.** Don't put a Prometheus `Counter` mutex
   on the data path. See `internal/engine/metrics_state.go`.
8. **New defenses get a regression test in `tests/malicious/`.** A
   defense without a regression test will silently regress the next
   time the surrounding code is refactored. The
   `TestFDProxyOtherUIDCannotConnect` and `FuzzMergeWGQuickStrict`
   tests are the working examples.

## When you change a surface

A short checklist before you open the PR:

1. Did you read the relevant per-surface section above?
2. Did you preserve every invariant the section enumerates?
3. If you removed an invariant, did you update both this doc and
   `docs/reference/security-model.md`?
4. Does your change cross a lock boundary? Re-read the lock map for
   the affected package.
5. Did you add a regression test under `tests/malicious/` for the
   thing you fixed or added?

If any answer is "no", that's a flag, not necessarily a block — but it
should be a deliberate "no" with a reason in the PR description.
