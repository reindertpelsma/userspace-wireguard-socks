<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Metrics

`uwgsocks` exposes optional Prometheus-compatible metrics on a separate
listener from the admin API. Read [security-model.md](../contributing/security-conventions.md)
first if you haven't — the trust boundary between the two listeners is
the load-bearing reason the metrics endpoint is its own port.

## Configuration

```yaml
metrics:
  listen: "127.0.0.1:9091"   # empty disables the subsystem entirely
  token: ""                  # empty = no auth; set to require Bearer token
  per_peer_detail: false     # opt-in; emits one series per peer (capped)
  max_per_peer: 1024         # cap on per_peer_detail series; rest aggregate
```

`metrics.listen` accepts the same shapes as `api.listen` — TCP `host:port`
or `unix:/path/to/socket`. There is **no separate** `metrics.listen_path`
because Prometheus universally expects `/metrics`.

When `metrics.token` is set, the endpoint requires
`Authorization: Bearer <token>`. When empty, the endpoint is
unauthenticated — fine for loopback or firewalled binds, dangerous on
network-reachable addresses. The operator picks; the daemon doesn't
second-guess.

## Why a separate listener

Prometheus scrape configs are routinely committed to git, mirrored across
teams, and packaged with Grafana dashboards. The secret hygiene there is
much lower than the admin-token hygiene. Putting metrics on the admin API
port would make a leaked Grafana scrape config equal admin compromise.

A separate listener with a separate token (or no token) lets the operator
firewall metrics off to the monitoring VPN, share the scrape secret with
dashboards safely, and rotate it independently of the admin token.

## Metric format reference (for dashboard authors)

The Prometheus exposition follows the standard format. For each
metric you'll add to a dashboard, the table below tells you exactly
what to expect.

| Metric name | Type | Labels | Unit | Increments / Reads | Useful PromQL |
|---|---|---|---|---|---|
| `uwgsocks_build_info` | gauge | `version`, `go_version`, `lite` | (always 1) | startup only | `uwgsocks_build_info` (instant value, single label set) |
| `uwgsocks_peers` | gauge | none | count | recomputed at scrape | `uwgsocks_peers` (point-in-time) |
| `uwgsocks_peers_handshaked` | gauge | none | count | recomputed at scrape | `uwgsocks_peers - uwgsocks_peers_handshaked` (peers down) |
| `uwgsocks_dynamic_peers` | gauge | none | count | recomputed at scrape | `uwgsocks_dynamic_peers` |
| `uwgsocks_active_connections` | gauge | none | count | recomputed at scrape | `uwgsocks_active_connections` |
| `uwgsocks_relay_conntrack_flows` | gauge | none | count | recomputed at scrape | `uwgsocks_relay_conntrack_flows` (alert when growing without bound) |
| `uwgsocks_bytes_received_total` | counter | none | bytes | per-packet inc | `rate(uwgsocks_bytes_received_total[1m])` (Bps) |
| `uwgsocks_bytes_transmitted_total` | counter | none | bytes | per-packet inc | `rate(uwgsocks_bytes_transmitted_total[1m])` (Bps) |
| `uwgsocks_tcp_retransmits_total` | counter | none | count | gVisor TCP retransmit | `rate(uwgsocks_tcp_retransmits_total[1m])` (loss proxy) |
| `uwgsocks_mesh_requests_total` | counter | `result` ∈ {`ok`, `rate_limited`, `auth_failed`} | count | per-request inc | `rate(uwgsocks_mesh_requests_total[1m]) by (result)` |
| `uwgsocks_turn_carrier_drops_total` | counter | none | count | drops on full carrier ch | spike = TURN carrier saturation |
| `uwgsocks_socks_connections_capped_total` | counter | none | count | SOCKS5 over-cap reject | spike = client misbehaving or cap too low |
| `uwgsocks_conntrack_refusals_total` | counter | none | count | relay-flow refused | spike = conntrack sized too small / flood |
| `uwgsocks_roaming_endpoint_changes_total` | counter | none | count | per-peer endpoint flip | spike = NAT instability or attack |
| `uwgsocks_peer_bytes_received_total` | counter | `peer` (WG pubkey) | bytes | per-peer per-packet | `rate(uwgsocks_peer_bytes_received_total[1m])` per peer (opt-in: `per_peer_detail: true`) |
| `uwgsocks_peer_bytes_transmitted_total` | counter | `peer` | bytes | per-peer per-packet | per-peer egress (opt-in) |
| `uwgsocks_peer_last_handshake_unix_seconds` | gauge | `peer` | unix seconds | recomputed at scrape | `time() - uwgsocks_peer_last_handshake_unix_seconds` = handshake age |

### Per-label expansion notes

- `peer` label values are WireGuard public keys (base64). Public
  keys are public; the label is safe to expose to scrape jobs.
- `result` on `uwgsocks_mesh_requests_total` is exactly three values
  with the spellings above — case-sensitive.
- `version`, `go_version`, `lite` on `uwgsocks_build_info` are
  set once at process start and don't change.

### Type semantics

- **counter**: monotonically increasing across the process
  lifetime. Resets to 0 at process restart. Use `rate()` /
  `increase()`, never the raw value.
- **gauge**: instantaneous value at scrape time. Use directly.

### Alert thresholds (suggested starting points)

| Condition | PromQL | Why |
|---|---|---|
| Peer not handshaking | `(uwgsocks_peers - uwgsocks_peers_handshaked) > 0 for 5m` | Static peer offline |
| Mesh-control auth failures | `rate(uwgsocks_mesh_requests_total{result="auth_failed"}[5m]) > 0` | Wrong PSK or replay attack |
| Conntrack at capacity | `rate(uwgsocks_conntrack_refusals_total[5m]) > 0` | Flow table full |
| Endpoint flapping | `rate(uwgsocks_roaming_endpoint_changes_total[5m]) > 1` | NAT instability |
| Roaming-no-handshake | `(time() - uwgsocks_peer_last_handshake_unix_seconds) > 600` | Per-peer (opt-in) — peer dead |

## What's exposed in v1

### Standard collectors (always on)

- `go_*` — Go runtime (goroutines, GC, mem stats). From
  `prometheus.NewGoCollector`.
- `process_*` — fds, CPU, RSS, virtual memory. From
  `prometheus.NewProcessCollector`.
- `uwgsocks_build_info{version, go_version, lite}` — always 1, version
  metadata in labels.

### Aggregate counters

- `uwgsocks_bytes_received_total` — sum of bytes received from all peers.
- `uwgsocks_bytes_transmitted_total` — sum transmitted.
- `uwgsocks_tcp_retransmits_total` — gVisor netstack retransmit counter
  (proxy for upstream packet loss; let PromQL `rate()` it).
- `uwgsocks_mesh_requests_total{result}` — `ok` / `rate_limited` /
  `auth_failed`.
- `uwgsocks_turn_carrier_drops_total` — frames dropped because a TURN
  WebSocket / WebTransport carrier's read channel was full.
- `uwgsocks_socks_connections_capped_total` — SOCKS5 connections rejected
  because the global concurrent-connection cap was full.
- `uwgsocks_conntrack_refusals_total` — new relay flows refused because
  the conntrack table or per-peer cap was at capacity. Non-zero = sizing
  is too small or someone is flooding.
- `uwgsocks_roaming_endpoint_changes_total` — count of peer outer-endpoint
  changes observed by a 30-second poller. Very fast back-and-forth roaming
  may undercount; documented limitation.

### Aggregate gauges

- `uwgsocks_peers` — configured peers (whether handshaked or not).
- `uwgsocks_peers_handshaked` — peers with at least one handshake this
  process lifetime.
- `uwgsocks_dynamic_peers` — mesh-discovered peers currently tracked.
- `uwgsocks_active_connections` — transparent-inbound connection table
  size. Does NOT count SOCKS / HTTP / socket-API sessions.
- `uwgsocks_relay_conntrack_flows` — active relay conntrack flows.

### Per-peer (opt-in: `per_peer_detail: true`)

Capped at `metrics.max_per_peer` (default 1024). Peers beyond the cap
aggregate into `peer="_overflow"` so the operator still sees the volume
but Prometheus doesn't get an unbounded cardinality explosion.

- `uwgsocks_peer_bytes_received_total{peer}` — per-peer rx counter.
- `uwgsocks_peer_bytes_transmitted_total{peer}` — per-peer tx counter.
- `uwgsocks_peer_last_handshake_unix_seconds{peer}` — most recent
  successful handshake (Unix seconds; 0 if never).

`peer` is the WireGuard public key (base64). Public keys are public; safe
to expose as a label.

## What's NOT in v1 (deferred)

Documented here so the gap is explicit, not hidden:

- **Session-died counters** (KEEPALIVE timeout, REKEY_TIMEOUT). The
  underlying `wireguard-go` doesn't expose these as counters; the only
  ways to capture them are log-string-matching the device's logger or a
  periodic state-diff inference. Both are gross. Doing well > doing fast.
- **Per-listener accept counters.** WireGuard's own handshake counters
  cover most of what an operator wants to alert on.
- **ACL drop counters by plane.** The deny paths are scattered across
  many call sites; instrumenting cleanly is a focused PR of its own.
- **Per-flow metrics.** Cardinality death. Not coming.

## Operational notes

### Cardinality

Each metric with a `peer` label costs one Prometheus time series per
peer. With `per_peer_detail: false` (the default) there are zero
peer-labeled series. With it on, the cap is hard at `max_per_peer`.

For relay-hub deployments with thousands of peers, **leave
`per_peer_detail` off** and use the aggregate `uwgsocks_bytes_*_total`
counters instead. They're sufficient for capacity planning.

### Scrape cost

Per scrape, the metrics handler:

- Calls `Engine.Status()` once per scrape (which calls
  `device.IpcGet()` on the WireGuard device).
- Holds `e.relayMu` briefly to read `len(e.relayFlows)`.
- Holds `e.dynamicMu` (read lock) briefly.

There is no per-packet metric machinery — every counter increment
either lives on a code path that is not in the data plane, or uses an
`atomic.Uint64` add that contends with no other lock. Scrape every 15-30s
without affecting tunnel throughput.

### Recommended PromQL

```promql
# Bytes/sec rx + tx for the WireGuard tunnel:
rate(uwgsocks_bytes_received_total[1m])
rate(uwgsocks_bytes_transmitted_total[1m])

# Approximate retransmit rate (proxy for upstream loss):
rate(uwgsocks_tcp_retransmits_total[5m])

# Mesh request error budget:
sum by (result) (rate(uwgsocks_mesh_requests_total[5m]))

# Conntrack pressure: %% of cap consumed
uwgsocks_relay_conntrack_flows / 65536  # adjust for your conntrack_max_flows
```

### Recommended alerts

```promql
# Conntrack table is filling up — tune conntrack_max_flows or investigate.
uwgsocks_relay_conntrack_flows > 50000

# SOCKS cap is biting — legitimate users may be blocked.
rate(uwgsocks_socks_connections_capped_total[5m]) > 0

# Mesh control under attack or a misbehaving peer.
rate(uwgsocks_mesh_requests_total{result="rate_limited"}[5m]) > 1

# TURN carrier under-provisioned (chronic drops).
rate(uwgsocks_turn_carrier_drops_total[5m]) > 0.1
```
