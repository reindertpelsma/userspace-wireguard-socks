<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Testing And Security Plan

This project is intentionally tested without root, `/dev/net/tun`, public Internet dependencies, or container privileges. The tests run WireGuard, gVisor netstack, SOCKS5/HTTP proxy paths, transparent forwarding, DNS, relay, and API behavior as normal Go processes.

## Threat Model

These are the properties tests and review should protect:

- Proxy clients must not get remote code execution.
- WireGuard peers must not reach host loopback unless host forwarding is explicitly enabled for that path.
- ACL bypass must not happen for inbound, outbound, or relay traffic.
- Malformed WireGuard, IP, TCP, UDP, ICMP, DNS, SOCKS5, and HTTP proxy inputs must not panic or allocate unbounded memory.
- The API must not expose private or preshared key material and must not allow unauthenticated mutation on non-loopback sockets.
- DNS must not silently fall back to system DNS when `DNS=` is configured for tunnel resolution.
- Tables and buffers must be bounded: connection states, transparent TCP receive windows, DNS transactions, SOCKS UDP sessions, and relay/forward state.

## Current Automated Coverage

Run:

```bash
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
go test ./internal/engine -run '^$' -bench BenchmarkLoopbackSOCKSThroughput -benchtime=3x
./scripts/iperf_loopback.sh
```

The main suite covers:

- Two-instance WireGuard TCP/UDP data paths.
- SOCKS5 CONNECT, UDP ASSOCIATE, and BIND.
- HTTP proxy GET and CONNECT.
- IPv4 and IPv6 tunnel traffic, IPv6 outer endpoints, and ICMP/ICMPv6 ping.
- Local forwards and reverse forwards for TCP/UDP.
- PROXY protocol v1/v2 parsing, stripping, and injection.
- Reverse-forward reachability from SOCKS clients.
- Transparent inbound TCP/UDP termination to host sockets.
- Outbound proxy fallback lists for SOCKS-originated and WireGuard-inbound traffic.
- Most-specific-prefix routing for overlapping `AllowedIPs` and outbound proxy subnets.
- Host forwarding defaults and virtual `Address=` subnet rejection.
- Reserved IPv4 and IPv6 tunnel-address filtering.
- Source IP enforcement against malicious WireGuard peers.
- Relay forwarding allow and deny ACL behavior.
- API peer, ACL, status, ping, and runtime forward operations.
- API mutation while traffic is flowing with many ACL rules.
- Raw socket API TCP, UDP, UDP reconnect/disconnect, TCP listener/accept, DNS frame, and malformed-frame behavior.
- Linux LD_PRELOAD managed-fd proof path for connected TCP, connected UDP, unconnected UDP, TCP listener accept, duplicated fds, fork inheritance, selected exec inheritance, and malicious manager-input rejection through `uwgfdproxy`.
- DNS-over-WireGuard resolution and tunnel-hosted DNS transaction behavior.
- Malformed parser and packet fuzz seeds.
- Packet loss, jitter, tail-drop-like queue overflow, and multi-stream transfer.
- Connection table overflow grace and transparent TCP memory budget behavior.

`scripts/iperf_loopback.sh` builds `uwgsocks` when needed, writes temporary
demo WireGuard configs, starts two binaries, exposes an iperf3 server through a
server-side reverse-forward and a client-side local TCP/UDP forward, runs TCP
and UDP iperf3 clients, prints a JSON-derived summary, then cleans up.

## Coverage Plan For Remaining Gaps

Keep adding tests in this order:

1. `cmd/uwgsocks`: table-test flag combinations with `--check` through `exec.CommandContext`, especially repeated `--peer`, `--forward`, `--reverse-forward`, and `--outbound-proxy`. This is startup glue, so it is lower risk than packet handling.
2. Mixed proxy listener: one test that speaks SOCKS5 and one that speaks HTTP to the same `mixed` listener.
3. API item paths: negative tests for `/v1/peers/{public_key}`, bad peer keys, bad ACL list names, bad forward definitions, and method-not-allowed responses.
4. Transparent UDP error paths: force host dial failure and assert the ICMP unreachable packet is emitted to the tunnel path.
5. DNS TCP transaction exhaustion: mirror the existing UDP max-inflight test for TCP.
6. Static endpoint roaming fallback: make the endpoint change, stop handshakes, and assert the configured endpoint is restored without waiting for a long real timer.
7. Additional fuzz targets for HTTP CONNECT parsing and SOCKS5 UDP datagram parsing with length caps.

Very small pure helpers such as `max`, `minPositive`, and string-formatting wrappers are acceptable to leave covered indirectly unless they become security-sensitive.

## Manual Soak

For a release candidate, run two binaries for hours:

- Loopback impaired network with random latency, jitter, burst loss, and tail drops.
- Real VPS or commercial WireGuard exit with browser video, speed tests, and DNS-heavy browsing.
- Many concurrent SOCKS TCP flows and UDP ASSOCIATE flows.
- Periodic API peer, ACL, forward, and reverse-forward updates.
- Metrics collected from `/v1/status`: goroutine count from the process, heap from pprof if enabled externally, active connection table size, transfer counters, and last handshake.

Also run a real-world browser test through SOCKS5, including HTTP/3-capable sites, because UDP behavior through SOCKS5 clients varies in practice.

## External Review Checklist

Before calling this production-safe, ask another engineer to review:

- Host-forwarding defaults and redirect behavior.
- Tunnel address filtering defaults.
- SOCKS5 parser, especially UDP ASSOCIATE and BIND.
- HTTP proxy CONNECT parsing and authentication.
- API authentication and key redaction.
- DNS fallback behavior and transaction caps.
- WireGuard peer update and `AllowedIPs` cache update path.
- Transparent TCP backpressure and global memory limits.
- Relay ACL behavior and directional reply rules.
