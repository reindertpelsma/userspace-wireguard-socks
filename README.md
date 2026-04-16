# Userspace WireGuard Gateway

Run WireGuard networking without root, without `/dev/net/tun`, without routing
table changes, and without a system VPN interface.

`uwgsocks` embeds WireGuard and a userspace TCP/IP stack in one process. Apps can
enter that stack through HTTP/SOCKS proxies, local forwards, the raw socket API,
the Linux `uwgwrapper`/`uwgfdproxy` path, or the Go library API.

## Quick Start

```bash
# Build the local binaries.
bash compile.sh

# Start a rootless WireGuard client exposing HTTP and SOCKS proxies.
./uwgsocks --wg-config ./client.conf --http 127.0.0.1:8080 --socks5 127.0.0.1:1080

# Use a proxy-aware app.
curl -x http://127.0.0.1:8080 https://example.com

# Or run an app that does not know about proxies.
./uwgwrapper --api http://127.0.0.1:8080 -- curl https://example.com
```

For a complete local two-peer demo, start `examples/exit-server.yaml` and
`examples/exit-client.yaml` as described in [Full-Technical-How-To.md](Full-Technical-How-To.md).

## Binaries

- `uwgsocks`: rootless userspace WireGuard client/server, proxy, raw socket API,
  forwarding engine, DNS helper, ACL engine, and runtime API.
- `uwgwrapper`: Linux launcher that routes ordinary applications through
  `uwgsocks` using `LD_PRELOAD`, seccomp-assisted ptrace, or ptrace fallback.
- `uwgfdproxy`: local Unix-socket bridge used by the wrapper and by advanced
  raw socket API clients.
- `uwgkm`: optional kernel WireGuard manager built by `uwgsocks-ui`; it is for
  hosts where you do want a normal kernel WireGuard interface and have the
  privileges to create one.
- `turn/`: standalone open TURN relay for deterministic UDP relay ports. It can
  be used with `uwgsocks` TURN mode when peers need a relay-friendly UDP path.
- `uwgsocks-ui/`: separate web UI repo embedded in this checkout for managing
  users, peers, ACLs, generated YAML, daemon restarts, 2FA/OIDC, and per-peer
  traffic shaping.

## What Works Today

- Rootless WireGuard client and server mode.
- IPv4, IPv6, TCP, UDP, DNS, and ping-style ICMP/ICMPv6.
- HTTP proxy, SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, and SOCKS5 BIND.
- Local forwards and tunnel-side reverse forwards with optional PROXY protocol.
- Transparent inbound termination from WireGuard peers to host sockets.
- Peer-to-peer relay forwarding with ACLs and stateful conntrack.
- Runtime API for status, ping, peer updates, ACL updates, forwards, and
  WireGuard config replacement.
- Raw socket API for connected TCP/UDP/ICMP, TCP listeners, UDP listener-style
  sockets, DNS frames, and local fd bridging.
- `uwgwrapper` transport modes: preload only, preload + seccomp + ptrace,
  ptrace + simple seccomp, and ptrace without seccomp. `NO_NEW_PRIVILEGES` is
  enabled by default for launched processes.
- Per-peer and global traffic shaping for upload, download, and buffering
  latency. Runtime peer API updates can change shapers without restarting.
- Optional TURN bind mode, including `turn.include_wg_public_key` for relays
  that want the WireGuard public key embedded in the TURN username.

## Routing Model

For proxy and raw socket clients, `uwgsocks` first checks local tunnel
addresses and reverse forwards, then peer `AllowedIPs`, then configured
outbound proxy fallbacks, then direct fallback if `proxy.fallback_direct` is
enabled. Destinations inside local `Address=` subnets but not routed by peer
`AllowedIPs` are rejected instead of leaking to the host network.

See [docs/proxy-routing.md](docs/proxy-routing.md) for the detailed order.

## Wrapper Notes

Use SOCKS or HTTP when an application supports it. Use `uwgwrapper` when the app
does not.

```bash
./uwgsocks --config ./examples/socksify.yaml
./uwgwrapper --api unix:/tmp/uwgsocks-http.sock --transport auto -- curl https://example.com
```

`uwgwrapper --transport auto` picks the fastest available correct mode. In
restricted containers it can fall back when seccomp or ptrace are unavailable.
Explicit loopback connections and binds bypass the tunnel. Binding tunnel-side
listeners requires `proxy.bind` or `socket_api.bind`; low ports additionally
require `proxy.lowbind`.

## Configuration

`uwgsocks` merges:

1. YAML runtime config from `--config`.
2. wg-quick config from `wireguard.config_file`, `wireguard.config`,
   `--wg-config`, or `--wg-inline`.
3. CLI overrides and repeated additions.

Start with [docs/configuration.md](docs/configuration.md). The raw socket
protocol is documented in [docs/socket-protocol.md](docs/socket-protocol.md).

## Build And Test

Requirements: Go, gcc, and npm only when building `uwgsocks-ui`.

```bash
bash compile.sh
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
```

The test suite runs rootless local WireGuard instances and covers proxy paths,
raw socket API, wrapper preload/ptrace paths, IPv6, ICMP, relay ACLs, DNS,
traffic shaping, and runtime API updates. See [docs/testing.md](docs/testing.md).

## More Documentation

- [Full technical how-to](Full-Technical-How-To.md)
- [Configuration reference](docs/configuration.md)
- [Raw socket API](docs/socket-protocol.md)
- [Proxy routing](docs/proxy-routing.md)
- [Testing and security plan](docs/testing.md)
- [TURN relay](turn/README.md)
- [UI server](uwgsocks-ui/README.md)

## License

ISC License
