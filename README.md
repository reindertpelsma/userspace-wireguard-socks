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
- `turn/`: standalone open TURN relay for deterministic UDP relay ports. It can
  be used with `uwgsocks` TURN mode when peers need a relay-friendly UDP path.

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

Requirements: Go, gcc on Linux when building `uwgwrapper`, and npm only when
building `uwgsocks-ui`.

```bash
export GOTOOLCHAIN=auto
bash compile.sh
go test ./...
go test -race ./internal/config ./internal/engine ./tests/malicious ./tests/preload
```

On macOS, `bash compile.sh` builds `uwgsocks` and skips the Linux-only
`uwgwrapper`. On Windows, use `compile.bat`, which builds `uwgsocks.exe`.

The test suite runs rootless local WireGuard instances and covers proxy paths,
raw socket API, wrapper preload/ptrace paths, IPv6, ICMP, relay ACLs, DNS,
traffic shaping, and runtime API updates. See [docs/testing.md](docs/testing.md).

## More Documentation

- [Full technical how-to](Full-Technical-How-To.md)
- [Configuration reference](docs/configuration.md)
- [Raw socket API](docs/socket-protocol.md)
- [Proxy routing](docs/proxy-routing.md)
- [Testing and security plan](docs/testing.md)
- [Termux arm64 bring-up plan](docs/termux-arm64-bringup.md)
- [TURN relay](turn/README.md)
- [UI server](uwgsocks-ui/README.md)

## License

ISC License
