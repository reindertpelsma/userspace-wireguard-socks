# Userspace WireGuard Gateway

WireGuard networking without root, without kernel modules, and without touching the host network stack.

`uwgsocks` is a rootless WireGuard data plane: userspace WireGuard, userspace TCP/IP, pluggable outer transports, proxy entrypoints, relay logic, and a raw socket API in a single binary. It runs anywhere: containers, CI pipelines, Android Termux, Windows, macOS, and locked-down hosts where kernel WireGuard or `/dev/net/tun` are unavailable.

## Why this exists

Standard WireGuard requires root and a kernel TUN interface. That rules it out for containers, unprivileged CI jobs, and any system where you cannot change the routing table. It also uses plain UDP, which is easy to block or fingerprint in restrictive networks.

`uwgsocks` removes both constraints — and uniquely, it works as a **server** too. You can host a WireGuard exit node, relay hub, or lightweight mesh coordinator on any machine, under any account, with no installation: a Mac mini, a Termux session, a Windows desktop, a container, or an IoT device.

## Looking for a VPN server with a web UI?

See [simple-wireguard-server](https://github.com/reindertpelsma/simple-wireguard-server) — a zero-install WireGuard control plane built on top of `uwgsocks`. It adds a dashboard, user management, OIDC login, protected service publishing, transport-aware client configs, and optional peer syncing / P2P discovery.

## Quick Start

```bash
bash compile.sh

# Start a rootless WireGuard client.
./uwgsocks --wg-config client.conf --socks5 127.0.0.1:1080

# Use a proxy-aware app through the tunnel.
curl --proxy socks5://127.0.0.1:1080 https://example.com

# Or transparently route any Linux app — no proxy support required.
./uwgsocks --config examples/socksify.yaml
./uwgwrapper -- curl https://example.com

# Generate keys or a starter config pair without wireguard-tools.
./uwgsocks genkey
./uwgsocks pubkey < privatekey.txt
./uwgsocks genpair --server-address 10.0.0.1/32 --client-address 10.0.0.2/32 --server-endpoint vpn.example.com:51820
```

## What it covers

- Rootless WireGuard client and server mode
- SOCKS5, HTTP proxy, local forwards, reverse forwards, and relay forwarding
- Linux transparent app wrapping via `uwgwrapper` and fdproxy
- Raw socket API for TCP, UDP, ICMP ping, listener sockets, and DNS frames
- Outer transports for difficult networks: UDP, TCP, TLS, HTTP(S), QUIC, DTLS, and TURN
- Optional mesh control for peer syncing and direct peer discovery on top of standard WireGuard keys

## How apps enter the tunnel

| Method | When to use |
|---|---|
| SOCKS5 / HTTP proxy | App has built-in proxy support |
| Port forwards | Fixed ports you want mapped locally |
| `uwgwrapper` (Linux) | App has no proxy support — intercepts socket calls via LD_PRELOAD, falls back to ptrace for static Go/Rust binaries |
| Raw socket API | Embedding `uwgsocks` as a Go library |

## Surviving restrictive firewalls

Standard WireGuard UDP is easy to fingerprint and block. `uwgsocks` can carry WireGuard over:

`udp` · `tcp` · `tls` · `https` (WebSocket) · `quic` (WebTransport) · `dtls` · `turn`

A single `#!TCP=required` comment in your wg-quick config is enough to switch a peer to TCP transport — no YAML needed. The same directive parser also supports transport URLs and mesh control hints such as `#!URL=...` and `#!Control=...`.

## vs. Alternatives

| | `uwgsocks` | Kernel WireGuard | Tailscale / Headscale | proxychains |
|---|---|---|---|---|
| Root required | No | Yes | No | No |
| Works in containers | Yes | Requires CAP_NET_ADMIN | Yes | Yes |
| **Host a server rootlessly** | **Yes** | No | No | — |
| Runs on macOS / Windows / Android as server | Yes | No | No | — |
| Survives DPI / port blocks | Yes | No | No | No |
| Routes apps without proxy support | Yes (uwgwrapper) | Via system routing | Via system routing | Partially (TCP only, no static binaries) |
| Standard WireGuard peers | Yes | Yes | No (Tailscale protocol) | — |
| Peer sync over standard WireGuard configs | Yes | No | No | — |
| Self-hosted, no SaaS dependency | Yes | Yes | Headscale (partial) | — |

## Binaries

- **`uwgsocks`** — WireGuard engine, SOCKS5/HTTP proxy, port forwards, ACL engine, DNS, relay, and runtime API. Runs on Linux, macOS, and Windows.
- **`uwgwrapper`** — Linux-only launcher that transparently routes any application through `uwgsocks`. Uses LD_PRELOAD for the fast path and ptrace/seccomp for static binaries.
- **`turn/`** — standalone TURN relay for relay-friendly UDP paths, CGNAT traversal, and reverse-proxy-friendly HTTP/HTTPS/QUIC carriers.

## Build

```bash
bash compile.sh   # builds uwgsocks everywhere; builds uwgwrapper on Linux amd64/arm64
go test ./...
```

Requires Go. Building `uwgwrapper` additionally requires gcc on Linux. See [docs/compatibility.md](docs/compatibility.md) for supported platforms.

For Windows host-TUN mode, ship the official signed `wintun.dll` next to
`uwgsocks.exe` in the release zip, or install it into `C:\\Windows\\System32`.

Tagged releases also publish the standalone `turn` server for Linux, macOS,
and Windows. Linux release assets include `amd64`, `arm64`, `riscv64`, and
`mips64`; macOS and Windows include `amd64` and `arm64`.
SOCKS5/HTTP, forwards, relay, and the raw socket API do not need `wintun.dll`;
only host-TUN mode does.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Host TUN how-to](docs/howto/host-tun.md)
- [Transport modes](docs/transport-modes.md)
- [Proxy routing order](docs/proxy-routing.md)
- [Testing and security model](docs/testing.md)
- [Raw socket API](docs/socket-protocol.md)
- [TURN relay](turn/README.md)
- [How-to guides](docs/howto/README.md)

## License

ISC License
