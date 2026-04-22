# Userspace WireGuard Gateway

WireGuard for applications and servers without root, kernel modules, or host
routing changes.

`uwgsocks` is a userspace WireGuard runtime for the common pain points:
containers, CI jobs, locked-down hosts, laptops, and appliances where a system
VPN is awkward but applications or services still need WireGuard networking.

It can run as a client, server, relay, or peer-sync hub, and traffic can enter
through SOCKS5, HTTP, forwards, a raw socket API, Linux wrapper interception,
or host TUN.

## Quick Start

```bash
bash compile.sh

# Rootless client with SOCKS5
./uwgsocks --wg-config client.conf --socks5 127.0.0.1:1080
curl --proxy socks5://127.0.0.1:1080 https://example.com

# Linux transparent app wrapping
./uwgsocks --config examples/socksify.yaml
./uwgwrapper -- curl https://example.com

# Generate keys/config helpers without wireguard-tools
./uwgsocks genkey
./uwgsocks genpair --server-address 10.0.0.1/32 --client-address 10.0.0.2/32
```

## Main Binaries

| Binary | Purpose |
|---|---|
| `uwgsocks` | Full userspace WireGuard runtime: proxies, relay, API, DNS, mesh control, transports |
| `uwgsocks-lite` | Reduced-feature build for minimal deployments |
| `uwgwrapper` | Linux-only transparent interception for apps without SOCKS5/HTTP support |
| `turn` | Standalone TURN relay with HTTP/HTTPS/QUIC carrier support |

## Install

Unix-like hosts:

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- uwgsocks
```

Windows:

```powershell
curl.exe -fsSLo install.bat https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.bat
install.bat uwgsocks
```

Release tags also publish container images:
- `ghcr.io/reindertpelsma/uwgsocks:<tag>`
- `ghcr.io/reindertpelsma/uwgsocks-turn:<tag>`

## Platform Status

- Supported and repeatedly tested:
  - `uwgsocks`: Linux, macOS, Windows, FreeBSD
  - `uwgwrapper`: Linux amd64/arm64 on glibc and musl
- Experimental targets:
  - `uwgsocks` on `linux/riscv64`, `linux/mips`, `linux/mipsle`
- Not yet claimed as supported:
  - `linux/386`, `windows/386`

See the compatibility and host-TUN docs for OpenBSD notes, Windows `wintun.dll`
requirements, and experimental architectures.

## Documentation

- [Configuration guide](docs/configuration.md)
- [Complete config map](docs/config-reference.md)
- [Transport modes](docs/transport-modes.md)
- [Host TUN](docs/howto/host-tun.md)
- [Mesh control / peer sync](docs/howto/mesh-control.md)
- [Proxy routing order](docs/proxy-routing.md)
- [Raw socket API](docs/socket-protocol.md)
- [Testing and compatibility](docs/testing.md)
- [TURN relay](turn/README.md)

Looking for a web UI and multi-user control plane? See
[simple-wireguard-server](https://github.com/reindertpelsma/simple-wireguard-server).

## License

ISC License
