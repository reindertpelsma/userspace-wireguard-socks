<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Build And Quick Start

## Build

You can download release binaries, or build locally with Go 1.25 or newer:

```bash
export GOTOOLCHAIN=auto
bash compile.sh
```

On Linux this produces `uwgsocks` and `uwgwrapper`. On macOS it produces
`uwgsocks` and skips the Linux-only wrapper. On Windows use `compile.bat` to
build `uwgsocks.exe`.

## Quick Start

The files under `examples/` are a self-contained localhost demo. They contain
demonstration-only keys and configure the client with `AllowedIPs = 0.0.0.0/0`
so IPv4 SOCKS traffic can egress through the server process.

Terminal 1, the WireGuard server acting as exit relay:

```bash
./uwgsocks \
  --config ./examples/server.yaml \
  --listen-port 51820 \
  --inbound-transparent=true
```

Terminal 2, the WireGuard client:

```bash
./uwgsocks \
  --config ./examples/client.yaml \
  --socks5 127.0.0.1:1080
```

Terminal 3, curl through SOCKS:

```bash
curl -x "socks5h://127.0.0.1:1080" -v https://www.google.com/
```

Check status:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:9090/v1/status
```

Run a one-shot config check:

```bash
./uwgsocks --config ./examples/client.yaml --check
```

## Common Deployment Shapes

Use selected port mappings:

- expose SOCKS5 or HTTP for applications that already support proxies
- define local `forwards` from host ports to WireGuard destinations
- define `reverse_forwards` from userspace WireGuard IPs and ports to host services

Use it as a rootless egress peer:

- run with `inbound.transparent: true`
- configure peers to route Internet or LAN prefixes to this server
- optionally enable `dns_server.listen` so peers can resolve names using the server host's resolver

Use it with a host TUN interface when an application insists on seeing a
kernel interface:

- enable `tun.enabled: true`
- optionally enable `tun.configure: true`
- traffic from that interface is still terminated in userspace and follows the same ACL, AllowedIPs, fallback, TCP, UDP, ICMP, and IPv6 behavior

Use it from another Go program:

- import the library
- start an engine without exposing SOCKS5 or HTTP
- dial or listen on userspace WireGuard addresses directly

Example files:

- [examples/forwarding.yaml](../../examples/forwarding.yaml)
- [examples/multi-peer.yaml](../../examples/multi-peer.yaml)
- [examples/exit-server.yaml](../../examples/exit-server.yaml)
- [examples/exit-client.yaml](../../examples/exit-client.yaml)
- [examples/socksify.yaml](../../examples/socksify.yaml)
- [examples/uwgsocks.service](../../examples/uwgsocks.service)

Transparent egress example:

```bash
# Server, on the egress host:
./uwgsocks --config ./examples/exit-server.yaml

# Client, on the application host:
./uwgsocks --config ./examples/exit-client.yaml
curl -x socks5h://127.0.0.1:1080 https://www.google.com/
```

Forward and reverse-forward example:

```bash
./uwgsocks --config ./examples/forwarding.yaml
```

## Troubleshooting The Local Demo

If a SOCKS request fails with curl output such as `Can't complete SOCKS5 connection ... (4)`, check:

- rebuild after code changes
- stop stale demo processes so client and server are using the same files and ports
- confirm the client and server public keys are crossed correctly
- confirm `examples/client.conf` points at the running server endpoint
- query `/v1/status` on the server API and check `has_handshake` and transfer counters
- if `DNS = 100.64.90.1`, keep `100.64.90.1/32` inside client `AllowedIPs` or remove `DNS=` to use system DNS
- with `AllowedIPs = 0.0.0.0/0`, the server host still needs direct reachability or a matching `proxy.outbound_proxies` rule for the `inbound` role

For the deeper configuration and routing details behind these examples, continue with
[Configuration and Routing](configuration-and-routing.md).
