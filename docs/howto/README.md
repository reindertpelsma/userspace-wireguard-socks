<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# How-To Index

`uwgsocks` is a rootless WireGuard gateway, relay, and application router. It
is for the developer who wants WireGuard inside a container, CI job, laptop, or
locked-down server without touching kernel routes.

If you only remember one thing: this project bridges WireGuard into a userspace
`gVisor` TCP/IP stack. That makes it a rootless network hypervisor, not just a
SOCKS proxy and not just a `wireguard-go` wrapper.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- uwgsocks
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- uwgwrapper
curl -fsSL https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/main/install.sh | sh -s -- turn
```

Build from source instead:

```bash
bash compile.sh
```

On Windows, use the release page or the install instructions in the repository
root [README.md](../../README.md).

## Read In Order

1. [01 Simple Client Proxy](01-simple-client-proxy.md)
2. [02 Server And Ingress](02-server-and-ingress.md)
3. [03 Wrapper Interception](03-wrapper-interception.md)
4. [04 Firewall And ACLs](04-firewall-and-acls.md)
5. [05 Mesh Coordination](05-mesh-coordination.md)
6. [06 Pluggable Transports](06-pluggable-transports.md)
7. [07 TURN Relay Ingress](07-turn-relay-ingress.md)
8. [08 Reference Map](08-reference-map.md)
9. [09 Unix Socket Forwards](09-unix-socket-forwards.md)
10. [10 Minecraft Soak (Paper + uwgwrapper)](10-minecraft-soak.md)

## Demo Notes

- The examples under [`examples/`](../../examples/README.md) ship with fixed
  local-demo keys so you can test immediately.
- For production, generate real keys with `uwgsocks genkey` or
  `uwgsocks genpair`.
- The commands in this guide were written against the files in `examples/`.
- The important config blocks are inlined in each how-to so you do not have to
  bounce between markdown and example files to understand the setup.
- The public-subdomain ingress story is powered by `uwgsocks` plus the
  companion control plane
  [`simple-wireguard-server`](https://github.com/reindertpelsma/simple-wireguard-server).
