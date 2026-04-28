<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Tunneling — what `uwgsocks` tunnels and how

`uwgsocks` runs a full WireGuard implementation in user-space.
The encryption, peer state, key rotation, and packet authentication
are all the standard WireGuard protocol — no custom modifications.
What's different from kernel WireGuard is what happens to the
packets after they're decrypted: instead of being delivered to a
kernel TUN device, they go into a userspace TCP/IP stack (gVisor
netstack) which terminates flows and surfaces them through the
proxy / forward / socket-API surfaces.

## Inputs

`uwgsocks` accepts these as packet sources:

- **WireGuard outer packets** from peers (UDP / TCP / TLS / DTLS /
  HTTP / HTTPS / QUIC / TURN — see
  [transports.md](transports.md)).
- **SOCKS5 / HTTP proxy clients** on the host. See
  [proxies-and-forwards.md](proxies-and-forwards.md).
- **Host-side forwards** that bind a host port and forward to a
  tunnel address. See [proxies-and-forwards.md](proxies-and-forwards.md).
- **Reverse forwards** that bind a tunnel-side address and dial
  out to the host network.
- **Raw socket API clients** speaking the documented socket
  protocol on `/v1/socket` or `/uwg/socket`. See
  [reference/socket-protocol.md](../reference/socket-protocol.md).
- **`uwgwrapper`-intercepted Linux applications** routed
  transparently through the wrapper. See
  [transparent-wrapper.md](transparent-wrapper.md).
- **Host TUN device** when `tun.enabled: true`. See
  [host-tun.md](host-tun.md).

## Outputs (per packet)

For each IP packet (or socket flow) routed through the engine, the
decision tree is:

1. **Local tunnel addresses** — terminate inside the netstack.
2. **Reverse forwards** — match a tunnel-side listen address.
3. **Peer `AllowedIPs`** — encrypt + send via the matching peer's
   outer transport.
4. **Local-tunnel-subnet leak prevention** — drop instead of
   leaking onto the host network.
5. **Outbound proxy** — fall back to a configured upstream SOCKS5 /
   HTTP proxy.
6. **Direct host dialing** — final fallback if `fallback_direct: true`.
7. **Relay-to-peer** — forwarding for peers configured as relay
   participants. See [relay-and-acls.md](relay-and-acls.md).

The full ordering is the same across the SOCKS5 listener, the HTTP
listener, the raw socket API, and the wrapper path. See
[proxies-and-forwards.md](proxies-and-forwards.md) for routing
specifics + the leak-prevention guarantees.

## What it does NOT tunnel

- **Host network changes**: routes, DNS resolvers, default gateway.
  When `tun.enabled: false` (the default), the host's networking
  is unaffected. Apps must opt-in via SOCKS5 / HTTP / wrapper.
- **Layer-2 frames**: this is an L3 tunnel. ARP, mDNS, DHCP don't
  cross.
- **Multicast**: dropped by default. The
  `filtering.drop_ipv6_link_local_multicast` knob defends against
  the noisier IPv6 link-local multicast.
- **Broadcast traffic**: same as multicast.

## Threat boundary

WireGuard outer packets, tunnelled inner traffic, DNS hostnames
needing resolution, and SOCKS5/HTTP proxy clients are **all
untrusted inputs** (per
[contributing/security-conventions.md](../contributing/security-conventions.md)).
Every parser, every length field, every map insertion that touches
those inputs is in scope for the security audit.

The runtime API (token-gated) is the trusted surface — operators
manage `uwgsocks` through it.

## Engine vs lite

The full engine includes mesh-control, traffic shaping, advanced
transports, and the TURN server. The `-tags lite` build excludes
those, leaving a small surface for low-attack-surface deployments.
See [contributing/testing.md](../contributing/testing.md) for the
build-tag table.
