<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Proxy Routing

`uwgsocks` makes a routing decision for every SOCKS5/HTTP request, every
connected raw socket API/fdproxy TCP/UDP/ICMP request, and every transparent
inbound WireGuard TCP/UDP flow. The short version is:

1. Local tunnel addresses are handled first.
2. Explicit reverse forwards win before peer routing.
3. Peer `AllowedIPs` win before direct or proxy fallback.
4. `Address=` subnets can reserve virtual interface space so traffic does not
   leak to normal Internet fallback.
5. Configured outbound proxy fallback rules are tried before direct host dials.
6. Direct host dialing happens only when that path is enabled for the traffic
   source.

For SOCKS5/HTTP outbound connections:

1. If the destination is one of this peer's tunnel addresses, `localhost`, or
   `127.0.0.0/8`, first check whether a reverse forward owns the same userspace
   address and port.
2. If no reverse forward owns it, apply `host_forward.proxy`; if proxy host
   forwarding is disabled, reject the connection.
3. If the destination matches any reverse-forward userspace listener, dial that
   reverse-forward target. This also works when a SOCKS client connects to an
   arbitrary reverse-forward IP routed to this peer.
4. If the destination IP matches any peer `AllowedIPs`, route through the
   userspace WireGuard netstack. Overlapping `AllowedIPs` are matched
   most-specific-prefix first.
5. If the destination is inside an `Address=` subnet such as
   `10.10.10.2/24` but no peer `AllowedIPs` route it, reject it instead of
   leaking to direct fallback.
6. If a configured outbound SOCKS5/HTTP proxy matches the destination subnet
   and role, use that proxy.
7. If it does not match and `fallback_direct: false`, reject the connection.
8. Otherwise, if `fallback_direct: true`, dial directly on the host network.

Transparent inbound WireGuard TCP/UDP termination uses the same ordered model,
except it uses the `inbound` outbound-proxy role and `host_forward.inbound`.

Connected raw socket API and fdproxy TCP/UDP requests use the same ordered
model as SOCKS5/HTTP. Connected ICMP ping sockets follow the same ACL and
AllowedIPs checks, but direct fallback is opportunistic host ping-socket
support only: there is no outbound proxy equivalent for ICMP. When the runtime
does not have tunnel IPv6 configured, raw socket API/fdproxy IPv6 connects are
rejected immediately so applications can fall back to IPv4 instead of waiting
for a host-level timeout.

Optional host TUN mode uses this same outbound model too. Packets from the host
TUN interface are terminated in a second userspace netstack; TCP, UDP, and
ping-style ICMP/ICMPv6 flows then pass through outbound ACLs, reverse-forward
matching, peer `AllowedIPs`, outbound proxy fallbacks, and `fallback_direct` in
the same order as raw socket/fdproxy traffic.

Outbound proxy fallback rules are useful when the process running `uwgsocks`
must itself reach the Internet through another proxy:

```yaml
proxy:
  honor_environment: true
  outbound_proxies:
    - type: socks5
      address: 127.0.0.1:1081
      roles: [socks]
      subnets: [0.0.0.0/0, ::/0]
    - type: http
      address: 127.0.0.1:3128
      roles: [inbound]
      subnets: [203.0.113.0/24]
```

`roles: [socks]` applies to connections that originated from the host-facing
SOCKS5/HTTP proxy. `roles: [inbound]` applies to transparent TCP/UDP flows that
originated from WireGuard peers and are being terminated to host sockets.
`roles: [both]` applies to both. Empty `subnets` means match everything; when
multiple rules match, the most-specific subnet wins. HTTP proxies are used only
for TCP CONNECT, so UDP falls through to the next matching SOCKS5 proxy or to
direct fallback if enabled.