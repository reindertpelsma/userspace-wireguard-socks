# MTU and overhead reference

## WireGuard header overhead

Each WireGuard data packet wraps the inner IP packet with:

| Outer transport | Overhead |
|---|---|
| IPv4 + UDP | 20 (IPv4) + 8 (UDP) + 32 (WireGuard header + auth tag) = **60 bytes** |
| IPv6 + UDP | 40 (IPv6) + 8 (UDP) + 32 (WireGuard header + auth tag) = **80 bytes** |

On a standard Ethernet path with outer MTU 1500:

- IPv4 outer → max inner MTU = 1500 − 60 = **1440**
- IPv6 outer → max inner MTU = 1500 − 80 = **1420**

The default `wireguard.mtu` of **1420** is the conservative choice: it works
correctly regardless of whether the outer path runs over IPv4 or IPv6, and
leaves a small safety margin for networks that report 1500 but silently drop
packets a few bytes below that.

## Configuring MTU

```yaml
wireguard:
  mtu: 1420   # inner tunnel MTU (default)

tun:
  mtu: 1420   # host TUN MTU; inherits wireguard.mtu when unset
```

If your physical network uses jumbo frames (e.g. 9000 bytes) you can raise
`wireguard.mtu` accordingly. If you are tunnelling over a restrictive path
(e.g. PPPoE with effective 1492, or a VPN-inside-a-VPN), lower it to
`physical_mtu − 60` (IPv4) or `physical_mtu − 80` (IPv6).

## Minimum safe MTU

IPv6 mandates every link deliver at least **1280 bytes** without
fragmentation. Many real-world applications that run on IPv4 also break below
1280 because they assume TCP/UDP frames fit in a single IP datagram of at
least that size. **Do not set `wireguard.mtu` below 1280.**

## TCP MSS clamping

To avoid PMTU black-holes for TCP connections passing through the tunnel,
uwgsocks rewrites the `MSS` option in TCP SYN and SYN-ACK packets to at most
`mtu − 40` (IPv4) or `mtu − 60` (IPv6). This is equivalent to what a Linux
router does with `iptables -j TCPMSS --clamp-mss-to-pmtu`.

MSS clamping is enabled by default:

```yaml
inbound:
  tcp_mss_clamp: true   # default
```

Disabling it is only useful in narrow debugging scenarios; leave it on in
production.

## Overhead per outer transport

### UDP (default WireGuard transport)

No additional overhead beyond the WireGuard header described above. Use
`mtu = physical_mtu − 60` (IPv4) or `mtu = physical_mtu − 80` (IPv6).

### TCP, TLS, HTTP, HTTPS

These are stream transports. WireGuard packets are length-prefixed and sent
over a TCP stream, so the outer TCP layer handles its own segmentation. There
is **no inner MTU constraint** — any `wireguard.mtu` value is valid. Keep the
default 1420 unless you have a specific reason to change it.

### QUIC and WebTransport (`quic://`, `quic+ws://`)

QUIC adds roughly 25–35 bytes of framing per UDP datagram on top of IP+UDP.
When uwgsocks uses raw QUIC streams the effective headroom is comparable to
UDP but slightly smaller; as a conservative starting point lower the inner MTU
by an additional 40 bytes:

```
wireguard.mtu ≈ physical_mtu − 60 (IPv4) − 40 (QUIC) = 1400 for Ethernet
```

QUIC streams fragment application data internally, so an over-large
`wireguard.mtu` does not cause dropped packets — it causes the QUIC layer to
split the WireGuard datagram across multiple QUIC frames, adding slight
latency. Staying at 1380–1400 avoids that.

### TURN

TURN adds framing on top of its own outer transport:

| TURN carrier | Extra overhead |
|---|---|
| TURN over UDP | 4 bytes (ChannelData header) + STUN overhead ≈ **36–56 bytes** total above WG |
| TURN over TCP/TLS | Stream transport — inner MTU irrelevant (see TCP section) |
| TURN over HTTP/HTTPS | Stream transport — inner MTU irrelevant |
| TURN over QUIC | See QUIC section above |

For TURN-over-UDP lower `wireguard.mtu` by an additional 56 bytes:

```
wireguard.mtu ≈ physical_mtu − 60 (IPv4) − 56 (TURN) = 1384 for Ethernet
```

For TURN over TCP/TLS/HTTP/HTTPS the inner MTU is irrelevant.
