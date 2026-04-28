# Transport Modes

Standard WireGuard uses UDP over IPv4 or IPv6. That is the best default when
it works, but it is not enough for every deployment.

`uwgsocks` adds alternate outer transports for situations such as:

1. The host cannot expose a WireGuard UDP port directly, but can accept web-style traffic.
2. The process must reach the network through a proxy first.
3. A small relay is needed to front a private WireGuard server.
4. The network blocks UDP, has MTU trouble, or fingerprints VPN traffic aggressively.
5. The deployment needs WireGuard to blend in with ordinary HTTPS, HTTP/3, or TURN traffic.

The supported transport families are:

- UDP
- TCP
- TLS
- HTTP
- HTTPS
- QUIC (HTTP/3)
- DTLS
- TURN

Most of them can also be carried through outbound SOCKS5 or HTTP(S) proxies.

Connection-oriented transports such as TCP, TLS, HTTP, HTTPS, and QUIC still
support WireGuard roaming semantics. When a session fails, `uwgsocks` tears
down the outer connection and reconnects when WireGuard needs to re-handshake.

The transport wrapper itself does not change the cryptographic security of the
WireGuard payload. WireGuard remains the authenticated and encrypted tunnel.
The outer transport only changes how the encrypted packets move across the
network.

## UDP

UDP is the default and preferred transport.

- Client mode: each peer uses its own ephemeral source port. This mode cannot
  receive unsolicited inbound WireGuard traffic.
- Listen mode: one stable UDP port is bound and reused for all peers. This is
  the mode used when `ListenPort` or `wireguard.listen_port` is set.

```yaml
transports:
  - name: standard-wireguard
    base: udp
    listen: true
    listen_port: 51820
```

## TCP

TCP is useful when UDP is unavailable or badly handled by the network.

Semantics:

- Connect mode: `uwgsocks` opens a TCP connection when a peer becomes active.
- Listen mode: `uwgsocks` accepts inbound TCP clients on the configured port.
- Packets are framed on the stream with a 2-byte big-endian length prefix.

Trade-off:

- TCP works in more places.
- TCP also introduces head-of-line blocking and is usually slower than UDP.

```yaml
transports:
  - name: wireguard-tcp
    base: tcp
    listen: true
    listen_port: 51820
```

## TLS

TLS is WireGuard-over-TCP wrapped in TLS.

Use it when the traffic needs to look like generic TLS rather than plain TCP.
In many deployments, HTTP or HTTPS transport is a better fit because it works
more naturally with reverse proxies and CDN-style edges.

By default, clients do not need PKI validation for the transport itself because
WireGuard already authenticates the tunnel. TLS here is primarily an outer
carrier and compatibility layer.

```yaml
transports:
  - name: wireguard-tls
    base: tls
    listen: true
    listen_port: 8443
```

## HTTP And HTTPS

HTTP and HTTPS carry WireGuard inside WebSocket frames, one WireGuard packet
per binary frame.

This is useful when:

- the server must sit behind a reverse proxy
- the deployment wants a URL-based endpoint
- the network is more tolerant of web traffic than raw UDP

`uwgsocks` also supports a raw HTTP upgrade mode compatible with ProxyGuard.
That can help on intermediaries that handle upgraded streams better than
WebSocket backpressure.

```yaml
transports:
  - name: wireguard-http
    base: http
    websocket:
      upgrade_mode: websocket
    listen: true
    listen_port: 80

  - name: wireguard-https
    base: https
    websocket:
      upgrade_mode: websocket
    listen: true
    listen_port: 443
    tls:
      cert_file: /etc/letsencrypt/live/vpn/fullchain.pem
      key_file: /etc/letsencrypt/live/vpn/privkey.pem
      verify_peer: false
      reload_interval: 60s
      ca_file: ""
      server_sni: vpn.example.com
```

## QUIC (HTTP/3)

QUIC is the high-performance answer when HTTP-style fronting is needed but TCP
meltdown is unacceptable.

Why it matters:

- HTTP and HTTPS over TCP can suffer badly under loss because the outer stream
  stalls all inner traffic.
- QUIC keeps the outer carrier on UDP, usually port `443`, while still fitting
  into modern HTTP/3 infrastructure.

`uwgsocks` uses QUIC WebTransport and also accepts WebSocket-over-HTTP/3 on the
same path. That lets one edge URL serve both stream-oriented and UDP-friendly
outer transport paths.

```yaml
transports:
  - name: wireguard-quic
    base: quic
    listen: true
    listen_port: 443
    tls:
      cert_file: /etc/letsencrypt/live/vpn/fullchain.pem
      key_file: /etc/letsencrypt/live/vpn/privkey.pem
      verify_peer: false
      reload_interval: 60s
      ca_file: ""
      server_sni: vpn.example.com
```

## DTLS

DTLS is the UDP-native analogue of TLS.

Use it when the deployment wants traffic that looks more like WebRTC-style UDP
than plain WireGuard UDP, without introducing TCP head-of-line blocking.

```yaml
transports:
  - name: wireguard-dtls
    base: dtls
    listen: true
    listen_port: 52201
```

## TURN

TURN is the relay option for deployments where direct inbound UDP is not
available.

Typical uses:

- fronting a private WireGuard server behind NAT
- reaching a server through restrictive networks
- relaying through carriers that already resemble ordinary WebRTC/TURN traffic

Supported TURN carrier modes:

- TURN UDP
- TURN TCP
- TURN TLS
- TURN DTLS
- TURN HTTP over WebSocket or raw HTTP upgrade
- TURN HTTPS over WebSocket or raw HTTP upgrade
- TURN QUIC over WebTransport datagrams, with RFC 9220 WebSocket over HTTP/3 on the same path

```yaml
transports:
  - name: turn
    base: turn
    listen: true
    turn:
      server: turn.example.com:3478
      username: wg
      password: secret
      realm: example
      protocol: udp
      no_create_permission: false
      include_wg_public_key: false
      permissions: [198.51.100.10/32]
```

For TURN over HTTP, HTTPS, or QUIC, the default path is `/turn`. The same
listener accepts both WebSocket framing and raw `Upgrade: TURN` streams.

## Proxying The Outer Transport

If the host running `uwgsocks` must first reach the network through another
proxy, the outer transport can be routed through SOCKS5 or HTTP(S).

Important limitation:

- SOCKS5 can carry UDP-style transports such as UDP, TURN UDP, and DTLS.
- HTTP CONNECT is stream-oriented, so UDP-style transports must switch to a
  stream-oriented carrier such as TCP, TLS, HTTP, or HTTPS.

```yaml
proxy:
  type: socks5
  socks5:
    server: 127.0.0.1:1080
    username: ""
    password: ""
  http:
    server: proxy.example.com:443
    username: ""
    password: ""
```

For anonymous HTTPS proxies, `uwgsocks` defaults to relaxed certificate
verification because WireGuard still authenticates the tunnel payload. If proxy
credentials are configured, the runtime validates the proxy certificate by
default so those credentials are not exposed to a spoofed proxy endpoint.
