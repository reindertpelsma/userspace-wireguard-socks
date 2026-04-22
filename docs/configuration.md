<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Configuration Reference

`uwgsocks` merges configuration from YAML, wg-quick config, and CLI flags. YAML
is the base, `wireguard.config_file` and `wireguard.config` are merged into the
WireGuard section, then CLI flags append or override values.

This document explains the behavior behind the main config blocks. For the
single searchable YAML map that includes every field in one place, also keep
[Complete configuration reference](config-reference.md) open.

## WireGuard

```yaml
wireguard:
  private_key: ""
  listen_port: null
  listen_addresses: []
  addresses: []
  dns: []
  mtu: 1420
  config_file: ""
  config: ""
  roam_fallback_seconds: 120
  post_up: []
  post_down: []
  peers:
    - public_key: ""
      preshared_key: ""
      endpoint: ""
      allowed_ips: []
      persistent_keepalive: 25
      transport: ""
      traffic_shaper:
        upload_bps: 0
        download_bps: 0
        latency_ms: 0
```

If `listen_port` is omitted, the process acts as an outbound client and lets the kernel choose UDP source ports. If it is set, WireGuard UDP is bound in server mode. `listen_addresses` restricts the local bind IPs; empty means wildcard IPv4/IPv6.
`wireguard.peers[].transport` selects a transport by name from the top-level
`transports:` list. Leave it empty to use the first transport, or the legacy
UDP / TURN path when `transports` is not configured.

Per-peer mesh fields extend the normal WireGuard peer model without replacing it:

- `control_url`: tunnel-side HTTP URL of another peer's mesh control endpoint.
- `mesh_enabled`: opt this peer into mesh discovery / syncing.
- `mesh_disable_acls`: opt out of client-side dynamic ACL enforcement.
- `mesh_accept_acls`: advertise that this peer enforces the distributed ACL subset locally.
- `mesh_trust`: `untrusted`, `trusted_always`, or `trusted_if_dynamic_acls` for relay fallback policy when direct and relayed paths mix.

Relevant CLI flags:

```bash
--wg-config PATH
--wg-inline TEXT
--private-key KEY
--listen-port PORT
--listen-address IP
--address CIDR
--dns IP
--mtu N
--roam-fallback SECONDS
--peer 'public_key=...,allowed_ips=...,endpoint=...,persistent_keepalive=25'
```

## TURN

```yaml
turn:
  server: turn.example.com:3478
  protocol: udp
  username: wg-client
  password: shared-secret
  realm: example
  permissions:
    - 203.0.113.10/32
  include_wg_public_key: false
  tls:
    cert_file: ""
    key_file: ""
    verify_peer: false
    reload_interval: ""
    ca_file: ""
    server_sni: null
```

When `turn.server` is set, WireGuard UDP packets are sent through a TURN
allocation instead of directly binding the normal WireGuard UDP socket. This is
useful behind NATs, carrier networks, and container platforms where inbound UDP
is awkward but outbound UDP to a relay is possible.

`turn.protocol` may be `udp`, `tcp`, `tls`, or `dtls`. The legacy top-level
`turn:` block is a convenience wrapper for a single TURN transport. When you
need multiple listeners, QUIC / WebSocket obfuscation, or more than one
transport choice, use `transports:` instead.

`permissions` is the initial TURN permission list. In addition, `uwgsocks`
automatically adds configured peer endpoints as permissions so static
WireGuard peers can receive traffic through the relay.

`include_wg_public_key` controls the `wgbind.TURNBind.IncludeWGPublicKey`
behavior. When true, `uwgsocks` encrypts this instance's WireGuard public key
with the TURN password and appends it to the TURN username as
`username---ciphertext`. The companion TURN relay can use that metadata to
associate allocations with a WireGuard identity. Leave it false for generic
TURN servers.

The UI server exposes this as `-turn-include-wg-public-key` and
`TURN_INCLUDE_WG_PUBLIC_KEY`.

## Proxies

```yaml
proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
  http_listeners: []
  mixed: ""
  username: ""
  password: ""
  fallback_direct: true
  fallback_socks5: ""
  ipv6: null
  udp_associate: true
  udp_associate_ports: ""
  https_proxying: true
  https_proxy_verify: pki
  https_proxy_ca_file: ""
  bind: false
  lowbind: false
  prefer_ipv6_for_udp_over_socks: false
  honor_environment: true
  outbound_proxies:
    - type: socks5
      address: 127.0.0.1:1081
      username: ""
      password: ""
      roles: [socks, inbound]
      subnets: [0.0.0.0/0, ::/0]
```

`outbound_proxies` replaces the older single-purpose fallback fields. `fallback_socks5` and `inbound.host_dial_proxy_socks5` still work and are internally converted to outbound proxy rules for compatibility.
`proxy.bind` enables SOCKS5 BIND and is also accepted by the raw socket API as
a compatibility switch for listener-style tunnel binds. `proxy.lowbind`
controls whether raw socket/fdproxy binds below port 1024 are allowed; leave it
false when wrappers should behave like an unprivileged process.

`proxy.http` accepts both classic HTTP proxy traffic and CONNECT tunnels. It
also supports absolute-form HTTPS proxying such as
`GET https://example.com/ HTTP/1.1`. Control that path with:

- `proxy.https_proxying`: allow or forbid absolute-form HTTPS proxying.
- `proxy.https_proxy_verify`: `none`, `pki`, `ca`, or `both`.
- `proxy.https_proxy_ca_file`: PEM CA bundle used by `ca` and `both`.

`proxy.udp_associate_ports` pins SOCKS5 UDP ASSOCIATE relay sockets to a single
port or inclusive range such as `40000-40100`. The runtime skips ports already
occupied by the OS or by other live SOCKS UDP associates in the same process.
`proxy.http_listeners` adds extra HTTP listeners in addition to `proxy.http`,
typically Unix sockets.

Roles:

- `socks`: host-facing SOCKS5/HTTP proxy fallback traffic.
- `inbound`: transparent WireGuard inbound traffic terminated to host sockets.
- `both`: both paths.
- `proxy` and `client` are aliases for `socks`.
- `wireguard` is an alias for `inbound`.

CLI:

```bash
--socks5 127.0.0.1:1080
--http 127.0.0.1:8080
--mixed 127.0.0.1:8081
--proxy-username alice
--proxy-password secret
--fallback-direct=false
--fallback-socks5 127.0.0.1:1081
--outbound-proxy 'http://alice:secret@127.0.0.1:3128;roles=socks,inbound;subnets=203.0.113.0/24'
--honor-proxy-env=false
--socks5-udp-associate=true
--socks5-udp-associate-ports 40000-40100
--socks5-bind=true
--proxy-ipv6=false
--prefer-ipv6-for-udp-over-socks=true
```

HTTP outbound proxies are CONNECT-only and therefore TCP-only. SOCKS5 outbound proxies can carry TCP and UDP ASSOCIATE.

## Transports

```yaml
transports:
  - name: edge-https
    base: https
    listen: true
    listen_port: 443
    listen_addresses: [0.0.0.0, ::]
    tls:
      cert_file: /etc/letsencrypt/live/vpn/fullchain.pem
      key_file: /etc/letsencrypt/live/vpn/privkey.pem
      verify_peer: false
      reload_interval: 60s
      ca_file: ""
      server_sni: vpn.example.com
    websocket:
      path: /wireguard
      upgrade_mode: websocket
      host_header: vpn.example.com
      sni_hostname: ""
    proxy:
      type: http
      http:
        server: proxy.example.com:443
        username: ""
        password: ""
        tls:
          cert_file: ""
          key_file: ""
          verify_peer: true
          reload_interval: ""
          ca_file: ""
          server_sni: proxy.example.com
    ipv6_translate: false
    ipv6_prefix: 64:ff9b::/96
```

`transports` replaces the single-socket UDP-only assumption for outer
WireGuard transport. Each entry names a transport that peers can use through
`wireguard.peers[].transport`. The first transport is the default when a peer
does not name one explicitly.

`base` supports `udp`, `tcp`, `tls`, `dtls`, `http`, `https`, `turn`, and `quic`.
`listen: true` means this transport accepts incoming WireGuard sessions; the
listener port defaults to `wireguard.listen_port` unless `listen_port` overrides
it per transport.

Shared nested blocks:

- `tls`: server and client certificate settings shared by TLS, DTLS, HTTPS,
  QUIC, and TLS-capable proxy layers. `server_sni` is tri-state: omitted means
  infer from the destination hostname, explicit `null` means do not send SNI,
  and a string forces that SNI.
- `websocket`: used by HTTP-based transports. `path` defaults to `/`.
  `upgrade_mode` controls the client-side HTTP upgrade protocol:
  `websocket` (default) or `proxyguard` for native `Upgrade: UoTLV/1`.
  Listen mode always accepts both WebSocket and `UoTLV/1` on the same path.
  `host_header` overrides the HTTP Host header. `sni_hostname` is deprecated in
  favor of `tls.server_sni`.
- `proxy.type`: `none`, `socks5`, `http`, or `https`.

Proxy-specific nested blocks:

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
      protocol: tls
      no_create_permission: false
      include_wg_public_key: false
      permissions: [198.51.100.10/32]
      tls:
        cert_file: ""
        key_file: ""
        verify_peer: false
        reload_interval: ""
        ca_file: ""
        server_sni: turn.example.com
```

Notes:

- `turn.protocol` is `udp`, `tcp`, `tls`, or `dtls`.
- `turn.no_create_permission: true` is for open TURN relays.
- `turn.include_wg_public_key` appends an encrypted WireGuard public key
  to the TURN username for relays that understand that metadata.
- HTTP CONNECT proxies are stream-oriented, so UDP-style base transports become
  connection-oriented when carried through them.
- `ipv6_translate` and `ipv6_prefix` enable NAT64-style translation for IPv4
  peer endpoints when the outer network is IPv6-only.

Proxy config:


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
    tls:
      cert_file: ""
      key_file: ""
      verify_peer: false
      reload_interval: ""
      ca_file: ""
      server_sni: proxy.example.com
```

## Mesh Control

```yaml
mesh_control:
  listen: 100.64.0.1:8787
  challenge_rotate_seconds: 120
  active_peer_window_seconds: 120
  advertise_self: false
```

`mesh_control.listen` starts a small tunnel-only HTTP control endpoint inside the WireGuard netstack. It is intended for peer syncing and optional direct-path discovery between `uwgsocks` peers while keeping standard WireGuard public keys and `AllowedIPs`.

Current mesh control endpoints are used for:

- peer discovery and sync (`/v1/peers`)
- distributed ACL export (`/v1/acls`)
- challenge / authenticated control sessions (`/v1/challenge`)

Peer advertisements always include public key, `AllowedIPs`, and pairwise PSK material for sync-capable peers. The `endpoint` field is advertised only when the peer is currently reachable over a UDP-capable outer transport such as direct UDP or TURN UDP. HTTP/TLS/QUIC-only peers are still syncable, but they are not advertised as direct-P2P candidates.

wg-quick style configs can opt a peer into this with:

```ini
#!Control=http://100.64.0.1:8787
```

That directive is valid in a `[Peer]` section and maps to `control_url` plus `mesh_enabled: true`.

## Forwards

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432
    proxy_protocol: ""

reverse_forwards:
  - proto: udp
    listen: 100.64.90.99:5353
    target: 127.0.0.1:53
    proxy_protocol: v2
```

`forwards` listen on the host and dial over WireGuard. `reverse_forwards` listen inside the userspace tunnel and dial host targets. Reverse-forward listen IPs do not need to be listed in `Address=`; they only need to be routed to this peer by the sending peer.

CLI:

```bash
--forward 'tcp://127.0.0.1:15432=10.10.0.20:5432'
--forward 'udp://127.0.0.1:15353=100.64.90.1:53,proxy_protocol=v2'
--reverse-forward 'tcp://100.64.90.99:8443=127.0.0.1:443,proxy_protocol=v1'
```

## Transparent Inbound

```yaml
inbound:
  transparent: false
  consistent_port: loose
  disable_low_ports: true
  max_connections: 0
  max_connections_per_peer: 0
  connection_table_grace_seconds: 30
  tcp_receive_window_bytes: 1048576
  tcp_max_buffered_bytes: 268435456
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30
  host_dial_proxy_socks5: ""
  host_dial_bind_address: ""
  reply_icmp: true
  icmp_rate_limit_per_sec: 10
  forward_icmp_errors: true
  tcp_mss_clamp: true
```

CLI:

```bash
--inbound-transparent=true
--consistent-port loose
--disable-low-ports=true
--max-connections 4096
--max-connections-per-peer 512
--connection-table-grace 30
--tcp-receive-window 1048576
--tcp-max-buffered 268435456
--tcp-idle-timeout 900
--udp-idle-timeout 30
--host-dial-bind-address 192.0.2.10
```

`max_connections` still caps the whole transparent inbound table. The new
`max_connections_per_peer` limit keeps one WireGuard peer from monopolizing
that table while leaving headroom for other peers.

## Traffic Shaping

```yaml
traffic_shaper:
  upload_bps: 0
  download_bps: 0
  latency_ms: 15

wireguard:
  peers:
    - public_key: BASE64_PUBLIC_KEY
      allowed_ips: [100.64.90.2/32]
      traffic_shaper:
        upload_bps: 1048576
        download_bps: 2097152
        latency_ms: 20
```

CLI:

```bash
--traffic-upload-bps 1048576
--traffic-download-bps 2097152
--traffic-latency-ms 20
--peer 'public_key=...,allowed_ips=100.64.90.2/32,upload_bps=1048576,download_bps=2097152,latency_ms=20'
```

The top-level `traffic_shaper` block is a global per-peer default. A peer's own
`traffic_shaper` overrides those values for that peer only. TCP uses
backpressure on stream reads and writes, while UDP uses the packet shaper and
drops bursts once the bounded queue budget is exceeded.

## Host Forwarding And Filters

```yaml
host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1
    redirect_tun: false
  inbound:
    enabled: false
    redirect_ip: ""
    redirect_tun: false

routing:
  enforce_address_subnets: true

filtering:
  drop_ipv6_link_local_multicast: true
  drop_ipv4_invalid: true
```

CLI:

```bash
--proxy-host-forward=true
--proxy-host-forward-redirect 127.0.0.1
--proxy-host-forward-tun=false
--inbound-host-forward=false
--inbound-host-forward-redirect 192.0.2.10
--inbound-host-forward-tun=false
--enforce-address-subnets=true
--drop-ipv4-invalid=true
--drop-ipv6-link-local-multicast=true
```

`redirect_tun: true` requires `tun.enabled: true`. It makes host forwarding
dial the original tunnel IP on the host TUN interface instead of rewriting to
loopback or `redirect_ip`, which is useful for applications that bind
specifically to the TUN address.

## Optional Host TUN

Host TUN mode is disabled by default. It exists for applications that need a
kernel network interface; it is not required for SOCKS5/HTTP, forwards,
reverse forwards, the raw socket API, or `uwgwrapper`.

```yaml
tun:
  enabled: false
  name: uwgsocks0
  mtu: 0
  configure: false
  route_allowed_ips: true
  routes: []
  dns_servers: []
  dns_resolv_conf: ""
  fallback_system_dns: []
  up: []
  down: []
```

When enabled, `uwgsocks` creates a host TUN interface and connects it to a
second userspace netstack. TCP, UDP, and ping-style ICMP/ICMPv6 flows from
that interface are terminated by `uwgsocks` and use the same outbound ACL,
AllowedIPs, outbound proxy, and `fallback_direct` routing as SOCKS5/HTTP and
the raw socket API.

`tun.configure` applies host interface settings through the local platform:
Linux uses netlink, macOS uses `ifconfig`/`route`, FreeBSD uses
`ifconfig`/`route`, and Windows uses the native TUN adapter plus `netsh`
route/address commands. It sets the MTU, assigns the WireGuard `Address=`
prefixes, brings the interface up where needed, and installs routes. If
`route_allowed_ips` is true, peer `AllowedIPs` are routed to the TUN interface;
`routes` adds extra CIDRs. Overlapping routes are reduced before installation,
so a broader route such as `172.16.0.0/12` suppresses a contained route such as
`172.18.0.0/16`.

`dns_servers` optionally configures host DNS servers on the TUN interface when
the platform backend supports it. Today that is best-effort on Linux
(`resolvectl` or `systemd-resolve`) and Windows (`netsh`). macOS `utun` and
FreeBSD `tun` DNS configuration are not currently automated by `uwgsocks`.

`dns_resolv_conf` is an explicit opt-in override for DNS server updates. When
set to an absolute path, `uwgsocks` writes `tun.dns_servers` as plain
`nameserver ...` lines to that file instead of talking to the host DNS manager.
This is useful in containers, VMs, or custom DNS setups where `/etc/resolv.conf`
or a dedicated resolver include file is the integration point.

`fallback_system_dns` is only for the outer WireGuard transport itself. When
host-TUN routes are active and a peer endpoint is configured as a hostname,
`uwgsocks` resolves that hostname through these bypass DNS servers instead of
relying on the system resolver to escape the tunnel. If empty, `uwgsocks`
falls back to a built-in public resolver list (`1.1.1.1`, `1.0.0.1`,
`8.8.8.8`, `8.8.4.4`, and their IPv6 equivalents).

`tun.up` and `tun.down` are shell commands and run only when `scripts.allow` or
`--allow-scripts` is enabled.

Before host-TUN routes are installed, `uwgsocks` snapshots the current host
egress source addresses and reuses them for the outer WireGuard transport's
direct TCP/UDP dials. That prevents the common single-homed loop where a small
test route or broad default route would otherwise recurse back into the TUN.
On multihomed hosts, explicit host routes for peer endpoints are still the
safer option when you intentionally route very broad prefixes.

CLI:

```bash
--tun=true
--tun-name uwgsocks0
--tun-mtu 1420
--tun-configure=true
--tun-route-allowed-ips=true
--tun-route 10.77.0.0/16
--tun-up 'echo up'
--tun-down 'echo down'
```

Helper commands in the main binary can generate WireGuard material when
`wireguard-tools` is not installed:

```bash
uwgsocks genkey
uwgsocks genpsk
uwgsocks pubkey < privatekey.txt
uwgsocks genpair --server-address 10.77.0.1/32 --client-address 10.77.0.2/32 --server-endpoint vpn.example.com:51820
uwgsocks add-client --server-config server.conf --client-address 10.77.0.3/32 --server-endpoint vpn.example.com:51820
```

`uwgsocks status --text --api unix:/run/uwgsocks/api.sock` prints a compact
terminal view similar to `wg show`, while plain `uwgsocks status` still prints
JSON.

## ACLs And Relay

```yaml
relay:
  enabled: false
  conntrack: true
  conntrack_max_flows: 65536
  conntrack_max_per_peer: 4096

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
  inbound: []
  outbound:
    - action: allow
      source: 127.0.0.1/32
      destination: 100.64.90.0/24
      destination_port: "80-443"
  relay: []
```

CLI:

```bash
--relay=true
--relay-conntrack=true
--relay-conntrack-max-flows 65536
--relay-conntrack-max-per-peer 4096
--acl-inbound-default deny
--acl-outbound 'allow dst=100.64.90.0/24 dport=80-443'
--acl-relay 'allow src=100.64.90.2/32 dst=100.64.90.3/32 dport=443'
```

Relay forwarding uses stateful connection tracking by default. New TCP SYNs,
new UDP conversations, and ICMP echo requests are checked against the relay
ACL; established replies and matching ICMP error packets are then allowed from
the conntrack table. UDP and ICMP echo entries idle out after 30 seconds by
default, while TCP follows the configured TCP idle timeout with shorter
handshake and close windows. Set `relay.conntrack: false` or
`--relay-conntrack=false` to restore the older stateless behavior where relay
ACLs are purely directional and reply rules must be configured explicitly.

## DNS And API

```yaml
dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024

api:
  listen: 127.0.0.1:9090
  token: replace-with-a-long-random-token
  allow_unauthenticated_unix: false

socket_api:
  bind: false
  transparent_bind: false
  udp_inbound: false

proxy:
  http: 127.0.0.1:8080
  http_listeners:
    - unix:/run/uwgsocks/http.sock
  bind: false
  lowbind: false
```

`dns_server.listen` hosts a small DNS server **inside the WireGuard tunnel**.
Peers can point their tunnel-side DNS setting at this address to resolve
internet and internal names through the server. It is not a host `:53` bind
and it does not expose your machine's resolver directly on the LAN.

The runtime `api.listen` endpoint is the management and integration surface for
control planes such as `uwgsocks-ui`. It exposes live status, peer and ACL
updates, forward management, and the low-level socket protocol. Use a Unix
socket where possible; use an HTTP listener plus `api.token` when another
process must reach it over TCP.

CLI:

```bash
--dns-listen 100.64.90.1:53
--dns-max-inflight 1024
--api-listen 127.0.0.1:9090
--api-token replace-with-a-long-random-token
--api-allow-unauthenticated-unix
```

Runtime API endpoints:

- `GET /v1/status`
- `GET /v1/ping`
- `GET /v1/interface_ips`
- `GET /v1/socket`
- `GET/POST/PUT/DELETE /v1/peers`
- `GET/PUT/POST /v1/acls`
- `GET/POST/PUT/DELETE /v1/acls/{inbound|outbound|relay}`
- `GET/POST/DELETE /v1/forwards`
- `PUT/POST /v1/wireguard/config`

`/v1/wireguard/config` accepts a wg-quick-style config body or JSON
`{"config":"..."}`. It never executes or retains `PreUp`, `PostUp`,
`PreDown`, or `PostDown`. It replaces the live WireGuard private key, listen
port when supplied, and peer set, while rejecting `Address`, `DNS`, and `MTU`
changes that require rebuilding the userspace netstack.

`/v1/socket` is the HTTP-upgraded raw socket protocol documented in
[`docs/socket-protocol.md`](socket-protocol.md). It is the lowest-level local
integration surface in `uwgsocks`: a program can create TCP, UDP, ICMP ping,
and listener-style sockets directly on top of the userspace TCP/IP stack
instead of going through SOCKS5 or HTTP proxying. `uwgwrapper` and other local
integrations use this path when they need "real" sockets rather than proxy
semantics.

Connected TCP/UDP sockets do not need `socket_api.bind`. Connected ICMP ping
sockets are also supported and are checked against outbound ACL rules with
protocol `icmp`. Connected TCP/UDP sockets follow the same `AllowedIPs`,
outbound-proxy, and `fallback_direct` routing order as SOCKS5/HTTP. Connected
ICMP ping sockets use the same ACL and `AllowedIPs` checks, then fall back to a
host unprivileged ping socket only when the kernel supports it. Raw socket API
IPv6 connect attempts are rejected immediately when the runtime itself has no
tunnel IPv6 so Happy Eyeballs can fall back to IPv4.

TCP listener sockets require `socket_api.bind: true` or `proxy.bind: true`.
UDP listener-style sockets are allowed even when `bind` is false, but they are
established-only unless `socket_api.udp_inbound: true`: replies are delivered
only from remote IP:port pairs the client has contacted recently. Binding to
addresses outside this peer's assigned WireGuard IPs requires
`socket_api.transparent_bind: true`. Binding below port 1024 additionally
requires `proxy.lowbind: true`. UDP listener-style sockets can be converted to
connected UDP sockets, reconnected to another peer, or disconnected again by
sending a `connect` frame with `listener_connection_id` set to the existing UDP
socket ID.

`proxy.http_listeners` adds extra HTTP proxy listeners in addition to
`proxy.http`. This lets the same HTTP proxy, including `/uwg/socket`, be
available on both a TCP address and a Unix socket.

## Scripts And Logging

```yaml
scripts:
  allow: false

log:
  verbose: false
```

`scripts.allow` gates all shell-hook execution, including `wireguard.pre_up`,
`wireguard.post_up`, `wireguard.pre_down`, `wireguard.post_down`, `tun.up`,
and `tun.down`. It defaults off. Leave it false for untrusted config files,
including provider-supplied or internet-downloaded `wg-quick` files.
Runtime API updates through `/v1/wireguard/config` always strip those hooks,
even when scripts are enabled. `log.verbose` switches WireGuard device logging
from error-only to verbose mode and also enables additional runtime warnings
from higher layers.

API client commands:

```bash
uwgsocks status
uwgsocks ping 100.64.90.1 --count 3
uwgsocks peers
uwgsocks add-peer --public-key PEER_PUBLIC_KEY --allowed-ip 100.64.90.3/32
uwgsocks remove-peer PEER_PUBLIC_KEY
uwgsocks acl-list outbound
uwgsocks acl-add outbound 'allow dst=100.64.90.0/24 dport=80-443'
uwgsocks acl-set --file ./outbound-acl.json outbound
uwgsocks acl-remove --index 0 outbound
uwgsocks wg-setconf ./client.conf
uwgsocks interface-ips
uwgsocks forwards
uwgsocks add-forward --proto tcp --listen 127.0.0.1:18080 --target 100.64.90.1:80
uwgsocks add-forward --reverse --proto tcp --listen 100.64.90.99:8443 --target 127.0.0.1:443
uwgsocks remove-forward forward.runtime.1
```

Set `UWGS_API` and `UWGS_API_TOKEN`, or pass `--api` and `--token` to each API
client command. `--api` accepts `http://host:port`, `host:port`, or
`unix:/path/to/api.sock`.

## Other CLI Flags

```bash
--config PATH
--allow-scripts
--verbose
--check
```

`--allow-scripts` enables `PreUp`, `PostUp`, `PreDown`, `PostDown`, `tun.up`,
and `tun.down` commands. Leave it off for untrusted config files, especially
`wg-quick` configs that were downloaded or supplied by a remote party.
