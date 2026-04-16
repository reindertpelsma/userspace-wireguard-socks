<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Configuration Reference

`uwgsocks` merges configuration from YAML, wg-quick config, and CLI flags. YAML is the base, `wireguard.config_file` and `wireguard.config` are merged into the WireGuard section, then CLI flags append or override values.

## WireGuard

```yaml
wireguard:
  private_key: ""
  listen_port: 51820
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
```

If `listen_port` is omitted, the process acts as an outbound client and lets the kernel choose UDP source ports. If it is set, WireGuard UDP is bound in server mode. `listen_addresses` restricts the local bind IPs; empty means wildcard IPv4/IPv6.

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

## Proxies

```yaml
proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
  mixed: ""
  username: ""
  password: ""
  fallback_direct: true
  fallback_socks5: ""
  honor_environment: true
  outbound_proxies:
    - type: socks5
      address: 127.0.0.1:1081
      username: ""
      password: ""
      roles: [socks, inbound]
      subnets: [0.0.0.0/0, ::/0]
  udp_associate: true
  bind: false
  lowbind: false
  ipv6: null
  prefer_ipv6_for_udp_over_socks: false
```

`outbound_proxies` replaces the older single-purpose fallback fields. `fallback_socks5` and `inbound.host_dial_proxy_socks5` still work and are internally converted to outbound proxy rules for compatibility.
`proxy.bind` enables SOCKS5 BIND and is also accepted by the raw socket API as
a compatibility switch for listener-style tunnel binds. `proxy.lowbind`
controls whether raw socket/fdproxy binds below port 1024 are allowed; leave it
false when wrappers should behave like an unprivileged process.

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
--socks5-bind=true
--proxy-ipv6=false
--prefer-ipv6-for-udp-over-socks=true
```

HTTP outbound proxies are CONNECT-only and therefore TCP-only. SOCKS5 outbound proxies can carry TCP and UDP ASSOCIATE.

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
--connection-table-grace 30
--tcp-receive-window 1048576
--tcp-max-buffered 268435456
--tcp-idle-timeout 900
--udp-idle-timeout 30
--host-dial-bind-address 192.0.2.10
```

## Host Forwarding And Filters

```yaml
host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1
  inbound:
    enabled: false
    redirect_ip: ""

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
--inbound-host-forward=false
--inbound-host-forward-redirect 192.0.2.10
--enforce-address-subnets=true
--drop-ipv4-invalid=true
--drop-ipv6-link-local-multicast=true
```

## ACLs And Relay

```yaml
relay:
  enabled: false

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
--acl-inbound-default deny
--acl-outbound 'allow dst=100.64.90.0/24 dport=80-443'
--acl-relay 'allow src=100.64.90.2/32 dst=100.64.90.3/32 dport=443'
```

Relay ACLs are directional. For a TCP relay flow, allow both the client-to-server rule and the server-to-client reply rule when the default is deny.

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
`{"config":"..."}`. It never executes `PostUp`/`PostDown`. It replaces the
live WireGuard private key, listen port when supplied, and peer set, while
rejecting `Address`, `DNS`, and `MTU` changes that require rebuilding the
userspace netstack.

`/v1/socket` is the HTTP-upgraded raw socket protocol documented in
[`docs/socket-protocol.md`](socket-protocol.md). Connected TCP/UDP sockets do
not need `socket_api.bind`. TCP listener sockets require `socket_api.bind:
true` or `proxy.bind: true`. UDP listener-style sockets are allowed even when
`bind` is false, but
they are established-only unless `socket_api.udp_inbound: true`: replies are
delivered only from remote IP:port pairs the client has contacted recently.
Binding to addresses outside this peer's assigned WireGuard IPs requires
`socket_api.transparent_bind: true`. Binding below port 1024 additionally
requires `proxy.lowbind: true`. UDP listener-style sockets can be
converted to connected UDP sockets, reconnected to another peer, or disconnected
again by sending a `connect` frame with `listener_connection_id` set to the
existing UDP socket ID.

`proxy.http_listeners` adds extra HTTP proxy listeners in addition to
`proxy.http`. This lets the same HTTP proxy, including `/uwg/socket`, be
available on both a TCP address and a Unix socket.

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

`--allow-scripts` enables `PostUp` and `PostDown` commands from wg-quick config. Leave it off for untrusted config files.
