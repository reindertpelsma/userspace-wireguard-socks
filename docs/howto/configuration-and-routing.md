<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Configuration And Routing

Use [Configuration reference](../configuration.md) for the exhaustive YAML
schema. This guide keeps the practical model and the most important snippets in
one place.

## Configuration Sources

There are three configuration sources:

1. YAML runtime config, for example `--config ./uwg.yaml`
2. WireGuard wg-quick config, via `wireguard.config_file`, `wireguard.config`, `--wg-config`, or `--wg-inline`
3. CLI flags

Load order:

```text
YAML base
  -> YAML wireguard.config_file / wireguard.config
  -> CLI --wg-config / --wg-inline
  -> CLI scalar overrides and repeated additions
  -> normalization and validation
```

Repeated values such as `--address`, `--dns`, `--peer`, `--forward`,
`--reverse-forward`, and ACL rules are appended.

## WireGuard Config

The parser accepts the wg-quick ini-like format:

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY_BASE64
Address = 100.64.90.2/32
DNS = 100.64.90.1
MTU = 1420

[Peer]
PublicKey = SERVER_PUBLIC_KEY_BASE64
Endpoint = vpn.example.com:51820
AllowedIPs = 100.64.90.1/32, 10.10.0.0/16
PersistentKeepalive = 25
```

Supported fields:

- `[Interface]`: `PrivateKey`, `ListenPort`, `Address`, `DNS`, `MTU`, `PreUp`, `PostUp`, `PreDown`, `PostDown`
- `[Peer]`: `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive`

Accepted but ignored because this runtime never changes the host routing table:
`Table`, `SaveConfig`.

All four hook lists are parsed but ignored unless `scripts.allow: true` or
`--allow-scripts` is set. Runtime API replacement via `/v1/wireguard/config`
always strips them, even when scripts are enabled.

To restrict server-mode listening to specific local IPs:

```yaml
wireguard:
  listen_port: 51820
  listen_addresses:
    - 203.0.113.10
    - 2001:db8::10
```

## TURN Bind Mode

`uwgsocks` can use a TURN allocation as the WireGuard bind:

```yaml
turn:
  server: turn.example.com:3478
  username: wg-client
  password: shared-secret
  realm: example
  permissions:
    - 203.0.113.10:51820
  include_wg_public_key: false
```

That is useful when the process can send UDP to a relay but cannot receive
inbound UDP directly.

## YAML Example

Client proxy shape:

```yaml
wireguard:
  config_file: ./examples/client.conf
  roam_fallback_seconds: 120

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
  fallback_direct: true
  honor_environment: true
  udp_associate: true
  bind: false
  lowbind: false

host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1

routing:
  enforce_address_subnets: true

tun:
  enabled: false
  configure: false

forwards:
  - proto: tcp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432

reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8443
    target: 127.0.0.1:443

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
```

Server or egress shape:

```yaml
wireguard:
  config_file: ./examples/server.conf

inbound:
  transparent: true

dns_server:
  listen: 100.64.90.1:53

api:
  listen: 127.0.0.1:9090
  token: replace-with-a-long-random-token
```

## Proxy Routing

The routing rules are designed to be predictable:

- explicit forwards win before transparent behavior
- peer `AllowedIPs` win before fallback proxying or direct access
- `Address=` subnets can reserve virtual interface space to prevent leaks
- outbound SOCKS5 and HTTP proxy fallback rules are checked before direct host dials

The SOCKS5 server supports:

- `CONNECT` for TCP streams
- `UDP ASSOCIATE`
- `BIND` for tunnel-side TCP listeners when `proxy.bind` is enabled
- optional username/password auth

Extra HTTP listeners can be added with `proxy.http_listeners`, including Unix
sockets:

```yaml
proxy:
  http: 127.0.0.1:8080
  http_listeners:
    - unix:/tmp/http.sock
```

For the full routing decision tree, see [Proxy routing reference](../proxy-routing.md).

## Forwards

`forwards` listen on the host and dial through WireGuard:

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432
```

`reverse_forwards` listen inside the userspace WireGuard netstack and dial out
on the host:

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8443
    target: 127.0.0.1:443
  - proto: udp
    listen: 100.64.90.99:5353
    target: 127.0.0.1:53
```

Per-forward PROXY protocol is supported:

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:8443
    target: 100.64.90.10:443
    proxy_protocol: v1

reverse_forwards:
  - proto: udp
    listen: 100.64.90.99:5353
    target: 127.0.0.1:53
    proxy_protocol: v2
```

## Address Space, Host Forwarding, And TUN

`Address=` prefixes are treated like interface routes. With
`Address = 10.10.10.2/24`, a proxy request for `10.10.10.99` must still match
a peer `AllowedIPs`, or it is rejected.

Configure that behavior with:

```yaml
routing:
  enforce_address_subnets: true
```

Host forwarding is separate from transparent forwarding:

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
```

Optional host TUN mode is an explicit compatibility layer for applications that
must see a kernel interface:

```yaml
tun:
  enabled: true
  name: uwgsocks0
  mtu: 1420
  configure: true
  route_allowed_ips: true
  routes:
    - 10.77.0.0/16
```

## DNS

When `DNS=` is set in the WireGuard config:

- DNS servers inside `AllowedIPs` are queried through the userspace WireGuard netstack
- DNS servers outside `AllowedIPs` are queried directly on the host network, with a warning
- if no `DNS=` is configured, system DNS is used for proxy hostname resolution

Tunnel-hosted DNS is enabled with:

```yaml
dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024
```

## Inbound Transparent Mode

When `inbound.transparent: true`, TCP and UDP packets arriving from a WireGuard
peer are terminated in the userspace netstack and converted into normal host
sockets. This is the mode that lets a rootless `uwgsocks` server act as an
Internet or LAN exit point.

Static peer endpoints fall back to their configured `Endpoint=` after roaming
if the live endpoint stops handshaking for
`wireguard.roam_fallback_seconds`.

## ACLs

ACL lists exist for inbound, outbound, and relay traffic. Rules are evaluated
in order, first match wins, and omitted fields are wildcards.

Relay forwarding is stateful by default. Relay ACLs decide only whether a new
TCP SYN, UDP conversation, or ICMP echo request may be created; established
reverse traffic and ICMP errors that quote an existing flow are then allowed by
relay conntrack.

Example:

```yaml
acl:
  outbound_default: deny
  outbound:
    - action: allow
      source: 127.0.0.1/32
      destination: 100.64.90.0/24
      destination_port: "80-443"
```

For every field and default, use [Configuration reference](../configuration.md).
