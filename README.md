<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Userspace WireGuard SOCKS Gateway

`uwgsocks` runs WireGuard and a TCP/UDP/IP stack entirely in userspace, then exposes useful application-facing entry points:

The goal is to make WireGuard usable in environments where a kernel tunnel is unavailable or undesirable: rootless processes, restricted containers, CI workers, locked-down servers, or applications that should use WireGuard as a transport without changing the host routing table.

Examples of the vast amount of supported use cases:
- Connecting to or hosting Wireguard server on rootless / Docker containers (even in the most restrictive settings, without root)
- Connecting your web browser for certain sites to Wireguard using a SOCKS proxy without root or managling your network interfaces
- Connecting remotely to machines network where you do not have root access, using this application as exit proxy for regular internet traffic
- Connecting your personal runs on a HPC cluster or rented GPUs to your secure network where you do not have root or are in a restricted docker container
- Opening a private Wireguard connection on your user of a shared machine (e.g HPC) without allowing other users to use the network, without requiring root or complex UID-based iptables.
- Adding or embedding Wireguard to an existing SaaS application to connect to on-premise IoT devices, without requiring network setup access. There is both an API available and also a embeddable library allowing you to connect through TCP/IP over Wireguard stack directly from your software.
- Using Wireguard to connect only selective applications to the VPN without requiring complex iptables/ip routing.
- You need to connect remotely to a machine, but that machine can only access the internet through a provided HTTP/SOCKS proxy. This application can then act as your VPN server to the internet, transperantly routing connections over a SOCKS/HTTP proxy.
- Port forwarding an application (e.g http reverse proxy) running in a restrictive environment to the internet, using a small server that has a public IP. Wireguard supports transperantly forwarding this traffic, including preservation of the source IP

For whatever reason you do not want or can't mess with routing, firewall, `/dev/net/tun` or root access this application will provide the best support possible for your VPN need.

The app is designed to replace most functionalities that regular Wireguard tunnels provided with root access, including TCP/UDP/IPv6, inbound/outbound connections, firewall ACLs and even using your Wireguard as a relay server all without requiring any permissions.

Since it does not use your regular network routing, applications connect through Wireguard in a variety of supported ways:
- You can forward local TCP/UDP ports over Wireguard or vice versa. Proxy protocol is supported so that the source IP will not get lost. 
- Connecting to the local network of the machine running ugwsocks
- Using SOCKS/HTTP proxy to connect applications to Wireguard for both TCP/UDP.
- Letting unmodified existing applications that do not support SOCKS/HTTP connect to Wireguard or listen for services using the preload wrapper (EXPERIMENTAL)
- Embedding the Wireguard TCP/IP stack as library in your existing applications
- Forwarding Wireguard traffic between multiple peers, allowing you to run a wireguard relay server for clients behind firewalls without root or messing with P2P

## Build

Install Go 1.24 or newer, then:

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgfdproxy ./cmd/uwgfdproxy
```

If you want also to build the experimental sockisfy wrapper so you can tunnel abritary applications over Wireguard without SOCKS or root

```bash
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgfdproxy ./cmd/uwgfdproxy
gcc -shared -fPIC -O2 -Wall -Wextra -o ./uwgpreload.so tests/preload/testdata/uwgpreload.c -ldl
```

The resulting `uwgsocks` and `uwgfdproxy` binaries are static executables.

## Quick Start

The files under `examples/` are a self-contained localhost demo. They contain
demonstration-only keys and configure the client with `AllowedIPs = 0.0.0.0/0`,
so IPv4 SOCKS traffic can egress through the server process.

Terminal 1 - the Wireguard server acting as exit relay to the internet:

```bash
./uwgsocks \
  --config ./examples/server.yaml \
  --listen-port 51820 \
  --inbound-transparent=true
```

Terminal 2 - the Wireguard client securely connecting to the exit relay:

```bash
./uwgsocks \
  --config ./examples/client.yaml \
  --socks5 127.0.0.1:1080
```

Terminal 3 - curl using socks proxy to contact google through Wireguard:

```bash
curl -x "socks5h://127.0.0.1:1080" -v https://www.google.com/
```

Check whether the peers handshook and moved bytes:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:9090/v1/status
```

Run a one-shot config check:

```bash
./uwgsocks --config ./examples/client.yaml --check
```

## Common Uses How To

Use selected port mappings:

- expose a SOCKS5 or HTTP proxy for applications that already support proxies
- define local `forwards` from host ports to WireGuard destinations
- define `reverse_forwards` from userspace WireGuard IPs/ports to host services

Use it as a rootless egress peer:

- run with `inbound.transparent: true`
- configure peers to route Internet or LAN prefixes to this server
- let the server process terminate inbound TCP/UDP packets to normal host sockets
- optionally enable `dns_server.listen` so peers can resolve names using the server host's resolver

Use it from another Go program:

- import the library
- start an engine without exposing SOCKS5/HTTP
- dial or listen on userspace WireGuard addresses directly

Use it as a socksify-style local transport:

- run `uwgsocks` with a Unix HTTP listener that exposes `/uwg/socket`
- run `uwgfdproxy` against that listener
- use the experimental LD_PRELOAD wrapper from `tests/preload/testdata` to
  route selected libc TCP/UDP sockets through the WireGuard netstack

Example files:

- [examples/forwarding.yaml](examples/forwarding.yaml): local forwards and tunnel-side reverse forwards
- [examples/multi-peer.yaml](examples/multi-peer.yaml): multi-peer server shape with relay ACLs
- [examples/exit-server.yaml](examples/exit-server.yaml): rootless transparent egress peer with tunnel-hosted DNS
- [examples/exit-client.yaml](examples/exit-client.yaml): SOCKS/HTTP client for an egress peer
- [examples/socksify.yaml](examples/socksify.yaml): Unix socket API listener for `uwgfdproxy`
- [examples/uwgsocks.service](examples/uwgsocks.service): systemd unit template

Forward/reverse-forward example:

```bash
./uwgsocks --config ./examples/forwarding.yaml
```

Transparent egress example:

```bash
# Server, on the egress host:
./uwgsocks --config ./examples/exit-server.yaml

# Client, on the application host:
./uwgsocks --config ./examples/exit-client.yaml
curl -x socks5h://127.0.0.1:1080 https://www.google.com/
```


Let existing applications without SOCKS support connect to Wireguard rootless (EXPERIMENTAL):

```bash
./uwgsocks --config ./examples/socksify.yaml
./uwgfdproxy --listen /run/uwgsocks/fdproxy.sock \
  --api unix:/run/uwgsocks/http.sock \
  --socket-path /uwg/socket

LD_PRELOAD=./uwgpreload.so \
UWGS_FDPROXY=/run/uwgsocks/fdproxy.sock \
  wget https://www.google.com
```

Throughput smoke test with a real WireGuard config (e.g [Nordvpn Wireguard](https://github.com/sfiorini/NordVPN-Wireguard)):

```bash
./uwgsocks --wg-config ./my-provider-like-nordvpn.conf \
  --api-listen unix:/run/uwgsocks/api.sock \
  --api-allow-unauthenticated-unix
./uwgfdproxy --listen /run/uwgsocks/fdproxy.sock \
  --api unix:/run/uwgsocks/api.sock
LD_PRELOAD=./uwgpreload.so UWGS_FDPROXY=/run/uwgsocks/fdproxy.sock \
  speedtest-cli --secure --simple
```

```
Application -> uwgpreload.so overriding libc functions -> (local UNIX socket file) -> uwgfdproxy managing TCP/UDP sockets routing through Wireguard -> (HTTP/socks API + auth possible) -> uwgsocks daemon connecting to Wireguard -> userspace UDP connection -> Wireguard server
```

Prerequisite is that your application is dynamically linked to libc (almost all applications are), statically linked applications cannot be connected rootless through Wireguard if they do not support SOCKS/HTTP proxy directly.

The uwgfdproxy tracks/handles all socket connections that are routed through the userspace Wireguard, even across forks and executable transition boundaries.
This setup allows you to seperate the process that connects to Wireguard to the process that manages sockets. For connecting several containers (each running uwgfdproxy daemon) to the ugwsocks you run rootless on a host or a central container (running the ugwsocks). 

You can run the --api as HTTP endpoint instead of unix socket file descriptor, `fdproxy.sock` must be a unix socket file in the same environment (e.g container / vm / computer) for the preload wrapper to connect to. Control access using regular unix permissions on the socket files.

## Configuration Sources

There are three configuration sources.

1. YAML runtime config: `--config ./uwg.yaml`
2. WireGuard wg-quick config: `wireguard.config_file`, `wireguard.config`, `--wg-config`, or `--wg-inline`
3. CLI flags

Load order:

```text
YAML base
  -> YAML wireguard.config_file / wireguard.config
  -> CLI --wg-config / --wg-inline
  -> CLI scalar overrides and repeated additions
  -> normalization and validation
```

For repeated values such as `--address`, `--dns`, `--peer`, `--forward`, `--reverse-forward`, and ACL rules, CLI values are appended to config values.

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

Supported wg-quick fields:

- `[Interface]`: `PrivateKey`, `ListenPort`, `Address`, `DNS`, `MTU`, `PostUp`, `PostDown`
- `[Peer]`: `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive`

Accepted but ignored because this runtime never changes the host routing table: `PreUp`, `PreDown`, `Table`, `SaveConfig`.

See [examples/client.conf](examples/client.conf) and [examples/server.conf](examples/server.conf).

By default a configured `ListenPort` uses wireguard-go's normal wildcard IPv4
and IPv6 UDP listeners. To restrict server-mode listening to specific local IPs
from YAML or CLI:

```yaml
wireguard:
  listen_port: 51820
  listen_addresses:
    - 203.0.113.10
    - 2001:db8::10
```

```bash
./uwgsocks --listen-port 51820 --listen-address 203.0.113.10 --listen-address 2001:db8::10
```

## YAML Config

Client proxy example:

```yaml
wireguard:
  config_file: ./examples/client.conf
  roam_fallback_seconds: 120

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
  username: ""
  password: ""
  fallback_direct: true
  honor_environment: true
  outbound_proxies:
    - type: http
      address: 127.0.0.1:3128
      roles: [socks, inbound]
      subnets: [203.0.113.0/24]
  udp_associate: true
  bind: false
  prefer_ipv6_for_udp_over_socks: false

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

forwards:
  - proto: tcp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432
    # Optional. Valid values are v1 or v2. For UDP, use v2.
    proxy_protocol: ""

reverse_forwards:
  - proto: tcp
    # This is a userspace tunnel listener, not a host bind. The IP does not
    # need to be assigned by Address= as long as peers route it here.
    listen: 100.64.90.99:8443
    target: 127.0.0.1:443
    # On reverse forwards the header is written to the host-side target.
    proxy_protocol: v1

inbound:
  transparent: false
  host_dial_bind_address: ""

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
```

Server/egress peer example:

```yaml
wireguard:
  config_file: ./examples/server.conf
  roam_fallback_seconds: 120

inbound:
  transparent: true

host_forward:
  inbound:
    enabled: false
    redirect_ip: ""

routing:
  enforce_address_subnets: true

filtering:
  drop_ipv6_link_local_multicast: true
  drop_ipv4_invalid: true

dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024

api:
  listen: 127.0.0.1:9090
  token: replace-with-a-long-random-token

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
```

See [examples/client.yaml](examples/client.yaml) and [examples/server.yaml](examples/server.yaml).

## Proxy Routing

The routing rules are designed to be predictable:

- explicit local/tunnel forwards win before transparent behavior
- peer `AllowedIPs` win before fallback proxying or direct Internet access
- `Address=` subnets can reserve virtual interface space to prevent leaks
- outbound SOCKS5/HTTP proxy fallback rules are checked before direct host dials

Most users only need `proxy.fallback_direct`, `inbound.transparent`, and
`host_forward.*`. The full decision tree is kept in
[Proxy Routing](docs/proxy-routing.md) so the README can stay approachable.

The SOCKS5 server is implemented in this repository and supports:

- `CONNECT` for TCP streams
- `UDP ASSOCIATE` for UDP datagrams, enabled by default with `proxy.udp_associate`
- `BIND` for accepting one TCP connection on a userspace WireGuard address, disabled by default with `proxy.bind`
- optional SOCKS5 username/password auth and HTTP Basic proxy auth with `proxy.username` and `proxy.password`

Proxy listeners accept normal TCP host:port addresses. They also accept
`unix:/path/to/socket` for local tools that can speak SOCKS5 or HTTP proxy over
a Unix socket. The main HTTP listener is `proxy.http`; extra HTTP listeners can
be added with `proxy.http_listeners`, which is useful when you want both a TCP
listener for containers and a Unix socket for local fd-bridge tools:

```yaml
proxy:
  http: 127.0.0.1:8080
  http_listeners:
    - unix:/run/uwgsocks/http.sock
```

`BIND` is intentionally off by default because it lets proxy clients request
listeners inside the userspace tunnel. When enabled, a BIND listener owns that
tunnel port; transparent forwarding does not also claim the same port. BIND
uses an ephemeral tunnel port and accepts a single incoming TCP connection. If
the SOCKS5 request names an expected peer IP or port, other peers are rejected.

For hostname targets, WireGuard-routable addresses are preferred over direct
fallback addresses. If IPv6 is enabled and both routes are otherwise equal, TCP
hostname connects try IPv6 before IPv4. SOCKS5 UDP ASSOCIATE hostnames prefer
IPv4 by default because UDP has no reliable connect-time failure signal; set
`proxy.prefer_ipv6_for_udp_over_socks: true` to invert that behavior.

IPv6 proxy hostname resolution is automatic: it is enabled if the config has any
IPv6 peer `AllowedIPs` or the host has a non-loopback IPv6 address. Override it
with:

```yaml
proxy:
  ipv6: false
```

## Forwards

`forwards` listen on the host and dial through WireGuard:

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432
```

`reverse_forwards` listen inside the userspace WireGuard netstack and dial out
on the host. This is useful when you want to publish only selected ports to
WireGuard peers instead of enabling broad transparent host forwarding:

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8443
    target: 127.0.0.1:443
  - proto: udp
    listen: 100.64.90.99:5353
    target: 127.0.0.1:53
```

Reverse-forward listen IPs are userspace-only. They may be arbitrary addresses
that peers route to this WireGuard node, even if they are not listed under
`Address=`.

Per-forward PROXY protocol is available when the backend needs the original
client address:

```yaml
forwards:
  - proto: tcp
    listen: 127.0.0.1:8443
    target: 100.64.90.10:443
    # Parses and strips an incoming host-side PROXY header, then binds the
    # tunnel-side source to that address.
    proxy_protocol: v1

reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8443
    target: 127.0.0.1:443
    # Writes a PROXY header to the host-side target.
    proxy_protocol: v1
  - proto: udp
    listen: 100.64.90.99:5353
    target: 127.0.0.1:53
    # UDP uses PROXY v2 because v1 only has TCP4/TCP6 address families.
    proxy_protocol: v2
```

CLI equivalents:

```bash
./uwgsocks --forward 'tcp://127.0.0.1:8443=100.64.90.10:443,proxy_protocol=v1'
./uwgsocks --reverse-forward 'udp://100.64.90.99:5353=127.0.0.1:53,proxy_protocol=v2'
```

## Routing And Host Forwarding

`Address=` prefixes from the WireGuard config are treated like interface
routes. With `Address = 10.10.10.2/24`, a proxy request for `10.10.10.99` must
match a peer `AllowedIPs`; otherwise it is rejected. With `Address =
10.10.10.2/32`, only `10.10.10.2` is considered local and other `10.10.10.0/24`
addresses may still use the normal fallback behavior.

Configure this with:

```yaml
routing:
  enforce_address_subnets: true
```

Host forwarding is deliberately separate from transparent forwarding:

```yaml
host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1
  inbound:
    enabled: false
    redirect_ip: ""
```

`host_forward.proxy` applies only to SOCKS5/HTTP requests to this peer's tunnel
IPs, `localhost`, and `127.0.0.0/8`. It defaults on and redirects to loopback.
`host_forward.inbound` applies only to WireGuard packets addressed to this
peer's tunnel IPs when no userspace tunnel listener owns the port. It defaults
off because enabling it can expose loopback-only host services to remote peers.

WireGuard packets to `127.0.0.0/8` are always treated as illegal tunnel traffic
by the default address filter. Override the filters only for very controlled
test setups:

```yaml
filtering:
  drop_ipv6_link_local_multicast: true
  drop_ipv4_invalid: true
```

## DNS Behavior

If `DNS=` is set in the WireGuard config, SOCKS5 hostname requests resolve through those configured DNS servers. The program does not silently fall back to the system resolver when configured DNS fails.

- DNS servers inside peer `AllowedIPs` are queried through the userspace WireGuard netstack.
- DNS servers outside peer `AllowedIPs` are queried directly on the host network, with a warning, because they are explicitly configured but not tunnel-routable.
- If no `DNS=` is configured, host system DNS is used for proxy hostname resolution.

Tunnel-hosted DNS is useful when this peer is an egress peer. Other WireGuard
peers can ask this process to resolve hostnames using the resolver available on
the server host, without exposing a host-side port 53 listener.

Enable it with:

```yaml
dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024
```

That listener is bound inside the userspace WireGuard netstack, not on the host. Peers can send UDP or TCP DNS requests to `100.64.90.1:53`; `uwgsocks` parses the DNS request, performs the actual lookup through the host resolver, tracks the DNS transaction, and returns the response over WireGuard.

## Inbound Transparent Mode

When `inbound.transparent: true`, TCP/UDP packets arriving from a WireGuard peer are terminated in the userspace netstack and converted into normal host sockets. This is the mode that lets a rootless `uwgsocks` server act as an Internet or LAN exit point for WireGuard peers:

```text
peer packet -> WireGuard -> gVisor TCP/UDP -> connect/sendto/read/write on host
```

Most users only need `transparent: true`. Advanced tuning such as connection
table limits, TCP receive windows, and idle timers is documented in
[Configuration Reference](docs/configuration.md).

Static WireGuard peer endpoints fall back to their configured `Endpoint=` after roaming if the live endpoint stops handshaking for `wireguard.roam_fallback_seconds` seconds. The default is `120`; peers without a configured endpoint remain dynamic.

When the connection table is full, new connections are rejected unless there is a TCP connection older than the grace window; that older TCP connection is closed and the slot is reused. UDP sessions are short-lived and expire through the UDP idle timeout.

## ACLs

ACL lists exist for inbound, outbound, and relay traffic. Rules are evaluated in order, first match wins, and omitted fields are wildcards.

YAML:

```yaml
acl:
  outbound_default: deny
  outbound:
    - action: allow
      source: 127.0.0.1/32
      destination: 100.64.90.0/24
      destination_port: "80-443"
```

CLI:

```bash
./uwgsocks \
  --acl-outbound-default deny \
  --acl-outbound 'allow dst=100.64.90.0/24 dport=80-443'
```

## Management API

Enable the API:

```yaml
api:
  listen: 127.0.0.1:9090
  token: replace-with-a-long-random-token
```

If the API binds to anything other than loopback, a token is required.
For a Unix socket, omit the token only when explicitly enabled:

```yaml
api:
  listen: unix:/run/uwgsocks/api.sock
  allow_unauthenticated_unix: true
```

Endpoints:

- `GET /v1/status`
- `GET /v1/ping?target=100.64.90.2&count=4&timeout_ms=1000`
- `GET /v1/interface_ips`
- `GET /v1/socket`
- `GET /v1/peers`
- `GET /v1/peers/{public_key}`
- `POST /v1/peers`
- `PUT /v1/peers`
- `DELETE /v1/peers?public_key=...`
- `PUT /v1/wireguard/config`
- `GET /v1/acls`
- `PUT /v1/acls`
- `GET /v1/acls/{inbound|outbound|relay}`
- `POST /v1/acls/{inbound|outbound|relay}`
- `PUT /v1/acls/{inbound|outbound|relay}`
- `DELETE /v1/acls/{inbound|outbound|relay}?index=N`
- `GET /v1/forwards`
- `POST /v1/forwards`
- `DELETE /v1/forwards?name=...`

Example:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:9090/v1/peers
```

Status example:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:9090/v1/status
```

The response includes the live WireGuard listen port, current transparent
connection-table size, peer endpoints, `AllowedIPs`, transfer counters, and the
last handshake timestamp reported by wireguard-go. It does not expose private or
preshared keys.

Ping example:

```bash
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  'http://127.0.0.1:9090/v1/ping?target=100.64.90.2&count=4&timeout_ms=1000'
```

Add a runtime reverse forward:

```bash
curl -X POST -H 'Authorization: Bearer replace-with-a-long-random-token' \
  -H 'Content-Type: application/json' \
  -d '{"reverse":true,"proto":"tcp","listen":"100.64.90.99:8443","target":"127.0.0.1:443","proxy_protocol":"v1"}' \
  http://127.0.0.1:9090/v1/forwards
```

The ping endpoint sends ICMP echo requests through the userspace WireGuard
netstack and returns JSON with transmitted count, received count, packet loss,
per-packet status, and round-trip times.

Replace the live WireGuard peer device config from a wg-quick-style file:

```bash
curl -X PUT -H 'Authorization: Bearer replace-with-a-long-random-token' \
  --data-binary @client.conf \
  http://127.0.0.1:9090/v1/wireguard/config
```

This runtime config API never executes `PostUp` or `PostDown`. It also rejects
`Address`, `DNS`, and `MTU` changes that would require rebuilding the userspace
netstack; restart the process for those.

The binary also includes a small API client:

```bash
export UWGS_API=http://127.0.0.1:9090
export UWGS_API_TOKEN=replace-with-a-long-random-token

./uwgsocks status
./uwgsocks ping 100.64.90.1 --count 3
./uwgsocks peers
./uwgsocks add-peer --public-key PEER_PUBLIC_KEY --allowed-ip 100.64.90.3/32
./uwgsocks remove-peer PEER_PUBLIC_KEY
./uwgsocks acl-list outbound
./uwgsocks acl-add outbound 'allow dst=100.64.90.0/24 dport=80-443'
./uwgsocks acl-set --file ./outbound-acl.json outbound
./uwgsocks acl-remove --index 0 outbound
./uwgsocks wg-setconf ./client.conf
./uwgsocks interface-ips
./uwgsocks forwards
./uwgsocks add-forward --proto tcp --listen 127.0.0.1:18080 --target 100.64.90.1:80
./uwgsocks add-forward --reverse --proto tcp --listen 100.64.90.99:8443 --target 127.0.0.1:443
./uwgsocks remove-forward forward.runtime.1
```

The raw socket API is for local clients that need connected TCP/UDP, tunnel-side
bind/listen, or DNS transactions without SOCKS5 limitations. It uses HTTP
upgrade on `/v1/socket`; the HTTP proxy listener also exposes `/uwg/socket`.
Enable listener-style sockets explicitly:

```yaml
socket_api:
  bind: true
  transparent_bind: false
  udp_inbound: false
```

With `bind: false`, TCP listener sockets are rejected, but UDP bind-style
sockets still work in an established-only mode: the client can send datagrams to
multiple remotes from one bound UDP socket and receive replies only from those
recently contacted IP:port pairs. That state follows the UDP idle timer. A UDP
socket can also be reconnected by sending a `connect` frame with
`listener_connection_id` set to the existing UDP socket ID; an all-zero
destination disconnects it again.

For Linux preload experiments, `uwgfdproxy` is a local Unix socket manager for
a socksify-like layer. The preload wrapper creates a normal dummy socket, and
when the app targets the tunnel it replaces that fd with a manager fd backed by
the raw socket API. Connected TCP remains a byte stream, UDP is length-framed so
datagram boundaries survive, and TCP listener accepts use a manager
`ACCEPT`/`ATTACH` handshake. That lets many applications keep using normal
`read(2)`, `write(2)`, `send(2)`, `recv(2)`, `sendto(2)`, `recvfrom(2)`,
`dup(2)`, and polling calls:

```bash
go build -o uwgfdproxy ./cmd/uwgfdproxy
./uwgfdproxy --listen /tmp/uwgfdproxy.sock --api unix:/run/uwgsocks/api.sock
./uwgfdproxy --listen /tmp/uwgfdproxy.sock --api unix:/run/uwgsocks/http.sock --socket-path /uwg/socket
```

The preload wrapper lives under `tests/preload/testdata` for now and is tested
as an integration proof, not shipped as a production compatibility layer. It
currently covers connected TCP, connected UDP, unconnected UDP
`sendto`/`recvfrom`, TCP listener `accept`, duplicated fds, fork inheritance,
selected exec inheritance, malicious manager-input rejection, and loopback
connect passthrough. Remaining production socksify work includes
`sendmsg`/`recvmsg`, libc resolver interposition, more `select`/`epoll`
coverage, UDP exec re-identification, and true dual host-loopback plus
tunnel-side `0.0.0.0` listener behavior.

## Local Demo Troubleshooting

If the SOCKS request fails with a curl message such as `Can't complete SOCKS5
connection ... (4)`, check:

- Rebuild the binary after code changes: `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks`
- Stop stale demo processes so the client and server are using the same files and ports.
- Confirm the keys are crossed: `examples/client.conf` peer public key is the server public key, and `examples/server.conf` peer public key is the client public key.
- Confirm `examples/client.conf` points at the running server endpoint, for the localhost demo `Endpoint = 127.0.0.1:51820`.
- Query `/v1/status` on the server API. If `has_handshake` is false or counters stay at zero, the SOCKS proxy accepted the request but WireGuard did not establish the peer session.
- With `DNS = 100.64.90.1`, hostname requests made with `socks5h://` depend on the tunnel-hosted DNS server. If you change client `AllowedIPs`, keep `100.64.90.1/32` included or remove `DNS=` to use system DNS.
- With `AllowedIPs = 0.0.0.0/0`, internet egress goes through the server process. The server host must be able to reach the destination directly, or through a matching `proxy.outbound_proxies` rule with the `inbound` role.

## Library Use

Other Go programs can embed the engine:

```go
package main

import (
	"io"
	"log"
	"net/netip"
	"os"

	uwg "github.com/reindertpelsma/userspace-wireguard-socks"
)

func main() {
	cfg, err := uwg.LoadConfig("server.yaml")
	if err != nil {
		log.Fatal(err)
	}
	eng, err := uwg.New(cfg, log.New(os.Stderr, "uwg: ", log.LstdFlags))
	if err != nil {
		log.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		log.Fatal(err)
	}
	defer eng.Close()

	ln, err := eng.ListenTCP(netip.MustParseAddrPort("100.64.90.1:8080"))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			_, _ = io.WriteString(conn, "Hello World\n")
		}()
	}
}
```

The repository includes a rootless test for this pattern in
`library_example_test.go`. Use `DialContext` if you want the same
AllowedIPs/fallback behavior as the SOCKS/HTTP proxy. Use `DialTunnelContext`
if the connection must stay inside WireGuard.

## Testing

The test suite is rootless and does not use `/dev/net/tun`:

```bash
go test ./...
go vet ./...
```

Coverage includes two-instance WireGuard flows, SOCKS/HTTP/local forward paths, reverse forwards, PROXY protocol v1/v2 handling, SOCKS5 auth, SOCKS5 UDP ASSOCIATE and BIND, BIND default-off behavior, raw socket API TCP/UDP/listen/reconnect/DNS paths, LD_PRELOAD managed-fd TCP/UDP/listen/fork/exec proof, IPv4 and IPv6 tunnel traffic, IPv6 outer endpoints, IPv6 ICMP ping, primary source-address selection with secondary address aliases, TCP RST on rejected transparent TCP, synthetic ICMP unreachable packets for rejected UDP, packet loss transfer, multi-peer relay, configured DNS over WireGuard, hosted DNS over tunnel UDP/TCP, malformed WireGuard/IP/TCP/UDP/ICMP/DNS packets, source-IP enforcement, reserved tunnel-address filtering, virtual `Address=` subnet rejection, host-forward policy, ACL/API runtime updates, Unix-socket API binding, peer refresh after server restart, and connection-table overflow behavior.

Run the loopback throughput benchmark:

```bash
go test ./internal/engine -run '^$' -bench BenchmarkLoopbackSOCKSThroughput -benchtime=3x
```

The benchmark starts two userspace WireGuard instances on loopback, connects
through the SOCKS5 proxy, and moves echo traffic through the tunnel without
requiring root, `/dev/net/tun`, or iperf3.

Run an iperf3 loopback check through host forwards plus reverse forwards:

```bash
./scripts/iperf_loopback.sh
```

## Features

- SOCKS5, HTTP, or mixed SOCKS5/HTTP proxy listeners on the host
- local TCP/UDP forwards, similar in spirit to SSH local forwarding
- reverse TCP/UDP forwards that listen inside the userspace WireGuard netstack and dial arbitrary host targets
- Full UDP and IPv6 support
- Multi wireguard peer support
- transparent inbound TCP/UDP termination for packets arriving from WireGuard peers
- Socksify-like wrapper that allows any application to use your Wireguard without requiring SOCKS support
- optional tunnel-hosted DNS service
- Firewall ACLs to restrict inbound or outbound connections filtering on ports and IP-addresses
- optional L3 relay forwarding between WireGuard peers
- optional management API for peers, ACLs, and runtime forwards, without requiring any restarts of the tunnel
- experimental LD preload wrapper to let existing applications connect through Wireguard that do not support SOCKS.
- Go library APIs for applications that want WireGuard transport without exposing a proxy

## Notes

TCP keepalive frames are not visible through Go `net.Conn` stream reads, so TCP idle timers reset on userspace-visible reads and writes. UDP empty datagrams are visible and do reset the UDP idle timer.

Full RFC6040 ECN tunneling is not currently implemented because wireguard-go's bind interface does not expose per-packet outer TOS/TrafficClass metadata to this layer. The userspace TCP stack still handles its own congestion control for terminated connections.

More detailed notes:

- [Configuration Reference](docs/configuration.md)
- [Testing And Security Plan](docs/testing.md)
- [Raw Socket API](docs/socket-protocol.md)
