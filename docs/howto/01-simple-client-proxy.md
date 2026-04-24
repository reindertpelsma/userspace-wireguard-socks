<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 01 Simple Client Proxy

Previous: [How-To Index](README.md)  
Next: [02 Server And Ingress](02-server-and-ingress.md)

This is the fastest honest demo: one normal WireGuard config on the server,
one normal WireGuard config on the client, and a rootless SOCKS5/HTTP gateway
on top.

The files below are the same configs shipped as:

- [`examples/server.conf`](../../examples/server.conf)
- [`examples/server.yaml`](../../examples/server.yaml)
- [`examples/client.conf`](../../examples/client.conf)
- [`examples/client.yaml`](../../examples/client.yaml)

## Generate Real Keys For Production

For the local demo, the shipped example files already contain throwaway keys.
For a real deployment, generate fresh ones first:

```bash
server_priv=$(uwgsocks genkey)
server_pub=$(printf '%s\n' "$server_priv" | uwgsocks pubkey -in -)
client_priv=$(uwgsocks genkey)
client_pub=$(printf '%s\n' "$client_priv" | uwgsocks pubkey -in -)
```

If you want `uwgsocks` to print both sides for you, use:

```bash
uwgsocks genpair \
  --server-address 100.64.90.1/32 \
  --client-address 100.64.90.2/32 \
  --server-endpoint 127.0.0.1:51821
```

## Server Config

`server.conf`:

```ini
[Interface]
PrivateKey = 6C5zTlphKSL78OljtvARK9l+eHwHDihJzg88+6FxP1c=
Address = 100.64.90.1/32
ListenPort = 51821
MTU = 1420

[Peer]
PublicKey = ttwv7S4mBYUYVSXxToftw/119thxaoVmtEnjdaAWtzs=
AllowedIPs = 100.64.90.2/32
```

`server.yaml`:

```yaml
wireguard:
  config_file: ./examples/server.conf
  roam_fallback_seconds: 120

inbound:
  transparent: true
  consistent_port: loose
  disable_low_ports: true
  host_dial_bind_address: ""
  max_connections: 4096
  connection_table_grace_seconds: 30
  tcp_receive_window_bytes: 1048576
  tcp_max_buffered_bytes: 268435456
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30

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

relay:
  enabled: false

dns_server:
  listen: 100.64.90.1:53
  max_inflight: 1024

api:
  listen: 127.0.0.1:9090
  token: demo-api-token-change-me

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
```

Start it:

```bash
./uwgsocks --config ./examples/server.yaml
```

## Client Config

`client.conf`:

```ini
[Interface]
PrivateKey = SIcaKz9M+RGqA6MVnzbQsU9uvoyr1iBULxsdxyFQU3s=
Address = 100.64.90.2/32
DNS = 100.64.90.1
MTU = 1420

[Peer]
PublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
Endpoint = 127.0.0.1:51821
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`client.yaml`:

```yaml
wireguard:
  config_file: ./examples/client.conf
  roam_fallback_seconds: 120

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8082
  mixed: ""
  username: ""
  password: ""
  fallback_direct: true
  fallback_socks5: ""
  honor_environment: true
  outbound_proxies: []
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
  - proto: udp
    listen: 127.0.0.1:15353
    target: 100.64.90.1:53

inbound:
  transparent: false
  host_dial_bind_address: ""
  tcp_max_buffered_bytes: 268435456
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30

acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
```

Start the client in a second terminal:

```bash
./uwgsocks --config ./examples/client.yaml
```

That gives you:

- SOCKS5 on `127.0.0.1:1080`
- HTTP proxy on `127.0.0.1:8082`

This is still ordinary WireGuard config. `uwgsocks` is what turns it into a
rootless proxy gateway without touching the host routing table.

## Prove It Works

SOCKS5:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
```

HTTP proxy:

```bash
curl --proxy http://127.0.0.1:8082 https://ifconfig.me
```

Check daemon status over the authenticated API:

```bash
uwgsocks status \
  --api http://127.0.0.1:9090 \
  --token demo-api-token-change-me \
  --text

curl -H 'Authorization: Bearer demo-api-token-change-me' \
  http://127.0.0.1:9090/v1/status
```

## Why This Is Different

Standard WireGuard wants a kernel interface. `uwgsocks` does not. It injects
traffic into a userspace `gVisor` stack, then applies WireGuard, proxy routing,
ACLs, forwards, and optional relay logic inside one daemon.

That is why this works cleanly in:

- containers
- CI runners
- rootless dev shells
- locked-down corporate laptops

When this clicks, move on to local forwards and reverse ingress in
[02 Server And Ingress](02-server-and-ingress.md).
