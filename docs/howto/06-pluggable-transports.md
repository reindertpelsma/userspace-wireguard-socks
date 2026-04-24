<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 06 Pluggable Transports

Previous: [05 Mesh Coordination](05-mesh-coordination.md)  
Next: [07 TURN Relay Ingress](07-turn-relay-ingress.md)

Pluggable transports are the outer carrier for WireGuard packets.

Instead of sending WireGuard directly over UDP, `uwgsocks` can wrap it in:

- UDP
- TCP
- TLS
- HTTP / HTTPS
- QUIC
- TURN

This is how you get WireGuard through networks that block or fingerprint
ordinary UDP.

## TCP Meltdown In One Paragraph

Running one reliable byte stream inside another reliable byte stream is usually
a bad trade. If the outer TCP stream stalls, the inner WireGuard packets queue
behind head-of-line blocking. That is the “TCP meltdown” problem.

That is why QUIC matters: it still looks like modern HTTP/3-era traffic, but it
keeps the outer carrier on UDP instead of nesting TCP inside TCP.

## Server Config

The multi-transport server example is
[`examples/transport-http-quic.yaml`](../../examples/transport-http-quic.yaml).
For a copy-paste local demo, generate a short-lived certificate:

```bash
mkdir -p /tmp/uwg-certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 1 -subj '/CN=127.0.0.1' \
  -keyout /tmp/uwg-certs/key.pem \
  -out /tmp/uwg-certs/cert.pem
```

Then use:

```yaml
wireguard:
  private_key: 6C5zTlphKSL78OljtvARK9l+eHwHDihJzg88+6FxP1c=
  listen_port: 51821
  addresses:
    - 100.64.90.1/32
  peers:
    - public_key: ttwv7S4mBYUYVSXxToftw/119thxaoVmtEnjdaAWtzs=
      allowed_ips:
        - 100.64.90.2/32
      transport: web

inbound:
  transparent: true

reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8081
    target: 127.0.0.1:8081

transports:
  - name: udp
    base: udp
    listen: true
    listen_port: 51821

  - name: web
    base: https
    listen: true
    listen_port: 8443
    websocket:
      path: /wg
    tls:
      cert_file: /tmp/uwg-certs/cert.pem
      key_file: /tmp/uwg-certs/key.pem

  - name: quic
    base: quic
    listen: true
    listen_port: 8443
    websocket:
      path: /wg
    tls:
      cert_file: /tmp/uwg-certs/cert.pem
      key_file: /tmp/uwg-certs/key.pem
```

Save that as `/tmp/uwg-transport-server.yaml`.

Give the server something simple to publish:

```bash
python3 -m http.server 8081 --bind 127.0.0.1
```

That local app is never exposed directly on the host network. The reverse
forward publishes it on the tunnel as `100.64.90.99:8081`.

## HTTPS/WebSocket Demo

Use HTTPS first for the copy-paste proof. It is the most forgiving transport
when you are testing in a dev container, CI box, or browser-style proxy path.

Client `wg-quick` file:

```bash
cat >/tmp/uwg-transport-client.conf <<'EOF'
[Interface]
PrivateKey = SIcaKz9M+RGqA6MVnzbQsU9uvoyr1iBULxsdxyFQU3s=
Address = 100.64.90.2/32

[Peer]
PublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
Endpoint = https://127.0.0.1:8443/wg
AllowedIPs = 100.64.90.99/32
PersistentKeepalive = 25
#!SkipVerifyTLS=yes
EOF
```

Client runtime YAML:

```yaml
wireguard:
  config_file: /tmp/uwg-transport-client.conf

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8082
  fallback_direct: false
```

Save that as `/tmp/uwg-transport-client.yaml`, then run:

```bash
./uwgsocks --config /tmp/uwg-transport-server.yaml
./uwgsocks --config /tmp/uwg-transport-client.yaml
sleep 10
curl --proxy http://127.0.0.1:8082 http://100.64.90.99:8081
```

That proves WireGuard is moving through the HTTPS listener and reaching the app
on the server side.

For a real edge host, replace the local certificate paths with your actual TLS
files and replace `#!SkipVerifyTLS=yes` with normal certificate verification.

## Client Config In `.conf`

The client still looks like a normal WireGuard config. `uwgsocks` understands
tagged `Endpoint = scheme://...` values, plus `#!` hints such as
`#!TURN=...` and `#!SkipVerifyTLS=yes`.

QUIC client:

```ini
[Interface]
PrivateKey = SIcaKz9M+RGqA6MVnzbQsU9uvoyr1iBULxsdxyFQU3s=
Address = 100.64.90.2/32

[Peer]
PublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
Endpoint = quic://127.0.0.1:8443/wg
AllowedIPs = 100.64.90.99/32
PersistentKeepalive = 25
#!SkipVerifyTLS=yes
```

HTTPS/WebSocket client:

```ini
[Peer]
PublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
Endpoint = https://127.0.0.1:8443/wg
AllowedIPs = 100.64.90.99/32
PersistentKeepalive = 25
#!SkipVerifyTLS=yes
```

## Switch The Same Demo To QUIC

When you want the UDP-based carrier, make only these two changes:

Server peer:

```yaml
transport: quic
```

Client peer:

```ini
Endpoint = quic://127.0.0.1:8443/wg
```

Then rerun the same local app, server, client, and `curl` check.

In this sandbox the QUIC config validated, but the end-to-end data path did
not complete reliably. That is consistent with gVisor-style environments being
a poor QUIC baseline. On a normal Linux host, QUIC is the transport to prefer
when you need DPI resistance without TCP meltdown.

The important syntax is:

- `Endpoint = quic://host:port/path`
- `Endpoint = https://host:port/path`
- `#!TURN=...` for TURN-backed carriers
- `#!SkipVerifyTLS=yes` only for local/self-signed testing

## What To Choose

- Use plain UDP first when the network allows it.
- Use HTTPS/WebSocket when you need “looks like normal TLS on 443.”
- Use QUIC when you want a UDP carrier that survives DPI better than raw
  WireGuard and avoids TCP meltdown.
- Use TURN when the real server is hidden behind NAT or a firewall and needs a
  public relay.

If you are running inside a restrictive gVisor sandbox, treat UDP and
HTTPS/WebSocket as the safer production baseline. QUIC is strongest on normal
Linux hosts.
