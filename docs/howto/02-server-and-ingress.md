<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 02 Server And Ingress

Previous: [01 Simple Client Proxy](01-simple-client-proxy.md)  
Next: [03 Wrapper Interception](03-wrapper-interception.md)

`uwgsocks` gives you two complementary patterns:

- `forwards`: bind a local socket and dial a remote WireGuard destination
- `reverse_forwards`: bind inside the tunnel and send that traffic back to a
  local host service

The first is “reach a remote service from here.” The second is “publish a local
service inside the WireGuard network.”

## Start The Server Side

Terminal 1: start the server-side app that will be reached through a forward.

```bash
python3 -m http.server 8081 --bind 127.0.0.1
```

Terminal 2: start the rootless WireGuard server.

```bash
./uwgsocks --config ./examples/forwarding-server.yaml
```

## Start The Client Side

Terminal 3: start the local app that will be published back into the tunnel.

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

Terminal 4: start the forwarding example.

```bash
./uwgsocks --config ./examples/forwarding.yaml
```

The example file is [`examples/forwarding.yaml`](../../examples/forwarding.yaml):

```yaml
wireguard:
  config_file: ./examples/client.conf

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8082
  fallback_direct: false

forwards:
  - proto: tcp
    listen: 127.0.0.1:18081
    target: 100.64.90.1:8081

  - proto: udp
    listen: 127.0.0.1:15353
    target: 100.64.90.1:53

reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8080
    target: 127.0.0.1:8080
```

## Prove The Local Forward

This is the “local port forward” direction:

```bash
curl http://127.0.0.1:18081
```

That local socket is bound on the client host, but the traffic is served by the
app listening on the server host at `127.0.0.1:8081`.

## Prove The Reverse Forward

This is the “publish my local app inside WireGuard” direction:

```bash
curl --proxy http://127.0.0.1:8082 http://100.64.90.99:8080
```

You are reaching the client machine's local app through a tunnel-side listener,
without opening that app to the public internet or even to host loopback on
other machines.

## Public HTTPS Subdomains

For public internet ingress, run the companion control plane on a public host:

```bash
./uwgsocks-ui -listen 0.0.0.0:8080
```

That project manages `uwgsocks` as a child daemon and publishes protected
services through login-gated subdomains. The underlying tunnel hop is still
`reverse_forwards`; the UI adds:

- HTTPS edge termination
- subdomain routing
- access control
- share links and auth flows
- managed daemon config generation

## Secure Control Channel

`api.token` protects the runtime management plane. It is for:

- status and health checks
- live peer adds/removes
- ACL updates
- forward adds/removes
- full WireGuard config replacement

It is not the public HTTPS auth layer for end users. That happens in
`simple-wireguard-server`.

The server example already exposes:

```yaml
api:
  listen: 127.0.0.1:9090
  token: demo-api-token-change-me
```

Then query it:

```bash
uwgsocks status \
  --api http://127.0.0.1:9090 \
  --token demo-api-token-change-me \
  --text
```

## Useful CLI Subcommands

Key and config helpers:

- `uwgsocks genkey`
- `uwgsocks genpair`
- `uwgsocks add-client`

Runtime API helpers:

- `uwgsocks status`
- `uwgsocks ping`
- `uwgsocks peers`
- `uwgsocks add-peer`
- `uwgsocks remove-peer`
- `uwgsocks acl-list`
- `uwgsocks acl-add`
- `uwgsocks acl-set`
- `uwgsocks acl-remove`
- `uwgsocks forwards`
- `uwgsocks add-forward`
- `uwgsocks remove-forward`
- `uwgsocks wg-setconf`
- `uwgsocks setconf`

## Mental Model

- `uwgsocks`: the rootless WireGuard router and reverse-forward engine
- `simple-wireguard-server`: the browser-managed HTTPS ingress and control plane

Use them together when you want local services to appear on the public internet
without opening inbound ports on the origin machine.
