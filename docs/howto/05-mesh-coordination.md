<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 05 Mesh Coordination

Previous: [04 Firewall And ACLs](04-firewall-and-acls.md)  
Next: [06 Pluggable Transports](06-pluggable-transports.md)

`mesh_control` turns a normal WireGuard client/server layout into one private
peer network.

The model is:

- one reachable hub or parent keeps a stable path up
- peers ask that controller which other peers exist
- peers learn projected ACL state together with the peer list
- peers keep a working path through the hub while they also try to connect to
  each other directly
- multiple relay sites can share the same peer information instead of each box
  becoming its own isolated island

If you know Tailscale, this is the same broad idea. If you do not: think
“small HTTP controller inside the tunnel that teaches peers about each other.”

## Start The Hub

Terminal 1:

```bash
export UWG_EXAMPLES="$(pwd)/examples"
mkdir -p /tmp/uwg-mesh-hub
cd /tmp/uwg-mesh-hub
uwgsocks --config "$UWG_EXAMPLES/mesh-control-hub.yaml"
```

The hub config is:

```yaml
wireguard:
  private_key: qB9WhJbIT1jyY0Go6d3UAIYK+RlGo+ElwESBC/f9VGU=
  listen_port: 51820
  addresses:
    - 100.64.80.1/32
  peers:
    - public_key: NU/tZS6y+fCf9kepK4R8z05/BvftWcxkEk7Gl0iRdXU=
      preshared_key: 8CXDYhra0VTDEZGyhG83uJkcOiD2ZaSLXy9ma3T1glw=
      allowed_ips:
        - 100.64.80.2/32
      mesh_enabled: true
      mesh_accept_acls: true
    - public_key: Ba9+418zSeHDBiVcQheIzN+TL49gblCl/7RGYpSf+Bs=
      preshared_key: 8PxUasdty53JC9r/oCE6xWDKmOP6zbaTrFXiVQpvem8=
      allowed_ips:
        - 100.64.80.3/32
      mesh_enabled: true
      mesh_accept_acls: true

mesh_control:
  listen: 100.64.80.1:8787
  active_peer_window_seconds: 120

relay:
  enabled: true
  conntrack: true

acl:
  relay_default: deny
  relay:
    - action: allow
      source: 100.64.80.2/32
      destination: 100.64.80.1/32
      protocol: tcp
      destination_port: 8787
    - action: allow
      source: 100.64.80.3/32
      destination: 100.64.80.1/32
      protocol: tcp
      destination_port: 8787
    - action: allow
      source: 100.64.80.2/32
      destination: 100.64.80.3/32
      protocol: tcp
      destination_port: 8088
```

## Start Peer 1

Terminal 2:

```bash
export UWG_EXAMPLES="$(pwd)/examples"
mkdir -p /tmp/uwg-mesh-peer1
cd /tmp/uwg-mesh-peer1
uwgsocks --config "$UWG_EXAMPLES/mesh-control-peer.yaml"
```

Important bits:

```yaml
wireguard:
  private_key: UEtDwUyiNWwqG6PT8xyZUHCgobMuroIFdglygl821GM=
  addresses:
    - 100.64.80.2/32
  peers:
    - public_key: r4fi5ZkPzyk1kNywYwd8F1oEsdyo1JE1Sogzcgxuhwg=
      preshared_key: 8CXDYhra0VTDEZGyhG83uJkcOiD2ZaSLXy9ma3T1glw=
      endpoint: 127.0.0.1:51820
      allowed_ips:
        - 100.64.80.1/32
        - 100.64.80.3/32
      persistent_keepalive: 25
      control_url: http://100.64.80.1:8787
      mesh_enabled: true

proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
```

## Start Peer 2

Terminal 3:

```bash
export UWG_EXAMPLES="$(pwd)/examples"
mkdir -p /tmp/uwg-mesh-peer2
cd /tmp/uwg-mesh-peer2
uwgsocks --config "$UWG_EXAMPLES/mesh-control-peer2.yaml"
```

Important bits:

```yaml
wireguard:
  private_key: cIYDYnnDMGVmIggrKW+mkAJDpB8YEmdC3gBaFELCtUI=
  addresses:
    - 100.64.80.3/32
  peers:
    - public_key: r4fi5ZkPzyk1kNywYwd8F1oEsdyo1JE1Sogzcgxuhwg=
      preshared_key: 8PxUasdty53JC9r/oCE6xWDKmOP6zbaTrFXiVQpvem8=
      endpoint: 127.0.0.1:51820
      allowed_ips:
        - 100.64.80.1/32
        - 100.64.80.2/32
      persistent_keepalive: 25
      control_url: http://100.64.80.1:8787
      mesh_enabled: true

reverse_forwards:
  - proto: tcp
    listen: 100.64.80.3:8088
    target: 127.0.0.1:8088
```

Terminal 4: give peer 2 something to publish.

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

Wait about 20 seconds after both peers come up. The controller poll loop runs
on a timer, so the first peer list update is not instant.

```bash
sleep 20
```

## Prove The Mesh Works

From peer 1, first confirm the controller is reachable inside the tunnel:

```bash
curl --proxy socks5h://127.0.0.1:1080 http://100.64.80.1:8787/v1/challenge
```

Then reach peer 2's published service through the mesh:

```bash
curl --proxy http://127.0.0.1:8080 http://100.64.80.3:8088
```

Inspect the peer view:

```bash
uwgsocks status \
  --api unix:/tmp/uwg-mesh-peer1/uwgsocks.sock \
  --text
```

At this point you have:

- one stable parent path through the hub
- one controller distributing peers and projected policy
- one child peer learning another child peer
- a direct peer-to-peer attempt when the outer transport is UDP-capable
- automatic fallback to the parent relay path when direct connectivity is not
  possible

## Multi-Server Use

The same pattern works when you have more than one relay site.

Instead of “every server owns its own isolated peer list,” you get:

- one authoritative peer inventory
- more than one reachable server or relay site
- peer discovery distributed over the tunnel
- direct child-to-child paths where the network allows it

That is why mesh control matters even when you still want traditional relay
servers in the design.
