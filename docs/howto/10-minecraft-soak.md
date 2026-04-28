# Minecraft (Paper) over uwgsocks — soak test

Validates real-world TCP-bind + tunnel-routing under a Java/JVM
workload. Two paths are exercised:

- **wrapper-bind**: Paper runs under `uwgwrapper --transport=preload`.
  Its `bind(100.64.94.1:25577)` is intercepted by the LD_PRELOAD
  shim and routed through `fdproxy /uwg/socket` to the userspace
  netstack. The kernel sees no listener at all — the bind lives
  entirely on the tunnel side.
- **reverse_forward**: Paper binds normally on host loopback;
  uwgsocks reverse-forwards `100.64.94.1:25577 → 127.0.0.1:25577`.

Both paths reach Paper through the WireGuard tunnel from a peer.

## Layout

The recipe sets up two uwgsocks instances on one host (loopback
WG between them) plus one Paper server. A third peer slot is
reserved for an external client (laptop) so the same Paper is
reachable from outside via the WG endpoint on `:51820/udp`.

```
                  +---------------------------+
                  |     amd64 host            |
                  |                           |
   laptop -- WG --+--> uwgsocks-server :51820 |
                  |    100.64.94.1            |
                  |    socket_api.bind=true   |
                  |          ^                |
                  |          | /uwg/socket    |
                  |          v                |
                  |    Paper (under wrapper)  |
                  |    bound on tunnel        |
                  |    100.64.94.1:25577      |
                  |                           |
                  |    uwgsocks-client        |
                  |    100.64.94.2  (loopback |
                  |    WG to server, used by  |
                  |    in-host SLP probe)     |
                  +---------------------------+
```

## One-shot setup

```bash
# 0. Prereqs: java 21 GA (Adoptium Temurin), uwgsocks + uwgwrapper
#    binaries in $PWD, paper.jar (1.21.11+) in /tmp/mc-soak.
cd /tmp/mc-soak

# 1. Generate WG keys (server, soak-client, laptop).
SERVER_PRIV=$(./uwgsocks genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | ./uwgsocks pubkey)
CLIENT_PRIV=$(./uwgsocks genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV"  | ./uwgsocks pubkey)
LAPTOP_PRIV=$(./uwgsocks genkey)
LAPTOP_PUB=$(echo "$LAPTOP_PRIV"  | ./uwgsocks pubkey)

# 2. Server config — listens on UDP/51820, peers in 100.64.94.0/24,
#    no reverse_forward (Paper claims the tunnel addr via wrapper-bind).
cat > server.yaml <<EOF
wireguard:
  private_key: "$SERVER_PRIV"
  listen_port: 51820
  addresses: ["100.64.94.1/24"]
  mtu: 1420
  peers:
    - public_key: "$CLIENT_PUB"
      allowed_ips: ["100.64.94.2/32"]
    - public_key: "$LAPTOP_PUB"
      allowed_ips: ["100.64.94.10/32"]
api:
  listen: "unix:/tmp/mc-soak/server-api.sock"
  allow_unauthenticated_unix: true
socket_api:
  bind: true
proxy:
  http: "127.0.0.1:18791"
  bind: true
  fallback_direct: true
EOF

# 3. In-host client config (so we can SLP-probe the tunnel locally).
cat > client.yaml <<EOF
wireguard:
  private_key: "$CLIENT_PRIV"
  addresses: ["100.64.94.2/32"]
  mtu: 1420
  peers:
    - public_key: "$SERVER_PUB"
      endpoint: "127.0.0.1:51820"
      allowed_ips: ["100.64.94.0/24"]
      persistent_keepalive: 5
api:
  listen: "unix:/tmp/mc-soak/client-api.sock"
  allow_unauthenticated_unix: true
socket_api:
  bind: true
proxy:
  http: "127.0.0.1:18792"
  bind: true
  fallback_direct: true
EOF

# 4. Paper server.properties knobs that matter:
#    - server-ip=100.64.94.1   (tunnel addr — wrapper intercepts bind)
#    - use-native-transport=false  (Netty's epoll path isn't compatible
#                                   with our preload-managed fds)
#    - enable-status=true     (so SLP probes work)

# 5. Open UFW for the WG endpoint
sudo ufw allow 51820/udp comment "uwgsocks WG endpoint"

# 6. Start everything
./uwgsocks --config server.yaml > server.log 2>&1 &
./uwgsocks --config client.yaml > client.log 2>&1 &

./uwgwrapper -v --transport=preload \
  --api unix:/tmp/mc-soak/server-api.sock \
  --listen /tmp/mc-soak/fdproxy.sock \
  --socket-path /uwg/socket \
  -- /opt/java/temurin21/bin/java \
     -Dio.netty.transport.noNative=true \
     -Djava.net.preferIPv4Stack=true \
     -Xms1G -Xmx2G -jar paper.jar --nogui > paper-wrapped.log 2>&1 &
```

## Verifying via the WireGuard tunnel

In-host SLP through the tunnel:

```bash
python3 mc_ping_tunnel.py
# OK: motd="uwgsocks-mc-soak" v=Paper 1.21.11 p=774 players=0/4
```

Where `mc_ping_tunnel.py` opens `HTTP/1.1 CONNECT 100.64.94.1:25577`
through the client uwgsocks's HTTP proxy on `127.0.0.1:18792`,
then speaks Notchian Server-List-Ping over the resulting tunnel.

## From an external host (laptop)

Generate a `wg-quick` config:

```ini
[Interface]
PrivateKey = $LAPTOP_PRIV
Address = 100.64.94.10/32
MTU = 1420

[Peer]
PublicKey = $SERVER_PUB
Endpoint = <SERVER-PUBLIC-IP>:51820
AllowedIPs = 100.64.94.0/24
PersistentKeepalive = 15
```

Bring it up with `wg-quick up <conf>`, then point your Minecraft
client at `100.64.94.1:25577`. The connection traverses WG to the
server, hits the wrapper-bound listener, and is fanned out through
fdproxy to Paper inside the JVM.

## Known good versions (validated 2026-04-28)

- Paper 1.21.11 build 69
- Eclipse Temurin 21.0.11+10 LTS (Adoptium GA)
- uwgsocks branch `phase1/sigsys-preload` at commit `9bd8560+`
