<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Complete Configuration Reference

This is the searchable, field-by-field YAML map for the preferred `uwgsocks`
configuration surface.

Use [configuration.md](configuration.md) for the behavior behind these fields.

## Top-Level YAML

```yaml
wireguard:                     # Core WireGuard interface and peer settings.
  config_file: ""              # Path to wg-quick style config.
  config: ""                   # Inline wg-quick text.
  private_key: ""              # Base64 WireGuard private key.
  listen_port: 51820           # UDP listen port when listening directly.
  listen_addresses: []         # Restrict direct UDP listen IPs.
  addresses: []                # Local tunnel IPs/CIDRs.
  mtu: 1420                    # Userspace tunnel MTU.
  dns: []                      # DNS servers learned from wg-quick.
  roam_fallback_seconds: 120   # Restore static Endpoint after stale roaming.
  pre_up: []                   # Script hooks; only run when scripts.allow=true.
  post_up: []                  # Script hooks after startup; require scripts.allow=true.
  pre_down: []                 # Script hooks before shutdown; require scripts.allow=true.
  post_down: []                # Script hooks after shutdown; require scripts.allow=true.
  default_transport: ""        # Name from transports[].
  peers:
    - public_key: ""           # Base64 WireGuard public key for the peer.
      preshared_key: ""        # Optional base64 WireGuard preshared key.
      endpoint: ""             # host:port or tagged scheme URL.
      allowed_ips: []          # Routed subnets/IPs for this peer.
      persistent_keepalive: 0  # Keepalive interval in seconds; 0 disables it.
      traffic_shaper:
        upload_bps: 0          # Upload ceiling in bytes per second.
        download_bps: 0        # Download ceiling in bytes per second.
        latency_ms: 0          # Extra artificial latency in milliseconds.
      control_url: ""          # Mesh control URL for this parent peer.
      mesh_enabled: false      # Allow dynamic mesh peers to be learned from this peer.
      mesh_advertise: null     # null means default behavior.
      mesh_disable_acls: false # Opt out of distributed mesh ACL enforcement locally.
      mesh_accept_acls: false  # Usually enabled when this peer participates in mesh ACLs.
      mesh_trust: untrusted    # untrusted | trusted_always | trusted_if_dynamic_acls
      transport: ""            # Name from transports[].
      tcp_mode: ""             # Synthesized from #!TCP directives.
      skip_verify_tls: null    # Synthesized from #!SkipVerifyTLS.
      connect_url: ""          # Synthesized from #!URL.

forwards:                      # Host listeners that forward traffic into the tunnel.
  - proto: tcp                 # tcp | udp
    listen: 127.0.0.1:15432    # Host listen address or unix:// socket path.
    target: 100.64.90.1:5432   # Tunnel destination to dial. Must stay host:port.
    proxy_protocol: ""         # "" | v1 | v2
    allow_unnamed_dgram: false # Only for udp + unix+dgram listeners.
    frame_bytes: 0             # 0 | 2 | 4 for framed stream/message bridging.

reverse_forwards:              # Tunnel listeners that forward traffic back to the host.
  - proto: tcp                 # tcp | udp
    listen: 100.64.0.10:8443   # Tunnel-side listen address.
    target: 127.0.0.1:443      # Host destination to dial, or unix:// target.
    proxy_protocol: ""         # "" | v1 | v2
    frame_bytes: 0             # 0 | 2 | 4 for stream/message bridging.

host_forward:                  # Loopback/host reachability from proxy and inbound paths.
  proxy:
    enabled: true              # Allow proxy clients to reach host-local services.
    redirect_ip: ""            # Optional host IP to use instead of loopback.
    redirect_tun: false        # Re-enter through the host TUN path.
  inbound:
    enabled: false             # Allow inbound tunnel peers to reach host-local services.
    redirect_ip: ""            # Optional host IP to use instead of loopback.
    redirect_tun: false        # Re-enter through the host TUN path.

proxy:                         # Host-side SOCKS5/HTTP listener settings.
  socks5: ""                   # Host SOCKS5 listen address.
  http: ""                     # Host HTTP proxy listen address.
  http_listeners: []           # Extra HTTP listeners, including unix: paths.
  mixed: ""                    # Combined SOCKS5+HTTP listener.
  username: ""                 # Proxy auth username.
  password: ""                 # Proxy auth password.
  fallback_direct: true        # Allow direct host dials after routing misses.
  udp_associate: true          # Enable SOCKS5 UDP ASSOCIATE.
  udp_associate_ports: ""      # Optional port or range for UDP ASSOCIATE.
  https_proxying: true         # Accept absolute-form HTTPS proxy requests.
  https_proxy_verify: pki      # none | pki | ca | both
  https_proxy_ca_file: ""      # CA bundle for https_proxy_verify ca/both.
  bind: false                  # Enable SOCKS5 BIND and listener-style raw sockets.
  lowbind: false               # Allow ports below 1024 where supported.
  prefer_ipv6_for_udp_over_socks: false # Prefer IPv6 targets for UDP-over-SOCKS.
  honor_environment: true      # Import ALL_PROXY/HTTP(S)_PROXY fallbacks.
  outbound_proxies:
    - type: socks5             # socks5 | http
      address: 127.0.0.1:1080  # Upstream proxy host:port.
      username: ""             # Optional upstream auth username.
      password: ""             # Optional upstream auth password.
      roles: [socks, inbound]  # socks | inbound | both
      subnets: []              # CIDRs this proxy should handle.

inbound:                       # Transparent inbound handling from tunnel peers to host sockets.
  transparent: false           # Accept tunnel TCP/UDP directly to host sockets.
  consistent_port: loose       # strict | loose | disabled
  disable_low_ports: true      # Reject host ports below 1024 unless explicitly allowed.
  forward_icmp_errors: true    # Forward ICMP errors back into the tunnel when possible.
  tcp_mss_clamp: true          # Clamp MSS on inbound TCP to avoid PMTU issues.
  reply_icmp: true             # Generate local ICMP echo replies where supported.
  icmp_rate_limit_per_sec: 10  # Per-peer ICMP reply rate limit.
  max_connections: 0           # Global inbound connection cap; 0 means unlimited.
  max_connections_per_peer: 0  # Per-peer inbound connection cap; 0 means unlimited.
  connection_table_grace_seconds: 30 # Keep closed-flow state briefly for late packets.
  tcp_receive_window_bytes: 1048576  # Netstack TCP receive window for inbound flows.
  tcp_max_buffered_bytes: 268435456  # Global buffered TCP cap for inbound flows.
  host_dial_bind_address: ""   # Optional host source IP for transparent outbound dials.
  tcp_idle_timeout_seconds: 900 # Idle timeout for transparent inbound TCP flows.
  udp_idle_timeout_seconds: 30  # Idle timeout for transparent inbound UDP flows.

mesh_control:                  # Tunnel-only dynamic peer discovery and ACL control service.
  listen: ""                   # Tunnel-only HTTP control listener.
  challenge_rotate_seconds: 120 # Rotate auth challenges on this interval.
  active_peer_window_seconds: 120 # Only advertise recently active peers.
  subscribe_max_lifetime_seconds: 300 # Maximum lifetime for mesh event streams.
  advertise_self: false        # Include the current node itself in mesh responses.

tun:                           # Optional host TUN integration.
  enabled: false               # Create and use a host-visible TUN device.
  name: uwgsocks0              # Requested interface name where supported.
  mtu: 1420                    # Host TUN MTU.
  configure: false             # Apply addresses/routes/DNS automatically on the host.
  route_allowed_ips: true      # Install peer AllowedIPs onto the host TUN automatically.
  routes: []                   # Extra host routes to add to the TUN interface.
  dns_servers: []              # Host DNS servers for traffic entering via the host TUN.
  dns_resolv_conf: ""          # Absolute path to write nameserver lines into.
  fallback_system_dns: []      # DNS used only for outer transport hostnames.
  up: []                       # Script hooks; require scripts.allow=true.
  down: []                     # Teardown hooks; require scripts.allow=true.

acl:                           # Inbound, outbound, and relay firewall policy.
  inbound_default: allow       # allow | deny
  outbound_default: allow      # allow | deny
  relay_default: deny          # allow | deny
  inbound: []                  # Ordered inbound ACL rule list.
  outbound: []                 # Ordered outbound ACL rule list.
  relay: []                    # Ordered relay ACL rule list.

relay:                         # Peer-to-peer relay / SD-WAN forwarding mode.
  enabled: false               # Allow packets to be forwarded between WireGuard peers.
  conntrack: true              # Keep stateful relay conntrack enabled.
  conntrack_max_flows: 65536   # Global relay flow table cap.
  conntrack_max_per_peer: 4096 # Per-peer relay flow table cap.

api:                           # Runtime management API listener.
  listen: ""                   # unix://path.sock or host:port
  token: ""                    # Bearer token for HTTP listeners.
  allow_unauthenticated_unix: true # Allow trusted local Unix-socket callers without a token.

socket_api:                    # Raw socket protocol capabilities exposed over /v1/socket.
  bind: false                  # Allow listener/bind operations, not just connected sockets.
  transparent_bind: false      # Allow transparent source IP/port binding where supported.
  udp_inbound: false           # Allow UDP inbound listener semantics over the socket API.

dns_server:                    # Small DNS server hosted inside the tunnel.
  listen: ""                   # Tunnel-only DNS listener, not a host port bind.
  max_inflight: 1024           # Maximum concurrent DNS requests handled at once.

routing:                       # Global routing safety options.
  enforce_address_subnets: true # Reserve local Address= subnets so misses do not leak to host.

filtering:                     # Early packet sanitizing before normal routing/ACL logic.
  drop_ipv6_link_local_multicast: true # Drop noisy IPv6 link-local multicast traffic.
  drop_ipv4_invalid: true      # Drop obviously invalid IPv4 packets early.

traffic_shaper:                # Global bandwidth/latency shaping for all peers.
  upload_bps: 0                # Upload ceiling in bytes per second.
  download_bps: 0              # Download ceiling in bytes per second.
  latency_ms: 0                # Extra artificial latency in milliseconds.

scripts:                       # Safety gate for all script hooks.
  allow: false                 # Require explicit opt-in before any scripts run.

log:                           # Logging verbosity controls.
  verbose: false               # Enable verbose/debug-style logging.

transports:                    # Named outer WireGuard transport definitions.
  - name: udp                  # Transport name referenced by peers/default_transport.
    base: udp                  # udp | turn | tcp | tls | dtls | http | https | quic | url
    listen: true               # Accept inbound sessions on this transport.
    listen_port: 51820         # Listen port when the transport is in server mode.
    listen_addresses: []       # Restrict listen IPs for this transport.
    url: ""                    # Only for base: url.
    ipv6_translate: false      # Enable IPv4-to-IPv6 translation for this transport.
    ipv6_prefix: 64:ff9b::/96  # Translation prefix when ipv6_translate=true.
    tls:
      cert_file: ""            # Client or server certificate.
      key_file: ""             # Private key matching cert_file.
      verify_peer: false       # Verify the remote certificate/chain.
      reload_interval: ""      # Hot-reload TLS files on this interval.
      ca_file: ""              # Custom CA bundle for peer verification.
      server_sni: ""           # Override the SNI / expected server name.
    websocket:
      path: /wg                # Request path used for WebSocket or raw upgrade traffic.
      upgrade_mode: websocket  # websocket | proxyguard
      connect_host: ""         # Outer DNS/connect host for split-address setups.
      host_header: ""          # Inner Host/:authority override for fronting setups.
      advertise_http3: false   # Advertise HTTP/3 support on HTTPS listeners.
      sni_hostname: ""         # Deprecated; use tls.server_sni.
    turn:
      server: ""               # TURN server URL/host.
      username: ""             # TURN username.
      password: ""             # TURN password/secret.
      realm: ""                # TURN realm for long-term credentials.
      protocol: udp            # udp | tcp | tls | dtls | http | https | quic
      no_create_permission: false # Skip CREATE_PERMISSION and rely on the relay policy.
      include_wg_public_key: false # Mix the WireGuard public key into TURN auth when enabled.
      permissions: []          # Optional fixed TURN peer permissions.
      tls:
        cert_file: ""          # Client certificate for mutual TLS.
        key_file: ""           # Private key matching cert_file.
        verify_peer: false     # Verify the remote certificate/chain.
        reload_interval: ""    # Hot-reload TLS files on this interval.
        ca_file: ""            # Custom CA bundle for peer verification.
        server_sni: ""         # Override the SNI / expected server name.
    proxy:
      type: ""                 # none | socks5 | http
      socks5:
        server: ""             # SOCKS5 server host:port.
        username: ""           # SOCKS5 auth username.
        password: ""           # SOCKS5 auth password.
      http:
        server: ""             # HTTP proxy URL/host.
        username: ""           # HTTP proxy auth username.
        password: ""           # HTTP proxy auth password.
        tls:
          cert_file: ""        # Client certificate for mutual TLS.
          key_file: ""         # Private key matching cert_file.
          verify_peer: false   # Verify the remote certificate/chain.
          reload_interval: ""  # Hot-reload TLS files on this interval.
          ca_file: ""          # Custom CA bundle for peer verification.
          server_sni: ""       # Override the SNI / expected server name.
```

## ACL Rule Shape

`acl.inbound`, `acl.outbound`, and `acl.relay` all use the same rule object:

```yaml
- action: allow
  source: 100.64.0.0/24
  destination: 10.10.0.20/32
  sources: []
  destinations: []
  source_port: 12345
  destination_port: 80-443
  protocol: tcp
```

Rules are ordered. The first matching rule wins. If nothing matches, the list
default decides.

## Notes

- `dns_server.listen`, `mesh_control.listen`, and `reverse_forwards[].listen`
  bind inside the userspace WireGuard/netstack, not on the host.
- `tun.dns_servers` configures DNS for traffic entering the host TUN. It does
  not change how SOCKS5/HTTP-only mode resolves names.
- `tun.fallback_system_dns` is only for resolving outer transport hostnames
  outside the tunnel when host-TUN routes would otherwise loop.
- `wireguard.peers[].mesh_accept_acls` is often paired with `mesh_enabled`, but
  it is still an explicit peer capability.
