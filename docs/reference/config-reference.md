<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Complete Configuration Reference

This is the searchable, field-by-field YAML map for `uwgsocks`.

Use this document when you already know roughly what feature you want and need
to find the exact option name. Use [Configuration reference](configuration.md)
and the [how-to guides](../howto/README.md) for the behavior and deployment model behind those
options.

Values shown below are defaults where a sensible default exists, otherwise
empty placeholders.

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
  peers:                       # Static WireGuard peers loaded at startup.
    - public_key: ""           # Base64 WireGuard public key for the peer.
      preshared_key: ""        # Optional base64 WireGuard preshared key.
      endpoint: ""             # host:port or tagged scheme URL.
      allowed_ips: []          # Routed subnets/IPs for this peer.
      persistent_keepalive: 0  # Keepalive interval in seconds; 0 disables it.
      traffic_shaper:          # Optional per-peer bandwidth/latency shaping.
        upload_bps: 0          # Upload ceiling in bytes per second.
        download_bps: 0        # Download ceiling in bytes per second.
        latency_ms: 0          # Extra artificial latency in milliseconds.
      control_url: ""          # Mesh control URL for this parent peer.
      mesh_enabled: false      # Allow dynamic mesh peers to be learned from this peer.
      mesh_advertise: null     # null means default behavior.
      mesh_disable_acls: false # Opt out of distributed mesh ACL enforcement locally.
      mesh_accept_acls: false  # Usually auto-enabled when control_url+mesh_enabled.
      mesh_trust: untrusted    # untrusted | trusted_always | trusted_if_dynamic_acls
      transport: ""            # Name from transports[].
      tcp_mode: ""             # Synthesized from #!TCP directives.
      skip_verify_tls: null    # Synthesized from #!SkipVerifyTLS.
      connect_url: ""          # Synthesized from #!URL.

proxy:                         # Host-side SOCKS5/HTTP listener settings.
  socks5: ""                   # Host SOCKS5 listen address.
  http: ""                     # Host HTTP proxy listen address.
  http_listeners: []           # Extra HTTP listeners, including unix: paths.
  mixed: ""                    # Combined SOCKS5+HTTP listener.
  username: ""                 # Proxy auth username.
  password: ""                 # Proxy auth password.
  fallback_direct: true        # Allow direct host dials after routing misses.
  fallback_socks5: ""          # Compatibility alias for one SOCKS5 fallback.
  ipv6: null                   # Optional legacy override.
  udp_associate: true          # Enable SOCKS5 UDP ASSOCIATE.
  udp_associate_ports: ""      # Optional port or range for UDP ASSOCIATE.
  https_proxying: true         # HTTP absolute-form/CONNECT behavior.
  https_proxy_verify: pki      # none | pki | ca | both
  https_proxy_ca_file: ""      # Required when verify mode is ca/both.
  bind: false                  # Enable SOCKS5 BIND and listener-style raw sockets.
  lowbind: false               # Allow ports below 1024 where supported.
  prefer_ipv6_for_udp_over_socks: false # Prefer IPv6 UDP ASSOCIATE targets when both exist.
  honor_environment: true      # Import ALL_PROXY/HTTP(S)_PROXY fallbacks.
  outbound_proxies:            # Ordered fallback upstream proxies for selected roles.
    - type: socks5             # socks5 | http
      address: 127.0.0.1:1080  # Upstream proxy host:port.
      username: ""             # Optional upstream auth username.
      password: ""             # Optional upstream auth password.
      roles: [socks, inbound]  # socks | proxy | client | inbound | wireguard | both
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
  host_dial_proxy_socks5: ""   # Compatibility alias for inbound proxy fallback.
  host_dial_bind_address: ""   # Optional host source IP for transparent outbound dials.
  tcp_idle_timeout_seconds: 900 # Idle timeout for transparent inbound TCP flows.
  udp_idle_timeout_seconds: 30  # Idle timeout for transparent inbound UDP flows.

host_forward:                  # Loopback/host reachability from proxy and inbound paths.
  proxy:                       # Host-forward behavior for SOCKS5/HTTP/raw-socket proxy traffic.
    enabled: true              # Allow proxy clients to reach host-local services.
    redirect_ip: ""            # Optional host IP to use instead of loopback defaulting.
    redirect_tun: false        # Re-enter through the host TUN path.
  inbound:                     # Host-forward behavior for transparent inbound traffic.
    enabled: false             # Allow inbound tunnel peers to reach host-local services.
    redirect_ip: ""            # Optional host IP to use instead of loopback defaulting.
    redirect_tun: false        # Re-enter through the host TUN path.

mesh_control:                  # Tunnel-only dynamic peer discovery and ACL control service.
  listen: ""                   # Tunnel-only HTTP control listener.
  challenge_rotate_seconds: 120 # Rotate auth challenges on this interval.
  active_peer_window_seconds: 120 # Only advertise peers seen within this activity window.
  notify_window_seconds: 120   # Reserved compatibility knob.
  notify_min_interval_seconds: 60 # Reserved compatibility knob for future notify support.
  subscribe_max_lifetime_seconds: 300 # Maximum lifetime for mesh event streams.
  advertise_self: false        # Include the current node itself in mesh responses.

routing:                       # Global routing safety options.
  enforce_address_subnets: true # Reserve local Address= subnets so misses do not leak to host.

tun:                           # Optional host TUN integration.
  enabled: false               # Create and use a host-visible TUN device.
  name: uwgsocks0              # Requested interface name where the platform allows it.
  mtu: 1420                    # Host TUN MTU.
  configure: false             # Apply addresses/routes/DNS automatically on the host.
  route_allowed_ips: true      # Install peer AllowedIPs onto the host TUN automatically.
  routes: []                   # Extra host routes to add to the TUN interface.
  dns_servers: []              # Host DNS servers for traffic entering via the host TUN.
  dns_resolv_conf: ""          # Absolute path to write nameserver lines into.
  fallback_system_dns: []      # Bypass DNS used only for outer transport hostnames.
  up: []                       # Script hooks; require scripts.allow=true.
  down: []                     # Teardown hooks; require scripts.allow=true.

filtering:                     # Early packet sanitizing before normal routing/ACL logic.
  drop_ipv6_link_local_multicast: true # Drop noisy IPv6 link-local multicast traffic.
  drop_ipv4_invalid: true      # Drop obviously invalid IPv4 packets early.

traffic_shaper:                # Global bandwidth/latency shaping for all peers.
  upload_bps: 0                # Upload ceiling in bytes per second.
  download_bps: 0              # Download ceiling in bytes per second.
  latency_ms: 0                # Extra artificial latency in milliseconds.

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

acl:                           # Inbound, outbound, and relay firewall policy.
  inbound_default: allow       # allow | deny
  outbound_default: allow      # Default outbound decision when no rule matches.
  relay_default: deny          # Default relay decision when no rule matches.
  inbound: []                  # Ordered inbound ACL rule list.
  outbound: []                 # Ordered outbound ACL rule list.
  relay: []                    # Ordered relay ACL rule list.

forwards:                      # Host listeners that forward traffic into the tunnel.
  - proto: tcp                 # tcp | udp
    listen: 127.0.0.1:15432    # Host listen address or unix:// socket path for the forward.
    target: 10.10.0.20:5432    # Tunnel destination to dial. Must stay host:port.
    proxy_protocol: ""         # "" | v1 | v2
    allow_unnamed_dgram: false # Only for udp + unix+dgram forwards. Unnamed senders otherwise drop.
    frame_bytes: 0             # Only for tcp over unix+dgram or unix+seqpacket. 0 | 2 | 4 (0 defaults to 4).

reverse_forwards:              # Tunnel listeners that forward traffic back to the host.
  - proto: tcp                 # tcp | udp
    listen: 100.64.0.10:8443   # Tunnel-side listen address for the reverse forward.
    target: 127.0.0.1:443      # Host destination to dial, or unix:// target for local services.
    proxy_protocol: ""         # "" | v1 | v2
    frame_bytes: 0             # Only for tcp reverse forwards targeting unix+dgram or unix+seqpacket.

dns_server:                    # Small DNS server hosted inside the tunnel.
  listen: ""                   # Tunnel-only DNS listener, not a host port bind.
  max_inflight: 1024           # Maximum concurrent DNS requests handled at once.

scripts:                       # Safety gate for all script hooks.
  allow: false                 # Require explicit opt-in before any scripts run.

log:                           # Logging verbosity controls.
  verbose: false               # Enable verbose/debug-style logging.

turn:                          # Legacy shorthand for one TURN-backed transport.
  server: ""                   # Legacy shorthand for one TURN transport.
  protocol: udp                # udp | tcp | tls | dtls | http | https | quic
  username: ""                 # TURN username.
  password: ""                 # TURN password/secret.
  realm: ""                    # TURN realm for long-term credentials.
  permissions: []              # Optional fixed TURN peer permissions.
  no_create_permission: false  # Skip CREATE_PERMISSION and rely on relay policy.
  include_wg_public_key: false # Mix the WireGuard public key into TURN auth when enabled.
  tls:                         # TLS settings for tls/https/quic TURN modes.
    cert_file: ""              # Client certificate for mutual TLS, or server cert in server mode.
    key_file: ""               # Private key matching cert_file.
    verify_peer: false         # Verify the remote certificate/chain.
    reload_interval: ""        # Hot-reload TLS files on this interval.
    ca_file: ""                # Custom CA bundle for peer verification.
    server_sni: ""             # Override the SNI / expected server name.

transports:                    # Named outer WireGuard transport definitions.
  - name: udp                  # Transport name referenced by peers/default_transport.
    base: udp                  # udp | turn | tcp | tls | dtls | http | https | quic | quic-ws | url
    listen: true               # Accept inbound sessions on this transport.
    listen_port: 51820         # Listen port when the transport is in server mode.
    listen_addresses: []       # Restrict listen IPs for this transport.
    url: ""                    # Only for base: url
    ipv6_translate: false      # Enable 64:ff9b-style IPv4-to-IPv6 translation for this transport.
    ipv6_prefix: 64:ff9b::/96  # NAT64-style translation prefix when ipv6_translate=true.
    tls:                       # TLS settings for tls/https/quic transports.
      cert_file: ""            # Client certificate for mutual TLS, or server cert in server mode.
      key_file: ""             # Private key matching cert_file.
      verify_peer: false       # Verify the remote certificate/chain.
      reload_interval: ""      # Hot-reload TLS files on this interval.
      ca_file: ""              # Custom CA bundle for peer verification.
      server_sni: ""           # Override the SNI / expected server name.
    websocket:                 # HTTP/WebSocket framing settings for http/https/url transports.
      path: /wg                # Request path used for WebSocket or raw upgrade traffic.
      upgrade_mode: websocket  # websocket | proxyguard
      connect_host: ""         # Outer DNS/connect host for fronting or split-address setups.
      host_header: ""          # Inner Host/:authority override for fronting setups.
      advertise_http3: false   # Advertise HTTP/3 support on HTTPS listeners.
      sni_hostname: ""         # Deprecated; use tls.server_sni.
    turn:                      # TURN parameters when base: turn is used.
      server: ""               # TURN server URL/host.
      username: ""             # TURN username.
      password: ""             # TURN password/secret.
      realm: ""                # TURN realm for long-term credentials.
      protocol: udp            # udp | tcp | tls | dtls | http | https | quic
      no_create_permission: false # Skip CREATE_PERMISSION and rely on the server policy.
      include_wg_public_key: false # Mix the WireGuard public key into TURN auth when enabled.
      permissions: []          # Optional fixed TURN peer permissions.
      tls:                     # TLS settings for tls/https/quic TURN modes.
        cert_file: ""          # Client certificate for mutual TLS, or server cert in server mode.
        key_file: ""           # Private key matching cert_file.
        verify_peer: false     # Verify the remote certificate/chain.
        reload_interval: ""    # Hot-reload TLS files on this interval.
        ca_file: ""            # Custom CA bundle for peer verification.
        server_sni: ""         # Override the SNI / expected server name.
    proxy:                     # Optional upstream proxy used only for this transport.
      type: ""                 # none | socks5 | http
      socks5:                  # SOCKS5 upstream settings for this transport only.
        server: ""             # SOCKS5 server host:port.
        username: ""           # SOCKS5 auth username.
        password: ""           # SOCKS5 auth password.
      http:                    # HTTP proxy upstream settings for this transport only.
        server: ""             # HTTP proxy URL/host.
        username: ""           # HTTP proxy auth username.
        password: ""           # HTTP proxy auth password.
        tls:                   # TLS settings for HTTPS proxy connections.
          cert_file: ""        # Client certificate for mutual TLS, or server cert in server mode.
          key_file: ""         # Private key matching cert_file.
          verify_peer: false   # Verify the remote certificate/chain.
          reload_interval: ""  # Hot-reload TLS files on this interval.
          ca_file: ""          # Custom CA bundle for peer verification.
          server_sni: ""       # Override the SNI / expected server name.
```

## ACL Rule Shape

`acl.inbound`, `acl.outbound`, and `acl.relay` all use the same rule object:

```yaml
- action: allow                # allow | deny
  source: 100.64.0.0/24        # Singular source CIDR/IP.
  destination: 10.10.0.20/32   # Singular destination CIDR/IP.
  sources: []                  # Optional list form instead of many separate rules.
  destinations: []             # Optional destination list form instead of many separate rules.
  source_port: 12345           # Single port, range, or "*".
  destination_port: 80-443     # Single port, range, or "*".
  protocol: tcp                # tcp | udp | icmp
```

Rules are ordered. The first matching rule wins. If nothing matches, the list
default decides.

## Notes

- `turn:` is a convenience wrapper for one TURN-based transport. New configs
  should prefer `transports:`.
- `dns_server.listen`, `mesh_control.listen`, and `reverse_forwards[].listen`
  bind inside the userspace WireGuard/netstack, not on the host.
- `tun.dns_servers` configures DNS for traffic entering the host TUN. It does
  not change how SOCKS5/HTTP-only mode resolves names.
- `tun.fallback_system_dns` is only for resolving outer transport hostnames
  outside the tunnel when host-TUN routes would otherwise loop.
- `wireguard.peers[].mesh_accept_acls` is usually derived automatically from
  `control_url`, `mesh_enabled`, and `mesh_disable_acls`.
