<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Complete Configuration Reference

This is the searchable, field-by-field YAML map for `uwgsocks`.

Use this document when you already know roughly what feature you want and need
to find the exact option name. Use [Configuration reference](configuration.md)
and the how-to guides for the behavior and deployment model behind those
options.

Values shown below are defaults where a sensible default exists, otherwise
empty placeholders.

## Top-Level YAML

```yaml
wireguard:
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
  post_up: []
  pre_down: []
  post_down: []
  default_transport: ""        # Name from transports[].
  peers:
    - public_key: ""
      preshared_key: ""
      endpoint: ""             # host:port or tagged scheme URL.
      allowed_ips: []
      persistent_keepalive: 0
      traffic_shaper:
        upload_bps: 0
        download_bps: 0
        latency_ms: 0
      control_url: ""          # Mesh control URL for this parent peer.
      mesh_enabled: false
      mesh_advertise: null     # null means default behavior.
      mesh_disable_acls: false
      mesh_accept_acls: false  # Usually auto-enabled when control_url+mesh_enabled.
      mesh_trust: untrusted    # untrusted | trusted_always | trusted_if_dynamic_acls
      transport: ""            # Name from transports[].
      tcp_mode: ""             # Synthesized from #!TCP directives.
      skip_verify_tls: null    # Synthesized from #!SkipVerifyTLS.
      connect_url: ""          # Synthesized from #!URL.

proxy:
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
  prefer_ipv6_for_udp_over_socks: false
  honor_environment: true      # Import ALL_PROXY/HTTP(S)_PROXY fallbacks.
  outbound_proxies:
    - type: socks5             # socks5 | http
      address: 127.0.0.1:1080
      username: ""
      password: ""
      roles: [socks, inbound]  # socks | proxy | client | inbound | wireguard | both
      subnets: []              # CIDRs this proxy should handle.

inbound:
  transparent: false           # Accept tunnel TCP/UDP directly to host sockets.
  consistent_port: loose       # strict | loose | disabled
  disable_low_ports: true
  forward_icmp_errors: true
  tcp_mss_clamp: true
  reply_icmp: true
  icmp_rate_limit_per_sec: 10
  max_connections: 0
  max_connections_per_peer: 0
  connection_table_grace_seconds: 30
  tcp_receive_window_bytes: 1048576
  tcp_max_buffered_bytes: 268435456
  host_dial_proxy_socks5: ""   # Compatibility alias for inbound proxy fallback.
  host_dial_bind_address: ""
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30

host_forward:
  proxy:
    enabled: true
    redirect_ip: ""            # Optional host IP to use instead of loopback defaulting.
    redirect_tun: false        # Re-enter through the host TUN path.
  inbound:
    enabled: false
    redirect_ip: ""
    redirect_tun: false

mesh_control:
  listen: ""                   # Tunnel-only HTTP control listener.
  challenge_rotate_seconds: 120
  active_peer_window_seconds: 120
  notify_window_seconds: 120   # Reserved compatibility knob.
  notify_min_interval_seconds: 60
  subscribe_max_lifetime_seconds: 300
  advertise_self: false

routing:
  enforce_address_subnets: true

tun:
  enabled: false
  name: uwgsocks0
  mtu: 1420
  configure: false
  route_allowed_ips: true
  routes: []
  dns_servers: []              # Host DNS servers for traffic entering via the host TUN.
  dns_resolv_conf: ""          # Absolute path to write nameserver lines into.
  fallback_system_dns: []      # Bypass DNS used only for outer transport hostnames.
  up: []                       # Script hooks; require scripts.allow=true.
  down: []

filtering:
  drop_ipv6_link_local_multicast: true
  drop_ipv4_invalid: true

traffic_shaper:
  upload_bps: 0
  download_bps: 0
  latency_ms: 0

relay:
  enabled: false
  conntrack: true
  conntrack_max_flows: 65536
  conntrack_max_per_peer: 4096

api:
  listen: ""                   # unix://path.sock or host:port
  token: ""                    # Bearer token for HTTP listeners.
  allow_unauthenticated_unix: true

socket_api:
  bind: false
  transparent_bind: false
  udp_inbound: false

acl:
  inbound_default: allow       # allow | deny
  outbound_default: allow
  relay_default: deny
  inbound: []
  outbound: []
  relay: []

forwards:
  - proto: tcp                 # tcp | udp
    listen: 127.0.0.1:15432
    target: 10.10.0.20:5432
    proxy_protocol: ""         # "" | v1 | v2

reverse_forwards:
  - proto: tcp
    listen: 100.64.0.10:8443
    target: 127.0.0.1:443
    proxy_protocol: ""

dns_server:
  listen: ""                   # Tunnel-only DNS listener, not a host port bind.
  max_inflight: 1024

scripts:
  allow: false

log:
  verbose: false

turn:
  server: ""                   # Legacy shorthand for one TURN transport.
  protocol: udp                # udp | tcp | tls | dtls | http | https | quic
  username: ""
  password: ""
  realm: ""
  permissions: []
  include_wg_public_key: false
  tls:
    cert_file: ""
    key_file: ""
    verify_peer: false
    reload_interval: ""
    ca_file: ""
    server_sni: ""

transports:
  - name: udp
    base: udp                  # udp | turn | tcp | tls | dtls | http | https | quic | quic-ws | url
    listen: true
    listen_port: 51820
    listen_addresses: []
    url: ""                    # Only for base: url
    ipv6_translate: false
    ipv6_prefix: 64:ff9b::/96
    tls:
      cert_file: ""
      key_file: ""
      verify_peer: false
      reload_interval: ""
      ca_file: ""
      server_sni: ""
    websocket:
      path: /wg
      upgrade_mode: websocket  # websocket | proxyguard
      connect_host: ""
      host_header: ""
      advertise_http3: false
      sni_hostname: ""         # Deprecated; use tls.server_sni.
    turn:
      server: ""
      username: ""
      password: ""
      realm: ""
      protocol: udp            # udp | tcp | tls | dtls | http | https | quic
      no_create_permission: false
      include_wg_public_key: false
      permissions: []
      tls:
        cert_file: ""
        key_file: ""
        verify_peer: false
        reload_interval: ""
        ca_file: ""
        server_sni: ""
    proxy:
      type: ""                 # none | socks5 | http
      socks5:
        server: ""
        username: ""
        password: ""
      http:
        server: ""
        username: ""
        password: ""
        tls:
          cert_file: ""
          key_file: ""
          verify_peer: false
          reload_interval: ""
          ca_file: ""
          server_sni: ""
```

## ACL Rule Shape

`acl.inbound`, `acl.outbound`, and `acl.relay` all use the same rule object:

```yaml
- action: allow                # allow | deny
  source: 100.64.0.0/24        # Singular source CIDR/IP.
  destination: 10.10.0.20/32   # Singular destination CIDR/IP.
  sources: []                  # Optional list form instead of many separate rules.
  destinations: []
  source_port: 12345           # Single port, range, or "*".
  destination_port: 80-443
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
