// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMergeWGQuickParsesInterfaceAndPeer(t *testing.T) {
	priv := mustConfigKey(t)
	peer := mustConfigKey(t)
	psk := mustConfigKey(t)
	var wg WireGuard
	text := `
# client.conf
[Interface]
PrivateKey = ` + priv.String() + `
Address = 100.64.70.2/32, fd00::2/128
DNS = 100.64.70.1
MTU = 1280
ListenPort = 51820
PostUp = echo up
PostDown = echo down
PreUp = ignored
PreDown = ignored
Table = off
SaveConfig = false

[Peer]
PublicKey = ` + peer.PublicKey().String() + `
PresharedKey = ` + psk.String() + `
Endpoint = example.com:51820
AllowedIPs = 100.64.70.1/32, 10.0.0.0/24
PersistentKeepalive = 25
`
	if err := MergeWGQuick(&wg, text); err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != priv.String() || wg.ListenPort == nil || *wg.ListenPort != 51820 || wg.MTU != 1280 {
		t.Fatalf("interface parse mismatch: %+v", wg)
	}
	if strings.Join(wg.Addresses, ",") != "100.64.70.2/32,fd00::2/128" {
		t.Fatalf("addresses parse mismatch: %#v", wg.Addresses)
	}
	if strings.Join(wg.DNS, ",") != "100.64.70.1" {
		t.Fatalf("DNS parse mismatch: %#v", wg.DNS)
	}
	if len(wg.PostUp) != 1 || wg.PostUp[0] != "echo up" || len(wg.PostDown) != 1 || wg.PostDown[0] != "echo down" {
		t.Fatalf("PostUp/PostDown parse mismatch: %+v", wg)
	}
	if len(wg.Peers) != 1 {
		t.Fatalf("peers parse mismatch: %+v", wg.Peers)
	}
	got := wg.Peers[0]
	if got.PublicKey != peer.PublicKey().String() || got.PresharedKey != psk.String() || got.Endpoint != "example.com:51820" || got.PersistentKeepalive != 25 {
		t.Fatalf("peer parse mismatch: %+v", got)
	}
	if strings.Join(got.AllowedIPs, ",") != "100.64.70.1/32,10.0.0.0/24" {
		t.Fatalf("allowed IPs parse mismatch: %#v", got.AllowedIPs)
	}
}

func TestLoadYAMLMergesWGQuickFileAndRuntimeOptions(t *testing.T) {
	dir := t.TempDir()
	priv := mustConfigKey(t)
	peer := mustConfigKey(t)
	wgPath := filepath.Join(dir, "client.conf")
	if err := os.WriteFile(wgPath, []byte(`
[Interface]
PrivateKey = `+priv.String()+`
Address = 100.64.71.2/32
DNS = 100.64.71.1

[Peer]
PublicKey = `+peer.PublicKey().String()+`
AllowedIPs = 100.64.71.1/32
Endpoint = 127.0.0.1:51820
`), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "uwg.yaml")
	if err := os.WriteFile(yamlPath, []byte(`
wireguard:
  config_file: `+wgPath+`
proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8081
  http_listeners:
    - unix:/tmp/uwgsocks-http.sock
  username: alice
  password: secret
  fallback_direct: false
  udp_associate_ports: 41000-41010
  honor_environment: false
  outbound_proxies:
    - type: http
      address: 127.0.0.1:3128
      roles: [socks, inbound]
      subnets: [203.0.113.0/24]
inbound:
  transparent: true
  host_dial_bind_address: 0.0.0.0
  max_connections: 64
  max_connections_per_peer: 8
  tcp_max_buffered_bytes: 67108864
  tcp_idle_timeout_seconds: 900
  udp_idle_timeout_seconds: 30
traffic_shaper:
  upload_bps: 1000000
  download_bps: 2000000
  latency_ms: 25
host_forward:
  proxy:
    enabled: true
    redirect_ip: 127.0.0.1
  inbound:
    enabled: false
    redirect_tun: true
routing:
  enforce_address_subnets: true
tun:
  enabled: true
  name: wgapps0
  mtu: 1280
  configure: true
  route_allowed_ips: false
  routes:
    - 10.77.0.0/16
    - fd00:77::/64
  up:
    - echo tun-up
  down:
    - echo tun-down
filtering:
  drop_ipv6_link_local_multicast: true
  drop_ipv4_invalid: true
api:
  listen: 127.0.0.1:9090
  token: test-token
turn:
  server: 127.0.0.1:3478
  username: turn-user
  password: turn-pass
  realm: turn-realm
  permissions:
    - 203.0.113.10:51820
  include_wg_public_key: true
acl:
  inbound_default: allow
  outbound_default: deny
  relay_default: deny
  outbound:
    - action: allow
      destination: 100.64.71.0/24
      destination_port: "1-65535"
forwards:
  - proto: tcp
    listen: 127.0.0.1:8080
    target: 100.64.71.10:80
    proxy_protocol: v1
reverse_forwards:
  - proto: udp
    listen: 100.64.71.99:5353
    target: 127.0.0.1:53
    proxy_protocol: v2
dns_server:
  listen: 100.64.71.2:53
  max_inflight: 32
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.PrivateKey != priv.String() || len(cfg.WireGuard.Peers) != 1 || cfg.WireGuard.Peers[0].PublicKey != peer.PublicKey().String() {
		t.Fatalf("WireGuard config did not merge: %+v", cfg.WireGuard)
	}
	if cfg.Proxy.SOCKS5 != "127.0.0.1:1080" || cfg.Proxy.HTTP != "127.0.0.1:8081" || len(cfg.Proxy.HTTPListeners) != 1 || cfg.Proxy.HTTPListeners[0] != "unix:/tmp/uwgsocks-http.sock" || cfg.Proxy.Username != "alice" || cfg.Proxy.Password != "secret" || cfg.Proxy.UDPAssociatePorts != "41000-41010" || *cfg.Proxy.FallbackDirect || *cfg.Proxy.HonorEnvironment {
		t.Fatalf("proxy options mismatch: %+v", cfg.Proxy)
	}
	if len(cfg.Proxy.OutboundProxies) != 1 || cfg.Proxy.OutboundProxies[0].Type != "http" || cfg.Proxy.OutboundProxies[0].Address != "127.0.0.1:3128" || len(cfg.Proxy.OutboundProxies[0].Subnets) != 1 {
		t.Fatalf("outbound proxy options mismatch: %+v", cfg.Proxy.OutboundProxies)
	}
	if !*cfg.Inbound.Transparent || cfg.Inbound.HostDialBindAddress != "0.0.0.0" || cfg.Inbound.MaxConnections != 64 || cfg.Inbound.MaxConnectionsPerPeer != 8 || cfg.Inbound.TCPMaxBufferedBytes != 67108864 || cfg.Inbound.TCPIdleTimeoutSeconds != 900 || cfg.Inbound.UDPIdleTimeoutSeconds != 30 {
		t.Fatalf("inbound options mismatch: %+v", cfg.Inbound)
	}
	if cfg.TrafficShaper.UploadBps != 1000000 || cfg.TrafficShaper.DownloadBps != 2000000 || cfg.TrafficShaper.LatencyMillis != 25 {
		t.Fatalf("traffic shaper options mismatch: %+v", cfg.TrafficShaper)
	}
	if cfg.API.Listen != "127.0.0.1:9090" || cfg.API.Token != "test-token" {
		t.Fatalf("API options mismatch: %+v", cfg.API)
	}
	if cfg.TURN.Server != "127.0.0.1:3478" || cfg.TURN.Username != "turn-user" || cfg.TURN.Password != "turn-pass" || cfg.TURN.Realm != "turn-realm" || len(cfg.TURN.Permissions) != 1 || !cfg.TURN.IncludeWGPublicKey {
		t.Fatalf("TURN options mismatch: %+v", cfg.TURN)
	}
	if !*cfg.HostForward.Proxy.Enabled || *cfg.HostForward.Inbound.Enabled || cfg.HostForward.Proxy.RedirectIP != "127.0.0.1" || !cfg.HostForward.Inbound.RedirectTUN || !*cfg.Routing.EnforceAddressSubnets || !*cfg.Filtering.DropIPv4Invalid {
		t.Fatalf("routing/filter/host-forward options mismatch: host=%+v routing=%+v filtering=%+v", cfg.HostForward, cfg.Routing, cfg.Filtering)
	}
	if !cfg.TUN.Enabled || cfg.TUN.Name != "wgapps0" || cfg.TUN.MTU != 1280 || !cfg.TUN.Configure || *cfg.TUN.RouteAllowedIPs || strings.Join(cfg.TUN.Routes, ",") != "10.77.0.0/16,fd00:77::/64" || strings.Join(cfg.TUN.Up, ",") != "echo tun-up" || strings.Join(cfg.TUN.Down, ",") != "echo tun-down" {
		t.Fatalf("tun options mismatch: %+v", cfg.TUN)
	}
	if cfg.ACL.OutboundDefault != acl.Deny || len(cfg.ACL.Outbound) != 1 {
		t.Fatalf("ACL options mismatch: %+v", cfg.ACL)
	}
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].Target != "100.64.71.10:80" || cfg.Forwards[0].ProxyProtocol != "v1" {
		t.Fatalf("forward options mismatch: %+v", cfg.Forwards)
	}
	if len(cfg.ReverseForwards) != 1 || cfg.ReverseForwards[0].Proto != "udp" || cfg.ReverseForwards[0].Target != "127.0.0.1:53" || cfg.ReverseForwards[0].ProxyProtocol != "v2" {
		t.Fatalf("reverse forward options mismatch: %+v", cfg.ReverseForwards)
	}
	if cfg.DNSServer.Listen != "100.64.71.2:53" || cfg.DNSServer.MaxInflight != 32 {
		t.Fatalf("DNS server option mismatch: %+v", cfg.DNSServer)
	}
}

func TestLoadYAMLInlineWGQuick(t *testing.T) {
	priv := mustConfigKey(t)
	peer := mustConfigKey(t)
	path := filepath.Join(t.TempDir(), "inline.yaml")
	if err := os.WriteFile(path, []byte(`
wireguard:
  config: |
    [Interface]
    PrivateKey = `+priv.String()+`
    Address = 100.64.72.2/32

    [Peer]
    PublicKey = `+peer.PublicKey().String()+`
    AllowedIPs = 100.64.72.1/32
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.PrivateKey != priv.String() || len(cfg.WireGuard.Peers) != 1 {
		t.Fatalf("inline WireGuard config did not merge: %+v", cfg.WireGuard)
	}
}

func TestNormalizeRejectsHostForwardRedirectIPAndTUN(t *testing.T) {
	cfg := Default()
	cfg.HostForward.Proxy.RedirectIP = "127.0.0.1"
	cfg.HostForward.Proxy.RedirectTUN = true
	if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "redirect_ip and redirect_tun") {
		t.Fatalf("Normalize err=%v, want redirect conflict", err)
	}
}

func TestParseForwardArgProxyProtocolOption(t *testing.T) {
	f, err := ParseForwardArg("udp://127.0.0.1:5353=100.64.71.10:53,proxy_protocol=v2")
	if err != nil {
		t.Fatal(err)
	}
	if f.Proto != "udp" || f.Listen != "127.0.0.1:5353" || f.Target != "100.64.71.10:53" || f.ProxyProtocol != "v2" {
		t.Fatalf("parsed forward mismatch: %+v", f)
	}
}

func TestParsePeerArgTrafficShaperOptions(t *testing.T) {
	p, err := ParsePeerArg("public_key=peer,allowed_ips=100.64.90.1/32,upload_bps=4096,download_bps=8192,latency_ms=25")
	if err != nil {
		t.Fatal(err)
	}
	if p.TrafficShaper.UploadBps != 4096 || p.TrafficShaper.DownloadBps != 8192 || p.TrafficShaper.LatencyMillis != 25 {
		t.Fatalf("unexpected peer traffic shaper: %+v", p.TrafficShaper)
	}
}

func TestParseOutboundProxyArg(t *testing.T) {
	p, err := ParseOutboundProxyArg("http://alice:secret@127.0.0.1:3128;roles=socks,inbound;subnets=203.0.113.0/24,2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "http" || p.Address != "127.0.0.1:3128" || p.Username != "alice" || p.Password != "secret" {
		t.Fatalf("proxy parse mismatch: %+v", p)
	}
	if strings.Join(p.Roles, ",") != "socks,inbound" || strings.Join(p.Subnets, ",") != "203.0.113.0/24,2001:db8::/32" {
		t.Fatalf("proxy role/subnet parse mismatch: %+v", p)
	}
}

func mustConfigKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
