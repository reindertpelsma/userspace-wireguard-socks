// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/buildcfg"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func TestAllowTunnelPacketDropsLoopAndInvalidAddresses(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: cfg}

	if e.allowTunnelPacket(testIPv4TCPPacket("100.64.1.2", "100.64.1.2", 12345, 80)) {
		t.Fatal("packet with identical source and destination address was not dropped")
	}
	if e.allowTunnelPacket(testIPv4TCPPacket("0.1.2.3", "198.51.100.9", 12345, 80)) {
		t.Fatal("packet with invalid IPv4 source was not dropped")
	}
	if !e.allowTunnelPacket(testIPv4TCPPacket("100.64.1.2", "198.51.100.9", 12345, 80)) {
		t.Fatal("valid IPv4 TCP packet was unexpectedly dropped")
	}
}

func TestAllowEgressPacketWithRelayEnabledOnlyAppliesRelayACLToPeerTransit(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	conntrack := false
	relayEnabled := true
	cfg.Relay.Conntrack = &conntrack
	cfg.Relay.Enabled = &relayEnabled
	rel := acl.List{Default: acl.Deny}
	if err := rel.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		cfg:        cfg,
		relACL:     rel,
		localAddrs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		allowed: []netip.Prefix{
			netip.MustParsePrefix("100.64.2.0/24"),
			netip.MustParsePrefix("100.64.3.0/24"),
		},
	}

	if !e.allowEgressPacket(testIPv4TCPPacket("198.51.100.9", "100.64.2.2", 443, 40000)) {
		t.Fatal("relay ACL incorrectly filtered a non-relay packet from the host network back to a peer")
	}
	if !e.allowEgressPacket(testIPv4TCPPacket("100.64.0.1", "100.64.2.2", 40000, 443)) {
		t.Fatal("relay ACL incorrectly filtered locally-originated tunnel traffic")
	}
	if e.allowEgressPacket(testIPv4TCPPacket("100.64.2.2", "100.64.3.3", 40000, 443)) {
		t.Fatal("peer-to-peer relay transit bypassed the relay ACL")
	}
}

func TestAllowRelayPacketAppliesACLAndAddressSubnetReservations(t *testing.T) {
	cfg := config.Default()
	cfg.WireGuard.Addresses = []string{"100.64.0.1/24"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	conntrack := false
	cfg.Relay.Conntrack = &conntrack
	rel := acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "80",
		}},
	}
	if err := rel.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		cfg:           cfg,
		relACL:        rel,
		localAddrs:    []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		localPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")},
	}

	allowed := testIPv4TCPPacket("100.64.2.2", "100.64.2.3", 23456, 80)
	if !e.allowRelayPacket(allowed) {
		t.Fatal("relay ACL allow rule did not permit matching packet")
	}
	deniedByACL := testIPv4TCPPacket("100.64.2.2", "100.64.2.3", 23456, 443)
	if e.allowRelayPacket(deniedByACL) {
		t.Fatal("relay ACL allowed a packet outside the destination port rule")
	}
	reservedSubnet := testIPv4TCPPacket("100.64.2.2", "100.64.0.77", 23456, 80)
	if e.allowRelayPacket(reservedSubnet) {
		t.Fatal("relay allowed an unrouted destination inside the local Address= subnet")
	}
}

func TestRelayConntrackTCPAllowsEstablishedReverseWithDefaultDeny(t *testing.T) {
	e := testRelayEngine(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, nil)

	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.2.3", 40000, 443, tcpFlagSYN)) {
		t.Fatal("initial TCP SYN matching the relay ACL was denied")
	}
	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagSYN|tcpFlagACK)) {
		t.Fatal("reverse TCP SYN+ACK for tracked flow was denied")
	}
	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.2.3", 40000, 443, tcpFlagACK)) {
		t.Fatal("TCP ACK completing tracked flow was denied")
	}
	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("reverse TCP data/ACK for established flow was denied")
	}
	if e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40001, tcpFlagACK)) {
		t.Fatal("unrelated reverse TCP packet was allowed without a tracked flow")
	}
}

func TestRelayConntrackUDPAndICMPEstablished(t *testing.T) {
	e := testRelayEngine(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{
			{
				Action:      acl.Allow,
				Source:      "100.64.2.2/32",
				Destination: "100.64.2.3/32",
				DestPort:    "53",
				Protocol:    "udp",
			},
			{
				Action:      acl.Allow,
				Source:      "100.64.2.2/32",
				Destination: "100.64.2.3/32",
				Protocol:    "icmp",
			},
		},
	}, nil)

	if e.allowRelayPacket(testIPv4UDPPacket("100.64.2.3", "100.64.2.2", 53, 53000)) {
		t.Fatal("reverse UDP packet was allowed before an initiating flow existed")
	}
	if !e.allowRelayPacket(testIPv4UDPPacket("100.64.2.2", "100.64.2.3", 53000, 53)) {
		t.Fatal("initial UDP packet matching relay ACL was denied")
	}
	if !e.allowRelayPacket(testIPv4UDPPacket("100.64.2.3", "100.64.2.2", 53, 53000)) {
		t.Fatal("reverse UDP packet for tracked flow was denied")
	}
	if !e.allowRelayPacket(testIPv4ICMPEcho("100.64.2.2", "100.64.2.3", 8, 0x1234)) {
		t.Fatal("ICMP echo request matching relay ACL was denied")
	}
	if !e.allowRelayPacket(testIPv4ICMPEcho("100.64.2.3", "100.64.2.2", 0, 0x1234)) {
		t.Fatal("ICMP echo reply for tracked request was denied")
	}
	if e.allowRelayPacket(testIPv4ICMPEcho("100.64.2.3", "100.64.2.2", 8, 0x1234)) {
		t.Fatal("reverse ICMP echo request reused a tracked request flow")
	}
}

func TestRelayConntrackICMPErrorMatchesExistingFlow(t *testing.T) {
	e := testRelayEngine(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "1234",
			Protocol:    "udp",
		}},
	}, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")})
	original := testIPv4UDPPacket("100.64.2.2", "100.64.2.3", 40000, 1234)
	if !e.allowRelayPacket(original) {
		t.Fatal("initial UDP packet matching relay ACL was denied")
	}
	if !e.allowRelayPacket(testIPv4ICMPError("100.64.9.9", "100.64.2.2", original)) {
		t.Fatal("ICMP error from an allowed peer for tracked flow was denied")
	}
	if e.allowRelayPacket(testIPv4ICMPError("100.64.9.9", "100.64.9.8", original)) {
		t.Fatal("ICMP error with unrelated outer destination was allowed")
	}
	if e.allowRelayPacket(testIPv4ICMPError("198.51.100.9", "100.64.2.2", original)) {
		t.Fatal("ICMP error outside AllowedIPs was allowed")
	}
}

func TestRelayConntrackLimitsAndExpiry(t *testing.T) {
	e := testRelayEngine(t, acl.List{Default: acl.Allow}, []netip.Prefix{netip.MustParsePrefix("100.64.2.0/24")})
	e.cfg.Relay.ConntrackMaxFlows = 1
	e.cfg.Relay.ConntrackMaxPerPeer = 1

	now := time.Unix(1000, 0)
	first, ok := parseRelayPacket(testIPv4UDPPacket("100.64.2.2", "100.64.3.3", 40000, 53))
	if !ok {
		t.Fatal("failed to parse first UDP packet")
	}
	second, ok := parseRelayPacket(testIPv4UDPPacket("100.64.2.4", "100.64.3.4", 40001, 53))
	if !ok {
		t.Fatal("failed to parse second UDP packet")
	}
	if !e.allowRelayTracked(first, now) {
		t.Fatal("first UDP flow was denied")
	}
	if e.allowRelayTracked(second, now.Add(time.Second)) {
		t.Fatal("second UDP flow exceeded the per-peer/total conntrack limit")
	}
	if !e.allowRelayTracked(second, now.Add(31*time.Second)) {
		t.Fatal("expired UDP flow was not swept before admitting a new flow")
	}
}

func TestRelayConntrackIPv6TCP(t *testing.T) {
	e := testRelayEngine(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "fd00:64::2/128",
			Destination: "fd00:64::3/128",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, nil)

	if !e.allowRelayPacket(testIPv6TCPPacketFlags("fd00:64::2", "fd00:64::3", 40000, 443, tcpFlagSYN)) {
		t.Fatal("initial IPv6 TCP SYN matching relay ACL was denied")
	}
	if !e.allowRelayPacket(testIPv6TCPPacketFlags("fd00:64::3", "fd00:64::2", 443, 40000, tcpFlagSYN|tcpFlagACK)) {
		t.Fatal("reverse IPv6 TCP SYN+ACK for tracked flow was denied")
	}
}

func TestRelayStatelessFallbackRequiresBothPeersToAcceptDynamicACLs(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshAcceptACLs: true},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}, MeshAcceptACLs: false},
	})

	if e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("stateless reverse fallback was allowed even though only one peer accepts dynamic ACLs")
	}

	e = testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshAcceptACLs: true},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}, MeshAcceptACLs: true},
	})

	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("stateless reverse fallback was denied even though both peers accept dynamic ACLs")
	}
}

func TestRelayStatelessFallbackAllowsForwardDirectionWhenBothPeersAcceptDynamicACLs(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "80",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshAcceptACLs: true},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}, MeshAcceptACLs: true},
	})

	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.2", "100.64.2.3", 40000, 80, tcpFlagACK)) {
		t.Fatal("forward stateless fallback was denied for two ACL-capable peers")
	}
}

func TestRelayStatelessFallbackAllowsTrustedPeers(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshTrust: config.MeshTrustTrustedAlways},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}},
	})

	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("trusted_always peer did not enable stateless relay fallback")
	}
}

func TestRelayStatelessFallbackTrustedIfDynamicACLsRequiresCapablePeer(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshTrust: config.MeshTrustTrustedIfDynamicACLs},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}},
	})
	if e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("trusted_if_dynamic_acls allowed fallback without an ACL-capable peer on the other side")
	}

	e = testRelayEngineWithPeers(t, acl.List{
		Default: acl.Deny,
		Rules: []acl.Rule{{
			Action:      acl.Allow,
			Source:      "100.64.2.2/32",
			Destination: "100.64.2.3/32",
			DestPort:    "443",
			Protocol:    "tcp",
		}},
	}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshTrust: config.MeshTrustTrustedIfDynamicACLs},
		{PublicKey: "peer-b", AllowedIPs: []string{"100.64.2.3/32"}, MeshAcceptACLs: true},
	})
	if !e.allowRelayPacket(testIPv4TCPPacketFlags("100.64.2.3", "100.64.2.2", 443, 40000, tcpFlagACK)) {
		t.Fatal("trusted_if_dynamic_acls did not allow fallback with an ACL-capable peer on the other side")
	}
}

func TestMeshInboundACLAppliesToStaticParentAndDynamicChildSources(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{Default: acl.Allow}, []config.Peer{
		{PublicKey: "parent", AllowedIPs: []string{"100.64.50.1/32"}, MeshAcceptACLs: true},
	})
	e.localAddrs = []netip.Addr{netip.MustParseAddr("100.64.50.9")}
	e.dynamicPeers["child"] = &dynamicPeer{
		ParentPublicKey: "parent",
		Peer: config.Peer{
			PublicKey:      "child",
			AllowedIPs:     []string{"100.64.50.2/32"},
			MeshAcceptACLs: true,
		},
	}
	if err := e.applyMeshACLsWithDefault("parent", acl.Deny, []acl.Rule{
		{Action: acl.Allow, Source: "100.64.50.1/32", Destination: "100.64.50.9/32", DestPort: "80", Protocol: "tcp"},
		{Action: acl.Allow, Source: "100.64.50.2/32", Destination: "100.64.50.9/32", DestPort: "80", Protocol: "tcp"},
	}, nil); err != nil {
		t.Fatal(err)
	}

	if !e.allowTunnelPacket(testIPv4TCPPacketFlags("100.64.50.1", "100.64.50.9", 40000, 80, tcpFlagSYN)) {
		t.Fatal("mesh inbound ACL did not allow static parent packet matching rule")
	}
	if e.allowTunnelPacket(testIPv4TCPPacketFlags("100.64.50.1", "100.64.50.9", 40000, 81, tcpFlagSYN)) {
		t.Fatal("mesh inbound ACL allowed static parent packet outside rule")
	}
	if !e.allowTunnelPacket(testIPv4TCPPacketFlags("100.64.50.2", "100.64.50.9", 40000, 80, tcpFlagSYN)) {
		t.Fatal("mesh inbound ACL did not allow dynamic child packet matching rule")
	}
	if e.allowTunnelPacket(testIPv4TCPPacketFlags("100.64.50.2", "100.64.50.9", 40000, 81, tcpFlagSYN)) {
		t.Fatal("mesh inbound ACL allowed dynamic child packet outside rule")
	}
	if !e.allowTunnelPacket(testIPv4TCPPacketFlags("198.51.100.9", "100.64.50.9", 40000, 81, tcpFlagSYN)) {
		t.Fatal("mesh inbound ACL incorrectly applied to unrelated source")
	}
}

func TestMeshTrustedPeerOutboundACLIsEnforced(t *testing.T) {
	if buildcfg.Lite {
		t.Skip("mesh control is not built in lite mode")
	}
	e := testRelayEngineWithPeers(t, acl.List{Default: acl.Allow}, []config.Peer{
		{PublicKey: "peer-a", AllowedIPs: []string{"100.64.2.2/32"}, MeshTrust: config.MeshTrustTrustedAlways},
	})
	e.localAddrs = []netip.Addr{netip.MustParseAddr("100.64.0.1")}
	if err := e.applyMeshACLsWithDefault("peer-a", acl.Deny, nil, []acl.Rule{
		{Action: acl.Allow, Source: "100.64.0.1/32", Destination: "100.64.2.2/32", DestPort: "80", Protocol: "tcp"},
	}); err != nil {
		t.Fatal(err)
	}

	if !e.allowEgressPacket(testIPv4TCPPacketFlags("100.64.0.1", "100.64.2.2", 40000, 80, tcpFlagSYN)) {
		t.Fatal("trusted peer outbound ACL denied matching local packet")
	}
	if e.allowEgressPacket(testIPv4TCPPacketFlags("100.64.0.1", "100.64.2.2", 40000, 81, tcpFlagSYN)) {
		t.Fatal("trusted peer outbound ACL allowed non-matching local packet")
	}
}

func TestOutboundProxyMatchingUsesMostSpecificSubnet(t *testing.T) {
	cfg := config.Default()
	honorEnv := false
	cfg.Proxy.HonorEnvironment = &honorEnv
	cfg.Proxy.OutboundProxies = []config.OutboundProxy{
		{Type: "socks5", Address: "127.0.0.1:1000", Roles: []string{"socks"}, Subnets: []string{"10.0.0.0/8"}},
		{Type: "http", Address: "127.0.0.1:2000", Roles: []string{"socks"}, Subnets: []string{"10.20.0.0/16"}},
		{Type: "socks5", Address: "127.0.0.1:3000", Roles: []string{"inbound"}, Subnets: []string{"10.20.30.0/24"}},
		{Type: "socks5", Address: "127.0.0.1:4000", Roles: []string{"both"}},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: cfg}

	got := e.matchOutboundProxies(netip.MustParseAddr("10.20.30.40"), outboundRoleSocks)
	if len(got) != 3 {
		t.Fatalf("matched proxy count = %d, want 3: %+v", len(got), got)
	}
	if got[0].Address != "127.0.0.1:2000" || got[1].Address != "127.0.0.1:1000" || got[2].Address != "127.0.0.1:4000" {
		t.Fatalf("proxies were not sorted by most specific subnet: %+v", got)
	}
	got = e.matchOutboundProxies(netip.MustParseAddr("10.20.30.40"), outboundRoleInbound)
	if len(got) != 2 || got[0].Address != "127.0.0.1:3000" || got[1].Address != "127.0.0.1:4000" {
		t.Fatalf("inbound proxy role matching mismatch: %+v", got)
	}
}

func testRelayEngine(t *testing.T, rel acl.List, allowed []netip.Prefix) *Engine {
	t.Helper()
	cfg := config.Default()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := rel.Normalize(); err != nil {
		t.Fatal(err)
	}
	return &Engine{
		cfg:        cfg,
		relACL:     rel,
		allowed:    allowed,
		localAddrs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd00:64::1")},
	}
}

func testRelayEngineWithPeers(t *testing.T, rel acl.List, peers []config.Peer) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.WireGuard.Peers = append([]config.Peer(nil), peers...)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := rel.Normalize(); err != nil {
		t.Fatal(err)
	}
	allowed, routes, traffic, err := buildPeerTrafficState(cfg.WireGuard.Peers, cfg.TrafficShaper)
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{
		cfg:          cfg,
		relACL:       rel,
		allowed:      allowed,
		peerRoutes:   routes,
		peerTraffic:  traffic,
		localAddrs:   []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd00:64::1")},
		dynamicPeers: make(map[string]*dynamicPeer),
	}
}

func testIPv4TCPPacket(srcRaw, dstRaw string, srcPort, dstPort uint16) []byte {
	return testIPv4TCPPacketFlags(srcRaw, dstRaw, srcPort, dstPort, 0)
}

func testIPv4TCPPacketFlags(srcRaw, dstRaw string, srcPort, dstPort uint16, flags byte) []byte {
	src := netip.MustParseAddr(srcRaw).As4()
	dst := netip.MustParseAddr(dstRaw).As4()
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 40
	packet[9] = 6
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	packet[32] = 5 << 4
	packet[33] = flags
	return packet
}

func testIPv6TCPPacketFlags(srcRaw, dstRaw string, srcPort, dstPort uint16, flags byte) []byte {
	src := netip.MustParseAddr(srcRaw).As16()
	dst := netip.MustParseAddr(dstRaw).As16()
	packet := make([]byte, 60)
	packet[0] = 0x60
	packet[4] = 0
	packet[5] = 20
	packet[6] = 6
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	packet[40] = byte(srcPort >> 8)
	packet[41] = byte(srcPort)
	packet[42] = byte(dstPort >> 8)
	packet[43] = byte(dstPort)
	packet[52] = 5 << 4
	packet[53] = flags
	return packet
}

func testIPv4UDPPacket(srcRaw, dstRaw string, srcPort, dstPort uint16) []byte {
	src := netip.MustParseAddr(srcRaw).As4()
	dst := netip.MustParseAddr(dstRaw).As4()
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 28
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	packet[24] = 0
	packet[25] = 8
	return packet
}

func testIPv4ICMPEcho(srcRaw, dstRaw string, typ byte, id uint16) []byte {
	src := netip.MustParseAddr(srcRaw).As4()
	dst := netip.MustParseAddr(dstRaw).As4()
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 28
	packet[9] = 1
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	packet[20] = typ
	packet[24] = byte(id >> 8)
	packet[25] = byte(id)
	return packet
}

func testIPv4ICMPError(srcRaw, dstRaw string, inner []byte) []byte {
	src := netip.MustParseAddr(srcRaw).As4()
	dst := netip.MustParseAddr(dstRaw).As4()
	packet := make([]byte, 28+len(inner))
	packet[0] = 0x45
	total := len(packet)
	packet[2] = byte(total >> 8)
	packet[3] = byte(total)
	packet[9] = 1
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	packet[20] = 3
	packet[21] = 1
	copy(packet[28:], inner)
	return packet
}
