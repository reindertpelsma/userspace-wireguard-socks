// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/netip"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
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

func TestAllowRelayPacketAppliesACLAndAddressSubnetReservations(t *testing.T) {
	cfg := config.Default()
	cfg.WireGuard.Addresses = []string{"100.64.0.1/24"}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
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

func testIPv4TCPPacket(srcRaw, dstRaw string, srcPort, dstPort uint16) []byte {
	src := netip.MustParseAddr(srcRaw).As4()
	dst := netip.MustParseAddr(dstRaw).As4()
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	return packet
}
