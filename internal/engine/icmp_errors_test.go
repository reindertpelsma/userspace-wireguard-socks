// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestUDPUnreachablePacketIPv4AndIPv6(t *testing.T) {
	v4 := udpUnreachablePacket(netip.MustParseAddrPort("100.64.1.2:12345"), netip.MustParseAddrPort("192.0.2.10:53"))
	if len(v4) == 0 {
		t.Fatal("missing IPv4 ICMP unreachable")
	}
	ip4 := header.IPv4(v4[:header.IPv4MinimumSize])
	if got := ip4.Protocol(); got != uint8(header.ICMPv4ProtocolNumber) {
		t.Fatalf("IPv4 protocol=%d", got)
	}
	icmp4 := header.ICMPv4(ip4.Payload())
	if icmp4.Type() != header.ICMPv4DstUnreachable || icmp4.Code() != header.ICMPv4PortUnreachable {
		t.Fatalf("IPv4 ICMP type/code=%d/%d", icmp4.Type(), icmp4.Code())
	}

	v6 := udpUnreachablePacket(netip.MustParseAddrPort("[fd00::2]:12345"), netip.MustParseAddrPort("[2001:db8::10]:53"))
	if len(v6) == 0 {
		t.Fatal("missing IPv6 ICMP unreachable")
	}
	ip6 := header.IPv6(v6[:header.IPv6MinimumSize])
	if got := ip6.TransportProtocol(); got != header.ICMPv6ProtocolNumber {
		t.Fatalf("IPv6 next-header=%d", got)
	}
	icmp6 := header.ICMPv6(ip6.Payload())
	if icmp6.Type() != header.ICMPv6DstUnreachable || icmp6.Code() != header.ICMPv6PortUnreachable {
		t.Fatalf("IPv6 ICMP type/code=%d/%d", icmp6.Type(), icmp6.Code())
	}
}
