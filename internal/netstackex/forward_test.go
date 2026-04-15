// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package netstackex

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestPromiscuousTCPForwarderDirect(t *testing.T) {
	dev, netw, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.1.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netw.SetPromiscuous(true); err != nil {
		t.Fatal(err)
	}
	if err := netw.SetSpoofing(true); err != nil {
		t.Fatal(err)
	}

	seen := make(chan struct{}, 1)
	netw.SetTCPForwarder(0, 16, func(req *gtcp.ForwarderRequest) {
		req.Complete(false)
		seen <- struct{}{}
	})

	if _, err := dev.Write([][]byte{testTCPSYN(t, "100.64.1.2", "172.17.0.3", 12345, 80)}, 0); err != nil {
		t.Fatal(err)
	}

	select {
	case <-seen:
	case <-time.After(time.Second):
		stats := netw.stack.Stats()
		t.Logf("ip recv=%d valid=%d delivered=%d invalid_dst=%d malformed=%d tcp invalid=%d checksum=%d",
			stats.IP.PacketsReceived.Value(),
			stats.IP.ValidPacketsReceived.Value(),
			stats.IP.PacketsDelivered.Value(),
			stats.IP.InvalidDestinationAddressesReceived.Value(),
			stats.IP.MalformedPacketsReceived.Value(),
			stats.TCP.InvalidSegmentsReceived.Value(),
			stats.TCP.ChecksumErrors.Value(),
		)
		t.Fatal("forwarder did not receive injected SYN")
	}
}

func TestTCPForwarderRejectSendsRST(t *testing.T) {
	dev, netw, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.1.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netw.SetPromiscuous(true); err != nil {
		t.Fatal(err)
	}
	if err := netw.SetSpoofing(true); err != nil {
		t.Fatal(err)
	}

	netw.SetTCPForwarder(0, 16, func(req *gtcp.ForwarderRequest) {
		req.Complete(true)
	})

	if _, err := dev.Write([][]byte{testTCPSYN(t, "100.64.1.2", "172.17.0.3", 12345, 80)}, 0); err != nil {
		t.Fatal(err)
	}

	select {
	case view := <-netw.incomingPacket:
		packet := append([]byte(nil), view.AsSlice()...)
		view.Release()
		if len(packet) < header.IPv4MinimumSize+header.TCPMinimumSize {
			t.Fatalf("short reset packet: %x", packet)
		}
		ip := header.IPv4(packet[:header.IPv4MinimumSize])
		tcp := header.TCP(packet[ip.HeaderLength():])
		if got := tcp.Flags(); got&header.TCPFlagRst == 0 {
			t.Fatalf("reject did not send TCP RST, flags=%#x packet=%x", got, packet)
		}
		if got, want := ip.SourceAddress(), tcpip.AddrFromSlice(netip.MustParseAddr("172.17.0.3").AsSlice()); got != want {
			t.Fatalf("RST source mismatch: got %s want %s", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP RST")
	}
}

func TestMalformedPacketsAreDropped(t *testing.T) {
	dev, netw, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.2.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netw.SetPromiscuous(true); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case view, ok := <-netw.incomingPacket:
				if !ok {
					return
				}
				view.Release()
			}
		}
	}()
	defer close(done)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("malformed packet caused panic: %v", r)
		}
	}()
	for name, packet := range map[string][]byte{
		"malformed ip version": {0xf0, 0x00},
		"short ipv4":           {0x45, 0x00, 0x00},
		"invalid ipv4 ihl":     invalidIPv4IHL(),
		"invalid tcp header":   invalidTCPHeader(t),
		"mangled tcp state":    tcpACKWithoutState(t),
		"malformed udp":        malformedUDP(t),
		"malformed icmp":       malformedICMP(t),
	} {
		t.Run(name, func(t *testing.T) {
			_, _ = dev.Write([][]byte{packet}, 0)
		})
	}
}

func testTCPSYN(t *testing.T, src, dst string, srcPort, dstPort uint16) []byte {
	t.Helper()
	return testTCPPacket(t, src, dst, srcPort, dstPort, header.TCPFlagSyn, 1, 0)
}

func testTCPPacket(t *testing.T, src, dst string, srcPort, dstPort uint16, flags header.TCPFlags, seq, ack uint32) []byte {
	t.Helper()
	srcAddr := tcpip.AddrFromSlice(netip.MustParseAddr(src).AsSlice())
	dstAddr := tcpip.AddrFromSlice(netip.MustParseAddr(dst).AsSlice())
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)

	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tcp := header.TCP(packet[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, header.TCPMinimumSize)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return packet
}

func invalidIPv4IHL() []byte {
	packet := make([]byte, header.IPv4MinimumSize)
	packet[0] = 0x41
	return packet
}

func invalidTCPHeader(t *testing.T) []byte {
	packet := testTCPSYN(t, "100.64.2.2", "100.64.2.1", 12345, 80)
	packet[header.IPv4MinimumSize+12] = 0
	return packet
}

func tcpACKWithoutState(t *testing.T) []byte {
	return testTCPPacket(t, "100.64.2.2", "100.64.2.1", 12346, 80, header.TCPFlagAck, 100, 999999)
}

func malformedUDP(t *testing.T) []byte {
	t.Helper()
	srcAddr := tcpip.AddrFromSlice(netip.MustParseAddr("100.64.2.2").AsSlice())
	dstAddr := tcpip.AddrFromSlice(netip.MustParseAddr("100.64.2.1").AsSlice())
	packet := make([]byte, header.IPv4MinimumSize+4)
	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return packet
}

func malformedICMP(t *testing.T) []byte {
	t.Helper()
	srcAddr := tcpip.AddrFromSlice(netip.MustParseAddr("100.64.2.2").AsSlice())
	dstAddr := tcpip.AddrFromSlice(netip.MustParseAddr("100.64.2.1").AsSlice())
	packet := make([]byte, header.IPv4MinimumSize+1)
	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return packet
}
