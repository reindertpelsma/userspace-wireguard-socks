// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func (e *Engine) sendUDPUnreachable(src, dst netip.AddrPort) {
	if e.net == nil || e.cfg.Inbound.ForwardICMPErrors == nil || !*e.cfg.Inbound.ForwardICMPErrors {
		return
	}
	packet := udpUnreachablePacket(src, dst)
	if len(packet) != 0 {
		e.net.InjectOutboundPacket(packet)
	}
}

func udpUnreachablePacket(src, dst netip.AddrPort) []byte {
	if src.Addr().Is4() && dst.Addr().Is4() {
		return udpUnreachable4(src, dst)
	}
	if src.Addr().Is6() && dst.Addr().Is6() {
		return udpUnreachable6(src, dst)
	}
	return nil
}

func udpUnreachable4(src, dst netip.AddrPort) []byte {
	original := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	origIP := header.IPv4(original[:header.IPv4MinimumSize])
	origSrc := tcpip.AddrFromSlice(src.Addr().AsSlice())
	origDst := tcpip.AddrFromSlice(dst.Addr().AsSlice())
	origIP.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(original)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     origSrc,
		DstAddr:     origDst,
	})
	origIP.SetChecksum(^origIP.CalculateChecksum())
	header.UDP(original[header.IPv4MinimumSize:]).Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  header.UDPMinimumSize,
	})

	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(original))
	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     origDst,
		DstAddr:     origSrc,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(header.ICMPv4PortUnreachable)
	copy(icmp.Payload(), original)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	return packet
}

func udpUnreachable6(src, dst netip.AddrPort) []byte {
	original := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
	origIP := header.IPv6(original[:header.IPv6MinimumSize])
	origSrc := tcpip.AddrFromSlice(src.Addr().AsSlice())
	origDst := tcpip.AddrFromSlice(dst.Addr().AsSlice())
	origIP.Encode(&header.IPv6Fields{
		PayloadLength:     header.UDPMinimumSize,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           origSrc,
		DstAddr:           origDst,
	})
	header.UDP(original[header.IPv6MinimumSize:]).Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  header.UDPMinimumSize,
	})

	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize+len(original))
	ip := header.IPv6(packet[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(packet) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           origDst,
		DstAddr:           origSrc,
	})

	icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6DstUnreachable)
	icmp.SetCode(header.ICMPv6PortUnreachable)
	copy(icmp.Payload(), original)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    origDst,
		Dst:    origSrc,
	}))
	return packet
}
