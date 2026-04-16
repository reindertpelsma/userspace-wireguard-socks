// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const inboundICMPForwardTimeout = 5 * time.Second

func (e *Engine) handleICMPForward(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	src, dst, ok := transportEndpointAddrs(id)
	if !ok {
		return false
	}
	srcAP := netip.AddrPortFrom(src, 0)
	dstAP := netip.AddrPortFrom(dst, 0)
	if e.localAddrContains(dst) {
		return false
	}
	if !e.inboundAllowed(srcAP, dstAP, "icmp") || e.rejectTransparentDestination(dstAP) {
		return false
	}
	request, isIPv6, ok := inboundICMPEchoRequest(pkt)
	if !ok {
		return false
	}
	dialDst := dst
	if rewritten, ok, err := e.inboundHostForwardTarget(dstAP); err != nil {
		e.log.Printf("icmp forward target %s failed: %v", dst, err)
		return true
	} else if ok {
		dialDst = rewritten.Addr()
	}
	go e.forwardInboundICMPEcho(src, dst, dialDst, request, isIPv6)
	return true
}

func (e *Engine) forwardInboundICMPEcho(src, replyFrom, dialDst netip.Addr, request []byte, isIPv6 bool) {
	if e.net == nil {
		return
	}
	conn, err := e.dialHostPing(netip.Addr{}, dialDst)
	if err != nil {
		e.log.Printf("icmp forward host dial %s failed: %v", dialDst, err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(inboundICMPForwardTimeout))
	if _, err := conn.Write(request); err != nil {
		e.log.Printf("icmp forward write %s failed: %v", dialDst, err)
		return
	}
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err != nil {
		e.log.Printf("icmp forward read %s failed: %v", dialDst, err)
		return
	}
	packet := inboundICMPEchoReply(src, replyFrom, request, isIPv6)
	if len(packet) != 0 {
		e.net.InjectOutboundPacket(packet)
	}
}

func inboundICMPEchoRequest(pkt *stack.PacketBuffer) ([]byte, bool, bool) {
	request := append([]byte(nil), pkt.TransportHeader().Slice()...)
	payload := pkt.Data().ToBuffer()
	request = append(request, payload.Flatten()...)
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		h := header.ICMPv4(request)
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4Echo || h.Code() != 0 {
			return nil, false, false
		}
		return request, false, true
	case header.IPv6ProtocolNumber:
		h := header.ICMPv6(request)
		if len(h) < header.ICMPv6MinimumSize || h.Type() != header.ICMPv6EchoRequest || h.Code() != 0 {
			return nil, false, false
		}
		return request, true, true
	default:
		return nil, false, false
	}
}

func inboundICMPEchoReply(dst, src netip.Addr, request []byte, isIPv6 bool) []byte {
	if isIPv6 {
		return inboundICMPEchoReply6(dst, src, request)
	}
	return inboundICMPEchoReply4(dst, src, request)
}

func inboundICMPEchoReply4(dst, src netip.Addr, request []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+len(request))
	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(src.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(dst.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(packet[header.IPv4MinimumSize:])
	copy(icmp, request)
	icmp.SetType(header.ICMPv4EchoReply)
	icmp.SetCode(0)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	return packet
}

func inboundICMPEchoReply6(dst, src netip.Addr, request []byte) []byte {
	packet := make([]byte, header.IPv6MinimumSize+len(request))
	ip := header.IPv6(packet[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(request)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(src.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(dst.AsSlice()),
	})
	icmp := header.ICMPv6(packet[header.IPv6MinimumSize:])
	copy(icmp, request)
	icmp.SetType(header.ICMPv6EchoReply)
	icmp.SetCode(0)
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    tcpip.AddrFromSlice(src.AsSlice()),
		Dst:    tcpip.AddrFromSlice(dst.AsSlice()),
	}))
	return packet
}

func transportEndpointAddrs(id stack.TransportEndpointID) (src, dst netip.Addr, ok bool) {
	src, ok = netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	dst, ok = netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	return src.Unmap(), dst.Unmap(), true
}
