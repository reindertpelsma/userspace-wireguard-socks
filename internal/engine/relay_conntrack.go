// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	relayProtoICMP = 1

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10

	relayTCPHandshakeTimeout = 30 * time.Second
	relayTCPClosingTimeout   = 2 * time.Minute
	relayICMPTimeout         = 30 * time.Second
)

type relayFlowState uint8

const (
	relayFlowUDP relayFlowState = iota + 1
	relayFlowICMP
	relayTCPSynSent
	relayTCPSynRecv
	relayTCPEstablished
	relayTCPFinWait
	relayTCPTimeWait
)

type relayFlowKey struct {
	Proto    byte
	InitIP   netip.Addr
	InitPort uint16
	RespIP   netip.Addr
	RespPort uint16
}

type relayFlow struct {
	key              relayFlowKey
	state            relayFlowState
	last             time.Time
	finFromInitiator bool
	finFromResponder bool
}

type relayPacketMeta struct {
	proto    byte
	network  string
	src      netip.AddrPort
	dst      netip.AddrPort
	tcpFlags byte
	icmpType byte
	icmpID   uint16
	icmpErr  bool
	inner    *relayPacketMeta
}

func (e *Engine) allowRelayTracked(meta relayPacketMeta, now time.Time) bool {
	if meta.icmpErr {
		e.relayMu.Lock()
		defer e.relayMu.Unlock()
		e.ensureRelayFlowsLocked()
		e.relaySweepLocked(now)
		return e.allowRelayICMPErrorLocked(meta, now)
	}
	if !relayTrackable(meta) {
		return e.relayAllowed(meta.src, meta.dst, meta.network)
	}

	e.relayMu.Lock()
	e.ensureRelayFlowsLocked()
	e.relaySweepLocked(now)
	if flow, forward, ok := e.relayFindFlowLocked(meta); ok {
		allowed := e.allowExistingRelayFlowLocked(flow, forward, meta, now)
		e.relayMu.Unlock()
		return allowed
	}
	e.relayMu.Unlock()

	if !e.relayAllowed(meta.src, meta.dst, meta.network) {
		return false
	}
	if !relayCanOpenFlow(meta) {
		return false
	}

	e.relayMu.Lock()
	defer e.relayMu.Unlock()
	e.ensureRelayFlowsLocked()
	e.relaySweepLocked(now)
	if flow, forward, ok := e.relayFindFlowLocked(meta); ok {
		return e.allowExistingRelayFlowLocked(flow, forward, meta, now)
	}
	if !e.relayCanAddFlowLocked(meta) {
		return false
	}
	e.relayFlows[relayForwardKey(meta)] = newRelayFlow(meta, now)
	return true
}

func (e *Engine) ensureRelayFlowsLocked() {
	if e.relayFlows == nil {
		e.relayFlows = make(map[relayFlowKey]*relayFlow)
	}
}

func (e *Engine) relayFindFlowLocked(meta relayPacketMeta) (*relayFlow, bool, bool) {
	key := relayForwardKey(meta)
	if flow, ok := e.relayFlows[key]; ok {
		return flow, true, true
	}
	key = relayReverseKey(meta)
	if flow, ok := e.relayFlows[key]; ok {
		return flow, false, true
	}
	return nil, false, false
}

func (e *Engine) allowExistingRelayFlowLocked(flow *relayFlow, forward bool, meta relayPacketMeta, now time.Time) bool {
	switch flow.state {
	case relayFlowUDP:
		flow.last = now
		return true
	case relayFlowICMP:
		if forward && relayICMPEchoRequest(meta) || !forward && relayICMPEchoReply(meta) {
			flow.last = now
			return true
		}
		return false
	case relayTCPSynSent:
		if forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK == 0 {
			flow.last = now
			return true
		}
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.state = relayTCPSynRecv
			flow.last = now
			return true
		}
		return false
	case relayTCPSynRecv:
		if !forward && meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK != 0 {
			flow.last = now
			return true
		}
		if forward && meta.tcpFlags&tcpFlagACK != 0 && meta.tcpFlags&tcpFlagSYN == 0 {
			flow.state = relayTCPEstablished
			flow.last = now
			e.updateRelayTCPClosingLocked(flow, forward, meta)
			return true
		}
		return false
	case relayTCPEstablished, relayTCPFinWait, relayTCPTimeWait:
		flow.last = now
		if meta.tcpFlags&tcpFlagRST != 0 {
			delete(e.relayFlows, flow.key)
			return true
		}
		e.updateRelayTCPClosingLocked(flow, forward, meta)
		return true
	default:
		return false
	}
}

func (e *Engine) updateRelayTCPClosingLocked(flow *relayFlow, forward bool, meta relayPacketMeta) {
	if meta.tcpFlags&tcpFlagFIN == 0 {
		return
	}
	if forward {
		flow.finFromInitiator = true
	} else {
		flow.finFromResponder = true
	}
	if flow.finFromInitiator && flow.finFromResponder {
		flow.state = relayTCPTimeWait
	} else if flow.state == relayTCPEstablished {
		flow.state = relayTCPFinWait
	}
}

func (e *Engine) allowRelayICMPErrorLocked(meta relayPacketMeta, now time.Time) bool {
	if meta.inner == nil || !e.allowedContains(meta.src.Addr()) {
		return false
	}
	flow, _, ok := e.relayFindFlowLocked(*meta.inner)
	if !ok {
		return false
	}
	if meta.dst.Addr() != flow.key.InitIP && meta.dst.Addr() != flow.key.RespIP {
		return false
	}
	flow.last = now
	return true
}

func (e *Engine) relayCanAddFlowLocked(meta relayPacketMeta) bool {
	maxFlows := e.cfg.Relay.ConntrackMaxFlows
	if maxFlows <= 0 {
		maxFlows = 65536
	}
	if len(e.relayFlows) >= maxFlows {
		return false
	}
	maxPerPeer := e.cfg.Relay.ConntrackMaxPerPeer
	if maxPerPeer <= 0 {
		maxPerPeer = 4096
	}
	peer := e.relayPeerKey(meta.src.Addr())
	count := 0
	for _, flow := range e.relayFlows {
		if e.relayPeerKey(flow.key.InitIP) == peer {
			count++
			if count >= maxPerPeer {
				return false
			}
		}
	}
	return true
}

func (e *Engine) relayPeerKey(ip netip.Addr) string {
	if p, ok := e.allowedBestPrefix(ip); ok {
		return p.String()
	}
	return ip.Unmap().String()
}

func (e *Engine) relaySweepLocked(now time.Time) {
	if len(e.relayFlows) == 0 {
		return
	}
	if !e.relayLastSweep.IsZero() && now.Sub(e.relayLastSweep) < time.Second {
		return
	}
	e.relayLastSweep = now
	before := len(e.relayFlows)
	for key, flow := range e.relayFlows {
		if relayFlowExpired(flow, now, e.tcpIdleTimeout(), e.udpIdleTimeout()) {
			delete(e.relayFlows, key)
		}
	}
	if len(e.relayFlows) > 0 && len(e.relayFlows)*4 < before {
		shrunk := make(map[relayFlowKey]*relayFlow, len(e.relayFlows))
		for key, flow := range e.relayFlows {
			shrunk[key] = flow
		}
		e.relayFlows = shrunk
	}
}

func relayFlowExpired(flow *relayFlow, now time.Time, tcpIdle, udpIdle time.Duration) bool {
	idle := tcpIdle
	switch flow.state {
	case relayFlowUDP:
		idle = udpIdle
	case relayFlowICMP:
		idle = relayICMPTimeout
	case relayTCPSynSent, relayTCPSynRecv:
		idle = relayTCPHandshakeTimeout
	case relayTCPFinWait, relayTCPTimeWait:
		idle = relayTCPClosingTimeout
	}
	return idle > 0 && now.Sub(flow.last) > idle
}

func relayCanOpenFlow(meta relayPacketMeta) bool {
	switch meta.proto {
	case 6:
		return meta.tcpFlags&tcpFlagSYN != 0 && meta.tcpFlags&tcpFlagACK == 0
	case 17:
		return true
	case relayProtoICMP:
		return relayICMPEchoRequest(meta)
	default:
		return false
	}
}

func relayTrackable(meta relayPacketMeta) bool {
	switch meta.proto {
	case 6, 17:
		return true
	case relayProtoICMP:
		return relayICMPEcho(meta)
	default:
		return false
	}
}

func newRelayFlow(meta relayPacketMeta, now time.Time) *relayFlow {
	state := relayFlowUDP
	switch meta.proto {
	case 6:
		state = relayTCPSynSent
	case relayProtoICMP:
		state = relayFlowICMP
	}
	key := relayForwardKey(meta)
	return &relayFlow{key: key, state: state, last: now}
}

func relayForwardKey(meta relayPacketMeta) relayFlowKey {
	initPort := meta.src.Port()
	respPort := meta.dst.Port()
	proto := meta.proto
	if proto == relayProtoICMP {
		initPort = meta.icmpID
		respPort = 0
	}
	return relayFlowKey{
		Proto:    proto,
		InitIP:   meta.src.Addr().Unmap(),
		InitPort: initPort,
		RespIP:   meta.dst.Addr().Unmap(),
		RespPort: respPort,
	}
}

func relayReverseKey(meta relayPacketMeta) relayFlowKey {
	initPort := meta.dst.Port()
	respPort := meta.src.Port()
	proto := meta.proto
	if proto == relayProtoICMP {
		initPort = meta.icmpID
		respPort = 0
	}
	return relayFlowKey{
		Proto:    proto,
		InitIP:   meta.dst.Addr().Unmap(),
		InitPort: initPort,
		RespIP:   meta.src.Addr().Unmap(),
		RespPort: respPort,
	}
}

func parseRelayPacket(packet []byte) (relayPacketMeta, bool) {
	if len(packet) == 0 {
		return relayPacketMeta{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		return parseRelayIPv4Packet(packet)
	case 6:
		return parseRelayIPv6Packet(packet)
	default:
		return relayPacketMeta{}, false
	}
}

func parseRelayIPv4Packet(packet []byte) (relayPacketMeta, bool) {
	if len(packet) < 20 {
		return relayPacketMeta{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return relayPacketMeta{}, false
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total != 0 {
		if total < ihl || total > len(packet) {
			return relayPacketMeta{}, false
		}
		packet = packet[:total]
	}
	src := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	dst := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x1fff != 0 {
		return parseRelayTransport(packet[9], src, dst, nil)
	}
	return parseRelayTransport(packet[9], src, dst, packet[ihl:])
}

func parseRelayIPv6Packet(packet []byte) (relayPacketMeta, bool) {
	if len(packet) < 40 {
		return relayPacketMeta{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen > 0 {
		if 40+payloadLen > len(packet) {
			return relayPacketMeta{}, false
		}
		packet = packet[:40+payloadLen]
	}
	var src16, dst16 [16]byte
	copy(src16[:], packet[8:24])
	copy(dst16[:], packet[24:40])
	src := netip.AddrFrom16(src16)
	dst := netip.AddrFrom16(dst16)
	proto := packet[6]
	offset := 40
	for i := 0; i < 8; i++ {
		switch proto {
		case 0, 43, 60:
			if len(packet) < offset+2 {
				return relayPacketMeta{}, false
			}
			next := packet[offset]
			size := (int(packet[offset+1]) + 1) * 8
			if size < 8 || len(packet) < offset+size {
				return relayPacketMeta{}, false
			}
			proto = next
			offset += size
		case 44:
			if len(packet) < offset+8 {
				return relayPacketMeta{}, false
			}
			frag := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			proto = packet[offset]
			if frag&0xfff8 != 0 {
				return parseRelayTransport(proto, src, dst, nil)
			}
			offset += 8
		default:
			return parseRelayTransport(proto, src, dst, packet[offset:])
		}
	}
	return relayPacketMeta{}, false
}

func parseRelayTransport(proto byte, src, dst netip.Addr, transport []byte) (relayPacketMeta, bool) {
	switch proto {
	case 6:
		sp, dp := packetPorts(proto, transport)
		flags := byte(0)
		if len(transport) >= 14 {
			flags = transport[13]
		}
		return relayPacketMeta{
			proto:    6,
			network:  "tcp",
			src:      netip.AddrPortFrom(src.Unmap(), sp),
			dst:      netip.AddrPortFrom(dst.Unmap(), dp),
			tcpFlags: flags,
		}, true
	case 17:
		sp, dp := packetPorts(proto, transport)
		return relayPacketMeta{
			proto:   17,
			network: "udp",
			src:     netip.AddrPortFrom(src.Unmap(), sp),
			dst:     netip.AddrPortFrom(dst.Unmap(), dp),
		}, true
	case 1, 58:
		if len(transport) < 8 {
			return relayPacketMeta{
				proto:   relayProtoICMP,
				network: "icmp",
				src:     netip.AddrPortFrom(src.Unmap(), 0),
				dst:     netip.AddrPortFrom(dst.Unmap(), 0),
			}, true
		}
		meta := relayPacketMeta{
			proto:    relayProtoICMP,
			network:  "icmp",
			src:      netip.AddrPortFrom(src.Unmap(), 0),
			dst:      netip.AddrPortFrom(dst.Unmap(), 0),
			icmpType: transport[0],
		}
		if relayICMPEcho(meta) {
			meta.icmpID = binary.BigEndian.Uint16(transport[4:6])
		} else if relayICMPError(proto, transport[0]) {
			meta.icmpErr = true
			if inner, ok := parseRelayPacket(transport[8:]); ok {
				meta.inner = &inner
			}
		}
		return meta, true
	default:
		return relayPacketMeta{
			proto:   proto,
			network: "",
			src:     netip.AddrPortFrom(src.Unmap(), 0),
			dst:     netip.AddrPortFrom(dst.Unmap(), 0),
		}, true
	}
}

func relayICMPEcho(meta relayPacketMeta) bool {
	switch meta.icmpType {
	case 0, 8, 128, 129:
		return true
	default:
		return false
	}
}

func relayICMPEchoRequest(meta relayPacketMeta) bool {
	return meta.icmpType == 8 || meta.icmpType == 128
}

func relayICMPEchoReply(meta relayPacketMeta) bool {
	return meta.icmpType == 0 || meta.icmpType == 129
}

func relayICMPError(proto, typ byte) bool {
	if proto == 58 {
		return typ < 128
	}
	switch typ {
	case 3, 4, 5, 11, 12:
		return true
	default:
		return false
	}
}
