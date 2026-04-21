// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package engine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sort"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

type peerRoute struct {
	prefix    netip.Prefix
	publicKey string
}

type peerTraffic struct{}

func buildPeerTrafficState(peers []config.Peer, _ config.TrafficShaper) ([]netip.Prefix, []peerRoute, map[string]*peerTraffic, error) {
	allowed := make([]netip.Prefix, 0, len(peers))
	routes := make([]peerRoute, 0, len(peers))
	for _, peer := range peers {
		prefixes, err := config.PeerAllowedPrefixes([]config.Peer{peer})
		if err != nil {
			return nil, nil, nil, err
		}
		for _, prefix := range prefixes {
			allowed = append(allowed, prefix)
			routes = append(routes, peerRoute{prefix: prefix, publicKey: peer.PublicKey})
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].prefix.Bits() == routes[j].prefix.Bits() {
			return routes[i].publicKey < routes[j].publicKey
		}
		return routes[i].prefix.Bits() > routes[j].prefix.Bits()
	})
	return allowed, routes, map[string]*peerTraffic{}, nil
}

func (e *Engine) applyPeerTrafficState(peers []config.Peer) error {
	allowed, routes, traffic, err := buildPeerTrafficState(peers, config.TrafficShaper{})
	if err != nil {
		return err
	}
	e.allowedMu.Lock()
	e.allowed = allowed
	e.peerRoutes = routes
	e.peerTraffic = traffic
	e.allowedMu.Unlock()
	return nil
}

func (e *Engine) peerRouteForIP(ip netip.Addr) (peerRoute, bool) {
	ip = ip.Unmap()
	e.allowedMu.RLock()
	defer e.allowedMu.RUnlock()
	for _, route := range e.peerRoutes {
		if route.prefix.Contains(ip) {
			return route, true
		}
	}
	return peerRoute{}, false
}

func (e *Engine) peerKeyForIP(ip netip.Addr) string {
	if route, ok := e.peerRouteForIP(ip); ok {
		return route.publicKey
	}
	return ip.Unmap().String()
}

func (e *Engine) peerTrafficForIP(_ netip.Addr) *peerTraffic { return nil }

func (e *Engine) wrapDialedPeerConn(_ string, c net.Conn, _ netip.AddrPort) net.Conn { return c }

func (e *Engine) wrapAcceptedPeerConn(_ string, c net.Conn) net.Conn { return c }

func (e *Engine) wrapPeerListener(ln net.Listener) net.Listener { return ln }

func (e *Engine) wrapPeerPacketConn(pc net.PacketConn) net.PacketConn { return pc }

func (e *Engine) allowRelayTrafficPacket(_ []byte, _ relayPacketMeta) bool { return true }

func packetECNCapable(packet []byte) bool {
	if len(packet) < 2 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		return packet[1]&0x03 != 0
	case 6:
		trafficClass := ((packet[0] & 0x0f) << 4) | (packet[1] >> 4)
		return trafficClass&0x03 != 0
	default:
		return false
	}
}

func markPacketECN(packet []byte) bool {
	if len(packet) < 2 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		if packet[1]&0x03 == 0 {
			return false
		}
		packet[1] = (packet[1] &^ 0x03) | 0x03
		if len(packet) < 20 {
			return false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || ihl > len(packet) {
			return false
		}
		packet[10], packet[11] = 0, 0
		sum := ipv4HeaderChecksum(packet[:ihl])
		binary.BigEndian.PutUint16(packet[10:12], sum)
		return true
	case 6:
		trafficClass := ((packet[0] & 0x0f) << 4) | (packet[1] >> 4)
		if trafficClass&0x03 == 0 {
			return false
		}
		trafficClass = (trafficClass &^ 0x03) | 0x03
		packet[0] = (packet[0] & 0xf0) | (trafficClass >> 4)
		packet[1] = (packet[1] & 0x0f) | ((trafficClass & 0x0f) << 4)
		return true
	default:
		return false
	}
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
