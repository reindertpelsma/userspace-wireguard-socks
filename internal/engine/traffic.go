// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sort"
	"time"

	trafficshape "github.com/reindertpelsma/userspace-wireguard-socks/internal"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

type peerRoute struct {
	prefix    netip.Prefix
	publicKey string
}

type peerTraffic struct {
	shaper *trafficshape.Shaper
	stream *trafficshape.StreamShaper
}

func buildPeerTrafficState(peers []config.Peer, global config.TrafficShaper) ([]netip.Prefix, []peerRoute, map[string]*peerTraffic, error) {
	allowed := make([]netip.Prefix, 0, len(peers))
	routes := make([]peerRoute, 0, len(peers))
	traffic := make(map[string]*peerTraffic, len(peers))
	for _, peer := range peers {
		prefixes, err := config.PeerAllowedPrefixes([]config.Peer{peer})
		if err != nil {
			return nil, nil, nil, err
		}
		for _, prefix := range prefixes {
			allowed = append(allowed, prefix)
			routes = append(routes, peerRoute{prefix: prefix, publicKey: peer.PublicKey})
		}
		merged := mergeTrafficShaper(global, peer.TrafficShaper)
		if shaper := newPeerShaper(merged); shaper != nil {
			traffic[peer.PublicKey] = &peerTraffic{
				shaper: shaper,
				stream: shaper.Stream(),
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].prefix.Bits() == routes[j].prefix.Bits() {
			return routes[i].publicKey < routes[j].publicKey
		}
		return routes[i].prefix.Bits() > routes[j].prefix.Bits()
	})
	return allowed, routes, traffic, nil
}

func mergeTrafficShaper(global, peer config.TrafficShaper) config.TrafficShaper {
	if peer.UploadBps == 0 && peer.DownloadBps == 0 && peer.LatencyMillis == 0 {
		return global
	}
	out := global
	if peer.UploadBps != 0 {
		out.UploadBps = peer.UploadBps
	}
	if peer.DownloadBps != 0 {
		out.DownloadBps = peer.DownloadBps
	}
	if peer.LatencyMillis != 0 {
		out.LatencyMillis = peer.LatencyMillis
	}
	return out
}

func newPeerShaper(cfg config.TrafficShaper) *trafficshape.Shaper {
	if cfg.UploadBps <= 0 && cfg.DownloadBps <= 0 {
		return nil
	}
	latency := time.Duration(cfg.LatencyMillis) * time.Millisecond
	if latency <= 0 {
		latency = 15 * time.Millisecond
	}
	return trafficshape.NewShaper(trafficshape.ShaperConfig{
		UploadBps:     cfg.UploadBps,
		DownloadBps:   cfg.DownloadBps,
		TargetLatency: latency,
	})
}

func (e *Engine) applyPeerTrafficState(peers []config.Peer) error {
	e.cfgMu.RLock()
	global := e.cfg.TrafficShaper
	e.cfgMu.RUnlock()
	allowed, routes, traffic, err := buildPeerTrafficState(peers, global)
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

func (e *Engine) peerTrafficForIP(ip netip.Addr) *peerTraffic {
	ip = ip.Unmap()
	e.allowedMu.RLock()
	defer e.allowedMu.RUnlock()
	for _, route := range e.peerRoutes {
		if route.prefix.Contains(ip) {
			return e.peerTraffic[route.publicKey]
		}
	}
	return nil
}

func (e *Engine) wrapDialedPeerConn(network string, c net.Conn, dst netip.AddrPort) net.Conn {
	if c == nil {
		return nil
	}
	return e.wrapPeerConn(network, c, dst.Addr())
}

func (e *Engine) wrapAcceptedPeerConn(network string, c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	remote := addrPortFromNetAddr(c.RemoteAddr())
	if !remote.IsValid() {
		return c
	}
	return e.wrapPeerConn(network, c, remote.Addr())
}

func (e *Engine) wrapPeerConn(network string, c net.Conn, peerIP netip.Addr) net.Conn {
	peer := e.peerTrafficForIP(peerIP)
	if peer == nil || peer.shaper == nil {
		return c
	}
	switch networkBase(network) {
	case "tcp":
		if peer.stream == nil {
			return c
		}
		return &peerTrafficConn{Conn: c, stream: peer.stream}
	case "udp":
		return newPeerDatagramConn(c, peer.shaper)
	default:
		return c
	}
}

func (e *Engine) wrapPeerListener(ln net.Listener) net.Listener {
	if ln == nil {
		return nil
	}
	return &peerTrafficListener{Listener: ln, e: e}
}

func (e *Engine) wrapPeerPacketConn(pc net.PacketConn) net.PacketConn {
	if pc == nil {
		return nil
	}
	return &peerTrafficPacketConn{
		PacketConn: pc,
		e:          e,
		local:      addrPortFromNetAddr(pc.LocalAddr()),
	}
}

type peerTrafficConn struct {
	net.Conn
	stream *trafficshape.StreamShaper
}

func (c *peerTrafficConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.stream != nil {
		if waitErr := waitStreamBudget(c.stream.WaitDownload, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}
	return n, err
}

func (c *peerTrafficConn) Write(p []byte) (int, error) {
	if len(p) == 0 || c.stream == nil {
		return c.Conn.Write(p)
	}
	written := 0
	for written < len(p) {
		chunk := minInt(len(p)-written, 1400)
		if err := c.stream.WaitUpload(context.Background(), chunk); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

type peerDatagramConn struct {
	net.Conn
	shaper *trafficshape.Shaper
	hash   uint32
}

func newPeerDatagramConn(c net.Conn, shaper *trafficshape.Shaper) net.Conn {
	local := addrPortFromNetAddr(c.LocalAddr())
	remote := addrPortFromNetAddr(c.RemoteAddr())
	hash := uint32(0)
	if local.IsValid() && remote.IsValid() {
		hash = trafficshape.HashFlow(local, remote)
	}
	return &peerDatagramConn{Conn: c, shaper: shaper, hash: hash}
}

func (c *peerDatagramConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if n > 0 && c.shaper != nil {
			if allowed, _ := c.shaper.ShapeDownload(p[:n], c.hash); !allowed {
				if err != nil {
					return 0, err
				}
				continue
			}
		}
		return n, err
	}
}

func (c *peerDatagramConn) Write(p []byte) (int, error) {
	if len(p) > 0 && c.shaper != nil {
		if allowed, _ := c.shaper.ShapeUpload(p, c.hash); !allowed {
			return len(p), nil
		}
	}
	return c.Conn.Write(p)
}

type peerTrafficListener struct {
	net.Listener
	e *Engine
}

func (l *peerTrafficListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.e.wrapAcceptedPeerConn("tcp", c), nil
}

type peerTrafficPacketConn struct {
	net.PacketConn
	e     *Engine
	local netip.AddrPort
}

func (c *peerTrafficPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if n > 0 {
			remote := addrPortFromNetAddr(addr)
			if remote.IsValid() {
				if peer := c.e.peerTrafficForIP(remote.Addr()); peer != nil && peer.shaper != nil {
					hash := trafficshape.HashFlow(c.local, remote)
					if allowed, _ := peer.shaper.ShapeDownload(p[:n], hash); !allowed {
						if err != nil {
							return 0, nil, err
						}
						continue
					}
				}
			}
		}
		return n, addr, err
	}
}

func (c *peerTrafficPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	remote := addrPortFromNetAddr(addr)
	if len(p) > 0 && remote.IsValid() {
		if peer := c.e.peerTrafficForIP(remote.Addr()); peer != nil && peer.shaper != nil {
			hash := trafficshape.HashFlow(c.local, remote)
			if allowed, _ := peer.shaper.ShapeUpload(p, hash); !allowed {
				return len(p), nil
			}
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

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

func waitStreamBudget(wait func(context.Context, int) error, size int) error {
	for size > 0 {
		chunk := minInt(size, 1400)
		if err := wait(context.Background(), chunk); err != nil {
			return err
		}
		size -= chunk
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
