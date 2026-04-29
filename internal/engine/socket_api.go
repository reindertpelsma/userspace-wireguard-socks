// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

var maxSocketUDPPeers = 24576

type socketSession struct {
	id       uint64
	proto    uint8
	conn     net.Conn
	packet   net.PacketConn
	listener net.Listener
	// fixedDst is set for connected UDP sockets, including UDP listeners that
	// were later connected through the Linux-style reconnect frame. When empty,
	// UDP uses ActionUDPDatagram and tracks each remote peer separately.
	fixedDst netip.AddrPort
	udpMu    sync.Mutex
	udpPeers map[string]*udpPeerState

	acceptOnce sync.Once
	accepted   chan struct{}
	readOnce   sync.Once
	closeOnce  sync.Once
}

type socketServer struct {
	e      *Engine
	raw    net.Conn
	src    netip.AddrPort
	write  sync.Mutex
	mu     sync.Mutex
	sess   map[uint64]*socketSession
	closed chan struct{}
}

type udpPeerState struct {
	timer   *time.Timer
	expires time.Time
}

func (e *Engine) handleAPISocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	e.handleSocketUpgrade(w, r, addrPortFromString(r.RemoteAddr))
}

func (e *Engine) handleSocketUpgrade(w http.ResponseWriter, r *http.Request, src netip.AddrPort) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "uwg-socket/1") {
		writeAPIError(w, http.StatusBadRequest, "Upgrade: uwg-socket/1 is required")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "hijacking unsupported")
		return
	}
	c, br, err := hj.Hijack()
	if err != nil {
		return
	}
	if br.Reader.Buffered() > 0 {
		_ = c.Close()
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: uwg-socket/1\r\n\r\n")
	_ = c.SetDeadline(time.Time{})
	e.serveSocketProtocol(c, src)
}

func (e *Engine) serveSocketProtocol(c net.Conn, src netip.AddrPort) {
	s := &socketServer{
		e:      e,
		raw:    c,
		src:    src,
		sess:   make(map[uint64]*socketSession),
		closed: make(chan struct{}),
	}
	defer s.close()
	for {
		frame, err := socketproto.ReadFrame(c, socketproto.DefaultMaxPayload)
		if err != nil {
			return
		}
		if err := s.handleFrame(frame); err != nil {
			_ = s.send(socketproto.Frame{ID: frame.ID, Action: socketproto.ActionClose, Payload: []byte(err.Error())})
			s.closeSession(frame.ID, false)
		}
	}
}

func (s *socketServer) handleFrame(f socketproto.Frame) error {
	switch f.Action {
	case socketproto.ActionConnect:
		c, err := socketproto.DecodeConnect(f.Payload)
		if err != nil {
			return err
		}
		return s.handleConnect(f.ID, c)
	case socketproto.ActionAccept:
		return s.handleAccept(f.ID)
	case socketproto.ActionClose:
		s.closeSession(f.ID, false)
		return nil
	case socketproto.ActionData:
		return s.handleData(f.ID, f.Payload)
	case socketproto.ActionUDPDatagram:
		d, err := socketproto.DecodeUDPDatagram(f.Payload)
		if err != nil {
			return err
		}
		return s.handleUDPDatagram(f.ID, d)
	case socketproto.ActionDNS:
		return s.handleDNS(f.ID, f.Payload)
	default:
		return fmt.Errorf("unsupported socket action %d", f.Action)
	}
}

func (s *socketServer) handleConnect(id uint64, req socketproto.Connect) error {
	if id < socketproto.ClientIDBase {
		return errors.New("client connection IDs must use the upper range")
	}
	if req.Protocol == socketproto.ProtoUDP && req.ListenerID != 0 {
		return s.reconnectUDP(id, req)
	}
	s.closeSession(id, false)
	bind, dest, destSet, err := s.socketAddrs(req)
	if err != nil {
		return err
	}
	switch req.Protocol {
	case socketproto.ProtoTCP:
		if !destSet {
			return s.openTCPListener(id, bind, req.IPVersion)
		}
		return s.openTCPConn(id, bind, dest, req.IPVersion)
	case socketproto.ProtoUDP:
		if !destSet {
			return s.openUDPListener(id, bind, req.IPVersion)
		}
		return s.openUDPConn(id, bind, dest, req.IPVersion)
	case socketproto.ProtoICMP:
		if !destSet {
			return errors.New("socket API ICMP requires a destination")
		}
		return s.openICMPConn(id, bind, dest, req.IPVersion)
	default:
		return fmt.Errorf("unsupported socket protocol %d", req.Protocol)
	}
}

func (s *socketServer) socketAddrs(req socketproto.Connect) (bind, dest netip.AddrPort, destSet bool, err error) {
	if req.DestIP.IsValid() {
		destSet = true
		dest = netip.AddrPortFrom(req.DestIP, req.DestPort)
	} else if req.DestPort != 0 {
		return netip.AddrPort{}, netip.AddrPort{}, false, errors.New("destination port without destination IP")
	}
	if req.BindIP.IsValid() {
		if !s.e.localAddrContains(req.BindIP) && !s.e.cfg.SocketAPI.TransparentBind {
			return netip.AddrPort{}, netip.AddrPort{}, false, errors.New("transparent bind is disabled")
		}
		bind = netip.AddrPortFrom(req.BindIP, req.BindPort)
	} else if req.BindPort != 0 {
		ip, ok := s.e.firstLocalAddr(req.IPVersion)
		if !ok {
			return netip.AddrPort{}, netip.AddrPort{}, false, errors.New("no local WireGuard address for bind")
		}
		bind = netip.AddrPortFrom(ip, req.BindPort)
	}
	if destSet && s.e.tunnelAddrBlocked(dest.Addr()) {
		return netip.AddrPort{}, netip.AddrPort{}, false, errAddressFiltered
	}
	return bind, dest, destSet, nil
}

func (s *socketServer) openTCPConn(id uint64, bind, dest netip.AddrPort, version uint8) error {
	if !s.e.outboundAllowed(s.src, dest, "tcp") {
		return errProxyACL
	}
	ctx, cancel := context.WithTimeout(s.e.ctx, 30*time.Second)
	defer cancel()
	c, err := s.dialSocket(ctx, "tcp", bind, dest)
	if err != nil {
		return err
	}
	ss := &socketSession{id: id, proto: socketproto.ProtoTCP, conn: c}
	s.storeSession(ss)
	if err := s.sendAccept(id, version, socketproto.ProtoTCP, addrPortFromNetAddr(c.LocalAddr())); err != nil {
		s.closeSession(id, false)
		return err
	}
	ss.startReader(s, false)
	return nil
}

func (s *socketServer) openUDPConn(id uint64, bind, dest netip.AddrPort, version uint8) error {
	if !s.e.outboundAllowed(s.src, dest, "udp") {
		return errProxyACL
	}
	ctx, cancel := context.WithTimeout(s.e.ctx, 10*time.Second)
	defer cancel()
	c, err := s.dialSocket(ctx, "udp", bind, dest)
	if err != nil {
		return err
	}
	ss := &socketSession{id: id, proto: socketproto.ProtoUDP, conn: c, fixedDst: dest}
	s.storeSession(ss)
	if err := s.sendAccept(id, version, socketproto.ProtoUDP, addrPortFromNetAddr(c.LocalAddr())); err != nil {
		s.closeSession(id, false)
		return err
	}
	ss.startReader(s, false)
	return nil
}

func (s *socketServer) openICMPConn(id uint64, bind, dest netip.AddrPort, version uint8) error {
	if bind.Port() != 0 || dest.Port() != 0 {
		return errors.New("socket API ICMP does not use ports")
	}
	c, err := s.e.dialSocketICMP(s.src, bind, dest)
	if err != nil {
		return err
	}
	ss := &socketSession{id: id, proto: socketproto.ProtoICMP, conn: c}
	s.storeSession(ss)
	local := netip.AddrPortFrom(addrFromNetAddr(c.LocalAddr()), 0)
	if err := s.sendAccept(id, version, socketproto.ProtoICMP, local); err != nil {
		s.closeSession(id, false)
		return err
	}
	ss.startReader(s, false)
	return nil
}

func (s *socketServer) dialSocket(ctx context.Context, network string, bind, dest netip.AddrPort) (net.Conn, error) {
	if bind.Port() != 0 && bind.Port() < 1024 && !s.e.socketLowBindEnabled() {
		return nil, errors.New("binding low ports is disabled")
	}
	return s.e.dialSocketOutbound(ctx, network, s.src, bind, dest)
}

func (s *socketServer) openTCPListener(id uint64, bind netip.AddrPort, version uint8) error {
	if !s.e.socketBindEnabled() {
		return errors.New("socket API TCP bind is disabled")
	}
	if bind.Port() != 0 && bind.Port() < 1024 && !s.e.socketLowBindEnabled() {
		return errors.New("binding low ports is disabled")
	}
	if !bind.IsValid() {
		ip, ok := s.e.firstLocalAddr(version)
		if !ok {
			return errors.New("no local WireGuard address for TCP bind")
		}
		bind = netip.AddrPortFrom(ip, 0)
	}
	baseLn, err := s.e.net.ListenTCPAddrPort(bind)
	if err != nil {
		return err
	}
	ln := s.e.wrapPeerListener(baseLn)
	ss := &socketSession{id: id, proto: socketproto.ProtoTCP, listener: ln}
	s.storeSession(ss)
	if err := s.sendAccept(id, version, socketproto.ProtoTCP, addrPortFromNetAddr(ln.Addr())); err != nil {
		s.closeSession(id, false)
		return err
	}
	go s.acceptTCP(id, ln)
	return nil
}

func (s *socketServer) acceptTCP(listenerID uint64, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			s.sendClose(listenerID, err)
			s.closeSession(listenerID, false)
			return
		}
		src := addrPortFromNetAddr(c.RemoteAddr())
		dst := addrPortFromNetAddr(c.LocalAddr())
		if src.IsValid() && dst.IsValid() && !s.e.inboundAllowed(src, dst, "tcp") {
			_ = c.Close()
			continue
		}
		id := s.e.nextSocketServerID()
		ss := &socketSession{id: id, proto: socketproto.ProtoTCP, conn: c, accepted: make(chan struct{})}
		s.storeSession(ss)
		payload, err := socketproto.EncodeConnect(socketproto.Connect{
			ListenerID: listenerID,
			IPVersion:  socketproto.AddrVersion(dst.Addr()),
			Protocol:   socketproto.ProtoTCP,
			BindIP:     dst.Addr(),
			BindPort:   dst.Port(),
			DestIP:     src.Addr(),
			DestPort:   src.Port(),
		})
		if err != nil || s.send(socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}) != nil {
			s.closeSession(id, false)
			continue
		}
		go func(sess *socketSession) {
			select {
			case <-sess.accepted:
				sess.startReader(s, false)
			case <-time.After(30 * time.Second):
				s.sendClose(sess.id, errors.New("accept timeout"))
				s.closeSession(sess.id, false)
			case <-s.closed:
			}
		}(ss)
	}
}

func (s *socketServer) openUDPListener(id uint64, bind netip.AddrPort, version uint8) error {
	if bind.Port() != 0 && bind.Port() < 1024 && !s.e.socketLowBindEnabled() {
		return errors.New("binding low ports is disabled")
	}
	if !bind.IsValid() {
		ip, ok := s.e.firstLocalAddr(version)
		if !ok {
			return errors.New("no local WireGuard address for UDP bind")
		}
		bind = netip.AddrPortFrom(ip, 0)
	}
	basePC, err := s.e.net.ListenUDPAddrPort(bind)
	if err != nil {
		return err
	}
	pc := s.e.wrapPeerPacketConn(basePC)
	ss := &socketSession{id: id, proto: socketproto.ProtoUDP, packet: pc, udpPeers: make(map[string]*udpPeerState)}
	s.storeSession(ss)
	if err := s.sendAccept(id, version, socketproto.ProtoUDP, addrPortFromNetAddr(pc.LocalAddr())); err != nil {
		s.closeSession(id, false)
		return err
	}
	go ss.readPacketLoop(s)
	return nil
}

func (s *socketServer) reconnectUDP(id uint64, req socketproto.Connect) error {
	if req.ListenerID != id {
		return errors.New("UDP reconnect listener ID must match connection ID")
	}
	if req.BindIP.IsValid() || req.BindPort != 0 {
		return errors.New("UDP reconnect cannot change bind address")
	}
	if req.DestPort != 0 && !req.DestIP.IsValid() {
		return errors.New("destination port without destination IP")
	}
	destSet := req.DestIP.IsValid()
	dest := netip.AddrPort{}
	if destSet {
		dest = netip.AddrPortFrom(req.DestIP, req.DestPort)
		if s.e.tunnelAddrBlocked(dest.Addr()) {
			return errAddressFiltered
		}
		if !s.e.outboundAllowed(s.src, dest, "udp") {
			return errProxyACL
		}
	}
	s.mu.Lock()
	ss := s.sess[id]
	s.mu.Unlock()
	if ss == nil || ss.proto != socketproto.ProtoUDP || ss.packet == nil {
		return errors.New("UDP reconnect requires an existing UDP listener socket")
	}
	ss.setUDPFixedDst(dest)
	if destSet {
		if !ss.touchUDPPeer(dest, s.e.udpIdleTimeout()) {
			return errors.New("too many UDP peers for this socket session")
		}
	}
	return s.sendAccept(id, req.IPVersion, socketproto.ProtoUDP, addrPortFromNetAddr(ss.packet.LocalAddr()))
}

func (s *socketServer) handleAccept(id uint64) error {
	s.mu.Lock()
	ss := s.sess[id]
	s.mu.Unlock()
	if ss == nil || ss.accepted == nil {
		return nil
	}
	ss.acceptOnce.Do(func() { close(ss.accepted) })
	return nil
}

// handleData writes stream payloads, or one datagram for connected UDP. For
// unconnected UDP listener sockets the client must use ActionUDPDatagram so the
// remote address is carried with each datagram.
func (s *socketServer) handleData(id uint64, payload []byte) error {
	s.mu.Lock()
	ss := s.sess[id]
	s.mu.Unlock()
	if ss == nil {
		return errors.New("unknown connection ID")
	}
	if ss.proto == socketproto.ProtoUDP && ss.packet == nil && ss.conn == nil {
		return errors.New("malformed UDP socket session: no packet conn")
	}
	if ss.proto == socketproto.ProtoUDP && ss.packet != nil {
		dst := ss.udpFixedDst()
		if !dst.IsValid() {
			return errors.New("UDP socket is not connected")
		}
		if !ss.touchUDPPeer(dst, s.e.udpIdleTimeout()) {
			return errors.New("too many UDP peers for this socket session")
		}
		_, err := ss.packet.WriteTo(payload, net.UDPAddrFromAddrPort(dst))
		return err
	}
	if ss.conn == nil {
		return errors.New("unknown connection ID")
	}
	_, err := ss.conn.Write(payload)
	return err
}

func (s *socketServer) handleUDPDatagram(id uint64, d socketproto.UDPDatagram) error {
	s.mu.Lock()
	ss := s.sess[id]
	s.mu.Unlock()
	if ss == nil || ss.proto != socketproto.ProtoUDP {
		return errors.New("unknown UDP connection ID")
	}
	remote := netip.AddrPortFrom(d.RemoteIP, d.RemotePort)
	if fixed := ss.udpFixedDst(); fixed.IsValid() {
		if remote != fixed {
			return errors.New("UDP datagram remote does not match connected destination")
		}
		if ss.conn != nil {
			_, err := ss.conn.Write(d.Payload)
			return err
		}
		if ss.packet == nil {
			return errors.New("UDP listener is not open")
		}
		if !ss.touchUDPPeer(remote, s.e.udpIdleTimeout()) {
			return errors.New("too many UDP peers for this socket session")
		}
		_, err := ss.packet.WriteTo(d.Payload, net.UDPAddrFromAddrPort(remote))
		return err
	}
	if ss.packet == nil {
		return errors.New("UDP listener is not open")
	}
	if !s.e.outboundAllowed(s.src, remote, "udp") {
		return errProxyACL
	}
	if !ss.touchUDPPeer(remote, s.e.udpIdleTimeout()) {
		return errors.New("too many UDP peers for this socket session")
	}
	_, err := ss.packet.WriteTo(d.Payload, net.UDPAddrFromAddrPort(remote))
	return err
}

func (s *socketServer) handleDNS(id uint64, payload []byte) error {
	if !s.e.acquireDNSTransaction() {
		resp, err := refusedDNSPacket(payload)
		if err != nil {
			return err
		}
		return s.send(socketproto.Frame{ID: id, Action: socketproto.ActionDNS, Payload: resp})
	}
	defer s.e.releaseDNSTransaction()
	resp, err := exchangeSystemDNSPacket(payload)
	if err != nil {
		return err
	}
	return s.send(socketproto.Frame{ID: id, Action: socketproto.ActionDNS, Payload: resp})
}

func refusedDNSPacket(payload []byte) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetRcode(&req, dns.RcodeRefused)
	return resp.Pack()
}

func exchangeSystemDNSPacket(payload []byte) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(payload); err != nil {
		return nil, err
	}
	resp, err := exchangeSystemDNSAuto(&req)
	if err != nil {
		return nil, err
	}
	return resp.Pack()
}

func (s *socketServer) sendAccept(id uint64, version uint8, proto uint8, bind netip.AddrPort) error {
	payload, err := socketproto.EncodeAccept(socketproto.Accept{
		IPVersion: version,
		Protocol:  proto,
		BindIP:    bind.Addr(),
		BindPort:  bind.Port(),
	})
	if err != nil {
		return err
	}
	return s.send(socketproto.Frame{ID: id, Action: socketproto.ActionAccept, Payload: payload})
}

func (s *socketServer) sendClose(id uint64, err error) {
	msg := []byte("closed")
	if err != nil {
		msg = []byte(err.Error())
	}
	_ = s.send(socketproto.Frame{ID: id, Action: socketproto.ActionClose, Payload: msg})
}

func (s *socketServer) send(f socketproto.Frame) error {
	s.write.Lock()
	defer s.write.Unlock()
	return socketproto.WriteFrame(s.raw, f)
}

func (s *socketServer) storeSession(ss *socketSession) {
	s.mu.Lock()
	s.sess[ss.id] = ss
	s.mu.Unlock()
}

func (s *socketServer) closeSession(id uint64, notify bool) {
	s.mu.Lock()
	ss := s.sess[id]
	delete(s.sess, id)
	s.mu.Unlock()
	if ss == nil {
		return
	}
	ss.closeOnce.Do(func() {
		if ss.conn != nil {
			_ = ss.conn.Close()
		}
		if ss.packet != nil {
			_ = ss.packet.Close()
		}
		if ss.listener != nil {
			_ = ss.listener.Close()
		}
		ss.udpMu.Lock()
		for key, timer := range ss.udpPeers {
			timer.timer.Stop()
			delete(ss.udpPeers, key)
		}
		ss.udpMu.Unlock()
	})
	if notify {
		s.sendClose(id, net.ErrClosed)
	}
}

func (s *socketServer) close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Lock()
	ids := make([]uint64, 0, len(s.sess))
	for id := range s.sess {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.closeSession(id, false)
	}
	_ = s.raw.Close()
}

func (ss *socketSession) startReader(s *socketServer, datagrams bool) {
	ss.readOnce.Do(func() {
		go ss.readConnLoop(s, datagrams)
	})
}

func (ss *socketSession) readConnLoop(s *socketServer, datagrams bool) {
	buf := make([]byte, 64*1024)
	for {
		n, err := ss.conn.Read(buf)
		if n > 0 {
			action := socketproto.ActionData
			payload := append([]byte(nil), buf[:n]...)
			if datagrams {
				action = socketproto.ActionUDPDatagram
			}
			if s.send(socketproto.Frame{ID: ss.id, Action: action, Payload: payload}) != nil {
				s.closeSession(ss.id, false)
				return
			}
		}
		if err != nil {
			s.sendClose(ss.id, err)
			s.closeSession(ss.id, false)
			return
		}
	}
}

// readPacketLoop is the server-to-client half of UDP listener sockets. With
// socket_api.udp_inbound disabled it behaves like a stateful firewall: only
// remotes the client has recently sent to are allowed to send replies back.
func (ss *socketSession) readPacketLoop(s *socketServer) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := ss.packet.ReadFrom(buf)
		if err != nil {
			s.sendClose(ss.id, err)
			s.closeSession(ss.id, false)
			return
		}
		remote := addrPortFromNetAddr(addr)
		if !remote.IsValid() {
			continue
		}
		if fixed := ss.udpFixedDst(); fixed.IsValid() {
			if remote != fixed || !ss.touchKnownUDPPeer(remote, s.e.udpIdleTimeout()) {
				continue
			}
			if s.send(socketproto.Frame{ID: ss.id, Action: socketproto.ActionData, Payload: append([]byte(nil), buf[:n]...)}) != nil {
				s.closeSession(ss.id, false)
				return
			}
			continue
		}
		if !s.e.cfg.SocketAPI.UDPInbound {
			if !ss.touchKnownUDPPeer(remote, s.e.udpIdleTimeout()) {
				continue
			}
		}
		payload, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
			IPVersion:  socketproto.AddrVersion(remote.Addr()),
			RemoteIP:   remote.Addr(),
			RemotePort: remote.Port(),
			Payload:    append([]byte(nil), buf[:n]...),
		})
		if err != nil {
			continue
		}
		if s.send(socketproto.Frame{ID: ss.id, Action: socketproto.ActionUDPDatagram, Payload: payload}) != nil {
			s.closeSession(ss.id, false)
			return
		}
	}
}

func (e *Engine) nextSocketServerID() uint64 {
	id := atomic.AddUint64(&e.socketNext, 1)
	id &= socketproto.ClientIDBase - 1
	if id == 0 {
		id = atomic.AddUint64(&e.socketNext, 1) & (socketproto.ClientIDBase - 1)
	}
	return id
}

func (e *Engine) firstLocalAddr(version uint8) (netip.Addr, bool) {
	for _, ip := range e.localAddrs {
		if version == 4 && ip.Is4() || version == 6 && ip.Is6() {
			return ip, true
		}
	}
	if len(e.localAddrs) > 0 {
		return e.localAddrs[0], true
	}
	return netip.Addr{}, false
}

func (e *Engine) socketBindEnabled() bool {
	if e.cfg.SocketAPI.Bind {
		return true
	}
	return e.cfg.Proxy.Bind != nil && *e.cfg.Proxy.Bind
}

func (e *Engine) socketLowBindEnabled() bool {
	return e.cfg.Proxy.LowBind != nil && *e.cfg.Proxy.LowBind
}

func (ss *socketSession) udpFixedDst() netip.AddrPort {
	ss.udpMu.Lock()
	defer ss.udpMu.Unlock()
	return ss.fixedDst
}

func (ss *socketSession) setUDPFixedDst(dst netip.AddrPort) {
	ss.udpMu.Lock()
	ss.fixedDst = dst
	ss.udpMu.Unlock()
}

func (ss *socketSession) touchUDPPeer(remote netip.AddrPort, idle time.Duration) bool {
	if idle <= 0 {
		idle = 30 * time.Second
	}
	key := remote.String()
	ss.udpMu.Lock()
	defer ss.udpMu.Unlock()
	if ss.udpPeers == nil {
		ss.udpPeers = make(map[string]*udpPeerState)
	}
	if state := ss.udpPeers[key]; state != nil && state.timer != nil {
		state.expires = time.Now().Add(idle)
		state.timer.Reset(idle)
		return true
	}
	if maxSocketUDPPeers > 0 && len(ss.udpPeers) >= maxSocketUDPPeers {
		return false
	}
	state := &udpPeerState{expires: time.Now().Add(idle)}
	state.timer = time.AfterFunc(idle, func() {
		ss.udpMu.Lock()
		defer ss.udpMu.Unlock()
		if ss.udpPeers[key] == state {
			if remaining := time.Until(state.expires); remaining > 0 {
				state.timer.Reset(remaining)
				return
			}
			delete(ss.udpPeers, key)
		}
	})
	ss.udpPeers[key] = state
	return true
}

func (ss *socketSession) touchKnownUDPPeer(remote netip.AddrPort, idle time.Duration) bool {
	if idle <= 0 {
		idle = 30 * time.Second
	}
	key := remote.String()
	ss.udpMu.Lock()
	defer ss.udpMu.Unlock()
	state := ss.udpPeers[key]
	if state == nil || state.timer == nil {
		return false
	}
	state.expires = time.Now().Add(idle)
	state.timer.Reset(idle)
	return true
}
