// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// UDPTransport is a not-connection-oriented transport that sends and receives
// WireGuard packets as raw UDP datagrams.  It can operate in listen mode
// (fixed source port, accepts packets from any peer) or outbound-only mode
// (ephemeral source port per peer).
type UDPTransport struct {
	name     string
	dialer   *DirectDialer
	// listenAddrs is the set of local IP addresses to bind in listen mode.
	// Empty means all interfaces.
	listenAddrs []string
}

// NewUDPTransport creates a UDPTransport with the given name.
func NewUDPTransport(name string, listenAddrs []string, dialer *DirectDialer) *UDPTransport {
	if dialer == nil {
		dialer = NewDirectDialer(false, netip.Prefix{})
	}
	return &UDPTransport{name: name, dialer: dialer, listenAddrs: listenAddrs}
}

func (t *UDPTransport) Name() string                  { return t.name }
func (t *UDPTransport) IsConnectionOriented() bool    { return false }

// Dial creates an outbound-only UDP session to the given target.  A
// connected UDP socket is used so the OS assigns a stable ephemeral source
// port for this peer.
func (t *UDPTransport) Dial(ctx context.Context, target string) (Session, error) {
	conn, err := t.dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return nil, fmt.Errorf("udp transport %s: dial %s: %w", t.name, target, err)
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		// Wrap any net.Conn as a UDP session via byte streams.
		return &connSession{conn: conn, remote: target}, nil
	}
	return &udpSession{conn: udp, remote: target}, nil
}

// Listen opens UDP listeners on the configured addresses and the given port.
// Returns a UDPListener that yields inbound packets as sessions.
func (t *UDPTransport) Listen(_ context.Context, port int) (Listener, error) {
	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	var conns []*net.UDPConn
	chosen := port
	for _, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, fmt.Errorf("udp transport %s: invalid listen addr %q: %w", t.name, addr, err)
		}
		network := "udp4"
		if ip.Is6() {
			network = "udp6"
		}
		uc, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: chosen})
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, fmt.Errorf("udp transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			chosen = uc.LocalAddr().(*net.UDPAddr).Port
		}
		conns = append(conns, uc)
	}
	return &udpListener{conns: conns, name: t.name}, nil
}

// --- udpSession ------------------------------------------------------------

// udpSession wraps a connected *net.UDPConn.
type udpSession struct {
	conn   *net.UDPConn
	remote string
}

func (s *udpSession) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxUDPPayload)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *udpSession) WritePacket(pkt []byte) error {
	_, err := s.conn.Write(pkt)
	return err
}

func (s *udpSession) RemoteAddr() string { return s.remote }
func (s *udpSession) Close() error       { return s.conn.Close() }

// --- udpListener -----------------------------------------------------------

// udpListener listens on one or more UDP sockets and vends inbound packets as
// per-source sessions.
type udpListener struct {
	conns  []*net.UDPConn
	name   string
	// acceptCh funnels inbound packets from all listener goroutines.
	acceptCh chan inboundUDP
	once     chan struct{} // closed when started
}

type inboundUDP struct {
	data []byte
	from netip.AddrPort
	conn *net.UDPConn // which listener received it
}

func (l *udpListener) start() {
	l.acceptCh = make(chan inboundUDP, 256)
	l.once = make(chan struct{})
	close(l.once)
	for _, uc := range l.conns {
		go l.readLoop(uc)
	}
}

func (l *udpListener) readLoop(uc *net.UDPConn) {
	for {
		buf := make([]byte, maxUDPPayload)
		n, ap, err := uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		l.acceptCh <- inboundUDP{data: buf[:n], from: ap, conn: uc}
	}
}

func (l *udpListener) Accept(ctx context.Context) (Session, error) {
	if l.once == nil {
		l.start()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return &udpListenerSession{
			pkt:    pkt.data,
			from:   pkt.from,
			sender: pkt.conn,
		}, nil
	}
}

func (l *udpListener) Addr() net.Addr {
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0].LocalAddr()
}

func (l *udpListener) Close() error {
	var first error
	for _, uc := range l.conns {
		if err := uc.Close(); err != nil && first == nil {
			first = err
		}
	}
	if l.acceptCh != nil {
		close(l.acceptCh)
	}
	return first
}

// udpListenerSession represents one inbound UDP datagram.  Since UDP is
// connectionless, each datagram is its own "session".  Writes go back to
// the source address.
type udpListenerSession struct {
	pkt    []byte
	from   netip.AddrPort
	sender *net.UDPConn
	read   bool
}

func (s *udpListenerSession) ReadPacket() ([]byte, error) {
	if s.read {
		// Each listener session carries exactly one inbound datagram.
		return nil, net.ErrClosed
	}
	s.read = true
	return s.pkt, nil
}

func (s *udpListenerSession) WritePacket(pkt []byte) error {
	_, err := s.sender.WriteToUDPAddrPort(pkt, s.from)
	return err
}

func (s *udpListenerSession) RemoteAddr() string { return s.from.String() }
func (s *udpListenerSession) Close() error       { return nil }

// --- connSession (generic fallback) ----------------------------------------

// connSession wraps a generic net.Conn as a session.  Used when the dialler
// returns a non-UDPConn (e.g. when going through a proxy).
type connSession struct {
	conn   net.Conn
	remote string
}

func (s *connSession) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxUDPPayload)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *connSession) WritePacket(pkt []byte) error {
	_, err := s.conn.Write(pkt)
	return err
}

func (s *connSession) RemoteAddr() string { return s.remote }
func (s *connSession) Close() error       { return s.conn.Close() }

// maxUDPPayload is the maximum WireGuard packet size over UDP.
const maxUDPPayload = 65535
