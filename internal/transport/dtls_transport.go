// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"fmt"
	"net"

	piondtls "github.com/pion/dtls/v3"
)

// DTLSTransport is a connection-oriented transport that carries WireGuard
// packets over DTLS.  Unlike TCP/TLS there is no length prefix because DTLS
// is record-oriented (one WireGuard packet = one DTLS record).
//
// Primary use case: making WireGuard traffic resemble WebRTC DTLS flows to
// bypass deep packet inspection firewalls, while retaining lower latency than
// TCP-based transports.
type DTLSTransport struct {
	name        string
	dialer      ProxyDialer
	listenAddrs []string
	certMgr     *CertManager
	tlsCfg      TLSConfig
}

// NewDTLSTransport creates a DTLSTransport.
func NewDTLSTransport(name string, dialer ProxyDialer, listenAddrs []string, certMgr *CertManager, tlsCfg TLSConfig) *DTLSTransport {
	return &DTLSTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
	}
}

func (t *DTLSTransport) Name() string               { return t.name }
func (t *DTLSTransport) IsConnectionOriented() bool { return true }

// Dial opens a client-mode DTLS session to target.
func (t *DTLSTransport) Dial(ctx context.Context, target string) (Session, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("dtls transport %s: invalid target %q: %w", t.name, target, err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return nil, fmt.Errorf("dtls transport %s: resolve %s: %w", t.name, target, err)
	}

	cfg, err := buildDTLSClientConfig(t.tlsCfg, t.certMgr, host, false)
	if err != nil {
		return nil, fmt.Errorf("dtls transport %s: client config: %w", t.name, err)
	}

	// pion/dtls v3 has no context-aware Dial; apply deadline from ctx if set.
	pConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("dtls transport %s: listen udp: %w", t.name, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := pConn.SetDeadline(dl); err != nil {
			pConn.Close()
			return nil, fmt.Errorf("dtls transport %s: set deadline: %w", t.name, err)
		}
	}
	conn, err := piondtls.Client(pConn, udpAddr, cfg)
	if err != nil {
		pConn.Close()
		return nil, fmt.Errorf("dtls transport %s: dial %s: %w", t.name, target, err)
	}
	// Eagerly perform the DTLS handshake so the first ClientHello is sent
	// immediately.  The server's Accept() blocks until it sees that packet;
	// without this the two sides deadlock waiting for each other.
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("dtls transport %s: handshake %s: %w", t.name, target, err)
	}
	return &dtlsSession{conn: conn, remote: target}, nil
}

// Listen starts a DTLS server listener.
func (t *DTLSTransport) Listen(_ context.Context, port int) (Listener, error) {
	serverCfg, err := buildDTLSServerConfig(t.tlsCfg, t.certMgr)
	if err != nil {
		return nil, fmt.Errorf("dtls transport %s: server config: %w", t.name, err)
	}

	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	var listeners []dtlsListenerEntry
	chosen := port
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, l := range listeners {
				l.listener.Close()
			}
			return nil, fmt.Errorf("dtls transport %s: resolve %s:%d: %w", t.name, addr, port, err)
		}
		ln, err := piondtls.Listen("udp4", udpAddr, serverCfg)
		if err != nil {
			for _, l := range listeners {
				l.listener.Close()
			}
			return nil, fmt.Errorf("dtls transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			chosen = ln.Addr().(*net.UDPAddr).Port
		}
		listeners = append(listeners, dtlsListenerEntry{listener: ln})
	}
	return &dtlsMultiListener{listeners: listeners, name: t.name}, nil
}

// --- dtlsSession -----------------------------------------------------------

type dtlsSession struct {
	conn   *piondtls.Conn
	remote string
}

func (s *dtlsSession) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxWireGuardPacket)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *dtlsSession) WritePacket(pkt []byte) error {
	_, err := s.conn.Write(pkt)
	return err
}

func (s *dtlsSession) RemoteAddr() string { return s.remote }
func (s *dtlsSession) Close() error       { return s.conn.Close() }

// --- dtlsMultiListener -----------------------------------------------------

type dtlsListenerEntry struct {
	listener net.Listener
}

type dtlsMultiListener struct {
	listeners []dtlsListenerEntry
	name      string
}

func (l *dtlsMultiListener) Accept(ctx context.Context) (Session, error) {
	if len(l.listeners) == 1 {
		return l.acceptFrom(ctx, l.listeners[0].listener)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(l.listeners))
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, entry := range l.listeners {
		ln := entry.listener
		go func() {
			c, err := ln.Accept()
			if err == nil {
				if dtlsConn, ok := c.(*piondtls.Conn); ok {
					if herr := dtlsConn.HandshakeContext(ctx2); herr != nil {
						c.Close()
						c, err = nil, herr
					}
				}
			}
			select {
			case ch <- result{c, err}:
			case <-ctx2.Done():
				if c != nil {
					c.Close()
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return &dtlsConnSession{conn: r.conn, remote: r.conn.RemoteAddr().String()}, nil
	}
}

func (l *dtlsMultiListener) acceptFrom(ctx context.Context, ln net.Listener) (Session, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			// Eagerly complete the server-side DTLS handshake inside this
			// goroutine.  The client's Dial triggers HandshakeContext which
			// sends the ClientHello; the server must respond before returning
			// to the caller, otherwise both sides deadlock waiting for each
			// other.
			if dtlsConn, ok := c.(*piondtls.Conn); ok {
				if herr := dtlsConn.HandshakeContext(ctx); herr != nil {
					c.Close()
					ch <- result{nil, herr}
					return
				}
			}
		}
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return &dtlsConnSession{conn: r.conn, remote: r.conn.RemoteAddr().String()}, nil
	}
}

func (l *dtlsMultiListener) Addr() net.Addr {
	if len(l.listeners) == 0 {
		return nil
	}
	return l.listeners[0].listener.Addr()
}

func (l *dtlsMultiListener) Close() error {
	var first error
	for _, entry := range l.listeners {
		if err := entry.listener.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// dtlsConnSession wraps a net.Conn accepted from a DTLS listener.
type dtlsConnSession struct {
	conn   net.Conn
	remote string
}

func (s *dtlsConnSession) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxWireGuardPacket)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *dtlsConnSession) WritePacket(pkt []byte) error {
	_, err := s.conn.Write(pkt)
	return err
}

func (s *dtlsConnSession) RemoteAddr() string { return s.remote }
func (s *dtlsConnSession) Close() error       { return s.conn.Close() }
