// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// tcpIdleTimeout is the connection idle timeout for TCP/TLS transports.
	// Connections with no data for this long are closed unless the WireGuard
	// PersistentKeepalive is set, in which case the timeout is disabled.
	tcpIdleTimeout = 30 * time.Second

	// maxWireGuardPacket is the maximum WireGuard packet size (including
	// headers and padding).
	maxWireGuardPacket = 65535
)

// TCPTransport is a connection-oriented transport that carries WireGuard
// packets over a plain TCP stream.  Each packet is prefixed with a 2-byte
// big-endian length field.
type TCPTransport struct {
	name   string
	dialer ProxyDialer
	// listenAddrs restricts listen sockets to these IPs.  Empty = all.
	listenAddrs []string
	idleTimeout time.Duration
}

// NewTCPTransport creates a TCPTransport.
func NewTCPTransport(name string, dialer ProxyDialer, listenAddrs []string) *TCPTransport {
	return &TCPTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		idleTimeout: tcpIdleTimeout,
	}
}

func (t *TCPTransport) Name() string               { return t.name }
func (t *TCPTransport) IsConnectionOriented() bool { return true }

// Dial opens a client-mode TCP session to target.
func (t *TCPTransport) Dial(ctx context.Context, target string) (Session, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("tcp transport %s: dial %s: %w", t.name, target, err)
	}
	return newStreamSession(conn, target, t.idleTimeout), nil
}

// Listen binds a TCP listener.
func (t *TCPTransport) Listen(_ context.Context, port int) (Listener, error) {
	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	var listeners []net.Listener
	chosen := port
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("tcp transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			chosen = ln.Addr().(*net.TCPAddr).Port
		}
		listeners = append(listeners, ln)
	}
	return newStreamListener(listeners, t.name, t.idleTimeout, nil), nil
}

// --- streamSession ---------------------------------------------------------

// streamSession wraps a net.Conn with the 2-byte length-prefix framing used
// by TCP and TLS transports.
type streamSession struct {
	conn        net.Conn
	remote      string
	idleTimeout time.Duration
}

func newStreamSession(conn net.Conn, remote string, idle time.Duration) *streamSession {
	return &streamSession{conn: conn, remote: remote, idleTimeout: idle}
}

func (s *streamSession) RemoteAddr() string { return s.remote }
func (s *streamSession) Close() error       { return s.conn.Close() }

// SetIdleTimeout updates the idle timeout.  Pass 0 to disable.
func (s *streamSession) SetIdleTimeout(d time.Duration) {
	s.idleTimeout = d
}

func (s *streamSession) resetDeadline() {
	if s.idleTimeout > 0 {
		_ = s.conn.SetDeadline(time.Now().Add(s.idleTimeout))
	} else {
		_ = s.conn.SetDeadline(time.Time{})
	}
}

// ReadPacket reads one WireGuard packet from the stream.
func (s *streamSession) ReadPacket() ([]byte, error) {
	s.resetDeadline()
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:]))
	if size == 0 || size > maxWireGuardPacket {
		return nil, fmt.Errorf("stream session: invalid packet size %d", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WritePacket writes one WireGuard packet to the stream with a 2-byte length
// prefix.
func (s *streamSession) WritePacket(pkt []byte) error {
	if len(pkt) > maxWireGuardPacket {
		return fmt.Errorf("stream session: packet too large (%d)", len(pkt))
	}
	s.resetDeadline()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
	// Single write to avoid partial sends.
	buf := make([]byte, 2+len(pkt))
	copy(buf, hdr[:])
	copy(buf[2:], pkt)
	_, err := s.conn.Write(buf)
	return err
}

// --- streamListener --------------------------------------------------------

// streamListener accepts TCP (or TLS) connections.
type streamListener struct {
	listeners   []net.Listener
	name        string
	idleTimeout time.Duration
	// tlsConfig is applied when non-nil (TLS transport).
	wrapConn func(context.Context, net.Conn) (net.Conn, error)
}

func newStreamListener(listeners []net.Listener, name string, idle time.Duration, wrapConn func(context.Context, net.Conn) (net.Conn, error)) *streamListener {
	if wrapConn == nil {
		wrapConn = func(_ context.Context, c net.Conn) (net.Conn, error) { return c, nil }
	}
	sl := &streamListener{
		listeners:   listeners,
		name:        name,
		idleTimeout: idle,
		wrapConn:    wrapConn,
	}
	return sl
}

func (l *streamListener) Accept(ctx context.Context) (Session, error) {
	// If there is only one listener, accept directly.
	if len(l.listeners) == 1 {
		return l.acceptFrom(ctx, l.listeners[0])
	}
	// For multiple listeners, race them with a channel.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(l.listeners))
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, ln := range l.listeners {
		ln := ln
		go func() {
			c, err := ln.Accept()
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
		wrapped, err := l.wrapConn(ctx, r.conn)
		if err != nil {
			r.conn.Close()
			return nil, err
		}
		return newStreamSession(wrapped, r.conn.RemoteAddr().String(), l.idleTimeout), nil
	}
}

func (l *streamListener) acceptFrom(ctx context.Context, ln net.Listener) (Session, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		wrapped, err := l.wrapConn(ctx, r.conn)
		if err != nil {
			r.conn.Close()
			return nil, err
		}
		return newStreamSession(wrapped, r.conn.RemoteAddr().String(), l.idleTimeout), nil
	}
}

func (l *streamListener) Addr() net.Addr {
	if len(l.listeners) == 0 {
		return nil
	}
	return l.listeners[0].Addr()
}

func (l *streamListener) Close() error {
	var first error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
