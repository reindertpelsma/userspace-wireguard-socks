// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/net/proxy"
)

// SOCKS5Dialer implements ProxyDialer using a SOCKS5 proxy.
//
// TCP connections use the standard CONNECT command.
// UDP tunnelling uses SOCKS5 UDP ASSOCIATE.
type SOCKS5Dialer struct {
	Server   string // host:port
	Username string
	Password string
}

// NewSOCKS5Dialer creates a SOCKS5Dialer.
func NewSOCKS5Dialer(server, username, password string) (*SOCKS5Dialer, error) {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nil, fmt.Errorf("socks5 dialer: invalid server address %q: %w", server, err)
	}
	return &SOCKS5Dialer{Server: server, Username: username, Password: password}, nil
}

// DialContext connects to addr through the SOCKS5 proxy.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if d.Username != "" {
		auth = &proxy.Auth{User: d.Username, Password: d.Password}
	}
	dialer, err := proxy.SOCKS5("tcp", d.Server, auth, &contextDialer{})
	if err != nil {
		return nil, err
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := dialer.Dial(network, addr)
		ch <- result{c, e}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// DialPacket opens a SOCKS5 UDP ASSOCIATE tunnel.  It returns a PacketConn
// that wraps the SOCKS5 UDP relay, along with the relay address reported by
// the server (in host:port form).
func (d *SOCKS5Dialer) DialPacket(ctx context.Context, remoteHint string) (net.PacketConn, string, error) {
	// Establish TCP control connection for UDP ASSOCIATE.
	ctrlConn, err := d.DialContext(ctx, "tcp", d.Server)
	if err != nil {
		return nil, "", fmt.Errorf("socks5 udp associate: control connect: %w", err)
	}

	relayAddr, err := socks5UDPAssociate(ctrlConn, remoteHint)
	if err != nil {
		ctrlConn.Close()
		return nil, "", fmt.Errorf("socks5 udp associate: %w", err)
	}

	// Open local UDP socket pointed at the relay address.
	udpConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		ctrlConn.Close()
		return nil, "", fmt.Errorf("socks5 udp associate: dial relay: %w", err)
	}

	pc := &socks5UDPConn{
		UDPConn:  udpConn.(*net.UDPConn),
		ctrlConn: ctrlConn,
	}
	return pc, relayAddr, nil
}

// SupportsHostname returns true; SOCKS5 can forward hostname targets.
func (d *SOCKS5Dialer) SupportsHostname() bool { return true }

// socks5UDPAssociate sends a UDP ASSOCIATE request over the control
// connection and returns the relay address (host:port) the server provides.
func socks5UDPAssociate(ctrl net.Conn, hint string) (string, error) {
	// RFC 1928 §4: send VER, NMETHODS, METHODS (no-auth or user/pass)
	// We reuse the already-authenticated control connection; we only need
	// to send the UDP ASSOCIATE command.

	// Build UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=1, ADDR=0.0.0.0, PORT=0
	req := []byte{
		5, 3, 0, // VER CMD RSV
		1,            // ATYP: IPv4
		0, 0, 0, 0,   // DST.ADDR 0.0.0.0 (hint from caller ignored for now)
		0, 0,         // DST.PORT 0
	}
	_ = hint // TODO: parse hint and put IP/port in request for strict servers
	if _, err := ctrl.Write(req); err != nil {
		return "", err
	}
	// Read reply: VER REP RSV ATYP ...
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, hdr); err != nil {
		return "", err
	}
	if hdr[1] != 0 {
		return "", fmt.Errorf("socks5 UDP ASSOCIATE rejected: code %d", hdr[1])
	}
	var host string
	var port uint16
	switch hdr[3] {
	case 1: // IPv4
		b := make([]byte, 4+2)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			return "", err
		}
		host = net.IP(b[:4]).String()
		port = binary.BigEndian.Uint16(b[4:])
	case 4: // IPv6
		b := make([]byte, 16+2)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			return "", err
		}
		host = net.IP(b[:16]).String()
		port = binary.BigEndian.Uint16(b[16:])
	default:
		return "", fmt.Errorf("socks5 UDP ASSOCIATE: unsupported ATYP %d", hdr[3])
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// socks5UDPConn wraps a UDP connection with SOCKS5 UDP framing.
// Each packet is prefixed with a 10-byte SOCKS5 UDP header on send and the
// header is stripped on receive.
type socks5UDPConn struct {
	*net.UDPConn
	ctrlConn net.Conn
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, len(b)+262)
	n, addr, err := c.UDPConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < 10 {
		return 0, addr, fmt.Errorf("socks5 udp: short header")
	}
	// Strip RSV(2) + FRAG(1) + ATYP(1) + ADDR(4 or 16+1) + PORT(2)
	headerLen, err := socks5UDPHeaderLen(buf[:n])
	if err != nil {
		return 0, addr, err
	}
	payload := buf[headerLen:n]
	nn := copy(b, payload)
	return nn, addr, nil
}

func (c *socks5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, err
		}
	}
	hdr := buildSocks5UDPHeader(udpAddr)
	pkt := append(hdr, b...) //nolint:gocritic
	_, err := c.UDPConn.Write(pkt)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	err1 := c.UDPConn.Close()
	err2 := c.ctrlConn.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// socks5UDPHeaderLen returns the total header length for a SOCKS5 UDP datagram.
func socks5UDPHeaderLen(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("socks5 udp: too short")
	}
	// b[0..1] = RSV, b[2] = FRAG, b[3] = ATYP
	switch b[3] {
	case 1: // IPv4
		return 4 + 4 + 2, nil
	case 4: // IPv6
		return 4 + 16 + 2, nil
	case 3: // domain
		if len(b) < 5 {
			return 0, fmt.Errorf("socks5 udp: too short for domain")
		}
		return 4 + 1 + int(b[4]) + 2, nil
	}
	return 0, fmt.Errorf("socks5 udp: unknown ATYP %d", b[3])
}

func buildSocks5UDPHeader(addr *net.UDPAddr) []byte {
	ip := addr.IP.To4()
	if ip != nil {
		h := make([]byte, 10)
		h[3] = 1
		copy(h[4:8], ip)
		binary.BigEndian.PutUint16(h[8:], uint16(addr.Port))
		return h
	}
	ip = addr.IP.To16()
	h := make([]byte, 4+16+2)
	h[3] = 4
	copy(h[4:20], ip)
	binary.BigEndian.PutUint16(h[20:], uint16(addr.Port))
	return h
}

// contextDialer adapts net.Dialer to golang.org/x/net/proxy.Dialer.
type contextDialer struct{}

func (contextDialer) Dial(network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.Dial(network, addr)
}

// AddrPort extracts netip.AddrPort from a SOCKS5 UDP reply body.
func parseSOCKS5AddrPort(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 2 {
		return netip.AddrPort{}, 0, fmt.Errorf("too short")
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return netip.AddrPort{}, 0, fmt.Errorf("IPv4 short")
		}
		addr := netip.AddrFrom4([4]byte{b[1], b[2], b[3], b[4]})
		port := binary.BigEndian.Uint16(b[5:7])
		return netip.AddrPortFrom(addr, port), 7, nil
	case 4:
		if len(b) < 19 {
			return netip.AddrPort{}, 0, fmt.Errorf("IPv6 short")
		}
		addr := netip.AddrFrom16([16]byte(b[1:17]))
		port := binary.BigEndian.Uint16(b[17:19])
		return netip.AddrPortFrom(addr, port), 19, nil
	}
	return netip.AddrPort{}, 0, fmt.Errorf("unsupported ATYP %d", b[0])
}
