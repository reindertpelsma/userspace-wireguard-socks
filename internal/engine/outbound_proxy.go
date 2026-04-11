// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.org/x/net/proxy"
)

const (
	outboundRoleSocks   = "socks"
	outboundRoleInbound = "inbound"
)

func (e *Engine) dialOutboundProxy(ctx context.Context, network string, dst netip.AddrPort, role string) (net.Conn, bool, error) {
	proxies := e.matchOutboundProxies(dst.Addr(), role)
	if len(proxies) == 0 {
		return nil, false, nil
	}
	var last error
	for _, p := range proxies {
		c, err := dialOutboundProxyRule(ctx, network, dst, p)
		if err == nil {
			return c, true, nil
		}
		last = err
	}
	if last == nil {
		last = errProxyFallbackDisabled
	}
	return nil, true, last
}

func (e *Engine) matchOutboundProxies(dst netip.Addr, role string) []config.OutboundProxy {
	e.cfgMu.RLock()
	all := append([]config.OutboundProxy(nil), e.cfg.Proxy.OutboundProxies...)
	e.cfgMu.RUnlock()
	type match struct {
		proxy config.OutboundProxy
		bits  int
		order int
	}
	var matches []match
	for i, p := range all {
		if !outboundProxyHasRole(p, role) {
			continue
		}
		best := -1
		if len(p.Subnets) == 0 {
			best = 0
		}
		for _, raw := range p.Subnets {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			if prefix.Contains(dst) && prefix.Bits() > best {
				best = prefix.Bits()
			}
		}
		if best >= 0 {
			matches = append(matches, match{proxy: p, bits: best, order: i})
		}
	}
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0; j-- {
			if matches[j].bits < matches[j-1].bits || matches[j].bits == matches[j-1].bits && matches[j].order > matches[j-1].order {
				break
			}
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
	out := make([]config.OutboundProxy, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.proxy)
	}
	return out
}

func outboundProxyHasRole(p config.OutboundProxy, role string) bool {
	for _, raw := range p.Roles {
		switch strings.ToLower(raw) {
		case "both":
			return true
		case "proxy", "client":
			if role == outboundRoleSocks {
				return true
			}
		case "wireguard":
			if role == outboundRoleInbound {
				return true
			}
		default:
			if raw == role {
				return true
			}
		}
	}
	return false
}

func dialOutboundProxyRule(ctx context.Context, network string, dst netip.AddrPort, p config.OutboundProxy) (net.Conn, error) {
	switch p.Type {
	case "socks5":
		if strings.HasPrefix(network, "udp") {
			return dialSOCKS5UDP(ctx, p, dst)
		}
		auth := (*proxy.Auth)(nil)
		if p.Username != "" || p.Password != "" {
			auth = &proxy.Auth{User: p.Username, Password: p.Password}
		}
		d, err := proxy.SOCKS5("tcp", p.Address, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, dst.String())
		}
		return d.Dial(network, dst.String())
	case "http":
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("HTTP proxy %s cannot proxy %s", p.Address, network)
		}
		return dialHTTPConnectProxy(ctx, p, dst)
	default:
		return nil, fmt.Errorf("unsupported outbound proxy type %q", p.Type)
	}
}

func dialHTTPConnectProxy(ctx context.Context, p config.OutboundProxy, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", dst, dst)
	if p.Username != "" || p.Password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = c.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT returned %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: br}, nil
}

func dialSOCKS5UDP(ctx context.Context, p config.OutboundProxy, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	control, err := d.DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(deadline)
	}
	if err := socks5ClientHandshake(control, p); err != nil {
		_ = control.Close()
		return nil, err
	}
	if _, err := control.Write(append([]byte{socksVersion, socksCmdUDPAssociate, 0x00}, socks5AddrPortBytes(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))...)); err != nil {
		_ = control.Close()
		return nil, err
	}
	rep, relay, err := readSOCKS5ClientReply(control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	if rep != socksRepSuccess {
		_ = control.Close()
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE failed with reply %d", rep)
	}
	if relay.Addr().IsUnspecified() {
		hostAddr, err := proxyHostAddr(p.Address)
		if err != nil {
			_ = control.Close()
			return nil, err
		}
		relay = netip.AddrPortFrom(hostAddr, relay.Port())
	}
	udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	return &socks5UDPProxyConn{control: control, UDPConn: udp, target: dst}, nil
}

func proxyHostAddr(addr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.Addr{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.Addr{}, err
	}
	ap := addrPortFromNetAddr(ua)
	if !ap.IsValid() {
		return netip.Addr{}, fmt.Errorf("proxy address %q did not resolve to an IP", addr)
	}
	return ap.Addr(), nil
}

func socks5ClientHandshake(c net.Conn, p config.OutboundProxy) error {
	methods := []byte{0x00}
	if p.Username != "" || p.Password != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := c.Write(append([]byte{socksVersion, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != socksVersion {
		return errors.New("invalid SOCKS5 method response")
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		if len(p.Username) > 255 || len(p.Password) > 255 {
			return errors.New("SOCKS5 username/password too long")
		}
		auth := []byte{0x01, byte(len(p.Username))}
		auth = append(auth, p.Username...)
		auth = append(auth, byte(len(p.Password)))
		auth = append(auth, p.Password...)
		if _, err := c.Write(auth); err != nil {
			return err
		}
		var status [2]byte
		if _, err := io.ReadFull(c, status[:]); err != nil {
			return err
		}
		if status != [2]byte{0x01, 0x00} {
			return errors.New("SOCKS5 username/password rejected")
		}
		return nil
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported method %d", resp[1])
	}
}

func readSOCKS5ClientReply(r io.Reader) (byte, netip.AddrPort, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if hdr[0] != socksVersion || hdr[2] != 0x00 {
		return 0, netip.AddrPort{}, errors.New("invalid SOCKS5 reply")
	}
	addr, err := readSOCKSAddr(r, hdr[3])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ap, _ := addr.addrPort()
	return hdr[1], ap, nil
}

func socks5AddrPortBytes(dst netip.AddrPort) []byte {
	if dst.Addr().Is6() {
		ip := dst.Addr().As16()
		out := append([]byte{socksAtypIPv6}, ip[:]...)
		return appendPort(out, dst.Port())
	}
	ip := dst.Addr().As4()
	out := append([]byte{socksAtypIPv4}, ip[:]...)
	return appendPort(out, dst.Port())
}

func appendPort(out []byte, port uint16) []byte {
	return append(out, byte(port>>8), byte(port))
}

type socks5UDPProxyConn struct {
	*net.UDPConn
	control net.Conn
	target  netip.AddrPort
}

func (c *socks5UDPProxyConn) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+300)
	for {
		n, err := c.UDPConn.Read(buf)
		if err != nil {
			return 0, err
		}
		dst, payload, ok := parseSOCKSUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		ap, ok := dst.addrPort()
		if !ok || ap != c.target {
			continue
		}
		return copy(p, payload), nil
	}
}

func (c *socks5UDPProxyConn) Write(p []byte) (int, error) {
	packet, err := packSOCKSUDPDatagram(c.target, p)
	if err != nil {
		return 0, err
	}
	if _, err := c.UDPConn.Write(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPProxyConn) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.target)
}

func (c *socks5UDPProxyConn) Close() error {
	udpErr := c.UDPConn.Close()
	controlErr := c.control.Close()
	if udpErr != nil {
		return udpErr
	}
	return controlErr
}

func (c *socks5UDPProxyConn) SetDeadline(t time.Time) error {
	_ = c.control.SetDeadline(t)
	return c.UDPConn.SetDeadline(t)
}

func (c *socks5UDPProxyConn) SetReadDeadline(t time.Time) error {
	_ = c.control.SetReadDeadline(t)
	return c.UDPConn.SetReadDeadline(t)
}

func (c *socks5UDPProxyConn) SetWriteDeadline(t time.Time) error {
	_ = c.control.SetWriteDeadline(t)
	return c.UDPConn.SetWriteDeadline(t)
}
