// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	socksVersion = 0x05

	socksCmdConnect      = 0x01
	socksCmdBind         = 0x02
	socksCmdUDPAssociate = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSuccess              = 0x00
	socksRepGeneralFailure       = 0x01
	socksRepConnectionNotAllowed = 0x02
	socksRepNetworkUnreachable   = 0x03
	socksRepHostUnreachable      = 0x04
	socksRepConnectionRefused    = 0x05
	socksRepTTLExpired           = 0x06
	socksRepCommandNotSupported  = 0x07
	socksRepAddressNotSupported  = 0x08
)

var (
	errProxyACL              = errors.New("blocked by outbound ACL")
	errProxyFallbackDisabled = errors.New("fallback_direct is false")
	errVirtualSubnetUnrouted = errors.New("destination is inside a WireGuard Address subnet but no peer AllowedIPs route it")
	errAddressFiltered       = errors.New("destination address is blocked by tunnel address filters")
)

type socksAddr struct {
	atyp byte
	host string
	addr netip.Addr
	port uint16
}

func (a socksAddr) string() string {
	if a.host != "" {
		return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
	}
	if a.addr.IsValid() {
		return netip.AddrPortFrom(a.addr, a.port).String()
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(int(a.port)))
}

func (a socksAddr) addrPort() (netip.AddrPort, bool) {
	if !a.addr.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.addr, a.port), true
}

func (e *Engine) serveSOCKSConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := e.socksHandshake(c); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	cmd, dst, err := readSOCKSRequest(c)
	if err != nil {
		_ = writeSOCKSReply(c, socksRepGeneralFailure, netip.AddrPort{})
		return
	}
	src := addrPortFromNetAddr(c.RemoteAddr())
	switch cmd {
	case socksCmdConnect:
		e.serveSOCKSConnect(c, src, dst)
	case socksCmdUDPAssociate:
		e.serveSOCKSUDPAssociate(c, src)
	case socksCmdBind:
		e.serveSOCKSBind(c, src, dst)
	default:
		_ = writeSOCKSReply(c, socksRepCommandNotSupported, netip.AddrPort{})
	}
}

func (e *Engine) socksHandshake(rw io.ReadWriter) error {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != socksVersion || hdr[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	wantMethod := byte(0x00)
	if e.proxyAuthRequired() {
		wantMethod = 0x02
	}
	for _, method := range methods {
		if method == wantMethod {
			if _, err := rw.Write([]byte{socksVersion, wantMethod}); err != nil {
				return err
			}
			if wantMethod == 0x02 {
				return e.socksUsernamePasswordAuth(rw)
			}
			return nil
		}
	}
	_, _ = rw.Write([]byte{socksVersion, 0xff})
	return errors.New("no supported SOCKS5 auth method")
}

func (e *Engine) socksUsernamePasswordAuth(rw io.ReadWriter) error {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		_, _ = rw.Write([]byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 username/password auth version")
	}
	username := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(rw, username); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(rw, plen[:]); err != nil {
		return err
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(rw, password); err != nil {
		return err
	}
	if !e.proxyCredentialsOK(string(username), string(password)) {
		_, _ = rw.Write([]byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 username/password")
	}
	_, err := rw.Write([]byte{0x01, 0x00})
	return err
}

func (e *Engine) proxyAuthRequired() bool {
	return e.cfg.Proxy.Username != "" || e.cfg.Proxy.Password != ""
}

func (e *Engine) proxyCredentialsOK(username, password string) bool {
	if !e.proxyAuthRequired() {
		return true
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(e.cfg.Proxy.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(e.cfg.Proxy.Password)) == 1
	return userOK && passOK
}

func (e *Engine) proxyHTTPAuthOK(r *http.Request) bool {
	if !e.proxyAuthRequired() {
		return true
	}
	const prefix = "Basic "
	value := r.Header.Get("Proxy-Authorization")
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len(prefix):]))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	return ok && e.proxyCredentialsOK(username, password)
}

func (e *Engine) serveSOCKSConnect(client net.Conn, src netip.AddrPort, dst socksAddr) {
	if ap, ok := dst.addrPort(); ok && !e.outboundAllowed(src, ap) {
		_ = writeSOCKSReply(client, socksRepConnectionNotAllowed, netip.AddrPort{})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target, err := e.proxyDialWithSource(ctx, "tcp", dst.string(), src, false)
	if err != nil {
		_ = writeSOCKSReply(client, socksReplyFromError(err), netip.AddrPort{})
		return
	}
	defer target.Close()
	if err := writeSOCKSReply(client, socksRepSuccess, addrPortFromNetAddr(target.LocalAddr())); err != nil {
		return
	}
	proxyBothIdle(client, target, e.tcpIdleTimeout())
}

func (e *Engine) serveSOCKSUDPAssociate(control net.Conn, src netip.AddrPort) {
	if !*e.cfg.Proxy.UDPAssociate {
		_ = writeSOCKSReply(control, socksRepCommandNotSupported, netip.AddrPort{})
		return
	}
	host := socksUDPBindHost(control)
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		_ = writeSOCKSReply(control, socksRepGeneralFailure, netip.AddrPort{})
		return
	}
	defer pc.Close()
	bind := addrPortFromNetAddr(pc.LocalAddr())
	if err := writeSOCKSReply(control, socksRepSuccess, bind); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(done)
		_ = pc.Close()
	}()
	e.serveSOCKSUDPRelay(pc, src, done)
}

func socksUDPBindHost(c net.Conn) string {
	ap := addrPortFromNetAddr(c.LocalAddr())
	if ap.IsValid() && !ap.Addr().IsUnspecified() {
		return ap.Addr().String()
	}
	if ap.IsValid() && ap.Addr().Is6() {
		return "::1"
	}
	return "127.0.0.1"
}

type socksUDPSession struct {
	conn    net.Conn
	target  netip.AddrPort
	timer   *time.Timer
	expires time.Time
}

func (e *Engine) serveSOCKSUDPRelay(pc net.PacketConn, src netip.AddrPort, done <-chan struct{}) {
	type clientState struct {
		addr net.Addr
		host netip.Addr
	}
	var (
		client  clientState
		hasPeer bool
		mu      sync.Mutex
	)
	sessions := make(map[string]*socksUDPSession)
	timeout := e.udpIdleTimeout()
	expire := func(key string, sess *socksUDPSession) {
		mu.Lock()
		if sessions[key] != sess {
			mu.Unlock()
			return
		}
		if remaining := time.Until(sess.expires); remaining > 0 {
			sess.timer.Reset(remaining)
			mu.Unlock()
			return
		}
		delete(sessions, key)
		mu.Unlock()
		_ = sess.conn.Close()
	}
	touch := func(sess *socksUDPSession) {
		if timeout > 0 && sess.timer != nil {
			sess.expires = time.Now().Add(timeout)
			sess.timer.Reset(timeout)
		}
	}
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		peer := addrPortFromNetAddr(addr)
		if !peer.IsValid() {
			continue
		}
		if !hasPeer {
			client = clientState{addr: addr, host: peer.Addr()}
			hasPeer = true
		}
		if peer.Addr() != client.host {
			continue
		}
		dst, payload, ok := parseSOCKSUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, target, key, err := e.socksUDPSession(ctx, sessions, &mu, src, dst, timeout, expire, touch, pc, client.addr)
		cancel()
		if err != nil {
			continue
		}
		_, _ = c.Write(payload)
		mu.Lock()
		if sess := sessions[key]; sess != nil && sess.target == target {
			touch(sess)
		}
		mu.Unlock()
	}
}

func (e *Engine) socksUDPSession(ctx context.Context, sessions map[string]*socksUDPSession, mu *sync.Mutex, src netip.AddrPort, dst socksAddr, timeout time.Duration, expire func(string, *socksUDPSession), touch func(*socksUDPSession), pc net.PacketConn, client net.Addr) (net.Conn, netip.AddrPort, string, error) {
	candidates, err := e.resolveAddrPortCandidates(ctx, "udp", dst.string(), true)
	if err != nil {
		return nil, netip.AddrPort{}, "", err
	}
	for _, target := range candidates {
		if !e.outboundAllowed(src, target) {
			continue
		}
		key := target.String()
		mu.Lock()
		sess := sessions[key]
		if sess != nil {
			touch(sess)
			mu.Unlock()
			return sess.conn, target, key, nil
		}
		mu.Unlock()
		conn, err := e.dialProxyCandidate(ctx, "udp", target, src)
		if err != nil {
			continue
		}
		sess = &socksUDPSession{conn: conn, target: target}
		if timeout > 0 {
			sess.expires = time.Now().Add(timeout)
			sess.timer = time.AfterFunc(timeout, func() { expire(key, sess) })
		}
		mu.Lock()
		sessions[key] = sess
		mu.Unlock()
		go e.readSOCKSUDPReplies(pc, client, key, sess, sessions, mu)
		return conn, target, key, nil
	}
	return nil, netip.AddrPort{}, "", errProxyFallbackDisabled
}

func (e *Engine) readSOCKSUDPReplies(pc net.PacketConn, client net.Addr, key string, sess *socksUDPSession, sessions map[string]*socksUDPSession, mu *sync.Mutex) {
	defer sess.conn.Close()
	defer func() {
		if sess.timer != nil {
			sess.timer.Stop()
		}
		mu.Lock()
		if sessions[key] == sess {
			delete(sessions, key)
		}
		mu.Unlock()
	}()
	buf := make([]byte, 64*1024)
	for {
		n, err := sess.conn.Read(buf)
		if err != nil {
			return
		}
		active := false
		mu.Lock()
		if sessions[key] == sess && sess.timer != nil {
			sess.expires = time.Now().Add(e.udpIdleTimeout())
			sess.timer.Reset(e.udpIdleTimeout())
			active = true
		}
		mu.Unlock()
		if !active {
			return
		}
		packet, err := packSOCKSUDPDatagram(sess.target, buf[:n])
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(packet, client)
	}
}

func (e *Engine) serveSOCKSBind(control net.Conn, src netip.AddrPort, requested socksAddr) {
	if !*e.cfg.Proxy.Bind {
		_ = writeSOCKSReply(control, socksRepCommandNotSupported, netip.AddrPort{})
		return
	}
	bindAddr, err := e.socksBindAddr(requested)
	if err != nil {
		_ = writeSOCKSReply(control, socksRepAddressNotSupported, netip.AddrPort{})
		return
	}
	ln, err := e.net.ListenTCPAddrPort(bindAddr)
	if err != nil {
		_ = writeSOCKSReply(control, socksRepGeneralFailure, netip.AddrPort{})
		return
	}
	defer ln.Close()
	if err := writeSOCKSReply(control, socksRepSuccess, addrPortFromNetAddr(ln.Addr())); err != nil {
		return
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()
	timeout := e.tcpIdleTimeout()
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	var incoming net.Conn
	select {
	case res := <-accepted:
		if res.err != nil {
			_ = writeSOCKSReply(control, socksRepGeneralFailure, netip.AddrPort{})
			return
		}
		incoming = res.conn
	case <-time.After(timeout):
		_ = writeSOCKSReply(control, socksRepTTLExpired, netip.AddrPort{})
		return
	}
	defer incoming.Close()
	remote := addrPortFromNetAddr(incoming.RemoteAddr())
	local := addrPortFromNetAddr(incoming.LocalAddr())
	if !socksBindExpectedOK(requested, remote) {
		_ = writeSOCKSReply(control, socksRepConnectionNotAllowed, netip.AddrPort{})
		return
	}
	if !e.inboundAllowed(remote, local) || !e.outboundAllowed(src, local) {
		_ = writeSOCKSReply(control, socksRepConnectionNotAllowed, netip.AddrPort{})
		return
	}
	if err := writeSOCKSReply(control, socksRepSuccess, remote); err != nil {
		return
	}
	proxyBothIdle(control, incoming, e.tcpIdleTimeout())
}

func (e *Engine) socksBindAddr(requested socksAddr) (netip.AddrPort, error) {
	if requested.host != "" {
		return netip.AddrPort{}, errors.New("SOCKS BIND requires an IP address")
	}
	want6 := requested.addr.Is6()
	for _, addr := range e.localAddrs {
		if want6 == addr.Is6() {
			return netip.AddrPortFrom(addr, 0), nil
		}
	}
	if len(e.localAddrs) > 0 {
		return netip.AddrPortFrom(e.localAddrs[0], 0), nil
	}
	return netip.AddrPort{}, errors.New("no local tunnel addresses")
}

func socksBindExpectedOK(requested socksAddr, remote netip.AddrPort) bool {
	if !remote.IsValid() {
		return false
	}
	if requested.host != "" {
		return false
	}
	if requested.addr.IsValid() && !requested.addr.IsUnspecified() && requested.addr != remote.Addr() {
		return false
	}
	if requested.port != 0 && requested.port != remote.Port() {
		return false
	}
	return true
}

func (e *Engine) proxyDialWithSource(ctx context.Context, network, addr string, src netip.AddrPort, udpFromSOCKS bool) (net.Conn, error) {
	candidates, err := e.resolveAddrPortCandidates(ctx, network, addr, udpFromSOCKS)
	if err != nil {
		return nil, err
	}
	var last error
	for _, dst := range candidates {
		if !e.outboundAllowed(src, dst) {
			last = errProxyACL
			continue
		}
		c, err := e.dialProxyCandidate(ctx, network, dst, src)
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errProxyFallbackDisabled
	}
	return nil, last
}

func (e *Engine) dialProxyCandidate(ctx context.Context, network string, dst, src netip.AddrPort) (net.Conn, error) {
	if f, ok := e.matchReverseForward(network, dst); ok {
		return e.dialReverseForwardTarget(ctx, network, f, src, dst)
	}
	if rewritten, ok, err := e.proxyHostForwardTarget(dst); err != nil {
		return nil, err
	} else if ok {
		var d net.Dialer
		return d.DialContext(ctx, network, rewritten.String())
	}
	if e.tunnelAddrBlocked(dst.Addr()) {
		return nil, errAddressFiltered
	}
	if e.allowedContains(dst.Addr()) {
		return e.net.DialContext(ctx, network, dst.String())
	}
	if e.localPrefixContainsUnrouted(dst.Addr()) {
		return nil, errVirtualSubnetUnrouted
	}
	if c, matched, err := e.dialOutboundProxy(ctx, network, dst, outboundRoleSocks); matched || err != nil {
		return c, err
	}
	if !*e.cfg.Proxy.FallbackDirect {
		return nil, fmt.Errorf("%s: %w", dst.Addr(), errProxyFallbackDisabled)
	}
	if e.fallbackDialer != nil && strings.HasPrefix(network, "tcp") {
		if cd, ok := e.fallbackDialer.(interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}); ok {
			return cd.DialContext(ctx, network, dst.String())
		}
		return e.fallbackDialer.Dial(network, dst.String())
	}
	if e.fallbackDialer != nil && strings.HasPrefix(network, "udp") {
		return nil, errors.New("fallback_socks5 does not support UDP ASSOCIATE in this runtime")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, dst.String())
}

func (e *Engine) resolveAddrPortCandidates(ctx context.Context, network, addr string, udpFromSOCKS bool) ([]netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	pn, err := net.LookupPort(networkBase(network), port)
	if err != nil {
		return nil, err
	}
	ipv6Enabled := e.proxyIPv6Enabled()
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is6() && !ipv6Enabled {
			return nil, fmt.Errorf("IPv6 is disabled for proxy resolution")
		}
		return []netip.AddrPort{netip.AddrPortFrom(ip, uint16(pn))}, nil
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		out := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(pn))}
		if ipv6Enabled {
			out = append(out, netip.AddrPortFrom(netip.IPv6Loopback(), uint16(pn)))
		}
		return out, nil
	}
	addrs, err := e.lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var wg4, wg6, direct4, direct6 []netip.AddrPort
	for _, s := range addrs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if ip.Is6() && !ipv6Enabled {
			continue
		}
		dst := netip.AddrPortFrom(ip, uint16(pn))
		if e.allowedContains(ip) {
			if ip.Is6() {
				wg6 = append(wg6, dst)
			} else {
				wg4 = append(wg4, dst)
			}
			continue
		}
		if ip.Is6() {
			direct6 = append(direct6, dst)
		} else {
			direct4 = append(direct4, dst)
		}
	}
	var out []netip.AddrPort
	preferIPv6 := !udpFromSOCKS || *e.cfg.Proxy.PreferIPv6ForUDPOverSOCKS
	if preferIPv6 {
		out = append(out, wg6...)
		out = append(out, wg4...)
		out = append(out, direct6...)
		out = append(out, direct4...)
	} else {
		out = append(out, wg4...)
		out = append(out, wg6...)
		out = append(out, direct4...)
		out = append(out, direct6...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable addresses for %s", host)
	}
	return out, nil
}

func (e *Engine) proxyIPv6Enabled() bool {
	if e.cfg.Proxy.IPv6 != nil {
		return *e.cfg.Proxy.IPv6
	}
	if e.allowedHasIPv6() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip netip.Addr
		switch v := a.(type) {
		case *net.IPNet:
			ip, _ = netip.AddrFromSlice(v.IP)
		case *net.IPAddr:
			ip, _ = netip.AddrFromSlice(v.IP)
		}
		if ip.Is6() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func (e *Engine) allowedHasIPv6() bool {
	e.allowedMu.RLock()
	defer e.allowedMu.RUnlock()
	for _, p := range e.allowed {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

func networkBase(network string) string {
	if strings.HasPrefix(network, "udp") {
		return "udp"
	}
	return "tcp"
}

func readSOCKSRequest(r io.Reader) (byte, socksAddr, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, socksAddr{}, err
	}
	if hdr[0] != socksVersion || hdr[2] != 0x00 {
		return 0, socksAddr{}, errors.New("invalid SOCKS5 request")
	}
	addr, err := readSOCKSAddr(r, hdr[3])
	return hdr[1], addr, err
}

func readSOCKSAddr(r io.Reader, atyp byte) (socksAddr, error) {
	out := socksAddr{atyp: atyp}
	switch atyp {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return out, err
		}
		out.addr = netip.AddrFrom4(b)
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return out, err
		}
		out.addr = netip.AddrFrom16(b)
	case socksAtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return out, err
		}
		if l[0] == 0 {
			return out, errors.New("empty SOCKS domain")
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return out, err
		}
		out.host = string(name)
	default:
		return out, errors.New("unsupported SOCKS address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return out, err
	}
	out.port = binary.BigEndian.Uint16(p[:])
	return out, nil
}

func writeSOCKSReply(w io.Writer, rep byte, bind netip.AddrPort) error {
	if !bind.IsValid() {
		bind = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	header := []byte{socksVersion, rep, 0x00}
	if bind.Addr().Is6() {
		header = append(header, socksAtypIPv6)
		ip := bind.Addr().As16()
		header = append(header, ip[:]...)
	} else {
		header = append(header, socksAtypIPv4)
		ip := bind.Addr().As4()
		header = append(header, ip[:]...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], bind.Port())
	header = append(header, p[:]...)
	_, err := w.Write(header)
	return err
}

func parseSOCKSUDPDatagram(packet []byte) (socksAddr, []byte, bool) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return socksAddr{}, nil, false
	}
	r := bytes.NewReader(packet[4:])
	addr, err := readSOCKSAddr(r, packet[3])
	if err != nil {
		return socksAddr{}, nil, false
	}
	used := len(packet[4:]) - r.Len()
	return addr, packet[4+used:], true
}

func packSOCKSUDPDatagram(src netip.AddrPort, payload []byte) ([]byte, error) {
	var out []byte
	out = append(out, 0x00, 0x00, 0x00)
	if src.Addr().Is6() {
		out = append(out, socksAtypIPv6)
		ip := src.Addr().As16()
		out = append(out, ip[:]...)
	} else if src.Addr().Is4() {
		out = append(out, socksAtypIPv4)
		ip := src.Addr().As4()
		out = append(out, ip[:]...)
	} else {
		return nil, errors.New("invalid UDP reply source")
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], src.Port())
	out = append(out, p[:]...)
	out = append(out, payload...)
	return out, nil
}

func socksReplyFromError(err error) byte {
	switch {
	case err == nil:
		return socksRepSuccess
	case errors.Is(err, errProxyACL):
		return socksRepConnectionNotAllowed
	case errors.Is(err, errProxyFallbackDisabled):
		return socksRepNetworkUnreachable
	case errors.Is(err, errVirtualSubnetUnrouted):
		return socksRepNetworkUnreachable
	case errors.Is(err, errAddressFiltered):
		return socksRepAddressNotSupported
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return socksRepTTLExpired
	}
	var op *net.OpError
	if errors.As(err, &op) {
		if errors.Is(op.Err, os.ErrDeadlineExceeded) {
			return socksRepTTLExpired
		}
		if strings.Contains(strings.ToLower(op.Err.Error()), "refused") {
			return socksRepConnectionRefused
		}
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "refused"):
		return socksRepConnectionRefused
	case strings.Contains(text, "network is unreachable"), strings.Contains(text, "no route"):
		return socksRepNetworkUnreachable
	case strings.Contains(text, "host is unreachable"), strings.Contains(text, "no such host"), strings.Contains(text, "no usable addresses"):
		return socksRepHostUnreachable
	case strings.Contains(text, "address type"), strings.Contains(text, "ipv6 is disabled"):
		return socksRepAddressNotSupported
	default:
		return socksRepGeneralFailure
	}
}
