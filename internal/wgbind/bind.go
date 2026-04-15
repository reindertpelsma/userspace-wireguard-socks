// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package wgbind adapts wireguard-go's conn.Bind interface for two deployment
// modes: normal server-style UDP listening and outbound-only client sockets.
package wgbind

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type ResolverBind struct {
	Inner conn.Bind
}

func (b *ResolverBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return b.Inner.Open(port)
}

func (b *ResolverBind) Close() error {
	return b.Inner.Close()
}

func (b *ResolverBind) SetMark(mark uint32) error {
	return b.Inner.SetMark(mark)
}

func (b *ResolverBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	return b.Inner.Send(bufs, ep)
}

func (b *ResolverBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if _, err := netip.ParseAddrPort(s); err == nil {
		return b.Inner.ParseEndpoint(s)
	}
	ap, err := resolveAddrPort(s)
	if err != nil {
		return nil, err
	}
	return b.Inner.ParseEndpoint(ap.String())
}

func (b *ResolverBind) BatchSize() int {
	return b.Inner.BatchSize()
}

type ListenBind struct {
	Addresses []string

	mu    sync.Mutex
	conns []*net.UDPConn
	open  bool
}

func (b *ListenBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if len(b.Addresses) == 0 {
		return nil, 0, errors.New("listen bind requires at least one address")
	}
	chosen := int(port)
	var fns []conn.ReceiveFunc
	for _, s := range b.Addresses {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			b.closeLocked()
			return nil, 0, err
		}
		network := "udp4"
		if ip.Is6() {
			network = "udp6"
		}
		udp, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: chosen})
		if err != nil {
			b.closeLocked()
			return nil, 0, err
		}
		if chosen == 0 {
			chosen = udp.LocalAddr().(*net.UDPAddr).Port
		}
		b.conns = append(b.conns, udp)
		fns = append(fns, b.receiveFunc(udp))
	}
	b.open = true
	return fns, uint16(chosen), nil
}

func (b *ListenBind) receiveFunc(udp *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := udp.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &Endpoint{AddrPort: ap}
		return 1, nil
	}
}

func (b *ListenBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeLocked()
}

func (b *ListenBind) closeLocked() error {
	var first error
	for _, udp := range b.conns {
		if err := udp.Close(); err != nil && first == nil {
			first = err
		}
	}
	b.conns = nil
	b.open = false
	return first
}

func (b *ListenBind) SetMark(uint32) error {
	return nil
}

func (b *ListenBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ap, err := endpointAddrPort(ep)
	if err != nil {
		return err
	}
	b.mu.Lock()
	var udp *net.UDPConn
	for _, candidate := range b.conns {
		local := candidate.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		if local.Is6() == ap.Addr().Is6() {
			udp = candidate
			break
		}
	}
	if udp == nil && len(b.conns) > 0 {
		udp = b.conns[0]
	}
	b.mu.Unlock()
	if udp == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := udp.WriteToUDPAddrPort(buf, ap); err != nil {
			return err
		}
	}
	return nil
}

func (b *ListenBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := resolveAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AddrPort: ap}, nil
}

func (b *ListenBind) BatchSize() int {
	return 1
}

type OutboundOnlyBind struct {
	mu     sync.Mutex
	conns  map[netip.AddrPort]*peerConn
	recv   chan datagram
	closed chan struct{}
	open   bool
}

type peerConn struct {
	addr netip.AddrPort
	conn *net.UDPConn
}

type datagram struct {
	buf []byte
	ep  *Endpoint
}

func NewOutboundOnlyBind() *OutboundOnlyBind {
	return &OutboundOnlyBind{}
}

// Open intentionally refuses non-zero ports. In client mode we never listen on
// a host UDP port; each peer endpoint gets a connected UDP socket only after
// WireGuard has a datagram to send.
func (b *OutboundOnlyBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port != 0 {
		return nil, 0, fmt.Errorf("outbound-only bind cannot listen on port %d", port)
	}
	b.conns = make(map[netip.AddrPort]*peerConn)
	b.recv = make(chan datagram, 1024)
	b.closed = make(chan struct{})
	b.open = true
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *OutboundOnlyBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-b.closed:
		return 0, net.ErrClosed
	case d := <-b.recv:
		n := copy(bufs[0], d.buf)
		sizes[0] = n
		eps[0] = d.ep
		return 1, nil
	}
}

func (b *OutboundOnlyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	close(b.closed)
	for _, pc := range b.conns {
		_ = pc.conn.Close()
	}
	b.conns = nil
	b.open = false
	return nil
}

func (b *OutboundOnlyBind) SetMark(uint32) error {
	return nil
}

func (b *OutboundOnlyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ap, err := endpointAddrPort(ep)
	if err != nil {
		return err
	}
	pc, err := b.peerConn(ap)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if _, err := pc.conn.Write(buf); err != nil {
			b.dropPeerConn(ap, pc)
			time.Sleep(10 * time.Millisecond)
			pc, err = b.peerConn(ap)
			if err != nil {
				return err
			}
			if _, err := pc.conn.Write(buf); err != nil {
				b.dropPeerConn(ap, pc)
				return err
			}
		}
	}
	return nil
}

// peerConn lazily creates one connected UDP socket per peer endpoint. This
// gives the kernel a stable ephemeral source port per peer without requiring
// bind(2) to a public listening port.
func (b *OutboundOnlyBind) peerConn(ap netip.AddrPort) (*peerConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil, net.ErrClosed
	}
	if pc := b.conns[ap]; pc != nil {
		return pc, nil
	}
	ua := net.UDPAddrFromAddrPort(ap)
	udp, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return nil, err
	}
	pc := &peerConn{addr: ap, conn: udp}
	b.conns[ap] = pc
	go b.readLoop(pc)
	return pc, nil
}

func (b *OutboundOnlyBind) dropPeerConn(ap netip.AddrPort, pc *peerConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if current := b.conns[ap]; current == pc {
		delete(b.conns, ap)
	}
	_ = pc.conn.Close()
}

// readLoop translates connected-UDP reads back into wireguard-go ReceiveFunc
// datagrams tagged with the peer endpoint.
func (b *OutboundOnlyBind) readLoop(pc *peerConn) {
	for {
		buf := make([]byte, 64*1024)
		n, err := pc.conn.Read(buf)
		if err != nil {
			b.dropPeerConn(pc.addr, pc)
			return
		}
		d := datagram{buf: buf[:n], ep: &Endpoint{AddrPort: pc.addr}}
		select {
		case b.recv <- d:
		case <-b.closed:
			return
		}
	}
}

func (b *OutboundOnlyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := resolveAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AddrPort: ap}, nil
}

func (b *OutboundOnlyBind) BatchSize() int {
	return 1
}

type Endpoint struct {
	netip.AddrPort
}

func (e *Endpoint) ClearSrc() {}

func (e *Endpoint) SrcToString() string {
	return ""
}

func (e *Endpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *Endpoint) DstIP() netip.Addr {
	return e.Addr()
}

func (e *Endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func endpointAddrPort(ep conn.Endpoint) (netip.AddrPort, error) {
	switch v := ep.(type) {
	case *Endpoint:
		return v.AddrPort, nil
	default:
		ap, err := netip.ParseAddrPort(v.DstToString())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: %T", conn.ErrWrongEndpointType, ep)
		}
		return ap, nil
	}
}

func resolveAddrPort(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, errors.New("no addresses")
	}
	pn, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			return netip.AddrPortFrom(addr.Unmap(), uint16(pn)), nil
		}
	}
	return netip.AddrPort{}, errors.New("no usable addresses")
}
