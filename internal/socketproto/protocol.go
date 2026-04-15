// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package socketproto

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	HeaderLen         = 16
	DefaultMaxPayload = 1 << 20

	ActionConnect      uint16 = 1
	ActionAccept       uint16 = 2
	ActionClose        uint16 = 3
	ActionData         uint16 = 4
	ActionUDPDatagram  uint16 = 5
	ActionDNS          uint16 = 6
	ActionToSocketPair uint16 = 7

	ProtoTCP  uint8 = 1
	ProtoUDP  uint8 = 2
	ProtoICMP uint8 = 3

	ClientIDBase uint64 = 1 << 63
)

var (
	ErrFrameTooLarge = errors.New("socket protocol frame too large")
	ErrBadFrame      = errors.New("bad socket protocol frame")
)

type Frame struct {
	ID      uint64
	Action  uint16
	Flags   uint16
	Payload []byte
}

type Connect struct {
	ListenerID uint64
	IPVersion  uint8
	Protocol   uint8
	BindIP     netip.Addr
	BindPort   uint16
	DestIP     netip.Addr
	DestPort   uint16
}

type Accept struct {
	IPVersion uint8
	Protocol  uint8
	BindIP    netip.Addr
	BindPort  uint16
}

type UDPDatagram struct {
	IPVersion  uint8
	RemoteIP   netip.Addr
	RemotePort uint16
	Payload    []byte
}

func ReadFrame(r io.Reader, maxPayload int) (Frame, error) {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	var h [HeaderLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.BigEndian.Uint32(h[12:16]))
	if n > maxPayload {
		return Frame{}, ErrFrameTooLarge
	}
	f := Frame{
		ID:      binary.BigEndian.Uint64(h[0:8]),
		Action:  binary.BigEndian.Uint16(h[8:10]),
		Flags:   binary.BigEndian.Uint16(h[10:12]),
		Payload: make([]byte, n),
	}
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, err
	}
	return f, nil
}

func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > DefaultMaxPayload {
		return ErrFrameTooLarge
	}
	var h [HeaderLen]byte
	binary.BigEndian.PutUint64(h[0:8], f.ID)
	binary.BigEndian.PutUint16(h[8:10], f.Action)
	binary.BigEndian.PutUint16(h[10:12], f.Flags)
	binary.BigEndian.PutUint32(h[12:16], uint32(len(f.Payload)))
	if err := writeFull(w, h[:]); err != nil {
		return err
	}
	if len(f.Payload) == 0 {
		return nil
	}
	return writeFull(w, f.Payload)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func EncodeConnect(c Connect) ([]byte, error) {
	ipLen, err := ipLen(c.IPVersion)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16, 16+2*ipLen)
	binary.BigEndian.PutUint64(out[0:8], c.ListenerID)
	out[8] = c.IPVersion
	out[9] = c.Protocol
	binary.BigEndian.PutUint16(out[12:14], c.BindPort)
	binary.BigEndian.PutUint16(out[14:16], c.DestPort)
	out = appendAddr(out, c.IPVersion, c.BindIP)
	out = appendAddr(out, c.IPVersion, c.DestIP)
	return out, nil
}

func DecodeConnect(p []byte) (Connect, error) {
	if len(p) < 16 {
		return Connect{}, ErrBadFrame
	}
	c := Connect{
		ListenerID: binary.BigEndian.Uint64(p[0:8]),
		IPVersion:  p[8],
		Protocol:   p[9],
		BindPort:   binary.BigEndian.Uint16(p[12:14]),
		DestPort:   binary.BigEndian.Uint16(p[14:16]),
	}
	ipLen, err := ipLen(c.IPVersion)
	if err != nil {
		return Connect{}, err
	}
	if len(p) != 16+2*ipLen {
		return Connect{}, ErrBadFrame
	}
	c.BindIP = parseAddr(p[16:16+ipLen], c.IPVersion)
	c.DestIP = parseAddr(p[16+ipLen:], c.IPVersion)
	return c, nil
}

func EncodeAccept(a Accept) ([]byte, error) {
	ipLen, err := ipLen(a.IPVersion)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 6, 6+ipLen)
	out[0] = a.IPVersion
	out[1] = a.Protocol
	binary.BigEndian.PutUint16(out[4:6], a.BindPort)
	out = appendAddr(out, a.IPVersion, a.BindIP)
	return out, nil
}

func DecodeAccept(p []byte) (Accept, error) {
	if len(p) < 6 {
		return Accept{}, ErrBadFrame
	}
	a := Accept{IPVersion: p[0], Protocol: p[1], BindPort: binary.BigEndian.Uint16(p[4:6])}
	ipLen, err := ipLen(a.IPVersion)
	if err != nil {
		return Accept{}, err
	}
	if len(p) != 6+ipLen {
		return Accept{}, ErrBadFrame
	}
	a.BindIP = parseAddr(p[6:], a.IPVersion)
	return a, nil
}

func EncodeUDPDatagram(d UDPDatagram) ([]byte, error) {
	ipLen, err := ipLen(d.IPVersion)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4, 4+ipLen+len(d.Payload))
	out[0] = d.IPVersion
	binary.BigEndian.PutUint16(out[2:4], d.RemotePort)
	out = appendAddr(out, d.IPVersion, d.RemoteIP)
	out = append(out, d.Payload...)
	return out, nil
}

func DecodeUDPDatagram(p []byte) (UDPDatagram, error) {
	if len(p) < 4 {
		return UDPDatagram{}, ErrBadFrame
	}
	d := UDPDatagram{IPVersion: p[0], RemotePort: binary.BigEndian.Uint16(p[2:4])}
	ipLen, err := ipLen(d.IPVersion)
	if err != nil {
		return UDPDatagram{}, err
	}
	if len(p) < 4+ipLen {
		return UDPDatagram{}, ErrBadFrame
	}
	d.RemoteIP = parseAddr(p[4:4+ipLen], d.IPVersion)
	d.Payload = append([]byte(nil), p[4+ipLen:]...)
	return d, nil
}

func AddrVersion(addr netip.Addr) uint8 {
	if addr.Is6() {
		return 6
	}
	return 4
}

func AddrPort(ip netip.Addr, port uint16) netip.AddrPort {
	if !ip.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, port)
}

func appendAddr(out []byte, version uint8, addr netip.Addr) []byte {
	if version == 4 {
		var zero [4]byte
		if addr.IsValid() {
			a := addr.Unmap().As4()
			return append(out, a[:]...)
		}
		return append(out, zero[:]...)
	}
	var zero [16]byte
	if addr.IsValid() {
		a := addr.As16()
		return append(out, a[:]...)
	}
	return append(out, zero[:]...)
}

func parseAddr(b []byte, version uint8) netip.Addr {
	for _, v := range b {
		if v != 0 {
			if version == 4 {
				var a [4]byte
				copy(a[:], b)
				return netip.AddrFrom4(a)
			}
			var a [16]byte
			copy(a[:], b)
			return netip.AddrFrom16(a)
		}
	}
	return netip.Addr{}
}

func ipLen(version uint8) (int, error) {
	switch version {
	case 4:
		return 4, nil
	case 6:
		return 16, nil
	default:
		return 0, fmt.Errorf("%w: unsupported IP version %d", ErrBadFrame, version)
	}
}

func DialHTTP(ctx context.Context, endpoint, token, path string) (net.Conn, error) {
	if path == "" {
		path = "/v1/socket"
	}
	base := endpoint
	var network, address, host string
	if strings.HasPrefix(base, "unix:") {
		network = "unix"
		address = strings.TrimPrefix(strings.TrimPrefix(base, "unix://"), "unix:")
		host = "uwg"
	} else {
		if !strings.Contains(base, "://") {
			base = "http://" + base
		}
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "http" {
			return nil, fmt.Errorf("socket protocol only supports http or unix endpoints, got %q", u.Scheme)
		}
		network = "tcp"
		address = u.Host
		host = u.Host
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: uwg-socket/1\r\n", path, host)
	if token != "" {
		fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", token)
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(c, req.String()); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = c.Close()
		return nil, fmt.Errorf("socket upgrade returned %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() == 0 {
		return c, nil
	}
	return &BufferedConn{Conn: c, Reader: br}, nil
}

type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}
