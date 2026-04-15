// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var proxyProtocolV2Signature = []byte{'\r', '\n', '\r', '\n', 0x00, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}

type proxyProtocolHeader struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func parseProxyProtocolConn(c net.Conn, version string) (net.Conn, proxyProtocolHeader, error) {
	if version == "" {
		return c, proxyProtocolHeader{}, nil
	}
	br := bufio.NewReader(c)
	h, err := readProxyProtocolHeader(br, version)
	if err != nil {
		return c, proxyProtocolHeader{}, err
	}
	return &bufferedConn{Conn: c, r: br}, h, nil
}

func readProxyProtocolHeader(r *bufio.Reader, version string) (proxyProtocolHeader, error) {
	switch version {
	case "v1":
		line, err := readLimitedLine(r, 232)
		if err != nil {
			return proxyProtocolHeader{}, err
		}
		return parseProxyProtocolV1(line)
	case "v2":
		var fixed [16]byte
		if _, err := io.ReadFull(r, fixed[:]); err != nil {
			return proxyProtocolHeader{}, err
		}
		if !bytes.Equal(fixed[:12], proxyProtocolV2Signature) {
			return proxyProtocolHeader{}, errors.New("invalid PROXY v2 signature")
		}
		ln := int(binary.BigEndian.Uint16(fixed[14:16]))
		if ln > 512 {
			return proxyProtocolHeader{}, errors.New("PROXY v2 header too large")
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(r, payload); err != nil {
			return proxyProtocolHeader{}, err
		}
		return parseProxyProtocolV2(fixed[12], fixed[13], payload)
	default:
		return proxyProtocolHeader{}, fmt.Errorf("unsupported proxy_protocol %q", version)
	}
}

func stripProxyProtocolDatagram(packet []byte, version string) ([]byte, proxyProtocolHeader, error) {
	switch version {
	case "":
		return packet, proxyProtocolHeader{}, nil
	case "v1":
		idx := bytes.Index(packet, []byte("\r\n"))
		if idx < 0 || idx > 232 {
			return nil, proxyProtocolHeader{}, errors.New("invalid PROXY v1 datagram header")
		}
		h, err := parseProxyProtocolV1(string(packet[:idx+2]))
		if err != nil {
			return nil, proxyProtocolHeader{}, err
		}
		return packet[idx+2:], h, nil
	case "v2":
		if len(packet) < 16 || !bytes.Equal(packet[:12], proxyProtocolV2Signature) {
			return nil, proxyProtocolHeader{}, errors.New("invalid PROXY v2 datagram header")
		}
		ln := int(binary.BigEndian.Uint16(packet[14:16]))
		if ln > 512 || len(packet) < 16+ln {
			return nil, proxyProtocolHeader{}, errors.New("truncated PROXY v2 datagram header")
		}
		h, err := parseProxyProtocolV2(packet[12], packet[13], packet[16:16+ln])
		if err != nil {
			return nil, proxyProtocolHeader{}, err
		}
		return packet[16+ln:], h, nil
	default:
		return nil, proxyProtocolHeader{}, fmt.Errorf("unsupported proxy_protocol %q", version)
	}
}

func readLimitedLine(r *bufio.Reader, limit int) (string, error) {
	var b strings.Builder
	for b.Len() < limit {
		ch, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b.WriteByte(ch)
		if ch == '\n' {
			line := b.String()
			if !strings.HasSuffix(line, "\r\n") {
				return "", errors.New("PROXY v1 line missing CRLF")
			}
			return line, nil
		}
	}
	return "", errors.New("PROXY v1 header too large")
}

func parseProxyProtocolV1(line string) (proxyProtocolHeader, error) {
	line = strings.TrimSuffix(line, "\r\n")
	parts := strings.Fields(line)
	if len(parts) == 2 && parts[0] == "PROXY" && parts[1] == "UNKNOWN" {
		return proxyProtocolHeader{}, nil
	}
	if len(parts) != 6 || parts[0] != "PROXY" {
		return proxyProtocolHeader{}, errors.New("invalid PROXY v1 header")
	}
	if parts[1] != "TCP4" && parts[1] != "TCP6" {
		return proxyProtocolHeader{}, errors.New("unsupported PROXY v1 transport")
	}
	src, err := netip.ParseAddr(parts[2])
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	dst, err := netip.ParseAddr(parts[3])
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	sport, err := parseProxyProtocolPort(parts[4])
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	dport, err := parseProxyProtocolPort(parts[5])
	if err != nil {
		return proxyProtocolHeader{}, err
	}
	if (parts[1] == "TCP4") != src.Is4() || src.Is4() != dst.Is4() {
		return proxyProtocolHeader{}, errors.New("PROXY v1 address family mismatch")
	}
	return proxyProtocolHeader{Source: netip.AddrPortFrom(src, sport), Destination: netip.AddrPortFrom(dst, dport)}, nil
}

func parseProxyProtocolPort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, errors.New("invalid PROXY port")
	}
	return uint16(n), nil
}

func parseProxyProtocolV2(verCmd, famProto byte, payload []byte) (proxyProtocolHeader, error) {
	if verCmd>>4 != 0x2 {
		return proxyProtocolHeader{}, errors.New("invalid PROXY v2 version")
	}
	if verCmd&0x0f == 0x00 {
		return proxyProtocolHeader{}, nil
	}
	if verCmd&0x0f != 0x01 {
		return proxyProtocolHeader{}, errors.New("unsupported PROXY v2 command")
	}
	switch famProto {
	case 0x11, 0x12:
		if len(payload) < 12 {
			return proxyProtocolHeader{}, errors.New("truncated PROXY v2 IPv4 address block")
		}
		var src4, dst4 [4]byte
		copy(src4[:], payload[0:4])
		copy(dst4[:], payload[4:8])
		src := netip.AddrFrom4(src4)
		dst := netip.AddrFrom4(dst4)
		sport := binary.BigEndian.Uint16(payload[8:10])
		dport := binary.BigEndian.Uint16(payload[10:12])
		return proxyProtocolHeader{Source: netip.AddrPortFrom(src, sport), Destination: netip.AddrPortFrom(dst, dport)}, nil
	case 0x21, 0x22:
		if len(payload) < 36 {
			return proxyProtocolHeader{}, errors.New("truncated PROXY v2 IPv6 address block")
		}
		var src16, dst16 [16]byte
		copy(src16[:], payload[0:16])
		copy(dst16[:], payload[16:32])
		sport := binary.BigEndian.Uint16(payload[32:34])
		dport := binary.BigEndian.Uint16(payload[34:36])
		return proxyProtocolHeader{Source: netip.AddrPortFrom(netip.AddrFrom16(src16), sport), Destination: netip.AddrPortFrom(netip.AddrFrom16(dst16), dport)}, nil
	case 0x00:
		return proxyProtocolHeader{}, nil
	default:
		return proxyProtocolHeader{}, errors.New("unsupported PROXY v2 address family")
	}
}

func proxyProtocolBytes(version, network string, src, dst netip.AddrPort) ([]byte, error) {
	if version == "" {
		return nil, nil
	}
	if !src.IsValid() || !dst.IsValid() || src.Addr().Is4() != dst.Addr().Is4() {
		if version == "v1" {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		return append(append([]byte(nil), proxyProtocolV2Signature...), 0x20, 0x00, 0x00, 0x00), nil
	}
	switch version {
	case "v1":
		fam := "TCP6"
		if src.Addr().Is4() {
			fam = "TCP4"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, src.Addr(), dst.Addr(), src.Port(), dst.Port())), nil
	case "v2":
		return proxyProtocolV2Bytes(network, src, dst), nil
	default:
		return nil, fmt.Errorf("unsupported proxy_protocol %q", version)
	}
}

func proxyProtocolV2Bytes(network string, src, dst netip.AddrPort) []byte {
	out := append([]byte(nil), proxyProtocolV2Signature...)
	out = append(out, 0x21)
	proto := byte(0x01)
	if networkBase(network) == "udp" {
		proto = 0x02
	}
	if src.Addr().Is4() {
		out = append(out, 0x10|proto, 0x00, 12)
		s := src.Addr().As4()
		d := dst.Addr().As4()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	} else {
		out = append(out, 0x20|proto, 0x00, 36)
		s := src.Addr().As16()
		d := dst.Addr().As16()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	}
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], src.Port())
	binary.BigEndian.PutUint16(ports[2:4], dst.Port())
	out = append(out, ports[:]...)
	return out
}
