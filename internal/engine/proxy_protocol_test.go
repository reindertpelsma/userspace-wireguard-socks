// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bufio"
	"bytes"
	"net/netip"
	"testing"
)

func TestProxyProtocolV2RoundTripTCPAndUDP(t *testing.T) {
	src := netip.MustParseAddrPort("[2001:db8::1]:1234")
	dst := netip.MustParseAddrPort("[2001:db8::2]:443")
	for _, network := range []string{"tcp", "udp"} {
		header, err := proxyProtocolBytes("v2", network, src, dst)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readProxyProtocolHeader(bufio.NewReader(bytes.NewReader(header)), "v2")
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != src || got.Destination != dst {
			t.Fatalf("%s header mismatch: got %+v want %s -> %s", network, got, src, dst)
		}
	}
}

func TestProxyProtocolRejectsOversizedV1(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PROXY TCP4 ")
	for b.Len() < 300 {
		b.WriteByte('1')
	}
	b.WriteString("\r\n")
	if _, err := readProxyProtocolHeader(bufio.NewReader(&b), "v1"); err == nil {
		t.Fatal("oversized PROXY v1 header was accepted")
	}
}

func TestStripProxyProtocolDatagramV2(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:4567")
	dst := netip.MustParseAddrPort("100.64.1.20:53")
	header, err := proxyProtocolBytes("v2", "udp", src, dst)
	if err != nil {
		t.Fatal(err)
	}
	packet := append(append([]byte(nil), header...), []byte("dns-payload")...)
	payload, meta, err := stripProxyProtocolDatagram(packet, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Source != src || meta.Destination != dst {
		t.Fatalf("PROXY datagram metadata mismatch: %+v", meta)
	}
	if !bytes.Equal(payload, []byte("dns-payload")) {
		t.Fatalf("PROXY datagram payload mismatch: %q", payload)
	}
}
