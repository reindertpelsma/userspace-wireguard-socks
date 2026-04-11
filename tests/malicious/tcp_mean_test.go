// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package malicious

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/netstackex"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTCPMeanInvalidStateAndWindowPressure(t *testing.T) {
	h := newTCPMeanHarness(t, 4<<10, 32)
	conn, flow := h.handshake(t, 40000)
	defer conn.Close()

	probe := []byte("probe")
	h.writeTCP(t, flow.packet(header.TCPFlagAck|header.TCPFlagPsh, flow.seq, flow.ack, nil, probe))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	gotProbe := make([]byte, len(probe))
	if _, err := io.ReadFull(conn, gotProbe); err != nil {
		t.Fatalf("baseline TCP payload was not delivered before pressure: %v", err)
	}
	flow.seq += uint32(len(probe))

	// Motifs from TCP robustness work and historical low-MSS/SACK DoS bugs:
	// impossible SACK option lengths, out-of-window reset attempts, and many
	// far-future data segments that should not be queued into receive buffers.
	h.writeTCP(t, flow.packet(header.TCPFlagAck, flow.seq, flow.ack, malformedSACKOption(), nil))
	h.writeTCP(t, flow.packet(header.TCPFlagRst, flow.seq+1<<20, flow.ack, nil, nil))
	want := []byte("still-alive-after-mean-tcp")
	h.writeTCP(t, flow.packet(header.TCPFlagAck|header.TCPFlagPsh, flow.seq, flow.ack, nil, want))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("connection did not survive invalid TCP pressure: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch after TCP pressure: got %q want %q", got, want)
	}

	for i := 0; i < 256; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 512)
		h.writeTCP(t, flow.packet(header.TCPFlagAck, flow.seq+uint32(8<<20+i*1024), flow.ack, sackOption(flow.seq, flow.seq+1), payload))
	}

	freshConn, fresh := h.handshake(t, 40001)
	defer freshConn.Close()
	freshPayload := []byte("fresh-flow-after-window-pressure")
	h.writeTCP(t, fresh.packet(header.TCPFlagAck|header.TCPFlagPsh, fresh.seq, fresh.ack, nil, freshPayload))
	_ = freshConn.SetReadDeadline(time.Now().Add(time.Second))
	gotFresh := make([]byte, len(freshPayload))
	if _, err := io.ReadFull(freshConn, gotFresh); err != nil {
		t.Fatalf("new TCP flow failed after window pressure: %v", err)
	}
	if !bytes.Equal(gotFresh, freshPayload) {
		t.Fatalf("fresh payload mismatch after TCP pressure: got %q want %q", gotFresh, freshPayload)
	}
}

func TestTCPMeanManyConnectionsStayWithinReasonableMemory(t *testing.T) {
	h := newTCPMeanHarness(t, 4<<10, 64)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var conns []net.Conn
	for i := 0; i < 32; i++ {
		conn, flow := h.handshake(t, uint16(41000+i))
		conns = append(conns, conn)
		for j := 0; j < 32; j++ {
			h.writeTCP(t, flow.packet(header.TCPFlagAck, flow.seq+uint32(4<<20+j*512), flow.ack, nil, bytes.Repeat([]byte{byte(j)}, 256)))
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	// This is intentionally broad because Go/gVisor allocation patterns vary by
	// platform. A regression that queues every far-future segment across all
	// flows should blow through this comfortably in this small test.
	if after.Alloc > before.Alloc {
		if growth := after.Alloc - before.Alloc; growth > 64<<20 {
			t.Fatalf("TCP mean test grew heap too much: before=%d after=%d growth=%d", before.Alloc, after.Alloc, growth)
		}
	}
}

type tcpMeanHarness struct {
	t      *testing.T
	dev    tun.Device
	conns  chan net.Conn
	egress chan []byte
	local  netip.Addr
	remote netip.Addr
	port   uint16
}

type tcpMeanFlow struct {
	h        *tcpMeanHarness
	remotePt uint16
	seq      uint32
	ack      uint32
}

func newTCPMeanHarness(t *testing.T, rcvWnd, maxInFlight int) *tcpMeanHarness {
	t.Helper()
	local := netip.MustParseAddr("100.92.0.1")
	dev, netw, err := netstackex.CreateNetTUN([]netip.Addr{local}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	if err := netw.SetPromiscuous(true); err != nil {
		t.Fatal(err)
	}
	if err := netw.SetSpoofing(true); err != nil {
		t.Fatal(err)
	}
	conns := make(chan net.Conn, maxInFlight)
	egress := make(chan []byte, 4096)
	go drainTCPEgress(dev, egress)
	netw.SetTCPForwarder(rcvWnd, maxInFlight, func(req *gtcp.ForwarderRequest) {
		conn, err := netstackex.NewTCPConnFromForwarder(req)
		if err != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		conns <- conn
	})
	return &tcpMeanHarness{
		t:      t,
		dev:    dev,
		conns:  conns,
		egress: egress,
		local:  local,
		remote: netip.MustParseAddr("100.92.0.2"),
		port:   8080,
	}
}

func drainTCPEgress(dev tun.Device, out chan<- []byte) {
	for {
		buf := make([]byte, 2048)
		sizes := []int{0}
		_, err := dev.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			close(out)
			return
		}
		packet := append([]byte(nil), buf[:sizes[0]]...)
		select {
		case out <- packet:
		default:
		}
	}
}

func (h *tcpMeanHarness) handshake(t *testing.T, remotePort uint16) (net.Conn, tcpMeanFlow) {
	t.Helper()
	seq := uint32(100000 + int(remotePort))
	synOpts := append([]byte{}, tcpMSSOption(1)...)
	synOpts = append(synOpts, tcpWSOption(255)...)
	synOpts = append(synOpts, tcpSACKPermittedOption()...)
	h.writeTCP(t, h.tcpPacket(remotePort, h.port, header.TCPFlagSyn, seq, 0, synOpts, nil))

	var synAck tcpSeenPacket
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pkt := h.readTCP(t)
		if pkt.srcPort == h.port && pkt.dstPort == remotePort && pkt.flags&header.TCPFlagSyn != 0 && pkt.flags&header.TCPFlagAck != 0 {
			synAck = pkt
			break
		}
	}
	if synAck.flags == 0 {
		t.Fatalf("timed out waiting for SYN-ACK on remote port %d", remotePort)
	}

	ack := synAck.seq + 1
	nextSeq := seq + 1
	h.writeTCP(t, h.tcpPacket(remotePort, h.port, header.TCPFlagAck, nextSeq, ack, nil, nil))

	select {
	case conn := <-h.conns:
		return conn, tcpMeanFlow{h: h, remotePt: remotePort, seq: nextSeq, ack: ack}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for accepted TCP conn on remote port %d", remotePort)
		return nil, tcpMeanFlow{}
	}
}

func (f tcpMeanFlow) packet(flags header.TCPFlags, seq, ack uint32, opts, payload []byte) []byte {
	return f.h.tcpPacket(f.remotePt, f.h.port, flags, seq, ack, opts, payload)
}

type tcpSeenPacket struct {
	flags   header.TCPFlags
	seq     uint32
	ack     uint32
	srcPort uint16
	dstPort uint16
}

func (h *tcpMeanHarness) readTCP(t *testing.T) tcpSeenPacket {
	t.Helper()
	select {
	case packet, ok := <-h.egress:
		if !ok {
			t.Fatal("TCP egress reader stopped")
		}
		if len(packet) < header.IPv4MinimumSize+header.TCPMinimumSize {
			t.Fatalf("short TCP response packet: %x", packet)
		}
		ip := header.IPv4(packet)
		tcp := header.TCP(packet[ip.HeaderLength():])
		return tcpSeenPacket{
			flags:   tcp.Flags(),
			seq:     tcp.SequenceNumber(),
			ack:     tcp.AckNumber(),
			srcPort: tcp.SourcePort(),
			dstPort: tcp.DestinationPort(),
		}
	case <-time.After(time.Second):
		t.Fatal("timed out reading TCP packet from netstack")
		return tcpSeenPacket{}
	}
}

func (h *tcpMeanHarness) writeTCP(t *testing.T, packet []byte) {
	t.Helper()
	if _, err := h.dev.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
}

func (h *tcpMeanHarness) tcpPacket(srcPort, dstPort uint16, flags header.TCPFlags, seq, ack uint32, opts, payload []byte) []byte {
	opts = padTCPOptions(opts)
	tcpLen := header.TCPMinimumSize + len(opts)
	packet := make([]byte, header.IPv4MinimumSize+tcpLen+len(payload))
	srcAddr := tcpip.AddrFromSlice(h.remote.AsSlice())
	dstAddr := tcpip.AddrFromSlice(h.local.AsSlice())

	ip := header.IPv4(packet[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tcp := header.TCP(packet[header.IPv4MinimumSize : header.IPv4MinimumSize+tcpLen])
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(tcpLen),
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(tcp[header.TCPMinimumSize:], opts)
	copy(packet[header.IPv4MinimumSize+tcpLen:], payload)

	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(tcpLen+len(payload)))
	sum := tcp.CalculateChecksum(xsum)
	sum = checksum.Checksum(payload, sum)
	tcp.SetChecksum(^sum)
	return packet
}

func padTCPOptions(opts []byte) []byte {
	if len(opts)%4 == 0 {
		return opts
	}
	padded := append([]byte(nil), opts...)
	for len(padded)%4 != 0 {
		padded = append(padded, header.TCPOptionNOP)
	}
	return padded
}

func tcpMSSOption(mss uint16) []byte {
	return []byte{header.TCPOptionMSS, header.TCPOptionMSSLength, byte(mss >> 8), byte(mss)}
}

func tcpWSOption(ws byte) []byte {
	return []byte{header.TCPOptionWS, header.TCPOptionWSLength, ws}
}

func tcpSACKPermittedOption() []byte {
	return []byte{header.TCPOptionSACKPermitted, header.TCPOptionSackPermittedLength}
}

func sackOption(start, end uint32) []byte {
	out := []byte{header.TCPOptionSACK, 10}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], start)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint32(b[:], end)
	out = append(out, b[:]...)
	return out
}

func malformedSACKOption() []byte {
	return []byte{header.TCPOptionSACK, 7, 0, 0, 0, 1, 0}
}
