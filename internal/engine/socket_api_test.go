// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

func TestSocketAPIConnectTCPUDPAndListenTCP(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.92.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.92.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.92.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.92.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	tcpLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.92.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go serveEchoListener(tcpLn)

	udpPC, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.92.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	socketAddr := "http://" + clientEng.Addr("api")
	got := socketAPITCPEcho(t, socketAddr, "secret", netip.MustParseAddrPort("100.64.92.1:18080"), []byte("raw socket tcp"))
	if string(got) != "raw socket tcp" {
		t.Fatalf("TCP socket API echo mismatch: %q", got)
	}
	got = socketAPIUDPEcho(t, socketAddr, "secret", netip.MustParseAddrPort("100.64.92.1:18081"), []byte("raw socket udp"))
	if string(got) != "raw socket udp" {
		t.Fatalf("UDP socket API echo mismatch: %q", got)
	}
	got = socketAPIICMPEcho(t, socketAddr, "secret", netip.MustParseAddr("100.64.92.1"), []byte("raw socket icmp"))
	if string(got) != "raw socket icmp" {
		t.Fatalf("ICMP socket API echo mismatch: %q", got)
	}

	apiConn := socketAPIConn(t, socketAddr, "secret")
	defer apiConn.Close()
	listenerID := socketproto.ClientIDBase + 500
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.92.2")),
		Protocol:  socketproto.ProtoTCP,
		BindIP:    netip.MustParseAddr("100.64.92.2"),
		BindPort:  19090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: listenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept || frame.ID != listenerID {
		t.Fatalf("listener accept frame = id %d action %d payload %q", frame.ID, frame.Action, frame.Payload)
	}

	serverDone := make(chan []byte, 1)
	go func() {
		conn := retryEngineDial(t, serverEng, "tcp", "100.64.92.2:19090")
		defer conn.Close()
		_, _ = conn.Write([]byte("listener inbound"))
		buf := make([]byte, len("listener reply"))
		_, _ = io.ReadFull(conn, buf)
		serverDone <- buf
	}()
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionConnect || frame.ID >= socketproto.ClientIDBase {
		t.Fatalf("inbound connect frame = id %d action %d", frame.ID, frame.Action)
	}
	inboundID := frame.ID
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: inboundID, Action: socketproto.ActionAccept}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "listener inbound" {
		t.Fatalf("inbound data frame = action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: inboundID, Action: socketproto.ActionData, Payload: []byte("listener reply")}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-serverDone:
		if string(got) != "listener reply" {
			t.Fatalf("server got reply %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for listener reply")
	}

	udpAPI := socketAPIConn(t, socketAddr, "secret")
	defer udpAPI.Close()
	udpListenerID := socketproto.ClientIDBase + 501
	payload, err = socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.92.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.92.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(udpAPI, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, udpAPI)
	if frame.Action != socketproto.ActionAccept || frame.ID != udpListenerID {
		t.Fatalf("UDP listener accept frame = id %d action %d payload %q", frame.ID, frame.Action, frame.Payload)
	}
	unsolicited, err := serverEng.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("100.64.92.2:19091"))
	if err != nil {
		t.Fatal(err)
	}
	defer unsolicited.Close()
	if _, err := unsolicited.Write([]byte("unsolicited")); err != nil {
		t.Fatal(err)
	}
	_ = udpAPI.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(udpAPI, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP listener delivered unsolicited datagram with udp_inbound disabled: action %d payload %q", frame.Action, frame.Payload)
	}
	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.92.1")),
		RemoteIP:   netip.MustParseAddr("100.64.92.1"),
		RemotePort: 18081,
		Payload:    []byte("udp listener echo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(udpAPI, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, udpAPI)
	if frame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("UDP listener echo frame = action %d payload %q", frame.Action, frame.Payload)
	}
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDgram.Payload) != "udp listener echo" {
		t.Fatalf("UDP listener echo mismatch: %q", gotDgram.Payload)
	}
}

func TestSocketAPIRejectsICMPByACLAndUnroutedIPv6(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	cfg.ACL.Outbound = []acl.Rule{{Action: acl.Deny, Protocol: "icmp"}}
	fallback := false
	cfg.Proxy.FallbackDirect = &fallback
	eng := mustStart(t, cfg)

	conn := socketAPIConn(t, "http://"+eng.Addr("api"), "secret")
	defer conn.Close()
	id := socketproto.ClientIDBase + 710
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.93.2")),
		Protocol:  socketproto.ProtoICMP,
		DestIP:    netip.MustParseAddr("100.64.93.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("blocked by outbound ACL")) {
		t.Fatalf("ICMP ACL rejection frame = action %d payload %q", frame.Action, frame.Payload)
	}

	id++
	payload, err = socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("fd7a:115c:a1e0::99")),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    netip.MustParseAddr("fd7a:115c:a1e0::99"),
		DestPort:  443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("IPv6 is disabled")) {
		t.Fatalf("IPv6 rejection frame = action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIFallbackDirectTCPUDPAndICMP(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()
	udpPC, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.97.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	socketAddr := "http://" + eng.Addr("api")
	got := socketAPITCPEcho(t, socketAddr, "secret", netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), echo.Port)), []byte("raw socket direct tcp"))
	if string(got) != "raw socket direct tcp" {
		t.Fatalf("TCP direct fallback echo mismatch: %q", got)
	}
	udpPort := udpPC.LocalAddr().(*net.UDPAddr).Port
	got = socketAPIUDPEcho(t, socketAddr, "secret", netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), fmt.Sprintf("%d", udpPort))), []byte("raw socket direct udp"))
	if string(got) != "raw socket direct udp" {
		t.Fatalf("UDP direct fallback echo mismatch: %q", got)
	}
	if hostPingSupported(hostIP) {
		got = socketAPIICMPEcho(t, socketAddr, "secret", hostIP, []byte("raw socket direct icmp"))
		if string(got) != "raw socket direct icmp" {
			t.Fatalf("ICMP direct fallback echo mismatch: %q", got)
		}
	}
}

func TestSocketAPIHTTPProxySocketUpgradeRequiresAndAcceptsBasicAuth(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.98.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.98.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.98.2/32"}
	clientCfg.Proxy.HTTP = "127.0.0.1:0"
	clientCfg.Proxy.Username = "alice"
	clientCfg.Proxy.Password = "secret"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.98.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	tcpLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.98.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go serveEchoListener(tcpLn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := socketproto.DialHTTP(ctx, "http://"+clientEng.Addr("http"), "", "/uwg/socket"); err == nil {
		t.Fatal("unauthenticated /uwg/socket upgrade unexpectedly succeeded")
	}

	conn, err := socketproto.DialHTTP(ctx, "http://alice:secret@"+clientEng.Addr("http"), "", "/uwg/socket")
	if err != nil {
		t.Fatalf("authenticated /uwg/socket upgrade failed: %v", err)
	}
	defer conn.Close()

	id := socketproto.ClientIDBase + 812
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.98.1")),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    netip.MustParseAddr("100.64.98.1"),
		DestPort:  18080,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("authenticated /uwg/socket connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("proxy socket auth")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "proxy socket auth" {
		t.Fatalf("authenticated /uwg/socket echo mismatch: action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIUDPBindWithoutBindPrivilegeIsEstablishedOnly(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.95.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.95.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.95.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = false
	clientCfg.Inbound.UDPIdleTimeoutSeconds = 1
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.95.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	udpPC, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.95.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpPC.Close()
	go serveUDPEcho(udpPC)

	apiConn := socketAPIConn(t, "http://"+clientEng.Addr("api"), "secret")
	defer apiConn.Close()
	udpListenerID := socketproto.ClientIDBase + 600
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.95.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.95.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept || frame.ID != udpListenerID {
		t.Fatalf("UDP bind without privilege was not accepted: action %d payload %q", frame.Action, frame.Payload)
	}

	if _, err := udpPC.WriteTo([]byte("unsolicited"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.95.2:19091"))); err != nil {
		t.Fatal(err)
	}
	// 500ms still wasn't enough on macOS-latest under -race —
	// the unsolicited datagram took >500ms to round-trip under
	// race overhead and then leaked into the LATER established-echo
	// read at line 433. 2s gives the unsolicited path comfortable
	// budget to either (a) get correctly dropped or (b) arrive and
	// fail loudly here, never both.
	_ = apiConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP bind delivered unsolicited datagram with bind=false: action %d payload %q", frame.Action, frame.Payload)
	}

	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.95.1")),
		RemoteIP:   netip.MustParseAddr("100.64.95.1"),
		RemotePort: 18081,
		Payload:    []byte("udp established echo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: udpListenerID, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Action != socketproto.ActionUDPDatagram || string(gotDgram.Payload) != "udp established echo" {
		t.Fatalf("UDP established echo mismatch: action %d payload %q", frame.Action, gotDgram.Payload)
	}

	time.Sleep(1200 * time.Millisecond)
	if _, err := udpPC.WriteTo([]byte("expired"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.95.2:19091"))); err != nil {
		t.Fatal(err)
	}
	_ = apiConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("UDP bind delivered expired peer datagram with bind=false: action %d payload %q", frame.Action, frame.Payload)
	}
}

func TestSocketAPIUDPListenerCanReconnectAndDisconnect(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.96.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.96.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	udpOne, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.96.1:18101"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpOne.Close()
	go serveUDPEcho(udpOne)

	udpTwo, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.96.1:18102"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpTwo.Close()
	go serveUDPEcho(udpTwo)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.96.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.SocketAPI.Bind = false
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.96.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	apiConn := socketAPIConn(t, "http://"+clientEng.Addr("api"), "secret")
	defer apiConn.Close()
	id := socketproto.ClientIDBase + 700
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(netip.MustParseAddr("100.64.96.2")),
		Protocol:  socketproto.ProtoUDP,
		BindIP:    netip.MustParseAddr("100.64.96.2"),
		BindPort:  19091,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP listener accept failed: action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPReconnect(t, apiConn, id, netip.MustParseAddrPort("100.64.96.1:18101"))
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("connected-one")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "connected-one" {
		t.Fatalf("connected UDP first echo = action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPReconnect(t, apiConn, id, netip.MustParseAddrPort("100.64.96.1:18102"))
	if _, err := udpOne.WriteTo([]byte("old-remote"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.64.96.2:19091"))); err != nil {
		t.Fatal(err)
	}
	_ = apiConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if frame, err := socketproto.ReadFrame(apiConn, socketproto.DefaultMaxPayload); err == nil {
		t.Fatalf("reconnected UDP delivered old remote datagram: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: []byte("connected-two")}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionData || string(frame.Payload) != "connected-two" {
		t.Fatalf("connected UDP second echo = action %d payload %q", frame.Action, frame.Payload)
	}

	socketAPIUDPDisconnect(t, apiConn, id)
	dgram, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(netip.MustParseAddr("100.64.96.1")),
		RemoteIP:   netip.MustParseAddr("100.64.96.1"),
		RemotePort: 18101,
		Payload:    []byte("unconnected-again"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(apiConn, socketproto.Frame{ID: id, Action: socketproto.ActionUDPDatagram, Payload: dgram}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, apiConn)
	if frame.Action != socketproto.ActionUDPDatagram {
		t.Fatalf("unconnected UDP echo action = %d payload %q", frame.Action, frame.Payload)
	}
	gotDgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDgram.Payload) != "unconnected-again" {
		t.Fatalf("unconnected UDP echo mismatch: %q", gotDgram.Payload)
	}
}

func socketAPIUDPReconnect(t *testing.T, conn net.Conn, id uint64, dst netip.AddrPort) {
	t.Helper()
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		ListenerID: id,
		IPVersion:  socketproto.AddrVersion(dst.Addr()),
		Protocol:   socketproto.ProtoUDP,
		DestIP:     dst.Addr(),
		DestPort:   dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP reconnect failed: action %d payload %q", frame.Action, frame.Payload)
	}
}

func socketAPIUDPDisconnect(t *testing.T, conn net.Conn, id uint64) {
	t.Helper()
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		ListenerID: id,
		IPVersion:  4,
		Protocol:   socketproto.ProtoUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP disconnect failed: action %d payload %q", frame.Action, frame.Payload)
	}
}

func socketAPITCPEcho(t *testing.T, api, token string, dst netip.AddrPort, msg []byte) []byte {
	t.Helper()
	conn := socketAPIConn(t, api, token)
	defer conn.Close()
	id := socketproto.ClientIDBase + 10
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst.Addr()),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    dst.Addr(),
		DestPort:  dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("TCP connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: msg}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData {
		t.Fatalf("TCP data failed: action %d payload %q", frame.Action, frame.Payload)
	}
	return frame.Payload
}

func socketAPIUDPEcho(t *testing.T, api, token string, dst netip.AddrPort, msg []byte) []byte {
	t.Helper()
	conn := socketAPIConn(t, api, token)
	defer conn.Close()
	id := socketproto.ClientIDBase + 11
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst.Addr()),
		Protocol:  socketproto.ProtoUDP,
		DestIP:    dst.Addr(),
		DestPort:  dst.Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("UDP connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: msg}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData {
		t.Fatalf("UDP data failed: action %d payload %q", frame.Action, frame.Payload)
	}
	return frame.Payload
}

func socketAPIICMPEcho(t *testing.T, api, token string, dst netip.Addr, msg []byte) []byte {
	t.Helper()
	conn := socketAPIConn(t, api, token)
	defer conn.Close()
	id := socketproto.ClientIDBase + 12
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dst),
		Protocol:  socketproto.ProtoICMP,
		DestIP:    dst,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionAccept {
		t.Fatalf("ICMP connect failed: action %d payload %q", frame.Action, frame.Payload)
	}
	req, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x1234, Seq: 7, Data: msg},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: req}); err != nil {
		t.Fatal(err)
	}
	frame = readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionData {
		t.Fatalf("ICMP data failed: action %d payload %q", frame.Action, frame.Payload)
	}
	reply, err := icmp.ParseMessage(1, frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok || reply.Type != ipv4.ICMPTypeEchoReply || echo.Seq != 7 {
		t.Fatalf("unexpected ICMP reply: %#v", reply)
	}
	return echo.Data
}

func socketAPIConn(t *testing.T, api, token string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := socketproto.DialHTTP(ctx, api, token, "/v1/socket")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func readSocketFrame(t *testing.T, conn net.Conn) socketproto.Frame {
	t.Helper()
	// 10s normally is plenty for a localhost UDP echo. Under -race
	// on Windows GH runners the wireguard-go + gvisor pipeline takes
	// noticeably longer per packet (TestSocketAPIUDPBindWithoutBind-
	// PrivilegeIsEstablishedOnly hit i/o timeout at exactly 10s in
	// v0.1.0-beta.41). Scale by testDeadlineScale (10× under -race)
	// to match the rest of the integration suite.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second * testDeadlineScale))
	frame, err := socketproto.ReadFrame(conn, socketproto.DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestSocketProtocolRejectsMalformedFrame(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.93.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	conn := socketAPIConn(t, "http://"+eng.Addr("api"), "secret")
	defer conn.Close()
	if err := socketproto.WriteFrame(conn, socketproto.Frame{ID: socketproto.ClientIDBase + 1, Action: socketproto.ActionConnect, Payload: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	frame := readSocketFrame(t, conn)
	if frame.Action != socketproto.ActionClose || !bytes.Contains(frame.Payload, []byte("bad socket protocol frame")) {
		t.Fatalf("malformed frame response = action %d payload %q", frame.Action, frame.Payload)
	}
}
