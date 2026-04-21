package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
)

func TestWireguardGuard_Fuzz(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// 1. Random UDP packets (not Wireguard) -> rejected
	allowed, _ := guard.ProcessInbound([]byte{0, 0, 0, 0, 5}, remoteAddr, relayPort)
	if allowed {
		t.Error("Random UDP packet should be rejected")
	}

	// 2. Invalid mac1 in Handshake Initiation -> rejected
	initiation := make([]byte, HandshakeInitiationSize)
	initiation[0] = PacketHandshakeInitiation
	allowed, _ = guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if allowed {
		t.Error("Handshake Initiation with invalid mac1 should be rejected")
	}

	// 3. Handshake response / Cookie reply / Data with unknown receiver ID -> rejected
	data := make([]byte, MinDataPacketSize)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 9999) // Unknown receiver ID
	allowed, _ = guard.ProcessInbound(data, remoteAddr, relayPort)
	if allowed {
		t.Error("Packet with unknown receiver ID should be rejected")
	}
}

func TestWireguardGuard_HandshakeAndCookies(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// Create valid Handshake Initiation
	initiation := make([]byte, HandshakeInitiationSize)
	initiation[0] = PacketHandshakeInitiation
	binary.LittleEndian.PutUint32(initiation[4:8], 123) // sender index

	// Calculate mac1
	h, _ := blake2s.New256(nil)
	h.Write([]byte("mac1----"))
	h.Write(pubKey[:])
	mac1Key := h.Sum(nil)

	h128, _ := blake2s.New128(mac1Key)
	h128.Write(initiation[:116])
	copy(initiation[116:132], h128.Sum(nil))

	// Inbound Handshake Initiation -> allowed
	allowed, modified := guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if !allowed {
		t.Fatal("Valid Handshake Initiation should be allowed")
	}
	if modified == nil {
		t.Fatal("Handshake Initiation should be modified (cleared mac2)")
	}

	// Simulate Wireguard Server (Outbound Handshake Response)
	response := make([]byte, HandshakeResponseSize)
	response[0] = PacketHandshakeResponse
	binary.LittleEndian.PutUint32(response[4:8], 456)  // sender index (server)
	binary.LittleEndian.PutUint32(response[8:12], 123) // receiver index (client)

	if !guard.ProcessOutbound(response, remoteAddr, relayPort) {
		t.Fatal("Outbound Handshake Response should be allowed")
	}

	// Verify session is verified
	guard.mu.RLock()
	if len(guard.Sessions) != 1 || !guard.Sessions[0].Verified {
		t.Fatal("Session should be verified after server response")
	}
	guard.mu.RUnlock()

	// Data packet from client -> allowed
	data := make([]byte, MinDataPacketSize)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 456) // receiver ID = server's sender ID
	binary.LittleEndian.PutUint64(data[8:16], 1)  // counter

	allowed, _ = guard.ProcessInbound(data, remoteAddr, relayPort)
	if !allowed {
		t.Error("Data packet should be allowed")
	}
}

func TestWireguardGuard_DoSAndCookies(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	guard.DoSLevel = DoSLevelFull
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// Initiation without mac2 in DoS mode -> should return Cookie Reply
	initiation := make([]byte, HandshakeInitiationSize)
	initiation[0] = PacketHandshakeInitiation
	binary.LittleEndian.PutUint32(initiation[4:8], 123)

	h, _ := blake2s.New256(nil)
	h.Write([]byte("mac1----"))
	h.Write(pubKey[:])
	mac1Key := h.Sum(nil)
	h128, _ := blake2s.New128(mac1Key)
	h128.Write(initiation[:116])
	copy(initiation[116:132], h128.Sum(nil))

	allowed, modified := guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if allowed {
		t.Error("Initiation without mac2 in DoS mode should be rejected")
	}
	if modified == nil || modified[0] != PacketCookieReply {
		t.Fatal("Should return Cookie Reply")
	}

	// Now send initiation with valid mac2 (from our cookie)
	// First get the cookie
	ourCookie := guard.getCookie(net.ParseIP("1.2.3.4"))
	h128mac2, _ := blake2s.New128(ourCookie[:])
	h128mac2.Write(initiation[:132])
	copy(initiation[132:148], h128mac2.Sum(nil))

	allowed, _ = guard.ProcessInbound(initiation, remoteAddr, relayPort)
	if !allowed {
		t.Error("Initiation with valid mac2 should be allowed in DoS mode")
	}
}

func TestWireguardGuard_DataLimit(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
	relayPort := 3478

	// Establish verified session
	init := make([]byte, HandshakeInitiationSize)
	init[0] = PacketHandshakeInitiation
	// skip mac1 for simplicity, just hack the guard
	guard.mu.Lock()
	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    remoteAddr.String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	// Send data until limit
	data := make([]byte, 1024)
	data[0] = PacketData
	binary.LittleEndian.PutUint32(data[4:8], 456)

	for i := 0; i < 256; i++ {
		allowed, _ := guard.ProcessInbound(data, remoteAddr, relayPort)
		if !allowed {
			t.Fatalf("Failed at packet %d", i)
		}
	}

	// Next packet should be rejected
	allowed, _ := guard.ProcessInbound(data, remoteAddr, relayPort)
	if allowed {
		t.Error("Data limit (256KB) should be enforced")
	}
}

func TestWireguardGuard_SessionOverflow(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	// Fill session table with unverified sessions
	for i := 0; i < guard.MaxSessions; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1000 + i}
		guard.mu.Lock()
		guard.Sessions = append(guard.Sessions, &WireguardSession{
			RelayPort:  relayPort,
			RemoteAddr: addr.String(),
			Verified:   false,
		})
		guard.mu.Unlock()
	}

	// New verified outbound should replace an unverified one
	serverAddr := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}
	resp := make([]byte, HandshakeResponseSize)
	resp[0] = PacketHandshakeResponse
	binary.LittleEndian.PutUint32(resp[8:12], 123)

	if !guard.ProcessOutbound(resp, serverAddr, relayPort) {
		t.Fatal("Outbound should be allowed even if table is full")
	}

	found := false
	guard.mu.RLock()
	for _, s := range guard.Sessions {
		if s.RemoteAddr == serverAddr.String() && s.Verified {
			found = true
			break
		}
	}
	guard.mu.RUnlock()
	if !found {
		t.Error("New verified session should have replaced an unverified one")
	}
}

func TestWireguardGuard_RoamBurstEscalatesDoS(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    (&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}).String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.mu.Lock()
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	packet := make([]byte, MinDataPacketSize)
	packet[0] = PacketData
	binary.LittleEndian.PutUint32(packet[4:8], 456)
	binary.LittleEndian.PutUint64(packet[8:16], 1)

	if allowed, _ := guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}, relayPort); !allowed {
		t.Fatal("first roam packet should still be allowed before escalation")
	}
	if allowed, _ := guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("3.3.3.3"), Port: 3333}, relayPort); !allowed {
		t.Fatal("second burst roam packet should still be allowed before escalation")
	}
	guard.mu.Lock()
	guard.LastStatsReset = time.Now().Add(-11 * time.Second)
	guard.mu.Unlock()
	guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("4.4.4.4"), Port: 4444}, relayPort)
	if guard.DoSLevel == DoSLevelNone {
		t.Fatal("burst roam activity did not raise DoS level")
	}
}

func TestWireguardGuard_RoamSustainedEscalatesDoS(t *testing.T) {
	var pubKey [32]byte
	rand.Read(pubKey[:])
	guard := NewWireguardGuard(pubKey)
	relayPort := 3478

	sess := &WireguardSession{
		RelayPort:     relayPort,
		RemoteAddr:    (&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111}).String(),
		ClientPeerID:  123,
		ServerPeerID:  456,
		Verified:      true,
		LastServerPkt: time.Now(),
	}
	guard.mu.Lock()
	guard.Sessions = append(guard.Sessions, sess)
	guard.mu.Unlock()

	packet := make([]byte, MinDataPacketSize)
	packet[0] = PacketData
	binary.LittleEndian.PutUint32(packet[4:8], 456)
	binary.LittleEndian.PutUint64(packet[8:16], 1)

	remotes := []*net.UDPAddr{
		{IP: net.ParseIP("2.2.2.2"), Port: 2222},
		{IP: net.ParseIP("3.3.3.3"), Port: 3333},
		{IP: net.ParseIP("4.4.4.4"), Port: 4444},
	}
	for i, remote := range remotes {
		if allowed, _ := guard.ProcessInbound(packet, remote, relayPort); !allowed {
			t.Fatalf("roam packet %d should still be allowed before escalation", i)
		}
		guard.mu.Lock()
		sess.LastRoam = time.Now().Add(-time.Second)
		guard.mu.Unlock()
	}
	guard.mu.Lock()
	guard.LastStatsReset = time.Now().Add(-11 * time.Second)
	guard.mu.Unlock()
	guard.ProcessInbound(packet, &net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 5555}, relayPort)
	if guard.DoSLevel == DoSLevelNone {
		t.Fatal("sustained roam activity did not raise DoS level")
	}
}
