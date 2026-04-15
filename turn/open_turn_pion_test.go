package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	turn "github.com/pion/turn/v4"
)

func TestBuildPionServerAndRelayEcho(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "turn.yaml")
	cfgText := `realm: "example.org"
software: "go-open-turn"
allocation_ttl: "2m"
nonce_ttl: "2m"
listen:
  turn_listen: "127.0.0.1:3478"
  relay_ip: "127.0.0.1"
users:
  - username: "alice"
    password: "alice-pass"
    port: 40000
    permission_behavior: "allow"
    source_networks:
      - "127.0.0.0/8"
`
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := buildPionServer(cfg)
	if err != nil {
		t.Fatalf("buildPionServer: %v", err)
	}
	defer server.Close()

	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: "127.0.0.1:3478",
		TURNServerAddr: "127.0.0.1:3478",
		Conn:           clientConn,
		Username:       "alice",
		Password:       "alice-pass",
		Realm:          "example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer relayConn.Close()

	peer := echoConn.LocalAddr().(*net.UDPAddr)
	if err := relayConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := relayConn.WriteTo([]byte("hello-turn"), peer); err != nil {
		t.Fatalf("write via relay: %v", err)
	}
	buf := make([]byte, 2048)
	n, from, err := relayConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read via relay: %v", err)
	}
	if from.String() != peer.String() {
		t.Fatalf("unexpected peer: got %s want %s", from.String(), peer.String())
	}
	if got := string(buf[:n]); got != "hello-turn" {
		t.Fatalf("unexpected payload: %q", got)
	}
}

func TestLookupPortRangeMapping(t *testing.T) {
	cfg := Config{
		Realm:         "example.org",
		Software:      "go-open-turn",
		AllocationTTL: "1m",
		NonceTTL:      "1m",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:3479",
			RelayIP:    "127.0.0.1",
		},
		PortRanges: []RangeConfig{{
			Start:              41000,
			End:                41010,
			Password:           "shared-range-secret",
			PermissionBehavior: "allow",
			SourceNetworks:     []string{"127.0.0.0/8"},
			MappedRange: MappedRangeConfig{
				IP:        "203.0.113.10",
				StartPort: 51000,
			},
		}},
	}
	wrapper, err := newOpenRelayPion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, password, port, _, _, mapped, err := wrapper.lookup("41005")
	if err != nil {
		t.Fatal(err)
	}
	if password != "shared-range-secret" {
		t.Fatalf("unexpected password %q", password)
	}
	if port != 41005 {
		t.Fatalf("unexpected port %d", port)
	}
	if mapped == nil || mapped.String() != "203.0.113.10:51005" {
		t.Fatalf("unexpected mapped address %v", mapped)
	}
}

func TestAllowPeerRespectsSourceNetworks(t *testing.T) {
	_, srcNet, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &openRelayPion{
		reservations: map[string]*relayReservation{
			"alice|127.0.0.1": {
				Username: "alice",
				ClientIP: "127.0.0.1",
				Behavior: BehaviorAllow,
				Sources:  []*net.IPNet{srcNet},
			},
		},
	}
	if !wrapper.allowPeer(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, net.ParseIP("127.0.0.2")) {
		t.Fatal("expected loopback peer to be allowed")
	}
	if wrapper.allowPeer(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, net.ParseIP("192.0.2.1")) {
		t.Fatal("expected non-whitelisted peer to be denied")
	}
}

func Example_buildPionServer() {
	fmt.Println("buildPionServer constructs a Pion TURN server wrapper with open permission filtering.")
	// Output: buildPionServer constructs a Pion TURN server wrapper with open permission filtering.
}
