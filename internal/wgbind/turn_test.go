// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package wgbind

import (
	"net"
	"net/netip"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

func TestTURNBind(t *testing.T) {
	// 1. Start a local TURN server
	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := udpListener.LocalAddr().String()

	usersMap := map[string][]byte{
		"user": turn.GenerateAuthKey("user", "realm", "pass"),
	}

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: "realm",
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			if key, ok := usersMap[username]; ok {
				return key, true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 2. Test TURNBind
	tb := &TURNBind{
		Server:   serverAddr,
		Username: "user",
		Password: "pass",
		Realm:    "realm",
	}

	fns, port, err := tb.Open(0)
	if err != nil {
		t.Fatalf("failed to open TURNBind: %v", err)
	}
	if len(fns) == 0 {
		t.Fatal("no receive functions returned")
	}
	if port == 0 {
		t.Fatal("allocated port is 0")
	}
	t.Logf("Allocated TURN port: %d", port)

	// 3. Test sending
	dummyData := [][]byte{[]byte("hello")}
	ap, _ := netip.ParseAddrPort("127.0.0.1:12345")
	dummyEP := &Endpoint{AddrPort: ap}
	
	// Pre-create permission
	tb.UpdatePermissions([]string{"127.0.0.1:12345"})
	
	err = tb.Send(dummyData, dummyEP)
	if err != nil {
		t.Errorf("failed to send via TURN: %v", err)
	}

	// 4. Cleanup
	err = tb.Close()
	if err != nil {
		t.Errorf("failed to close TURNBind: %v", err)
	}
}
