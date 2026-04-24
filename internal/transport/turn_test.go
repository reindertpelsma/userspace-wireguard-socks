// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeTurnClient struct {
	createPermissionErr error
	created             []net.Addr
}

func (f *fakeTurnClient) Listen() error                         { return nil }
func (f *fakeTurnClient) Allocate() (net.PacketConn, error)     { return nil, nil }
func (f *fakeTurnClient) SendBindingRequest() (net.Addr, error) { return nil, nil }
func (f *fakeTurnClient) Close()                                {}
func (f *fakeTurnClient) CreatePermission(addrs ...net.Addr) error {
	if f.createPermissionErr != nil {
		return f.createPermissionErr
	}
	f.created = append(f.created, addrs...)
	return nil
}

type recordingPacketConn struct {
	writes []net.Addr
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *recordingPacketConn) WriteTo(_ []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, addr)
	return 0, nil
}
func (c *recordingPacketConn) Close() error { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestTURNTransportDialUsesOpenAllocationForWrites(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	tr := &TURNTransport{
		name:         "turn-test",
		open:         true,
		client:       &fakeTurnClient{},
		relayConn:    relay,
		grantedPeers: map[string]bool{},
	}

	sess, err := tr.Dial(context.Background(), target.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	const payload = "wg-turn-dial"
	if err := sess.WritePacket([]byte(payload)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	buf := make([]byte, 64)
	if err := target.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := target.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}

	if _, err := sess.ReadPacket(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadPacket error = %v, want net.ErrClosed", err)
	}
}

func TestTURNSessionWritePacketLazilyCreatesPermission(t *testing.T) {
	client := &fakeTurnClient{}
	relayConn := &recordingPacketConn{}
	tr := &TURNTransport{
		name:         "turn-test",
		cfg:          TURNConfig{NoCreatePermission: true},
		open:         true,
		client:       client,
		relayConn:    relayConn,
		grantedPeers: map[string]bool{},
	}

	sess := &turnSession{
		transport: tr,
		from:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001},
		relayConn: relayConn,
	}
	if err := sess.WritePacket([]byte("reply")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if len(client.created) != 1 {
		t.Fatalf("CreatePermission calls = %d, want 1", len(client.created))
	}
	gotAddr, ok := client.created[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("CreatePermission addr type = %T, want *net.UDPAddr", client.created[0])
	}
	if gotAddr.IP.String() != "127.0.0.1" || gotAddr.Port != 5 {
		t.Fatalf("CreatePermission addr = %v, want 127.0.0.1:5", gotAddr)
	}
	if len(relayConn.writes) != 1 {
		t.Fatalf("relay writes = %d, want 1", len(relayConn.writes))
	}

	// Same IP, different port should reuse the existing permission.
	sess.from = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50002}
	if err := sess.WritePacket([]byte("reply-2")); err != nil {
		t.Fatalf("second WritePacket: %v", err)
	}
	if len(client.created) != 1 {
		t.Fatalf("CreatePermission calls after second write = %d, want 1", len(client.created))
	}
	if len(relayConn.writes) != 2 {
		t.Fatalf("relay writes after second write = %d, want 2", len(relayConn.writes))
	}
}

func TestTURNSessionWritePacketReturnsPermissionError(t *testing.T) {
	client := &fakeTurnClient{createPermissionErr: errors.New("boom")}
	relayConn := &recordingPacketConn{}
	tr := &TURNTransport{
		name:         "turn-test",
		cfg:          TURNConfig{NoCreatePermission: true},
		open:         true,
		client:       client,
		relayConn:    relayConn,
		grantedPeers: map[string]bool{},
	}
	sess := &turnSession{
		transport: tr,
		from:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001},
		relayConn: relayConn,
	}
	if err := sess.WritePacket([]byte("reply")); err == nil || err.Error() != "boom" {
		t.Fatalf("WritePacket error = %v, want boom", err)
	}
	if len(relayConn.writes) != 0 {
		t.Fatalf("relay writes = %d, want 0", len(relayConn.writes))
	}
}
