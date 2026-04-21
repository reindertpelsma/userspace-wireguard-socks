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
		name:      "turn-test",
		open:      true,
		relayConn: relay,
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
