// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"net"
	"strings"
	"testing"
)

func TestWSConnReadFrameRejectsOversizedPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = server.Write([]byte{
			0x82, 0x7f,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, // 65536 bytes
		})
	}()

	ws := &wsConn{conn: client}
	_, err := ws.ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "websocket frame too large") {
		t.Fatalf("ReadFrame error=%v, want oversized-frame rejection", err)
	}
	<-done
}

func TestTryEnqueueAcceptDropsWhenFull(t *testing.T) {
	ch := make(chan int, 1)
	ch <- 1

	var closed, overloaded bool
	if ok := tryEnqueueAccept(ch, 2, make(chan struct{}), func() { closed = true }, func() { overloaded = true }); ok {
		t.Fatal("tryEnqueueAccept unexpectedly succeeded on full channel")
	}
	if closed {
		t.Fatal("closed callback unexpectedly ran on overload")
	}
	if !overloaded {
		t.Fatal("overloaded callback did not run")
	}
}

func TestTryEnqueueAcceptClosesOnShutdown(t *testing.T) {
	ch := make(chan int, 1)
	closeCh := make(chan struct{})
	close(closeCh)

	var closed, overloaded bool
	if ok := tryEnqueueAccept(ch, 2, closeCh, func() { closed = true }, func() { overloaded = true }); ok {
		t.Fatal("tryEnqueueAccept unexpectedly succeeded after shutdown")
	}
	if !closed {
		t.Fatal("closed callback did not run")
	}
	if overloaded {
		t.Fatal("overloaded callback unexpectedly ran on shutdown")
	}
}
