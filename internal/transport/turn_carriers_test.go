//go:build !lite

package transport

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTURNHTTPPacketConnWebSocketEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server, err := NewTURNHTTPServer(ln, "/turn")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.PacketConn.Close()

	go func() {
		buf := make([]byte, 2048)
		n, addr, err := server.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = server.PacketConn.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
	}()

	pc, err := DialTURNHTTPPacketConn(context.Background(), ln.Addr().String(), false, NewDirectDialer(false, netip.Prefix{}), nil, TLSConfig{}, WebSocketConfig{Path: "/turn"})
	if err != nil {
		t.Fatalf("dial packet conn: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := pc.WriteTo([]byte("hello"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, []byte("echo:hello")) {
		t.Fatalf("unexpected echo %q", string(got))
	}
}

func TestTURNHTTPStreamConnUpgradeEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server, err := NewTURNHTTPServer(ln, "/turn")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.PacketConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := server.Listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("world"))
	}()

	conn, err := DialTURNHTTPStreamConn(context.Background(), ln.Addr().String(), false, NewDirectDialer(false, netip.Prefix{}), nil, TLSConfig{}, WebSocketConfig{Path: "/turn"})
	if err != nil {
		t.Fatalf("dial stream conn: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, []byte("world")) {
		t.Fatalf("unexpected echo %q", string(buf))
	}
	<-done
}

func TestTURNQUICPacketConnEcho(t *testing.T) {
	certMgr, err := NewCertManager(TLSConfig{}, true)
	if err != nil {
		t.Fatalf("cert manager: %v", err)
	}
	defer certMgr.Close()

	server, err := ListenTURNQUICServer([]string{"127.0.0.1"}, 0, certMgr, TLSConfig{}, "/turn")
	if err != nil {
		t.Fatalf("listen quic turn: %v", err)
	}
	defer server.Close()

	go func() {
		buf := make([]byte, 2048)
		n, addr, err := server.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = server.PacketConn.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
	}()

	pc, err := DialTURNQUICPacketConn(context.Background(), server.Addr().String(), NewDirectDialer(false, netip.Prefix{}), nil, TLSConfig{}, WebSocketConfig{Path: "/turn"})
	if err != nil {
		t.Fatalf("dial quic packet conn: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := pc.WriteTo([]byte("hello"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, []byte("echo:hello")) {
		t.Fatalf("unexpected echo %q", string(got))
	}
}
