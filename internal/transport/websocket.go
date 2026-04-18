// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WebSocketTransport is a connection-oriented transport that carries WireGuard
// packets as WebSocket binary frames (one frame = one WireGuard packet).
//
// It supports:
//   - ws://  (HTTP upgrade, plain TCP)
//   - wss:// (HTTP upgrade over TLS)
//
// In listen mode an embedded HTTP server is started that upgrades inbound
// connections; in client mode a WebSocket dial is performed.
//
// Certificate validation mirrors TLSTransport: disabled by default because
// WireGuard already authenticates peers, but can be enabled with verifyPeer.
type WebSocketTransport struct {
	name        string
	dialer      ProxyDialer
	listenAddrs []string
	certMgr     *CertManager // nil for ws://, non-nil for wss://
	tlsCfg      TLSConfig
	useTLS      bool
	// path is the HTTP path for WebSocket upgrade. Defaults to "/".
	path string
	// hostHeader overrides the Host header sent in the HTTP upgrade request.
	// When empty, the target host is used.
	hostHeader string
}

type WebSocketOption func(*WebSocketTransport)

func WithWebSocketPath(path string) WebSocketOption {
	return func(t *WebSocketTransport) {
		if path == "" {
			t.path = "/"
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		t.path = path
	}
}

func WithWebSocketHostHeader(host string) WebSocketOption {
	return func(t *WebSocketTransport) {
		t.hostHeader = host
	}
}

func WithWebSocketSNIHostname(name string) WebSocketOption {
	return func(t *WebSocketTransport) {
		t.tlsCfg.ServerSNI = OptionalString{
			set:   true,
			value: &name,
		}
	}
}

// NewWebSocketTransport creates a WebSocketTransport.
// scheme should be "http" (ws://) or "https" (wss://).
func NewWebSocketTransport(name, scheme string, dialer ProxyDialer, listenAddrs []string, certMgr *CertManager, tlsCfg TLSConfig, opts ...WebSocketOption) *WebSocketTransport {
	t := &WebSocketTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
		useTLS:      scheme == "https",
		path:        "/",
	}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t
}

func (t *WebSocketTransport) Name() string               { return t.name }
func (t *WebSocketTransport) IsConnectionOriented() bool { return true }

// Dial opens a client-mode WebSocket session to target (host:port).
func (t *WebSocketTransport) Dial(ctx context.Context, target string) (Session, error) {
	// Build underlying TCP/TLS connection through the proxy dialer.
	tcpConn, err := t.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("ws transport %s: dial %s: %w", t.name, target, err)
	}

	var conn net.Conn = tcpConn
	scheme := "ws"
	if t.useTLS {
		scheme = "wss"
		clientCfg, cfgErr := buildTLSClientConfig(t.tlsCfg, t.certMgr, serverName(target), false)
		if cfgErr != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ws transport %s: TLS config: %w", t.name, cfgErr)
		}
		tlsConn := tls.Client(tcpConn, clientCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ws transport %s: TLS handshake: %w", t.name, err)
		}
		conn = tlsConn
	}

	wsConn, err := upgradeWebSocketClient(ctx, conn, target, scheme, t.path, t.hostHeader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws transport %s: upgrade: %w", t.name, err)
	}
	return &wsSession{conn: wsConn, remote: target}, nil
}

// Listen starts a WebSocket server.
func (t *WebSocketTransport) Listen(_ context.Context, port int) (Listener, error) {
	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}

	acceptCh := make(chan wsAcceptResult, 64)
	mux := http.NewServeMux()
	mux.HandleFunc(t.path, makeWSHandler(acceptCh))

	var listeners []net.Listener
	chosen := port
	for _, addr := range addrs {
		var ln net.Listener
		var err error
		listenAddr := fmt.Sprintf("%s:%d", addr, chosen)
		if t.useTLS {
			cfg, cfgErr := buildTLSServerConfig(t.tlsCfg, t.certMgr)
			if cfgErr != nil {
				for _, l := range listeners {
					l.Close()
				}
				return nil, fmt.Errorf("ws transport %s: TLS server config: %w", t.name, cfgErr)
			}
			ln, err = tls.Listen("tcp", listenAddr, cfg)
		} else {
			ln, err = net.Listen("tcp", listenAddr)
		}
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("ws transport %s: listen %s: %w", t.name, listenAddr, err)
		}
		if chosen == 0 {
			chosen = ln.Addr().(*net.TCPAddr).Port
		}
		listeners = append(listeners, ln)
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func(l net.Listener) { _ = srv.Serve(l) }(ln)
	}
	return &wsListener{acceptCh: acceptCh, listeners: listeners}, nil
}

// --- WebSocket framing (minimal, no external dependency) -------------------

// wsConn is a minimal WebSocket connection that handles binary frames.
// It uses the raw net.Conn after the HTTP upgrade and implements the
// RFC 6455 binary frame format (no compression, no fragmentation).
type wsConn struct {
	conn   net.Conn
	remote string
	// client-side connections must mask payload bytes (RFC 6455 §5.3).
	clientSide bool
}

type wsSession struct {
	conn   *wsConn
	remote string
}

func (s *wsSession) ReadPacket() ([]byte, error)  { return s.conn.ReadFrame() }
func (s *wsSession) WritePacket(pkt []byte) error { return s.conn.WriteFrame(pkt) }
func (s *wsSession) RemoteAddr() string           { return s.remote }
func (s *wsSession) Close() error                 { return s.conn.conn.Close() }

// ReadFrame reads one binary WebSocket frame payload.
func (w *wsConn) ReadFrame() ([]byte, error) {
	// Read 2-byte base header.
	var hdr [2]byte
	if _, err := io.ReadFull(w.conn, hdr[:]); err != nil {
		return nil, err
	}
	// fin := (hdr[0] & 0x80) != 0
	opcode := hdr[0] & 0x0f
	masked := (hdr[1] & 0x80) != 0
	payLen := int(hdr[1] & 0x7f)

	// Extended payload length.
	switch payLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.conn, ext[:]); err != nil {
			return nil, err
		}
		payLen = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.conn, ext[:]); err != nil {
			return nil, err
		}
		payLen = 0
		for _, b := range ext {
			payLen = payLen<<8 | int(b)
		}
	}

	// Masking key.
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.conn, mask[:]); err != nil {
			return nil, err
		}
	}

	// Payload.
	buf := make([]byte, payLen)
	if _, err := io.ReadFull(w.conn, buf); err != nil {
		return nil, err
	}
	if masked {
		for i := range buf {
			buf[i] ^= mask[i%4]
		}
	}

	// Connection close or ping.
	switch opcode {
	case 0x8: // close
		return nil, io.EOF
	case 0x9: // ping → respond with pong (best-effort)
		_ = w.writeRaw(0xa, buf)
		return w.ReadFrame() // read next frame
	}
	return buf, nil
}

// WriteFrame writes one binary WebSocket frame.
func (w *wsConn) WriteFrame(data []byte) error {
	return w.writeRaw(0x2, data) // opcode 0x2 = binary
}

func (w *wsConn) writeRaw(opcode byte, data []byte) error {
	n := len(data)
	var hdr []byte
	if w.clientSide {
		// Client frames are masked.
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		hdr = wsHeader(opcode, n, true, mask)
		frame := make([]byte, len(hdr)+n)
		copy(frame, hdr)
		for i := 0; i < n; i++ {
			frame[len(hdr)+i] = data[i] ^ mask[i%4]
		}
		_, err := w.conn.Write(frame)
		return err
	}
	hdr = wsHeader(opcode, n, false, [4]byte{})
	frame := make([]byte, len(hdr)+n)
	copy(frame, hdr)
	copy(frame[len(hdr):], data)
	_, err := w.conn.Write(frame)
	return err
}

func wsHeader(opcode byte, payLen int, masked bool, mask [4]byte) []byte {
	var b0 byte = 0x80 | opcode // FIN + opcode
	var b1 byte
	if masked {
		b1 = 0x80
	}
	var hdr []byte
	switch {
	case payLen < 126:
		hdr = []byte{b0, b1 | byte(payLen)}
	case payLen <= 0xFFFF:
		hdr = []byte{b0, b1 | 126, byte(payLen >> 8), byte(payLen)}
	default:
		hdr = []byte{b0, b1 | 127,
			0, 0, 0, 0,
			byte(payLen >> 24), byte(payLen >> 16), byte(payLen >> 8), byte(payLen),
		}
	}
	if masked {
		hdr = append(hdr, mask[:]...)
	}
	return hdr
}

func websocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// upgradeWebSocketClient performs the HTTP Upgrade handshake on conn.
func upgradeWebSocketClient(ctx context.Context, conn net.Conn, target, scheme, path, hostHeader string) (*wsConn, error) {
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)
	host, _, _ := net.SplitHostPort(target)
	if hostHeader == "" {
		hostHeader = host
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = hostHeader
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("ws upgrade failed: %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("ws upgrade failed: unexpected Upgrade header %q", resp.Header.Get("Upgrade"))
	}
	if !headerContainsToken(resp.Header, "Connection", "Upgrade") {
		return nil, fmt.Errorf("ws upgrade failed: missing Connection: Upgrade")
	}
	wantAccept := websocketAcceptKey(key)
	if resp.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		return nil, fmt.Errorf("ws upgrade failed: invalid Sec-WebSocket-Accept")
	}
	var wrapped net.Conn = conn
	if br.Buffered() > 0 {
		wrapped = &bufferedConn{Conn: conn, r: br}
	}
	return &wsConn{conn: wrapped, remote: target, clientSide: true}, nil
}

// makeWSHandler returns an http.HandlerFunc that upgrades connections and
// feeds them into acceptCh.
func makeWSHandler(acceptCh chan wsAcceptResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "websocket upgrade required", http.StatusBadRequest)
			return
		}
		if !headerContainsToken(r.Header, "Connection", "Upgrade") {
			http.Error(w, "connection upgrade required", http.StatusBadRequest)
			return
		}
		key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
		if key == "" {
			http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		// Send 101 switching protocols.
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAcceptKey(key))
		ws := &wsConn{conn: conn, remote: conn.RemoteAddr().String(), clientSide: false}
		select {
		case acceptCh <- wsAcceptResult{ws: ws}:
		default:
			conn.Close()
		}
	}
}

type wsAcceptResult struct {
	ws  *wsConn
	err error
}

// wsListener wraps the acceptCh from the embedded HTTP servers.
type wsListener struct {
	acceptCh  chan wsAcceptResult
	listeners []net.Listener
}

func (l *wsListener) Accept(ctx context.Context) (Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		if r.err != nil {
			return nil, r.err
		}
		return &wsSession{conn: r.ws, remote: r.ws.remote}, nil
	}
}

func (l *wsListener) Addr() net.Addr {
	if len(l.listeners) == 0 {
		return nil
	}
	return l.listeners[0].Addr()
}

func (l *wsListener) Close() error {
	var first error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
