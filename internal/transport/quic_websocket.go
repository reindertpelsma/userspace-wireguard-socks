// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUICWebSocketTransport carries WireGuard packets as WebSocket binary frames
// over an HTTP/3 bidirectional stream (RFC 9220 — WebSocket over HTTP/3).
//
// Unlike QUICTransport (which uses WebTransport datagrams), this transport
// runs WebSocket framing over the reliable HTTP/3 stream. This makes it
// compatible with reverse proxies (e.g. Cloudflare) that speak RFC 9220 on
// the QUIC side even when the origin serves plain HTTPS WebSocket.
//
// Protocol:
//   Client → extended CONNECT :protocol=websocket over HTTP/3 stream
//   Both sides then exchange standard RFC 6455 binary frames on that stream.
type QUICWebSocketTransport struct {
	name        string
	dialer      ProxyDialer
	listenAddrs []string
	certMgr     *CertManager
	tlsCfg      TLSConfig
	path        string
	connectHost string
	hostHeader  string
}

func NewQUICWebSocketTransport(
	name string,
	dialer ProxyDialer,
	listenAddrs []string,
	certMgr *CertManager,
	tlsCfg TLSConfig,
	path, hostHeader, connectHost string,
) *QUICWebSocketTransport {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &QUICWebSocketTransport{
		name:        name,
		dialer:      dialer,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
		path:        path,
		hostHeader:  hostHeader,
		connectHost: connectHost,
	}
}

func (t *QUICWebSocketTransport) Name() string               { return t.name }
func (t *QUICWebSocketTransport) IsConnectionOriented() bool { return true }

// Dial opens a RFC 9220 WebSocket-over-HTTP/3 session to target.
func (t *QUICWebSocketTransport) Dial(ctx context.Context, target string) (Session, error) {
	tlsCfg, err := buildTLSClientConfig(t.tlsCfg, t.certMgr, serverName(target), false)
	if err != nil {
		return nil, fmt.Errorf("quic-ws transport %s: TLS config: %w", t.name, err)
	}
	// Ensure ALPN advertises h3 for HTTP/3.
	tlsCfg.NextProtos = appendIfMissing(tlsCfg.NextProtos, "h3")

	connectTarget := target
	if t.connectHost != "" {
		_, port, _ := net.SplitHostPort(target)
		connectTarget = net.JoinHostPort(t.connectHost, port)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", connectTarget)
	if err != nil {
		return nil, fmt.Errorf("quic-ws transport %s: resolve %s: %w", t.name, connectTarget, err)
	}

	pc, _, err := t.dialer.DialPacket(ctx, connectTarget)
	if err != nil {
		return nil, fmt.Errorf("quic-ws transport %s: open udp: %w", t.name, err)
	}
	// Hide SyscallConn to avoid PMTU probing in gVisor environments.
	safePC := quicClientPacketConn{PacketConn: pc}

	qconn, err := quic.DialEarly(ctx, safePC, remoteAddr, tlsCfg, &quic.Config{
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("quic-ws transport %s: quic dial: %w", t.name, err)
	}

	tr := &http3.Transport{}
	clientConn := tr.NewClientConn(qconn)

	// authority is the :authority / Host for domain fronting inner host.
	authority := target
	if t.hostHeader != "" {
		authority = t.hostHeader
	}

	reqStream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, fmt.Errorf("quic-ws transport %s: open stream: %w", t.name, err)
	}

	// RFC 9220: extended CONNECT with :protocol=websocket.
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+authority+t.path, nil)
	req.Proto = "websocket"
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := reqStream.SendRequestHeader(req); err != nil {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, fmt.Errorf("quic-ws transport %s: send request: %w", t.name, err)
	}
	resp, err := reqStream.ReadResponse()
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, fmt.Errorf("quic-ws transport %s: read response: %w", t.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, fmt.Errorf("quic-ws transport %s: server returned %s", t.name, resp.Status)
	}

	// reqStream now carries the bidirectional stream; use WS framing on top.
	ws := &wsConn{conn: &quicWSConn{str: reqStream}, remote: target, clientSide: true}
	return &quicWSSession{
		ws:     ws,
		qconn:  qconn,
		pc:     pc,
		remote: target,
	}, nil
}

// Listen starts a QUIC HTTP/3 server that accepts RFC 9220 WebSocket upgrades.
func (t *QUICWebSocketTransport) Listen(_ context.Context, port int) (Listener, error) {
	if t.certMgr == nil {
		return nil, fmt.Errorf("quic-ws transport %s: server certificate manager is required", t.name)
	}

	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}

	acceptCh := make(chan quicWSAcceptResult, 64)
	closeCh := make(chan struct{})
	var (
		conns   []net.PacketConn
		servers []*http3.Server
	)
	chosen := port

	for _, addr := range addrs {
		serverTLS, err := buildTLSServerConfig(t.tlsCfg, t.certMgr)
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("quic-ws transport %s: TLS server config: %w", t.name, err)
		}

		mux := http.NewServeMux()
		mux.HandleFunc(t.path, makeQUICWSHandler(acceptCh, closeCh))

		h3 := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(serverTLS),
			Handler:   mux,
		}

		pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("quic-ws transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
				chosen = udpAddr.Port
			}
		}

		conns = append(conns, pc)
		servers = append(servers, h3)
		go func(s *http3.Server, c net.PacketConn) {
			_ = s.Serve(c)
		}(h3, pc)
	}

	return &quicWSListener{
		acceptCh: acceptCh,
		closeCh:  closeCh,
		conns:    conns,
		servers:  servers,
	}, nil
}

// makeQUICWSHandler returns an http.Handler for RFC 9220 WebSocket over HTTP/3.
// It handles extended CONNECT requests with :protocol=websocket.
func makeQUICWSHandler(acceptCh chan quicWSAcceptResult, closeCh chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RFC 9220: method must be CONNECT, Proto (from :protocol header) must be "websocket".
		if r.Method != http.MethodConnect || r.Proto != "websocket" {
			http.Error(w, "extended CONNECT with protocol=websocket required", http.StatusBadRequest)
			return
		}
		// Flush 200 status to open the bidirectional stream.
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Hijack the HTTP/3 stream for raw bidirectional use.
		// In http3, the ResponseWriter implements http.Hijacker for CONNECT streams.
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		ws := &wsConn{conn: conn, remote: r.RemoteAddr, clientSide: false}
		sess := &quicWSSession{ws: ws, remote: r.RemoteAddr}
		select {
		case acceptCh <- quicWSAcceptResult{sess: sess}:
		case <-closeCh:
			_ = conn.Close()
		}
	}
}

// --- quicWSConn adapts http3.RequestStream to net.Conn for wsConn ---

// quicWSConn wraps an http3.RequestStream so it satisfies net.Conn.
// Deadlines are controlled at the QUIC connection level; per-stream deadlines
// are forwarded to the RequestStream's SetDeadline method.
type quicWSConn struct {
	str *http3.RequestStream
}

var _ net.Conn = (*quicWSConn)(nil)

func (c *quicWSConn) Read(b []byte) (int, error)        { return c.str.Read(b) }
func (c *quicWSConn) Write(b []byte) (int, error)       { return c.str.Write(b) }
func (c *quicWSConn) Close() error                      { return c.str.Close() }
func (c *quicWSConn) LocalAddr() net.Addr               { return quicStreamAddr("local") }
func (c *quicWSConn) RemoteAddr() net.Addr              { return quicStreamAddr("remote") }
func (c *quicWSConn) SetDeadline(t time.Time) error     { return c.str.SetDeadline(t) }
func (c *quicWSConn) SetReadDeadline(t time.Time) error { return c.str.SetReadDeadline(t) }
func (c *quicWSConn) SetWriteDeadline(t time.Time) error { return c.str.SetWriteDeadline(t) }

type quicStreamAddr string

func (a quicStreamAddr) Network() string { return "quic" }
func (a quicStreamAddr) String() string  { return string(a) }

// --- quicWSSession --------------------------------------------------------

type quicWSSession struct {
	ws     *wsConn
	qconn  *quic.Conn  // nil on server side
	pc     net.PacketConn // nil on server side
	remote string
	once   sync.Once
}

func (s *quicWSSession) ReadPacket() ([]byte, error)  { return s.ws.ReadFrame() }
func (s *quicWSSession) WritePacket(pkt []byte) error { return s.ws.WriteFrame(pkt) }
func (s *quicWSSession) RemoteAddr() string           { return s.remote }

func (s *quicWSSession) Close() error {
	var first error
	s.once.Do(func() {
		if err := s.ws.conn.Close(); err != nil {
			first = err
		}
		if s.qconn != nil {
			if err := s.qconn.CloseWithError(0, ""); err != nil && first == nil {
				first = err
			}
		}
		if s.pc != nil {
			if err := s.pc.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

// --- quicWSListener -------------------------------------------------------

type quicWSAcceptResult struct {
	sess *quicWSSession
	err  error
}

type quicWSListener struct {
	acceptCh  chan quicWSAcceptResult
	closeCh   chan struct{}
	conns     []net.PacketConn
	servers   []*http3.Server
	closeOnce sync.Once
}

func (l *quicWSListener) Accept(ctx context.Context) (Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closeCh:
		return nil, net.ErrClosed
	case res := <-l.acceptCh:
		if res.err != nil {
			return nil, res.err
		}
		return res.sess, nil
	}
}

func (l *quicWSListener) Addr() net.Addr {
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0].LocalAddr()
}

func (l *quicWSListener) Close() error {
	var first error
	l.closeOnce.Do(func() {
		close(l.closeCh)
		for _, s := range l.servers {
			if err := s.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, c := range l.conns {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

// appendIfMissing adds s to slice only when not already present.
func appendIfMissing(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
