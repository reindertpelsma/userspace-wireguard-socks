// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

// URLTransport is a connection-oriented transport that auto-negotiates the
// best available protocol for a given URL, trying in order:
//
//  1. QUIC WebTransport (HTTP/3 datagrams)   — fastest, lowest overhead
//  2. QUIC WebSocket (RFC 9220)              — QUIC stream + WS framing
//  3. HTTPS WebSocket (TLS + TCP)            — broadest compatibility
//
// For http:// URLs only plain WebSocket (TCP) is tried.
// In listen mode the URL transport serves HTTPS / HTTP WebSocket and, for
// HTTPS URLs, both QUIC WebTransport and QUIC WebSocket (RFC 9220) on the
// same HTTP/3 path and UDP port.
type URLTransport struct {
	name        string
	listenAddrs []string
	certMgr     *CertManager
	tlsCfg      TLSConfig
	path        string
	connectHost string
	hostHeader  string
	useTLS      bool

	// sub-transports used for dialing
	wtTransport  *QUICTransport          // QUIC WebTransport
	qwsTransport *QUICWebSocketTransport // QUIC WebSocket (RFC 9220)
	wsTransport  *WebSocketTransport     // HTTPS/HTTP WebSocket

}

// NewURLTransport creates a URLTransport from a base URL, e.g.
// "https://example.com/wg" or "http://example.com/wg".
//
//   - dialer is used for all sub-transports (TCP / UDP packet conn)
//   - connectHost overrides DNS + connect host (domain fronting outer)
//   - hostHeader overrides HTTP :authority / Host (domain fronting inner)
//   - TLS settings (SNI, cert verification, cert files) from tlsCfg
func NewURLTransport(
	name string,
	rawURL string,
	dialer ProxyDialer,
	listenAddrs []string,
	certMgr *CertManager,
	tlsCfg TLSConfig,
	connectHost, hostHeader string,
	advertiseHTTP3 bool,
) (*URLTransport, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url transport %q: invalid URL %q: %w", name, rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("url transport %q: URL scheme must be http or https, got %q", name, scheme)
	}
	useTLS := scheme == "https"
	path := u.Path
	if path == "" {
		path = "/"
	}

	t := &URLTransport{
		name:        name,
		listenAddrs: listenAddrs,
		certMgr:     certMgr,
		tlsCfg:      tlsCfg,
		path:        path,
		connectHost: connectHost,
		hostHeader:  hostHeader,
		useTLS:      useTLS,
	}

	wsScheme := "http"
	if useTLS {
		wsScheme = "https"
	}
	wsOpts := []WebSocketOption{
		WithWebSocketPath(path),
		WithWebSocketHostHeader(hostHeader),
		WithWebSocketConnectHost(connectHost),
	}
	if advertiseHTTP3 {
		wsOpts = append(wsOpts, WithWebSocketAdvertiseHTTP3(true))
	}
	t.wsTransport = NewWebSocketTransport(name+"-ws", wsScheme, dialer, listenAddrs, certMgr, tlsCfg, wsOpts...)

	if useTLS {
		t.wtTransport = NewQUICTransport(name+"-wt", dialer, listenAddrs, certMgr, tlsCfg, path, hostHeader, connectHost)
		t.qwsTransport = NewQUICWebSocketTransport(name+"-qws", dialer, listenAddrs, certMgr, tlsCfg, path, hostHeader, connectHost)
	}

	return t, nil
}

func (t *URLTransport) Name() string               { return t.name }
func (t *URLTransport) IsConnectionOriented() bool { return true }

// Dial auto-negotiates the best protocol for target.
//
// For HTTPS URLs the order is:
//  1. QUIC WebTransport  (fastest)
//  2. QUIC WebSocket RFC 9220
//  3. HTTPS WebSocket    (most compatible)
//
// For HTTP URLs only plain WebSocket is tried.
func (t *URLTransport) Dial(ctx context.Context, target string) (Session, error) {
	if !t.useTLS {
		return t.wsTransport.Dial(ctx, target)
	}

	// Try QUIC WebTransport first.
	if t.wtTransport != nil {
		sess, err := t.wtTransport.Dial(ctx, target)
		if err == nil {
			return &urlSession{Session: sess, proto: "quic-wt"}, nil
		}
	}

	// Try QUIC WebSocket (RFC 9220).
	if t.qwsTransport != nil {
		sess, err := t.qwsTransport.Dial(ctx, target)
		if err == nil {
			return &urlSession{Session: sess, proto: "quic-ws"}, nil
		}
	}

	// Fall back to HTTPS WebSocket over TLS + TCP.
	sess, err := t.wsTransport.Dial(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("url transport %s: all protocols failed for %s: %w", t.name, target, err)
	}
	return &urlSession{Session: sess, proto: "https-ws"}, nil
}

// Listen starts listeners for all three protocols simultaneously on the same
// port so any client variant can connect.
//
// For http:// URLs only WebSocket is served.
// For https:// URLs: QUIC WebTransport + QUIC WebSocket + TLS/TCP WebSocket
// are served together.
func (t *URLTransport) Listen(ctx context.Context, port int) (Listener, error) {
	// TCP/TLS WebSocket listener (serves all HTTP-based WS upgrades).
	wsLn, err := t.wsTransport.Listen(ctx, port)
	if err != nil {
		return nil, fmt.Errorf("url transport %s: ws listen: %w", t.name, err)
	}

	if !t.useTLS {
		return wsLn, nil
	}

	quicLn, err := t.listenCombinedQUIC(ctx, port)
	if err != nil {
		_ = wsLn.Close()
		return nil, fmt.Errorf("url transport %s: quic listen: %w", t.name, err)
	}

	return newURLMultiListener(wsLn, quicLn, nil), nil
}

func (t *URLTransport) listenCombinedQUIC(_ context.Context, port int) (Listener, error) {
	if t.certMgr == nil {
		return nil, fmt.Errorf("url transport %s: certificate manager is required for https", t.name)
	}
	addrs := t.listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	acceptCh := make(chan urlCombinedQUICAcceptResult, 64)
	closeCh := make(chan struct{})
	var (
		conns   []net.PacketConn
		servers []*webtransport.Server
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
			return nil, fmt.Errorf("url transport %s: TLS server config: %w", t.name, err)
		}

		mux := http.NewServeMux()
		h3 := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(serverTLS),
			Handler:   mux,
		}
		server := &webtransport.Server{H3: h3}
		webtransport.ConfigureHTTP3Server(h3)
		mux.HandleFunc(t.path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect && r.Proto == "websocket" {
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				hj, ok := w.(http.Hijacker)
				if !ok {
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					return
				}
				ws := &wsConn{conn: conn, remote: r.RemoteAddr, clientSide: false}
				sess := &urlSession{
					Session: &quicWSSession{ws: ws, remote: r.RemoteAddr},
					proto:   "quic-ws",
				}
				_ = tryEnqueueAccept(acceptCh, urlCombinedQUICAcceptResult{sess: sess}, closeCh,
					func() { _ = conn.Close() },
					func() { _ = conn.Close() },
				)
				return
			}
			sess, err := server.Upgrade(w, r)
			if err != nil {
				return
			}
			item := urlCombinedQUICAcceptResult{
				sess: &urlSession{Session: &quicSession{sess: sess}, proto: "quic-wt"},
			}
			if tryEnqueueAccept(acceptCh, item, closeCh,
				func() { _ = sess.CloseWithError(0, "closed") },
				func() { _ = sess.CloseWithError(0, "overloaded") },
			) {
				<-sess.Context().Done()
			}
		})

		pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("url transport %s: listen %s:%d: %w", t.name, addr, port, err)
		}
		if chosen == 0 {
			if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
				chosen = udpAddr.Port
			}
		}
		conns = append(conns, pc)
		servers = append(servers, server)
		go func(s *webtransport.Server, c net.PacketConn) {
			_ = s.Serve(c)
		}(server, pc)
	}

	return &urlCombinedQUICListener{
		acceptCh: acceptCh,
		closeCh:  closeCh,
		conns:    conns,
		servers:  servers,
	}, nil
}

// --- urlSession wraps a Session with protocol metadata -------------------

type urlSession struct {
	Session
	proto string
}

func (s *urlSession) RemoteAddr() string { return s.Session.RemoteAddr() }

type urlCombinedQUICAcceptResult struct {
	sess Session
	err  error
}

type urlCombinedQUICListener struct {
	acceptCh  chan urlCombinedQUICAcceptResult
	closeCh   chan struct{}
	conns     []net.PacketConn
	servers   []*webtransport.Server
	closeOnce sync.Once
}

func (l *urlCombinedQUICListener) Accept(ctx context.Context) (Session, error) {
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

func (l *urlCombinedQUICListener) Addr() net.Addr {
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0].LocalAddr()
}

func (l *urlCombinedQUICListener) Close() error {
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

// --- urlMultiListener fans accepted sessions from all three listeners ----

type urlMultiListener struct {
	wsLn  Listener
	wtLn  Listener
	qwsLn Listener
	addr  net.Addr
}

func newURLMultiListener(wsLn, wtLn, qwsLn Listener) *urlMultiListener {
	return &urlMultiListener{wsLn: wsLn, wtLn: wtLn, qwsLn: qwsLn, addr: wsLn.Addr()}
}

func (l *urlMultiListener) Accept(ctx context.Context) (Session, error) {
	type result struct {
		sess Session
		err  error
	}
	ch := make(chan result, 3)
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	accept := func(ln Listener, proto string) {
		sess, err := ln.Accept(ctx2)
		if err != nil {
			select {
			case ch <- result{err: err}:
			case <-ctx2.Done():
			}
			return
		}
		select {
		case ch <- result{sess: &urlSession{Session: sess, proto: proto}}:
		case <-ctx2.Done():
			_ = sess.Close()
		}
	}
	go accept(l.wsLn, "https-ws")
	go accept(l.wtLn, "quic-wt")
	if l.qwsLn != nil {
		go accept(l.qwsLn, "quic-ws")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.sess, r.err
	}
}

func (l *urlMultiListener) Addr() net.Addr { return l.addr }

func (l *urlMultiListener) Close() error {
	var first error
	for _, ln := range []Listener{l.wsLn, l.wtLn, l.qwsLn} {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
