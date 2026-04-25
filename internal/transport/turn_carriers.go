// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

const turnWebSocketSubprotocol = "turn"

// maxTurnCarrierPeers caps the number of concurrent carrier-side peers a
// single turnMuxPacketConn will track. One entry is created per WebSocket /
// HTTP-upgrade / WebTransport session, so this bounds the memory + goroutine
// footprint visible from outside the host. Sized to comfortably exceed any
// realistic relay fan-out while still preventing trivial accept-loop floods.
const maxTurnCarrierPeers = 4096

// errTurnCarrierFull is returned by addPeer when the peer table is at
// capacity. Callers reject the upgrade.
var errTurnCarrierFull = errors.New("turn carrier: too many concurrent peers")

// TurnCarrierDropsTotal lives in turn_carriers_metrics.go so the metrics
// reference is available even in lite builds (where no TURN carriers exist
// and the counter therefore stays zero).

type turnMuxPacketConn struct {
	local     net.Addr
	closeFn   func() error
	closeOnce sync.Once

	mu    sync.RWMutex
	peers map[string]*turnPacketPeer

	readCh chan turnPacketDatagram

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	closedCh      chan struct{}

	// dropMu/drops/lastDropLog tracks frames discarded because readCh was
	// full so we can emit a single warning per second instead of either
	// silently losing them (the bug) or log-spamming under load.
	dropMu      sync.Mutex
	drops       uint64
	lastDropLog time.Time
}

type turnPacketPeer struct {
	addr  net.Addr
	write func([]byte) error
	close func() error
}

type turnPacketDatagram struct {
	payload []byte
	addr    net.Addr
}

func newTurnMuxPacketConn(local net.Addr, closeFn func() error) *turnMuxPacketConn {
	return &turnMuxPacketConn{
		local:    local,
		closeFn:  closeFn,
		peers:    make(map[string]*turnPacketPeer),
		readCh:   make(chan turnPacketDatagram, 256),
		closedCh: make(chan struct{}),
	}
}

func (c *turnMuxPacketConn) addPeer(addr net.Addr, write func([]byte) error, closeFn func() error) error {
	key := addr.String()
	c.mu.Lock()
	if old := c.peers[key]; old != nil && old.close != nil {
		_ = old.close()
		delete(c.peers, key)
	}
	if len(c.peers) >= maxTurnCarrierPeers {
		c.mu.Unlock()
		return errTurnCarrierFull
	}
	c.peers[key] = &turnPacketPeer{addr: addr, write: write, close: closeFn}
	c.mu.Unlock()
	return nil
}

func (c *turnMuxPacketConn) removePeer(addr net.Addr) {
	if addr == nil {
		return
	}
	key := addr.String()
	c.mu.Lock()
	delete(c.peers, key)
	c.mu.Unlock()
}

func (c *turnMuxPacketConn) deliver(addr net.Addr, payload []byte) {
	pkt := turnPacketDatagram{payload: append([]byte(nil), payload...), addr: addr}
	select {
	case c.readCh <- pkt:
	default:
		c.recordDrop()
	}
}

func (c *turnMuxPacketConn) recordDrop() {
	TurnCarrierDropsTotal.Add(1)
	c.dropMu.Lock()
	c.drops++
	now := time.Now()
	dropCount := c.drops
	logNow := now.Sub(c.lastDropLog) >= time.Second
	if logNow {
		c.lastDropLog = now
		c.drops = 0
	}
	c.dropMu.Unlock()
	if logNow {
		fmt.Fprintf(os.Stderr, "turn carrier: dropped %d datagrams (readCh full)\n", dropCount)
	}
}

func (c *turnMuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var deadline <-chan time.Time
	if t := c.readDeadlineValue(); !t.IsZero() {
		timer := time.NewTimer(time.Until(t))
		defer timer.Stop()
		deadline = timer.C
	}
	select {
	case <-c.closedCh:
		return 0, nil, net.ErrClosed
	case <-deadline:
		return 0, nil, &net.OpError{Op: "read", Net: "turn", Err: osErrDeadlineExceeded{}}
	case pkt := <-c.readCh:
		n := copy(p, pkt.payload)
		if n < len(pkt.payload) {
			return n, pkt.addr, io.ErrShortBuffer
		}
		return n, pkt.addr, nil
	}
}

func (c *turnMuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("turn carrier: destination address is required")
	}
	c.mu.RLock()
	peer := c.peers[addr.String()]
	c.mu.RUnlock()
	if peer == nil {
		return 0, fmt.Errorf("turn carrier: unknown peer %s", addr.String())
	}
	if err := peer.write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *turnMuxPacketConn) Close() error {
	var first error
	c.closeOnce.Do(func() {
		close(c.closedCh)
		c.mu.Lock()
		for _, peer := range c.peers {
			if peer.close != nil {
				if err := peer.close(); err != nil && first == nil {
					first = err
				}
			}
		}
		c.peers = map[string]*turnPacketPeer{}
		c.mu.Unlock()
		if c.closeFn != nil {
			if err := c.closeFn(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

func (c *turnMuxPacketConn) LocalAddr() net.Addr { return c.local }

func (c *turnMuxPacketConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *turnMuxPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *turnMuxPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *turnMuxPacketConn) readDeadlineValue() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

type osErrDeadlineExceeded struct{}

func (osErrDeadlineExceeded) Error() string   { return "i/o timeout" }
func (osErrDeadlineExceeded) Timeout() bool   { return true }
func (osErrDeadlineExceeded) Temporary() bool { return true }

type turnStreamListener struct {
	addr    net.Addr
	ch      chan net.Conn
	closeFn func() error
	closed  chan struct{}
	once    sync.Once
}

func newTurnStreamListener(addr net.Addr, closeFn func() error) *turnStreamListener {
	return &turnStreamListener{
		addr:    addr,
		ch:      make(chan net.Conn, 64),
		closeFn: closeFn,
		closed:  make(chan struct{}),
	}
}

func (l *turnStreamListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.ch:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *turnStreamListener) Close() error {
	var first error
	l.once.Do(func() {
		close(l.closed)
		if l.closeFn != nil {
			first = l.closeFn()
		}
	})
	return first
}

func (l *turnStreamListener) Addr() net.Addr { return l.addr }

type TURNHTTPServer struct {
	PacketConn net.PacketConn
	Listener   net.Listener
	addr       net.Addr

	closeOnce sync.Once
	closeFn   func() error
}

func (s *TURNHTTPServer) Addr() net.Addr { return s.addr }

func NewTURNHTTPServer(base net.Listener, path string) (*TURNHTTPServer, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var (
		server    *http.Server
		packetMux *turnMuxPacketConn
		streamLn  *turnStreamListener
	)
	closeFn := func() error {
		var first error
		if server != nil {
			if err := server.Close(); err != nil && first == nil {
				first = err
			}
		}
		if base != nil {
			if err := base.Close(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	packetMux = newTurnMuxPacketConn(base.Addr(), closeFn)
	streamLn = newTurnStreamListener(base.Addr(), closeFn)
	mux := http.NewServeMux()
	mux.HandleFunc(path, makeTURNHTTPUpgradeHandler(packetMux, streamLn))
	server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() { _ = server.Serve(base) }()
	return &TURNHTTPServer{
		PacketConn: packetMux,
		Listener:   streamLn,
		addr:       base.Addr(),
		closeFn:    closeFn,
	}, nil
}

func makeTURNHTTPUpgradeHandler(packetConn *turnMuxPacketConn, streamLn *turnStreamListener) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if !headerContainsToken(r.Header, "Connection", "Upgrade") {
			http.Error(w, "connection upgrade required", http.StatusBadRequest)
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
		upgrade := strings.TrimSpace(r.Header.Get("Upgrade"))
		switch {
		case strings.EqualFold(upgrade, "websocket"):
			key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
			if key == "" {
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nmissing Sec-WebSocket-Key")
				_ = conn.Close()
				return
			}
			if proto := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Protocol")); proto != "" && !headerTokenMatches(proto, turnWebSocketSubprotocol) {
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSec-WebSocket-Protocol must include turn")
				_ = conn.Close()
				return
			}
			ws := &wsConn{conn: conn, remote: conn.RemoteAddr().String(), clientSide: false}
			if err := packetConn.addPeer(conn.RemoteAddr(), ws.WriteFrame, conn.Close); err != nil {
				_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nturn carrier at capacity")
				_ = conn.Close()
				return
			}
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n", websocketAcceptKey(key), turnWebSocketSubprotocol)
			go pumpTURNWebSocketFrames(packetConn, conn.RemoteAddr(), ws)
		case strings.EqualFold(upgrade, "TURN"):
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: TURN\r\nSec-TURN-Transport: tcp\r\n\r\n")
			select {
			case <-streamLn.closed:
				_ = conn.Close()
			case streamLn.ch <- conn:
			default:
				_ = conn.Close()
			}
		default:
			_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nwebsocket or TURN upgrade required on this path")
			_ = conn.Close()
		}
	}
}

func pumpTURNWebSocketFrames(packetConn *turnMuxPacketConn, addr net.Addr, ws *wsConn) {
	defer func() {
		packetConn.removePeer(addr)
		_ = ws.conn.Close()
	}()
	for {
		pkt, err := ws.ReadFrame()
		if err != nil {
			return
		}
		packetConn.deliver(addr, pkt)
	}
}

func DialTURNHTTPStreamConn(ctx context.Context, target string, useTLS bool, dialer ProxyDialer, certMgr *CertManager, tlsCfg TLSConfig, wsCfg WebSocketConfig) (net.Conn, error) {
	connectAddr := target
	if wsCfg.ConnectHost != "" {
		_, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, fmt.Errorf("turn http stream: invalid target %q: %w", target, err)
		}
		connectAddr = net.JoinHostPort(wsCfg.ConnectHost, port)
	}
	conn, err := dialer.DialContext(ctx, "tcp", connectAddr)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
		clientCfg, err := buildTLSClientConfig(tlsCfg, certMgr, serverName(target), false)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		tlsConn := tls.Client(conn, clientCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	path := wsCfg.Path
	if path == "" {
		path = "/turn"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	host := target
	if wsCfg.HostHeader != "" {
		host = wsCfg.HostHeader
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+path, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Host = host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "TURN")
	req.Header.Set("Sec-TURN-Transport", "tcp")
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("TURN upgrade failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "TURN") {
		_ = conn.Close()
		return nil, fmt.Errorf("TURN upgrade failed: unexpected Upgrade header %q", resp.Header.Get("Upgrade"))
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

func DialTURNHTTPPacketConn(ctx context.Context, target string, useTLS bool, dialer ProxyDialer, certMgr *CertManager, tlsCfg TLSConfig, wsCfg WebSocketConfig) (net.PacketConn, error) {
	connectAddr := target
	if wsCfg.ConnectHost != "" {
		_, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, fmt.Errorf("turn ws: invalid target %q: %w", target, err)
		}
		connectAddr = net.JoinHostPort(wsCfg.ConnectHost, port)
	}
	conn, err := dialer.DialContext(ctx, "tcp", connectAddr)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
		clientCfg, err := buildTLSClientConfig(tlsCfg, certMgr, serverName(target), false)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		tlsConn := tls.Client(conn, clientCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	path := wsCfg.Path
	if path == "" {
		path = "/turn"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	host := target
	if wsCfg.HostHeader != "" {
		host = wsCfg.HostHeader
	}
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+path, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Host = host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Protocol", turnWebSocketSubprotocol)
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("turn websocket upgrade failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	ws := &wsConn{conn: &bufferedConn{Conn: conn, r: br}, remote: target, clientSide: true}
	return &turnDatagramPacketConn{
		local:  conn.LocalAddr(),
		remote: conn.RemoteAddr(),
		readFn: ws.ReadFrame,
		writeFn: func(pkt []byte) error {
			return ws.WriteFrame(pkt)
		},
		closeFn:       conn.Close,
		setDeadlineFn: func(t time.Time) error { return conn.SetDeadline(t) },
		setReadDeadlineFn: func(t time.Time) error {
			return conn.SetReadDeadline(t)
		},
		setWriteDeadlineFn: func(t time.Time) error {
			return conn.SetWriteDeadline(t)
		},
	}, nil
}

type turnDatagramPacketConn struct {
	local, remote      net.Addr
	readFn             func() ([]byte, error)
	writeFn            func([]byte) error
	closeFn            func() error
	setDeadlineFn      func(time.Time) error
	setReadDeadlineFn  func(time.Time) error
	setWriteDeadlineFn func(time.Time) error
}

func (c *turnDatagramPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := c.readFn()
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt)
	if n < len(pkt) {
		return n, c.remote, io.ErrShortBuffer
	}
	return n, c.remote, nil
}

func (c *turnDatagramPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := c.writeFn(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *turnDatagramPacketConn) Close() error        { return c.closeFn() }
func (c *turnDatagramPacketConn) LocalAddr() net.Addr { return c.local }
func (c *turnDatagramPacketConn) SetDeadline(t time.Time) error {
	if c.setDeadlineFn == nil {
		return nil
	}
	return c.setDeadlineFn(t)
}
func (c *turnDatagramPacketConn) SetReadDeadline(t time.Time) error {
	if c.setReadDeadlineFn == nil {
		return nil
	}
	return c.setReadDeadlineFn(t)
}
func (c *turnDatagramPacketConn) SetWriteDeadline(t time.Time) error {
	if c.setWriteDeadlineFn == nil {
		return nil
	}
	return c.setWriteDeadlineFn(t)
}

type TURNQUICServer struct {
	PacketConn net.PacketConn
	addr       net.Addr

	closeOnce sync.Once
	closeFn   func() error
}

func (s *TURNQUICServer) Addr() net.Addr { return s.addr }
func (s *TURNQUICServer) Close() error {
	if s.PacketConn != nil {
		return s.PacketConn.Close()
	}
	return nil
}

func ListenTURNQUICServer(listenAddrs []string, port int, certMgr *CertManager, tlsCfg TLSConfig, path string) (*TURNQUICServer, error) {
	if certMgr == nil {
		return nil, fmt.Errorf("turn quic server: certificate manager is required")
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	addrs := listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0"}
	}
	var (
		conns   []net.PacketConn
		servers []*webtransport.Server
	)
	closeFn := func() error {
		var first error
		for _, s := range servers {
			if err := s.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, c := range conns {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	var local net.Addr
	packetConn := newTurnMuxPacketConn(nil, closeFn)
	chosen := port
	for _, addr := range addrs {
		serverTLS, err := buildTLSServerConfig(tlsCfg, certMgr)
		if err != nil {
			_ = closeFn()
			return nil, err
		}
		mux := http.NewServeMux()
		h3 := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(serverTLS),
			Handler:   mux,
		}
		server := &webtransport.Server{H3: h3}
		webtransport.ConfigureHTTP3Server(h3)
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect && r.Proto == "websocket" {
				turnHandleQUICWebSocket(packetConn, w, r)
				return
			}
			sess, err := server.Upgrade(w, r)
			if err != nil {
				return
			}
			remote := sess.RemoteAddr()
			if err := packetConn.addPeer(remote, sess.SendDatagram, func() error {
				return sess.CloseWithError(0, "")
			}); err != nil {
				_ = sess.CloseWithError(0, "carrier at capacity")
				return
			}
			go pumpTURNWebTransport(packetConn, remote, sess)
		})
		pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", addr, chosen))
		if err != nil {
			_ = closeFn()
			return nil, err
		}
		if chosen == 0 {
			if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok {
				chosen = udpAddr.Port
			}
		}
		if local == nil {
			local = pc.LocalAddr()
			packetConn.local = local
		}
		conns = append(conns, pc)
		servers = append(servers, server)
		go func(s *webtransport.Server, c net.PacketConn) {
			defer func() {
				if recover() != nil {
					_ = packetConn.Close()
				}
			}()
			if err := s.Serve(c); err != nil && !errors.Is(err, net.ErrClosed) {
				_ = packetConn.Close()
			}
		}(server, pc)
	}
	return &TURNQUICServer{
		PacketConn: packetConn,
		addr:       local,
		closeFn:    closeFn,
	}, nil
}

func pumpTURNWebTransport(packetConn *turnMuxPacketConn, addr net.Addr, sess *webtransport.Session) {
	defer func() {
		packetConn.removePeer(addr)
		_ = sess.CloseWithError(0, "")
	}()
	for {
		pkt, err := sess.ReceiveDatagram(sess.Context())
		if err != nil {
			return
		}
		packetConn.deliver(addr, pkt)
	}
}

func turnHandleQUICWebSocket(packetConn *turnMuxPacketConn, w http.ResponseWriter, r *http.Request) {
	if proto := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Protocol")); proto != "" && !headerTokenMatches(proto, turnWebSocketSubprotocol) {
		http.Error(w, "Sec-WebSocket-Protocol must include turn", http.StatusBadRequest)
		return
	}
	w.Header().Set("Sec-WebSocket-Protocol", turnWebSocketSubprotocol)
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
	ws := &wsConn{conn: conn, remote: conn.RemoteAddr().String(), clientSide: false}
	if err := packetConn.addPeer(conn.RemoteAddr(), ws.WriteFrame, conn.Close); err != nil {
		_ = conn.Close()
		return
	}
	go pumpTURNWebSocketFrames(packetConn, conn.RemoteAddr(), ws)
}

func DialTURNQUICPacketConn(ctx context.Context, target string, dialer ProxyDialer, certMgr *CertManager, tlsCfg TLSConfig, wsCfg WebSocketConfig) (net.PacketConn, error) {
	tlsCfgClient, err := buildTLSClientConfig(tlsCfg, certMgr, serverName(target), false)
	if err != nil {
		return nil, err
	}
	tlsCfgClient.NextProtos = appendIfMissing(tlsCfgClient.NextProtos, "h3")
	authority := target
	if wsCfg.HostHeader != "" {
		authority = wsCfg.HostHeader
	}
	path := wsCfg.Path
	if path == "" {
		path = "/turn"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	urlStr := "https://" + authority + path
	connectTarget := target
	if wsCfg.ConnectHost != "" {
		_, port, _ := net.SplitHostPort(target)
		connectTarget = net.JoinHostPort(wsCfg.ConnectHost, port)
	}
	var packetConn net.PacketConn
	d := webtransport.Dialer{
		TLSClientConfig: tlsCfgClient,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			DisablePathMTUDiscovery:          true,
		},
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			pc, _, err := dialer.DialPacket(ctx, connectTarget)
			if err != nil {
				return nil, err
			}
			packetConn = pc
			remoteAddr, err := net.ResolveUDPAddr("udp", connectTarget)
			if err != nil {
				_ = pc.Close()
				packetConn = nil
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, quicClientPacketConn{PacketConn: pc}, remoteAddr, tlsCfg, cfg)
			if err != nil {
				_ = pc.Close()
				packetConn = nil
				return nil, err
			}
			return conn, nil
		},
	}
	resp, sess, err := d.Dial(ctx, urlStr, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if packetConn != nil {
			_ = packetConn.Close()
		}
		_ = d.Close()
		return nil, err
	}
	return &turnDatagramPacketConn{
		local:  packetConn.LocalAddr(),
		remote: sess.RemoteAddr(),
		readFn: func() ([]byte, error) {
			return sess.ReceiveDatagram(sess.Context())
		},
		writeFn: func(pkt []byte) error {
			return sess.SendDatagram(pkt)
		},
		closeFn: func() error {
			var first error
			if err := sess.CloseWithError(0, ""); err != nil && first == nil {
				first = err
			}
			if err := d.Close(); err != nil && first == nil {
				first = err
			}
			if packetConn != nil {
				if err := packetConn.Close(); err != nil && first == nil {
					first = err
				}
			}
			return first
		},
	}, nil
}

func headerTokenMatches(raw, want string) bool {
	for _, part := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}
