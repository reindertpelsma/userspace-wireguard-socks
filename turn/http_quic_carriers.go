package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

const turnWebSocketSubprotocol = "turn"

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

func (c *turnMuxPacketConn) addPeer(addr net.Addr, write func([]byte) error, closeFn func() error) {
	key := addr.String()
	c.mu.Lock()
	if old := c.peers[key]; old != nil && old.close != nil {
		_ = old.close()
	}
	c.peers[key] = &turnPacketPeer{addr: addr, write: write, close: closeFn}
	c.mu.Unlock()
}

func (c *turnMuxPacketConn) removePeer(addr net.Addr) {
	if addr == nil {
		return
	}
	c.mu.Lock()
	delete(c.peers, addr.String())
	c.mu.Unlock()
}

func (c *turnMuxPacketConn) deliver(addr net.Addr, payload []byte) {
	pkt := turnPacketDatagram{payload: append([]byte(nil), payload...), addr: addr}
	select {
	case c.readCh <- pkt:
	default:
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

type turnHTTPServer struct {
	PacketConn net.PacketConn
	Listener   net.Listener
	addr       net.Addr
}

func (s *turnHTTPServer) Addr() net.Addr { return s.addr }

func newTurnHTTPServer(base net.Listener, path string) (*turnHTTPServer, error) {
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
	}
	go func() { _ = server.Serve(base) }()
	return &turnHTTPServer{
		PacketConn: packetMux,
		Listener:   streamLn,
		addr:       base.Addr(),
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
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n", websocketAcceptKey(key), turnWebSocketSubprotocol)
			ws := &wsConn{conn: conn, remote: conn.RemoteAddr().String(), clientSide: false}
			packetConn.addPeer(conn.RemoteAddr(), ws.WriteFrame, conn.Close)
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

type turnQUICServer struct {
	PacketConn net.PacketConn
	addr       net.Addr
}

func (s *turnQUICServer) Addr() net.Addr { return s.addr }

func newTurnQUICServer(listener TURNListenerConfig, certMgr *turnCertManager) (*turnQUICServer, error) {
	if certMgr == nil {
		return nil, fmt.Errorf("turn quic server: certificate manager is required")
	}
	path := listener.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	addrs, port := turnListenerAddrs(listener.Listen)
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
		serverTLS, err := buildTurnTLSServerConfig(listener, certMgr)
		if err != nil {
			_ = closeFn()
			return nil, err
		}
		serverTLS.NextProtos = appendIfMissing(serverTLS.NextProtos, "h3")
		mux := http.NewServeMux()
		h3 := &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(serverTLS),
			Handler:   mux,
		}
		server := &webtransport.Server{H3: h3}
		webtransport.ConfigureHTTP3Server(h3)
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect && r.Proto == "websocket" {
				makeTURNQUICWebSocketHandler(packetConn)(w, r)
				return
			}
			sess, err := server.Upgrade(w, r)
			if err != nil {
				return
			}
			remote := sess.RemoteAddr()
			packetConn.addPeer(remote, sess.SendDatagram, func() error {
				return sess.CloseWithError(0, "")
			})
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
			_ = s.Serve(c)
		}(server, pc)
	}
	return &turnQUICServer{PacketConn: packetConn, addr: local}, nil
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

func makeTURNQUICWebSocketHandler(packetConn *turnMuxPacketConn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		addr := turnStringAddr(r.RemoteAddr)
		ws := &wsConn{conn: conn, remote: r.RemoteAddr, clientSide: false}
		packetConn.addPeer(addr, ws.WriteFrame, ws.conn.Close)
		go pumpTURNWebSocketFrames(packetConn, addr, ws)
	}
}

type wsConn struct {
	conn       net.Conn
	remote     string
	clientSide bool
}

func (w *wsConn) ReadFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(w.conn, hdr[:]); err != nil {
		return nil, err
	}
	opcode := hdr[0] & 0x0f
	masked := (hdr[1] & 0x80) != 0
	payLen := int(hdr[1] & 0x7f)
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
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.conn, mask[:]); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, payLen)
	if _, err := io.ReadFull(w.conn, buf); err != nil {
		return nil, err
	}
	if masked {
		for i := range buf {
			buf[i] ^= mask[i%4]
		}
	}
	switch opcode {
	case 0x8:
		return nil, io.EOF
	case 0x9:
		_ = w.writeRaw(0xa, buf)
		return w.ReadFrame()
	}
	return buf, nil
}

func (w *wsConn) WriteFrame(data []byte) error { return w.writeRaw(0x2, data) }

func (w *wsConn) writeRaw(opcode byte, data []byte) error {
	n := len(data)
	var hdr []byte
	if w.clientSide {
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
	var b0 byte = 0x80 | opcode
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
		hdr = []byte{b0, b1 | 127, 0, 0, 0, 0, byte(payLen >> 24), byte(payLen >> 16), byte(payLen >> 8), byte(payLen)}
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

func headerTokenMatches(raw, want string) bool {
	for _, part := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

type turnStringAddr string

func (a turnStringAddr) Network() string { return "turn" }
func (a turnStringAddr) String() string  { return string(a) }

func appendIfMissing(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func turnListenerAddrs(raw string) ([]string, int) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return []string{"0.0.0.0"}, 0
	}
	if host == "" {
		host = "0.0.0.0"
	}
	n, _ := strconv.Atoi(port)
	return []string{host}, n
}
