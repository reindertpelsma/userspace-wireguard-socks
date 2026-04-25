// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// WireGuard timer constants (from wireguard-go device/timers.go).
const (
	rekeyTimeout     = 5 * time.Second
	keepaliveTimeout = 10 * time.Second
	// reconnectRateLimit: if last establish < 2×rekeyTimeout ago, wait
	// rekeyTimeout before a new attempt.
	reconnectMinInterval = 2 * rekeyTimeout
)

// inboundPacket is a received WireGuard packet delivered to WireGuard's
// ReceiveFunc.
type inboundPacket struct {
	data []byte
	ep   conn.Endpoint
}

// sessionState tracks the lifecycle of one peer's transport session.
type sessionState struct {
	mu sync.Mutex

	// staticEP is the configured DialEndpoint or NotConnOrientedEndpoint.
	// It is set once and never changes unless the peer is reconfigured.
	staticEP conn.Endpoint

	// activeSession is the live connection-oriented session (nil for UDP/TURN
	// or when no session is established).
	activeSession Session

	// currentEP is the endpoint WireGuard currently knows for this peer —
	// either a ConnEstablishedEndpoint (when activeSession != nil) or staticEP.
	currentEP conn.Endpoint

	// transport is the Transport used for activeSession.
	transport Transport

	lastEstablish time.Time
	lastFailure   time.Time
	dialInFlight  bool
	// idleTimer fires when the connection has been idle for too long.
	idleTimer *time.Timer
	// idleDisabled is set when PersistentKeepalive > 0.
	idleDisabled bool
}

// SessionSnapshot is a read-only runtime view of one tracked peer transport
// session, used by status APIs.
type SessionSnapshot struct {
	TransportName     string
	State             string
	StaticTarget      string
	CurrentTarget     string
	StaticEndpoint    string
	CurrentEndpoint   string
	LocalAddr         string
	CarrierRemoteAddr string
	LogicalRemoteAddr string
}

// MultiTransportBind implements conn.Bind by multiplexing across multiple
// named Transport instances.  It manages:
//   - Multiple simultaneous listen-mode transports
//   - Per-peer session state for connection-oriented transports
//   - Roaming: any inbound packet updates the peer's active endpoint
//   - Idle timeout for connection-oriented sessions (30 s, unless keepalive)
//   - Rate-limited reconnect on sudden connection loss
type MultiTransportBind struct {
	mu sync.RWMutex

	// transports maps transport name → Transport.
	transports map[string]Transport

	// listenTransports is the ordered list of config-only (no live listener)
	// entries.  listener is always nil here; it exists only as configuration.
	listenTransports []listenEntry

	// activeListeners holds the live listenEntry values (with listeners) while
	// the bind is open.  It is created in Open() and nilled in closeLocked().
	activeListeners []listenEntry

	// defaultTransport is the name used by ParseEndpoint for plain host:port
	// strings.  Set via SetDefaultTransport.
	defaultTransport string

	// sessions maps peer ident (hex of IdentBytes) → sessionState.
	sessions map[string]*sessionState

	// recvCh feeds inbound packets to WireGuard's ReceiveFunc goroutine(s).
	recvCh chan inboundPacket

	// closed is closed when the bind is shut down.
	closed chan struct{}

	// cancelListeners cancels all active listener contexts.
	cancelListeners context.CancelFunc

	open bool

	// peerLookup is provided by the engine to query per-peer keepalive state.
	peerLookup PeerLookup

	// onEndpointReset is called when the engine must update a peer's IPC
	// endpoint after a connection dies.
	onEndpointReset EndpointResetFunc
}

type listenEntry struct {
	transport    Transport
	listener     Listener
	portOverride int // 0 means use the port passed to Open
}

// NewMultiTransportBind creates a MultiTransportBind.
// peerLookup and onEndpointReset may be nil; features that require them will
// be silently skipped.
func NewMultiTransportBind(peerLookup PeerLookup, onEndpointReset EndpointResetFunc) *MultiTransportBind {
	return &MultiTransportBind{
		transports:      make(map[string]Transport),
		sessions:        make(map[string]*sessionState),
		peerLookup:      peerLookup,
		onEndpointReset: onEndpointReset,
	}
}

// AddTransport registers a transport.  Must be called before Open.
func (b *MultiTransportBind) AddTransport(t Transport) {
	b.mu.Lock()
	b.transports[t.Name()] = t
	b.mu.Unlock()
}

// SetPeerSession configures the static endpoint for a peer identified by
// identBytes.  ep must be a NotConnOrientedEndpoint or DialEndpoint.
func (b *MultiTransportBind) SetPeerSession(identBytes []byte, ep conn.Endpoint, transport Transport, keepalive int) {
	key := hex.EncodeToString(identBytes)
	b.mu.Lock()
	s := b.sessions[key]
	if s == nil {
		s = &sessionState{}
		b.sessions[key] = s
	}
	b.mu.Unlock()

	s.mu.Lock()
	s.staticEP = ep
	s.currentEP = ep
	s.transport = transport
	s.idleDisabled = keepalive > 0
	s.mu.Unlock()
}

// ResetPeerSession closes any active session for the peer identified by
// identBytes and reverts its endpoint to the static configuration.
// Called by the engine's roam-fallback mechanism.
func (b *MultiTransportBind) ResetPeerSession(identBytes []byte) {
	key := hex.EncodeToString(identBytes)
	b.mu.RLock()
	s := b.sessions[key]
	b.mu.RUnlock()
	if s == nil {
		return
	}
	b.killSession(s, identBytes)
}

// Open starts all listen-mode transports and returns ReceiveFuncs for
// WireGuard.  Implements conn.Bind.
func (b *MultiTransportBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.recvCh = make(chan inboundPacket, 4096)
	b.closed = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	b.cancelListeners = cancel

	// Reset active listeners — b.listenTransports holds only config (no live listener).
	b.activeListeners = nil

	chosenPort := uint16(0)
	for _, t := range b.listenTransports {
		listenPort := int(port)
		if t.portOverride != 0 {
			listenPort = t.portOverride
		}
		ln, err := t.transport.Listen(ctx, listenPort)
		if err != nil {
			cancel()
			b.closeLocked()
			return nil, 0, err
		}
		entry := listenEntry{transport: t.transport, listener: ln, portOverride: t.portOverride}
		b.activeListeners = append(b.activeListeners, entry)
		if chosenPort == 0 {
			if addr := ln.Addr(); addr != nil {
				if ta, ok := addr.(*net.TCPAddr); ok {
					chosenPort = uint16(ta.Port)
				} else if ua, ok := addr.(*net.UDPAddr); ok {
					chosenPort = uint16(ua.Port)
				}
			}
		}
		// Capture this Open's closed channel for the acceptLoop. Reading
		// b.closed inside the loop would race with a subsequent Open after
		// Close (BindUpdate is exactly that pattern), since Open reassigns
		// the field under b.mu while the prior acceptLoop is still draining.
		go b.acceptLoop(ctx, entry, b.closed)
	}
	if chosenPort == 0 {
		chosenPort = port
	}
	b.open = true
	return []conn.ReceiveFunc{b.receiveFunc()}, chosenPort, nil
}

// AddListenTransport adds a transport that should be started in listen mode.
// Must be called before Open. The transport uses the port passed to Open.
func (b *MultiTransportBind) AddListenTransport(t Transport) {
	b.mu.Lock()
	b.listenTransports = append(b.listenTransports, listenEntry{transport: t})
	b.mu.Unlock()
}

// AddListenTransportWithPort adds a transport in listen mode with a specific
// port override. When port != 0 it takes priority over the port passed to Open.
func (b *MultiTransportBind) AddListenTransportWithPort(t Transport, port int) {
	b.mu.Lock()
	b.listenTransports = append(b.listenTransports, listenEntry{transport: t, portOverride: port})
	b.mu.Unlock()
}

func (b *MultiTransportBind) receiveFunc() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		case pkt := <-b.recvCh:
			n := copy(bufs[0], pkt.data)
			sizes[0] = n
			eps[0] = pkt.ep
			return 1, nil
		}
	}
}

// acceptLoop runs per listener and routes inbound sessions into recvCh.
// closed is captured at goroutine creation time (see Open) so a later Open
// reassigning b.closed cannot race the read here.
func (b *MultiTransportBind) acceptLoop(ctx context.Context, entry listenEntry, closed <-chan struct{}) {
	for {
		sess, err := entry.listener.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case <-closed:
			default:
			}
			return
		}
		if entry.transport.IsConnectionOriented() {
			go b.serveConnSession(ctx, entry.transport, sess)
		} else {
			go b.serveNotConnSession(ctx, entry.transport, sess)
		}
	}
}

// serveNotConnSession handles a single datagram from a not-connection-oriented
// listener (UDP, TURN).
func (b *MultiTransportBind) serveNotConnSession(_ context.Context, t Transport, sess Session) {
	defer sess.Close()
	pkt, err := sess.ReadPacket()
	if err != nil {
		return
	}
	ap, _ := netip.ParseAddrPort(sess.RemoteAddr())
	ep := NewNotConnOrientedEndpoint(t.Name(), ap)
	b.updatePeerEndpoint(ep.IdentBytes(), ep, sess)
	select {
	case b.recvCh <- inboundPacket{data: pkt, ep: ep}:
	case <-b.closed:
	}
}

// serveConnSession reads all packets from a connection-oriented session.
// Each packet updates the peer's active endpoint (roaming support).
func (b *MultiTransportBind) serveConnSession(_ context.Context, t Transport, sess Session) {
	var peerIdentBytes []byte
	defer func() {
		sess.Close()
		if peerIdentBytes != nil {
			b.onConnSessionDied(peerIdentBytes)
		}
	}()

	for {
		pkt, err := sess.ReadPacket()
		if err != nil {
			return
		}
		// On the first packet from this session determine the peer ident
		// from the remote address, build a ConnEstablishedEndpoint, and
		// register the session.
		if peerIdentBytes == nil {
			peerIdentBytes = buildIdent(t.Name(), sess.RemoteAddr())
			ep := NewConnEstablishedEndpoint(t.Name(), sess.RemoteAddr(), sess, peerIdentBytes)
			b.updatePeerEndpoint(peerIdentBytes, ep, sess)
		}
		key := hex.EncodeToString(peerIdentBytes)
		b.mu.RLock()
		s := b.sessions[key]
		b.mu.RUnlock()
		if s != nil {
			b.resetIdleTimer(s)
		}
		ep := NewConnEstablishedEndpoint(t.Name(), sess.RemoteAddr(), sess, peerIdentBytes)
		select {
		case b.recvCh <- inboundPacket{data: pkt, ep: ep}:
		case <-b.closed:
			return
		}
	}
}

// updatePeerEndpoint stores the active session for a peer and triggers a
// roaming update when the peer's endpoint changes.
func (b *MultiTransportBind) updatePeerEndpoint(identBytes []byte, ep conn.Endpoint, sess Session) {
	key := hex.EncodeToString(identBytes)
	b.mu.Lock()
	s := b.sessions[key]
	if s == nil {
		s = &sessionState{}
		b.sessions[key] = s
	}
	b.mu.Unlock()

	s.mu.Lock()
	old := s.activeSession
	s.activeSession = sess
	s.currentEP = ep
	s.mu.Unlock()

	// Close the old session after a short grace period — it may still be
	// delivering buffered packets.
	if old != nil && old != sess {
		go func() {
			time.Sleep(5 * time.Second)
			old.Close()
		}()
	}
}

// onConnSessionDied handles a connection-oriented session that closed
// unexpectedly (read error).
func (b *MultiTransportBind) onConnSessionDied(identBytes []byte) {
	key := hex.EncodeToString(identBytes)
	b.mu.RLock()
	s := b.sessions[key]
	b.mu.RUnlock()
	if s == nil {
		return
	}

	s.mu.Lock()
	s.activeSession = nil
	s.lastFailure = time.Now()
	// Revert to static endpoint so the next Send() can dial again.
	if s.staticEP != nil {
		s.currentEP = s.staticEP
	} else {
		s.currentEP = nil
	}
	staticEP := s.staticEP
	s.mu.Unlock()

	// Notify the engine so it can update the WireGuard IPC peer endpoint.
	if b.onEndpointReset != nil && staticEP != nil {
		te := AsTransportEndpoint(staticEP)
		addr := ""
		if te != nil {
			addr = staticEP.DstToString()
		}
		b.onEndpointReset(identBytes, addr)
	}

	// Reconnect immediately if the peer has keepalive or buffered data.
	shouldReconnect := false
	if b.peerLookup != nil {
		info := b.peerLookup(identBytes)
		if info.PersistentKeepalive > 0 || info.HasBufferedPackets {
			shouldReconnect = true
		}
	}
	if shouldReconnect && staticEP != nil {
		go b.reconnectPeer(s, identBytes)
	}
}

// reconnectPeer attempts to re-establish a connection-oriented session for a
// peer.  It applies a rate limit: if the last successful establish was within
// 2×rekeyTimeout, it waits rekeyTimeout before trying.
func (b *MultiTransportBind) reconnectPeer(s *sessionState, identBytes []byte) {
	s.mu.Lock()
	if s.dialInFlight || s.staticEP == nil || s.transport == nil {
		s.mu.Unlock()
		return
	}
	// Rate limit.
	if since := time.Since(s.lastEstablish); since < reconnectMinInterval {
		wait := rekeyTimeout - (since - rekeyTimeout)
		if wait > rekeyTimeout {
			wait = rekeyTimeout
		}
		s.mu.Unlock()
		time.Sleep(wait)
		s.mu.Lock()
	}
	if s.dialInFlight {
		s.mu.Unlock()
		return
	}
	s.dialInFlight = true
	target := s.staticEP.DstToString()
	t := s.transport
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), rekeyTimeout*3)
	defer cancel()
	sess, err := t.Dial(ctx, target)
	s.mu.Lock()
	s.dialInFlight = false
	if err != nil {
		s.lastFailure = time.Now()
		s.mu.Unlock()
		return
	}
	s.lastEstablish = time.Now()
	s.activeSession = sess
	ep := NewConnEstablishedEndpoint(t.Name(), target, sess, buildIdent(t.Name(), target))
	s.currentEP = ep
	s.mu.Unlock()

	go b.serveConnSession(context.Background(), t, sess)
	b.startIdleTimer(s, identBytes)
}

// Send transmits bufs to the given endpoint.  Implements conn.Bind.
func (b *MultiTransportBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	te := AsTransportEndpoint(ep)
	if te == nil {
		// Fallback: treat as not-connection-oriented if we can parse the addr.
		return b.sendNotConnOriented(bufs, ep.DstToString())
	}

	switch te.Kind() {
	case KindNotConnOriented:
		nce := ep.(*NotConnOrientedEndpoint)
		return b.sendNCO(nce, bufs)

	case KindDial:
		de := ep.(*DialEndpoint)
		return b.sendViaDial(bufs, de)

	case KindConnEstablished:
		cee := ep.(*ConnEstablishedEndpoint)
		sess := cee.Session()
		err := sendAll(sess, bufs)
		if err != nil {
			// Session died; update state and trigger reconnect.
			b.onConnSessionDied(cee.IdentBytes())
		}
		return err
	}
	return nil
}

// sendViaDial sends bufs through an active session for the DialEndpoint,
// dialling a new session if none exists.
func (b *MultiTransportBind) sendViaDial(bufs [][]byte, de *DialEndpoint) error {
	key := hex.EncodeToString(de.IdentBytes())
	b.mu.RLock()
	s := b.sessions[key]
	b.mu.RUnlock()

	if s == nil {
		b.mu.Lock()
		s = b.sessions[key]
		if s == nil {
			s = &sessionState{
				staticEP:  de,
				currentEP: de,
			}
			b.sessions[key] = s
		}
		b.mu.Unlock()
	}

	s.mu.Lock()
	if s.transport == nil {
		t := b.GetTransport(de.TransportID)
		s.transport = t
	}
	sess := s.activeSession
	t := s.transport
	s.mu.Unlock()

	if sess != nil {
		err := sendAll(sess, bufs)
		if err != nil {
			b.onConnSessionDied(de.IdentBytes())
		}
		return err
	}

	// No active session — dial one.
	if t == nil {
		return ErrTransportNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), rekeyTimeout*3)
	defer cancel()
	newSess, err := t.Dial(ctx, de.Target)
	if err != nil {
		return err
	}
	ep := NewConnEstablishedEndpoint(de.TransportID, de.Target, newSess, de.IdentBytes())
	s.mu.Lock()
	s.activeSession = newSess
	s.currentEP = ep
	s.lastEstablish = time.Now()
	s.mu.Unlock()

	go b.serveConnSession(context.Background(), t, newSess)
	b.startIdleTimer(s, de.IdentBytes())
	return sendAll(newSess, bufs)
}

// sendNCO sends bufs to a not-connection-oriented endpoint.
//
// Server path: a udpListenerSession is already stored in the session state
// (set by serveNotConnSession via updatePeerEndpoint).  That session's
// WritePacket sends through the bound listener socket back to the peer, so
// the reply always originates from the correct listen port.
//
// Client path: create a connected UDP socket per destination, cache it for
// 30 seconds of inactivity, and start a receive goroutine on it so replies
// are delivered to WireGuard's recvCh.
func (b *MultiTransportBind) sendNCO(nce *NotConnOrientedEndpoint, bufs [][]byte) error {
	t := b.GetTransport(nce.TransportID)
	if t == nil {
		return ErrTransportNotFound
	}

	key := hex.EncodeToString(nce.IdentBytes())

	// Fast path: use whatever session is already active for this peer.
	b.mu.RLock()
	s := b.sessions[key]
	b.mu.RUnlock()
	if s != nil {
		s.mu.Lock()
		sess := s.activeSession
		s.mu.Unlock()
		if sess != nil {
			if err := sendAll(sess, bufs); err == nil {
				b.resetIdleTimer(s)
				return nil
			}
			// Session failed — clear so we fall through to dial a new one.
			s.mu.Lock()
			if s.activeSession == sess {
				s.activeSession = nil
			}
			s.mu.Unlock()
		}
	}

	// Slow path: allocate session state if needed, then dial a connected socket.
	b.mu.Lock()
	if s == nil {
		s = &sessionState{staticEP: nce, currentEP: nce, transport: t}
		b.sessions[key] = s
	}
	b.mu.Unlock()

	// Double-check: another goroutine may have raced us to the socket.
	s.mu.Lock()
	if s.activeSession != nil {
		sess := s.activeSession
		s.mu.Unlock()
		err := sendAll(sess, bufs)
		b.resetIdleTimer(s)
		return err
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), rekeyTimeout*3)
	defer cancel()
	newSess, err := t.Dial(ctx, nce.DstToString())
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.activeSession != nil {
		// Lost the race — use the winning goroutine's session.
		existing := s.activeSession
		s.mu.Unlock()
		newSess.Close()
		err := sendAll(existing, bufs)
		b.resetIdleTimer(s)
		return err
	}
	s.activeSession = newSess
	s.mu.Unlock()

	// Receive goroutine: deliver inbound packets from the connected socket.
	go b.serveNCOOutboundSession(nce, newSess, key)
	b.startIdleTimer(s, nce.IdentBytes())
	return sendAll(newSess, bufs)
}

// serveNCOOutboundSession reads packets from a connected UDP socket (client
// outbound path) and delivers them to WireGuard's recvCh.  It exits when the
// socket is closed by the idle timer or by Close().
func (b *MultiTransportBind) serveNCOOutboundSession(nce *NotConnOrientedEndpoint, sess Session, key string) {
	defer func() {
		b.mu.RLock()
		s := b.sessions[key]
		b.mu.RUnlock()
		if s != nil {
			s.mu.Lock()
			if s.activeSession == sess {
				s.activeSession = nil
			}
			s.mu.Unlock()
		}
		sess.Close()
	}()
	for {
		pkt, err := sess.ReadPacket()
		if err != nil {
			return
		}
		select {
		case b.recvCh <- inboundPacket{data: pkt, ep: nce}:
		case <-b.closed:
			return
		}
	}
}

func (b *MultiTransportBind) sendNotConnOriented(bufs [][]byte, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return err
	}
	// Try UDP transport as fallback.
	for _, t := range b.transports {
		if !t.IsConnectionOriented() {
			sess, err := t.Dial(context.Background(), ap.String())
			if err != nil {
				continue
			}
			defer sess.Close()
			return sendAll(sess, bufs)
		}
	}
	return net.ErrClosed
}

// killSession closes the active session for a peer and reverts its endpoint.
func (b *MultiTransportBind) killSession(s *sessionState, identBytes []byte) {
	s.mu.Lock()
	sess := s.activeSession
	s.activeSession = nil
	if s.staticEP != nil {
		s.currentEP = s.staticEP
	}
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	if b.onEndpointReset != nil && s.staticEP != nil {
		b.onEndpointReset(identBytes, s.staticEP.DstToString())
	}
}

// startIdleTimer arms the idle timeout for a connection-oriented session.
// A zero or disabled timer is safe.
func (b *MultiTransportBind) startIdleTimer(s *sessionState, identBytes []byte) {
	s.mu.Lock()
	if s.idleDisabled {
		s.mu.Unlock()
		return
	}
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleTimer = time.AfterFunc(tcpIdleTimeout, func() {
		b.killSession(s, identBytes)
	})
	s.mu.Unlock()
}

// resetIdleTimer resets the idle timer on any packet activity.
func (b *MultiTransportBind) resetIdleTimer(s *sessionState) {
	s.mu.Lock()
	if s.idleTimer != nil && !s.idleDisabled {
		s.idleTimer.Reset(tcpIdleTimeout)
	}
	s.mu.Unlock()
}

// Close shuts down all listeners and sessions.  Implements conn.Bind.
func (b *MultiTransportBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	if b.cancelListeners != nil {
		b.cancelListeners()
	}
	close(b.closed)
	b.closeLocked()
	b.open = false
	return nil
}

func (b *MultiTransportBind) closeLocked() {
	for _, e := range b.activeListeners {
		if e.listener != nil {
			e.listener.Close()
		}
	}
	b.activeListeners = nil
	for _, s := range b.sessions {
		s.mu.Lock()
		if s.activeSession != nil {
			s.activeSession.Close()
		}
		if s.idleTimer != nil {
			s.idleTimer.Stop()
		}
		s.mu.Unlock()
	}
}

// SetMark implements conn.Bind (no-op for userspace).
func (b *MultiTransportBind) SetMark(_ uint32) error { return nil }

// BatchSize implements conn.Bind.
func (b *MultiTransportBind) BatchSize() int { return 1 }

// ParseEndpoint implements conn.Bind.  Returns the appropriate endpoint type
// based on whether a transport name prefix is present.
func (b *MultiTransportBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// Format: "transportName@host:port" for connection-oriented,
	// plain "host:port" for legacy UDP.
	if idx := findAtSign(s); idx > 0 {
		tName := s[:idx]
		target := s[idx+1:]
		b.mu.RLock()
		t := b.transports[tName]
		b.mu.RUnlock()
		if t != nil && t.IsConnectionOriented() {
			return NewDialEndpoint(tName, target), nil
		}
		if t != nil {
			ap, err := resolveAddrPort(target)
			if err != nil {
				return nil, err
			}
			return NewNotConnOrientedEndpoint(tName, ap), nil
		}
	}
	// Plain host:port → use the default not-connection-oriented transport.
	ap, err := resolveAddrPort(s)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	fallbackName := b.defaultTransport
	if fallbackName == "" {
		// Backward compat: pick first NCO transport from map.
		for name, t := range b.transports {
			if !t.IsConnectionOriented() {
				fallbackName = name
				break
			}
		}
	}
	b.mu.RUnlock()
	if fallbackName == "" {
		fallbackName = "udp"
	}
	return NewNotConnOrientedEndpoint(fallbackName, ap), nil
}

// SetDefaultTransport sets the transport name used by ParseEndpoint when the
// endpoint string is a plain host:port (no transport prefix).  Call this after
// BuildRegistry to guarantee deterministic fallback instead of map iteration.
func (b *MultiTransportBind) SetDefaultTransport(name string) {
	b.mu.Lock()
	b.defaultTransport = name
	b.mu.Unlock()
}

// GetTransport returns the named transport or nil.
func (b *MultiTransportBind) GetTransport(name string) Transport {
	b.mu.RLock()
	t := b.transports[name]
	b.mu.RUnlock()
	return t
}

// ListenPort returns the port the first listen-mode transport is bound to,
// or 0 if no listeners are active.
func (b *MultiTransportBind) ListenPort() uint16 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, e := range b.activeListeners {
		if e.listener == nil {
			continue
		}
		addr := e.listener.Addr()
		if addr == nil {
			continue
		}
		switch a := addr.(type) {
		case *net.UDPAddr:
			return uint16(a.Port)
		case *net.TCPAddr:
			return uint16(a.Port)
		}
	}
	return 0
}

// TransportNames returns the names of all registered transports.
func (b *MultiTransportBind) TransportNames() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names := make([]string, 0, len(b.transports))
	for n := range b.transports {
		names = append(names, n)
	}
	return names
}

// ActiveSessions returns the number of active connection-oriented sessions.
func (b *MultiTransportBind) ActiveSessions() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for _, s := range b.sessions {
		s.mu.Lock()
		if s.activeSession != nil {
			n++
		}
		s.mu.Unlock()
	}
	return n
}

// SessionSnapshots returns a point-in-time view of the tracked transport
// sessions. The result is safe to use after the method returns.
func (b *MultiTransportBind) SessionSnapshots() []SessionSnapshot {
	b.mu.RLock()
	sessions := make([]*sessionState, 0, len(b.sessions))
	for _, s := range b.sessions {
		sessions = append(sessions, s)
	}
	b.mu.RUnlock()

	out := make([]SessionSnapshot, 0, len(sessions))
	for _, s := range sessions {
		s.mu.Lock()
		staticEP := s.staticEP
		currentEP := s.currentEP
		activeSession := s.activeSession
		transport := s.transport
		s.mu.Unlock()

		snap := SessionSnapshot{}
		if te := AsTransportEndpoint(staticEP); te != nil {
			snap.TransportName = te.TransportName()
			snap.StaticTarget = identTargetAddr(te.IdentBytes())
			snap.StaticEndpoint = staticEP.DstToString()
		}
		if te := AsTransportEndpoint(currentEP); te != nil {
			if snap.TransportName == "" {
				snap.TransportName = te.TransportName()
			}
			snap.State = endpointKindString(te.Kind())
			snap.CurrentTarget = identTargetAddr(te.IdentBytes())
			snap.CurrentEndpoint = currentEP.DstToString()
		}
		if snap.TransportName == "" && transport != nil {
			snap.TransportName = transport.Name()
		}
		if snap.State == "" {
			if snap.StaticTarget != "" || snap.StaticEndpoint != "" {
				if te := AsTransportEndpoint(staticEP); te != nil {
					snap.State = endpointKindString(te.Kind())
				}
			} else if activeSession != nil {
				snap.State = "ConnEstablished"
			}
		}
		if infoProvider, ok := activeSession.(SessionInfoProvider); ok {
			info := infoProvider.SessionInfo()
			snap.LocalAddr = info.LocalAddr
			snap.CarrierRemoteAddr = info.CarrierRemoteAddr
			snap.LogicalRemoteAddr = info.LogicalRemoteAddr
		}
		out = append(out, snap)
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func sendAll(sess Session, bufs [][]byte) error {
	for _, buf := range bufs {
		if err := sess.WritePacket(buf); err != nil {
			return err
		}
	}
	return nil
}

func findAtSign(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return i
		}
	}
	return -1
}

func resolveAddrPort(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err == nil {
			return netip.AddrPortFrom(addr.Unmap(), uint16(portNum)), nil
		}
	}
	return netip.AddrPort{}, &net.AddrError{Err: "no usable address", Addr: s}
}

func endpointKindString(kind EndpointKind) string {
	switch kind {
	case KindNotConnOriented:
		return "NotConnOriented"
	case KindDial:
		return "DialEndpoint"
	case KindConnEstablished:
		return "ConnEstablished"
	default:
		return ""
	}
}
