package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	PacketHandshakeInitiation = 1
	PacketHandshakeResponse   = 2
	PacketCookieReply         = 3
	PacketData                = 4
)

const (
	HandshakeInitiationSize = 148
	HandshakeResponseSize   = 92
	CookieReplySize         = 64
	MinDataPacketSize       = 32
)

const (
	DefaultGlobalMaxSessions = 10000
	DefaultPerRelayMaxSessions = 1000
	SessionTimeout = 30 * time.Second
	UnverifiedDataLimit = 256 * 1024 // 256KB
	SpecialPacketRateLimit = 4 // per second
)

var (
	LabelMac1   = []byte("mac1----")
	LabelCookie = []byte("cookie--")
)

type DoSLevel int

const (
	DoSLevelNone DoSLevel = iota
	DoSLevelUnknownIPs
	DoSLevelFull
)

type WireguardSession struct {
	RelayPort      int
	RemoteAddr     string
	ClientPeerID   uint32 // sender index from client
	ServerPeerID   uint32 // sender index from server
	Verified       bool
	LastServerPkt  time.Time
	DoSDataCount   int64
	RateLimitTime  time.Time
	RateLimitCount int
	MaxCounter     uint64
	ForwardCookie  [16]byte
	LastMac1       [16]byte
}

type WireguardGuard struct {
	PublicKey [32]byte
	Mac1Key   [32]byte
	CookieKey [32]byte

	mu            sync.RWMutex
	Sessions      []*WireguardSession
	Secret        [32]byte
	SecretChanged time.Time
	DoSLevel      DoSLevel

	GlobalMaxSessions   int
	PerRelayMaxSessions map[int]int // relayPort -> maxSessions

	// Stats for DoS detection
	RoamCount      int
	HandshakeCount int
	RejectionCount int
	LastStatsReset time.Time
}

func NewWireguardGuard(publicKey [32]byte) *WireguardGuard {
	g := &WireguardGuard{
		PublicKey:           publicKey,
		LastStatsReset:      time.Now(),
		GlobalMaxSessions:   DefaultGlobalMaxSessions,
		PerRelayMaxSessions: make(map[int]int),
	}

	h, _ := blake2s.New256(nil)
	h.Write(LabelMac1)
	h.Write(publicKey[:])
	copy(g.Mac1Key[:], h.Sum(nil))

	h.Reset()
	h.Write(LabelCookie)
	h.Write(publicKey[:])
	copy(g.CookieKey[:], h.Sum(nil))

	g.rotateSecret()
	return g
}

func (g *WireguardGuard) rotateSecret() {
	rand.Read(g.Secret[:])
	g.SecretChanged = time.Now()
}

func (g *WireguardGuard) getCookie(ip net.IP) [16]byte {
	h, _ := blake2s.New128(g.Secret[:])
	h.Write(ip)
	var cookie [16]byte
	copy(cookie[:], h.Sum(nil))
	return cookie
}

func (g *WireguardGuard) verifyMac1(packet []byte, offset int) bool {
	if len(packet) < offset+16 {
		return false
	}
	h, _ := blake2s.New128(g.Mac1Key[:])
	h.Write(packet[:offset])
	mac := h.Sum(nil)
	return subtle.ConstantTimeCompare(packet[offset:offset+16], mac) == 1
}

func (g *WireguardGuard) verifyMac2(packet []byte, offset int, cookie [16]byte) bool {
	if len(packet) < offset+16 {
		return false
	}
	h, _ := blake2s.New128(cookie[:])
	h.Write(packet[:offset])
	mac := h.Sum(nil)
	return subtle.ConstantTimeCompare(packet[offset:offset+16], mac) == 1
}

func (g *WireguardGuard) ProcessInbound(packet []byte, remoteAddr net.Addr, relayPort int) (allowed bool, modifiedPacket []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if time.Since(g.SecretChanged) > 2*time.Minute {
		g.rotateSecret()
	}
	g.maintenance()

	if len(packet) < 4 {
		return false, nil
	}

	msgType := packet[0]
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		return false, nil
	}

	switch msgType {
	case PacketHandshakeInitiation:
		return g.handleInboundHandshakeInitiation(packet, remoteAddr, relayPort)
	case PacketHandshakeResponse, PacketCookieReply, PacketData:
		return g.handleInboundOther(packet, remoteAddr, relayPort)
	default:
		return false, nil
	}
}

func (g *WireguardGuard) handleInboundHandshakeInitiation(packet []byte, remoteAddr net.Addr, relayPort int) (bool, []byte) {
	if len(packet) != HandshakeInitiationSize {
		return false, nil
	}

	if !g.verifyMac1(packet, 116) {
		g.RejectionCount++
		return false, nil
	}

	clientIP := getIP(remoteAddr)
	ourCookie := g.getCookie(clientIP)

	var cookies [][16]byte
	cookies = append(cookies, ourCookie)

	sessionIdx := -1
	for i, s := range g.Sessions {
		if s.RelayPort == relayPort && s.RemoteAddr == remoteAddr.String() {
			if s.ForwardCookie != [16]byte{} {
				cookies = append(cookies, s.ForwardCookie)
			}
			sessionIdx = i
			break
		}
	}

	mac2Validated := false
	useForwarded := false
	for _, c := range cookies {
		if g.verifyMac2(packet, 132, c) {
			mac2Validated = true
			if c != ourCookie {
				useForwarded = true
			}
			break
		}
	}

	// DoS protection
	overload := g.DoSLevel != DoSLevelNone
	if overload {
		knownIP := false
		if g.DoSLevel == DoSLevelUnknownIPs {
			for _, s := range g.Sessions {
				if s.Verified && getIPStr(s.RemoteAddr) == clientIP.String() {
					knownIP = true
					break
				}
			}
		}

		if !mac2Validated && !knownIP {
			return false, g.createCookieReply(packet, remoteAddr)
		}
	}

	// Create or update session
	senderIndex := binary.LittleEndian.Uint32(packet[4:8])
	var sess *WireguardSession
	if sessionIdx == -1 {
		sess = &WireguardSession{
			RelayPort:    relayPort,
			RemoteAddr:   remoteAddr.String(),
			ClientPeerID: senderIndex,
		}

		maxForRelay := DefaultPerRelayMaxSessions
		if m, ok := g.PerRelayMaxSessions[relayPort]; ok {
			maxForRelay = m
		}

		relaySessCount := 0
		for _, s := range g.Sessions {
			if s.RelayPort == relayPort {
				relaySessCount++
			}
		}

		if len(g.Sessions) >= g.GlobalMaxSessions || relaySessCount >= maxForRelay {
			found := false
			// 1. Expired/timed out sessions
			for i, s := range g.Sessions {
				if time.Since(s.LastServerPkt) > SessionTimeout {
					g.Sessions[i] = sess
					found = true
					break
				}
			}
			// 2. Unverified sessions
			if !found {
				for i, s := range g.Sessions {
					if !s.Verified {
						// Prefer replacing from same relay if we hit per-relay limit
						if relaySessCount >= maxForRelay {
							if s.RelayPort == relayPort {
								g.Sessions[i] = sess
								found = true
								break
							}
						} else {
							// Global limit hit, replace any unverified
							g.Sessions[i] = sess
							found = true
							break
						}
					}
				}
			}
			if !found {
				g.RejectionCount++
				return false, nil
			}
		} else {
			g.Sessions = append(g.Sessions, sess)
		}
	} else {
		sess = g.Sessions[sessionIdx]
		sess.ClientPeerID = senderIndex
	}
	copy(sess.LastMac1[:], packet[116:132])

	g.HandshakeCount++

	// Forward handshake initiation. If mac2 was validated against our cookie, clear it.
	if mac2Validated && !useForwarded {
		modified := make([]byte, len(packet))
		copy(modified, packet)
		for i := 132; i < 148; i++ {
			modified[i] = 0
		}
		return true, modified
	}

	return true, packet
}

func (g *WireguardGuard) handleInboundOther(packet []byte, remoteAddr net.Addr, relayPort int) (bool, []byte) {
	msgType := packet[0]
	var receiverIndex uint32
	switch msgType {
	case PacketHandshakeResponse:
		if len(packet) != HandshakeResponseSize {
			return false, nil
		}
		receiverIndex = binary.LittleEndian.Uint32(packet[8:12])
	case PacketCookieReply:
		if len(packet) != CookieReplySize {
			return false, nil
		}
		receiverIndex = binary.LittleEndian.Uint32(packet[4:8])
	case PacketData:
		if len(packet) < MinDataPacketSize {
			return false, nil
		}
		receiverIndex = binary.LittleEndian.Uint32(packet[4:8])
	}

	var sess *WireguardSession
	clientAddrStr := remoteAddr.String()
	clientIP := getIP(remoteAddr).String()

	for _, s := range g.Sessions {
		if s.RelayPort != relayPort || s.ServerPeerID != receiverIndex {
			continue
		}

		match := false
		switch g.DoSLevel {
		case DoSLevelNone:
			match = true
		case DoSLevelUnknownIPs:
			if s.RemoteAddr == clientAddrStr {
				match = true
			} else {
				for _, s2 := range g.Sessions {
					if s2.Verified && getIPStr(s2.RemoteAddr) == clientIP {
						match = true
						break
					}
				}
			}
		case DoSLevelFull:
			if s.RemoteAddr == clientAddrStr {
				match = true
			}
		}

		if match {
			sess = s
			break
		}
	}

	if sess == nil {
		g.RejectionCount++
		return false, nil
	}

	// Roaming check
	if sess.RemoteAddr != clientAddrStr {
		g.RoamCount++
	}

	// Unverified sessions: no data allowed until verified
	if !sess.Verified {
		if msgType == PacketData {
			g.RejectionCount++
			return false, nil
		}
	}

	// Rate limit special packets
	if msgType == PacketHandshakeResponse || msgType == PacketCookieReply {
		now := time.Now()
		if sess.RateLimitTime.IsZero() || now.Sub(sess.RateLimitTime) > 1*time.Second {
			sess.RateLimitTime = now
			sess.RateLimitCount = 1
		} else {
			sess.RateLimitCount++
			if sess.RateLimitCount > SpecialPacketRateLimit {
				g.RejectionCount++
				return false, nil
			}
		}
	}

	// Data packet counter checks
	if msgType == PacketData {
		counter := binary.LittleEndian.Uint64(packet[8:16])
		if sess.MaxCounter > 0 {
			if counter < sess.MaxCounter {
				if sess.MaxCounter-counter > 4096 {
					g.RejectionCount++
					return false, nil
				}
			} else if counter-sess.MaxCounter > 65536 {
				g.RejectionCount++
				return false, nil
			}
		}
		if counter > sess.MaxCounter {
			sess.MaxCounter = counter
		}
	}

	// General checks
	if sess.LastServerPkt.IsZero() || time.Since(sess.LastServerPkt) > SessionTimeout {
		g.RejectionCount++
		return false, nil
	}

	// Data limit check
	sess.DoSDataCount += int64(len(packet))
	if sess.DoSDataCount > UnverifiedDataLimit {
		g.RejectionCount++
		return false, nil
	}

	if msgType == PacketHandshakeResponse {
		sess.ClientPeerID = binary.LittleEndian.Uint32(packet[4:8])
	}

	return true, packet
}

func (g *WireguardGuard) ProcessOutbound(packet []byte, remoteAddr net.Addr, relayPort int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(packet) < 4 {
		return false
	}
	msgType := packet[0]
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		return false
	}

	var senderID, receiverID uint32
	var hasSender, hasReceiver bool

	switch msgType {
	case PacketHandshakeInitiation:
		if len(packet) != HandshakeInitiationSize {
			return false
		}
		senderID = binary.LittleEndian.Uint32(packet[4:8])
		hasSender = true
	case PacketHandshakeResponse:
		if len(packet) != HandshakeResponseSize {
			return false
		}
		senderID = binary.LittleEndian.Uint32(packet[4:8])
		receiverID = binary.LittleEndian.Uint32(packet[8:12])
		hasSender = true
		hasReceiver = true
	case PacketCookieReply:
		if len(packet) != CookieReplySize {
			return false
		}
		receiverID = binary.LittleEndian.Uint32(packet[4:8])
		hasReceiver = true
	case PacketData:
		if len(packet) < MinDataPacketSize {
			return false
		}
		receiverID = binary.LittleEndian.Uint32(packet[4:8])
		hasReceiver = true
	default:
		return false
	}

	remoteAddrStr := remoteAddr.String()
	var sess *WireguardSession
	for _, s := range g.Sessions {
		if s.RelayPort != relayPort || s.RemoteAddr != remoteAddrStr {
			continue
		}
		match := true
		if hasSender && s.ServerPeerID != 0 && s.ServerPeerID != senderID {
			match = false
		}
		if hasReceiver && s.ClientPeerID != 0 && s.ClientPeerID != receiverID {
			match = false
		}
		if match {
			sess = s
			break
		}
	}

	if sess == nil {
		sess = &WireguardSession{
			RelayPort:  relayPort,
			RemoteAddr: remoteAddrStr,
		}

		maxForRelay := DefaultPerRelayMaxSessions
		if m, ok := g.PerRelayMaxSessions[relayPort]; ok {
			maxForRelay = m
		}

		relaySessCount := 0
		for _, s := range g.Sessions {
			if s.RelayPort == relayPort {
				relaySessCount++
			}
		}

		if len(g.Sessions) >= g.GlobalMaxSessions || relaySessCount >= maxForRelay {
			found := false
			// 1. Expired
			for i, s := range g.Sessions {
				if time.Since(s.LastServerPkt) > SessionTimeout {
					g.Sessions[i] = sess
					found = true
					break
				}
			}
			// 2. Unverified
			if !found {
				for i, s := range g.Sessions {
					if !s.Verified {
						if relaySessCount >= maxForRelay {
							if s.RelayPort == relayPort {
								g.Sessions[i] = sess
								found = true
								break
							}
						} else {
							g.Sessions[i] = sess
							found = true
							break
						}
					}
				}
			}
			if !found {
				return true // Trusted server, allow through even if we couldn't create a session entry?
			}
		} else {
			g.Sessions = append(g.Sessions, sess)
		}
	}

	if hasSender {
		sess.ServerPeerID = senderID
	}
	if hasReceiver {
		sess.ClientPeerID = receiverID
	}

	if msgType == PacketCookieReply {
		g.handleOutboundCookieReply(packet, sess)
	}

	sess.DoSDataCount = 0
	sess.LastServerPkt = time.Now()
	sess.Verified = true

	return true
}

func (g *WireguardGuard) handleOutboundCookieReply(packet []byte, sess *WireguardSession) {
	nonce := packet[8:32]
	encryptedCookie := packet[32:64]

	aead, err := chacha20poly1305.NewX(g.CookieKey[:])
	if err != nil {
		return
	}

	cookie, err := aead.Open(nil, nonce, encryptedCookie, sess.LastMac1[:])
	if err != nil {
		return
	}
	if len(cookie) == 16 {
		copy(sess.ForwardCookie[:], cookie)
	}
}

func (g *WireguardGuard) createCookieReply(initiationPacket []byte, remoteAddr net.Addr) []byte {
	reply := make([]byte, CookieReplySize)
	reply[0] = PacketCookieReply
	copy(reply[4:8], initiationPacket[4:8])

	nonce := make([]byte, 24)
	rand.Read(nonce)
	copy(reply[8:32], nonce)

	cookie := g.getCookie(getIP(remoteAddr))

	aead, _ := chacha20poly1305.NewX(g.CookieKey[:])
	aead.Seal(reply[32:32], nonce, cookie[:], initiationPacket[116:132])

	return reply
}

func (g *WireguardGuard) maintenance() {
	now := time.Now()

	// Update DoS level
	if now.Sub(g.LastStatsReset) > 10*time.Second {
		unverifiedCount := 0
		for _, s := range g.Sessions {
			if !s.Verified {
				unverifiedCount++
			}
		}

		if g.RoamCount > 10 || g.HandshakeCount > 50 || unverifiedCount > g.GlobalMaxSessions*0.8 || g.RejectionCount > 100 {
			if g.DoSLevel < DoSLevelFull {
				g.DoSLevel++
			}
		} else if g.RoamCount == 0 && g.HandshakeCount < 5 && unverifiedCount < g.GlobalMaxSessions*0.1 && g.RejectionCount < 10 {
			if g.DoSLevel > DoSLevelNone {
				// Only decrease after some time of silence
			}
		}

		g.RoamCount = 0
		g.HandshakeCount = 0
		g.RejectionCount = 0
		g.LastStatsReset = now
	}
}

func getIP(addr net.Addr) net.IP {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.IP
	}
	return nil
}

func getIPStr(addrStr string) string {
	host, _, _ := net.SplitHostPort(addrStr)
	return host
}

type GuardPacketConn struct {
	net.PacketConn
	Guard     *WireguardGuard
	RelayPort int
}

func (c *GuardPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		allowed, modified := c.Guard.ProcessInbound(p[:n], addr, c.RelayPort)
		if allowed {
			if modified != nil {
				n = copy(p, modified)
			}
			return n, addr, nil
		}
		if modified != nil {
			_, _ = c.PacketConn.WriteTo(modified, addr)
		}
	}
}

func (c *GuardPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.Guard.ProcessOutbound(p, addr, c.RelayPort) {
		return c.PacketConn.WriteTo(p, addr)
	}
	return len(p), nil
}
