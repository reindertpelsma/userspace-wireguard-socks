// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package fdproxy exposes a small Unix-socket manager used by the Linux
// preload/ptrace wrapper. It translates local manager fds into the HTTP-upgraded
// raw socket protocol served by uwgsocks, and also owns the host-loopback side
// for unspecified binds.
package fdproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
)

const (
	listenerProtoTCP = socketproto.ProtoTCP
	listenerProtoUDP = socketproto.ProtoUDP
)

type Options struct {
	Path         string
	API          string
	Token        string
	SocketPath   string
	Logger       *log.Logger
	AllowBind    bool
	AllowLowBind bool
}

type Server struct {
	ln           *net.UnixListener
	api          string
	path         string
	token        string
	logger       *log.Logger
	allowBind    bool
	allowLowBind bool
	nextID       uint64

	mu         sync.Mutex
	tcpMembers map[string]*tcpListenerMember
	tcpGroups  map[string]*tcpListenerGroup
	udpGroups  map[string]*udpListenerGroup
}

type connectRequest struct {
	proto     uint8
	protoName string
	dest      netip.AddrPort
	bindIP    netip.Addr
	bindPort  uint16
	reuseAddr bool
	reusePort bool
}

type tcpListenerMember struct {
	token  string
	local  net.Conn
	group  *tcpListenerGroup
	closed chan struct{}
}

type tcpListenerGroup struct {
	server      *Server
	key         string
	requestBind netip.AddrPort
	replyBind   netip.AddrPort

	reusable      bool
	allowTunnel   bool
	allowLoopback bool
	dummy         bool

	up      net.Conn
	upID    uint64
	loop    net.Listener
	writeMu sync.Mutex

	mu      sync.Mutex
	members map[string]*tcpListenerMember
	order   []string
	next    uint64
	accepts map[uint64]*tcpAcceptedConn
	closed  chan struct{}
}

type tcpAcceptedConn struct {
	id       uint64
	member   *tcpListenerMember
	remote   netip.AddrPort
	host     net.Conn
	attached net.Conn
	upstream bool
}

type udpListenerGroup struct {
	server      *Server
	key         string
	requestBind netip.AddrPort
	replyBind   netip.AddrPort

	reusable      bool
	allowLoopback bool
	allowTunnel   bool

	up      net.Conn
	upID    uint64
	loop    net.PacketConn
	writeMu sync.Mutex

	mu        sync.Mutex
	members   map[string]net.Conn
	order     []string
	peerOwner map[string]string
	closed    chan struct{}
}

func Listen(path, api, token string, logger *log.Logger) (*Server, error) {
	return ListenWithSocketPath(path, api, token, "/v1/socket", logger)
}

func ListenWithSocketPath(path, api, token, socketPath string, logger *log.Logger) (*Server, error) {
	return ListenWithOptions(Options{
		Path:         path,
		API:          api,
		Token:        token,
		SocketPath:   socketPath,
		Logger:       logger,
		AllowBind:    true,
		AllowLowBind: false,
	})
}

func ListenWithOptions(opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "uwgfdproxy: ", log.LstdFlags)
	}
	path := strings.TrimPrefix(strings.TrimPrefix(opts.Path, "unix://"), "unix:")
	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = "/v1/socket"
	}
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &Server{
		ln:           ln,
		api:          opts.API,
		path:         socketPath,
		token:        opts.Token,
		logger:       opts.Logger,
		allowBind:    opts.AllowBind,
		allowLowBind: opts.AllowLowBind,
		tcpMembers:   make(map[string]*tcpListenerMember),
		tcpGroups:    make(map[string]*tcpListenerGroup),
		udpGroups:    make(map[string]*udpListenerGroup),
	}, nil
}

func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

func (s *Server) Close() error {
	s.mu.Lock()
	tcpGroups := make([]*tcpListenerGroup, 0, len(s.tcpGroups))
	for _, group := range s.tcpGroups {
		tcpGroups = append(tcpGroups, group)
	}
	udpGroups := make([]*udpListenerGroup, 0, len(s.udpGroups))
	for _, group := range s.udpGroups {
		udpGroups = append(udpGroups, group)
	}
	s.mu.Unlock()
	for _, group := range tcpGroups {
		group.close()
	}
	for _, group := range udpGroups {
		group.close()
	}
	return s.ln.Close()
}

func (s *Server) Serve() error {
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c *net.UnixConn) {
	line, fd, err := recvRequest(c)
	if err != nil {
		_ = c.Close()
		s.logger.Printf("request failed: %v", err)
		return
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		_ = c.Close()
		s.logger.Printf("bad request %q", line)
		return
	}
	switch fields[0] {
	case "PING":
		_, _ = c.Write([]byte("PONG\n"))
		_ = c.Close()
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	case "CONNECT":
		s.handleConnect(c, fd, fields)
	case "LISTEN":
		s.handleListen(c, fd, fields)
	case "ATTACH":
		s.handleAttach(c, fd, fields)
	case "DNS":
		s.handleDNS(c, fd, fields)
	default:
		_ = c.Close()
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		s.logger.Printf("unsupported request %q", line)
	}
}

func (s *Server) handleConnect(c *net.UnixConn, fd int, fields []string) {
	req, err := parseConnectRequest(fields)
	if err != nil {
		_ = c.Close()
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		s.logger.Printf("bad CONNECT request %q: %v", strings.Join(fields, " "), err)
		return
	}
	local, closeControl, ok := s.localConn(c, fd)
	if !ok {
		return
	}
	defer closeControl()
	defer local.Close()

	upstreamBind, err := s.connectBindForUpstream(req)
	if err != nil {
		s.logger.Printf("CONNECT bind policy rejected %q: %v", strings.Join(fields, " "), err)
		return
	}
	up, bind, err := s.openUpstreamConnected(req.proto, req.dest, upstreamBind)
	if err != nil {
		s.logger.Printf("CONNECT upstream failed %q: %v", strings.Join(fields, " "), err)
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte(fmt.Sprintf("OK %s %d\n", bind.Addr(), bind.Port()))); err != nil {
		return
	}
	if req.proto == listenerProtoUDP {
		bridgeUDPConnected(local, up, socketproto.ClientIDBase+1)
		return
	}
	bridgeTCP(local, up, socketproto.ClientIDBase+1)
}

func (s *Server) handleListen(c *net.UnixConn, fd int, fields []string) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	req, err := parseListenRequest(fields)
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad LISTEN request %q: %v", strings.Join(fields, " "), err)
		return
	}
	switch req.proto {
	case listenerProtoTCP:
		member, bind, err := s.addTCPListenerMember(c, req)
		if err != nil {
			_ = c.Close()
			s.logger.Printf("tcp listener setup failed %q: %v", strings.Join(fields, " "), err)
			return
		}
		if _, err := c.Write([]byte(fmt.Sprintf("OKLISTEN %s %s %d\n", member.token, bind.Addr(), bind.Port()))); err != nil {
			member.group.removeMember(member.token)
			return
		}
		go member.watch()
	case listenerProtoUDP:
		group, token, bind, err := s.addUDPListenerMember(c, req)
		if err != nil {
			_ = c.Close()
			s.logger.Printf("udp listener setup failed %q: %v", strings.Join(fields, " "), err)
			return
		}
		_ = token
		if _, err := c.Write([]byte(fmt.Sprintf("OKUDP %s %d\n", bind.Addr(), bind.Port()))); err != nil {
			group.removeMember(token)
			return
		}
		go group.serveMember(token, c)
	default:
		_ = c.Close()
		s.logger.Printf("unsupported LISTEN proto %d", req.proto)
	}
}

func (s *Server) handleAttach(c *net.UnixConn, fd int, fields []string) {
	if len(fields) != 3 {
		_ = c.Close()
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		s.logger.Printf("bad ATTACH request %q", strings.Join(fields, " "))
		return
	}
	id, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		_ = c.Close()
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		s.logger.Printf("bad attach ID %q: %v", fields[2], err)
		return
	}
	local, closeControl, ok := s.localConn(c, fd)
	if !ok {
		return
	}
	defer func() {
		if !ok {
			closeControl()
		}
	}()

	s.mu.Lock()
	member := s.tcpMembers[fields[1]]
	s.mu.Unlock()
	if member == nil {
		_ = local.Close()
		closeControl()
		s.logger.Printf("unknown attach token %q", fields[1])
		return
	}
	if err := member.group.attach(id, member, local); err != nil {
		_ = local.Close()
		closeControl()
		s.logger.Printf("attach failed: %v", err)
		return
	}
	ok = false
}

func (s *Server) localConn(c *net.UnixConn, fd int) (net.Conn, func(), bool) {
	var local net.Conn = c
	if fd >= 0 {
		file := os.NewFile(uintptr(fd), "uwg-socketpair-peer")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			_ = c.Close()
			s.logger.Printf("file conn: %v", err)
			return nil, func() {}, false
		}
		local = conn
		return local, func() { _ = c.Close() }, true
	}
	return local, func() {}, true
}

func (s *Server) dialUp() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return socketproto.DialHTTP(ctx, s.api, s.token, s.path)
}

func (s *Server) nextToken(prefix string) string {
	n := atomic.AddUint64(&s.nextID, 1)
	return fmt.Sprintf("%s%x", prefix, n)
}

func (s *Server) nextGroupKey(prefix string, req connectRequest) string {
	if req.bindPort == 0 {
		return s.nextToken(prefix + "-ephemeral-")
	}
	return fmt.Sprintf("%s-%d-%s-%d", prefix, req.proto, req.bindIP, req.bindPort)
}

func (s *Server) connectBindForUpstream(req connectRequest) (netip.AddrPort, error) {
	if req.bindPort != 0 && req.bindPort < 1024 && !s.allowLowBind {
		return netip.AddrPort{}, syscall.EACCES
	}
	if !req.bindIP.IsValid() && req.bindPort == 0 {
		return netip.AddrPort{}, nil
	}
	if req.bindIP.IsValid() && req.bindIP.IsLoopback() {
		return netip.AddrPort{}, nil
	}
	if !s.allowBind {
		if req.bindPort == 0 {
			return netip.AddrPort{}, nil
		}
		return netip.AddrPortFrom(netip.Addr{}, req.bindPort), nil
	}
	if req.bindIP.IsValid() && req.bindIP.IsUnspecified() {
		return netip.AddrPortFrom(netip.Addr{}, req.bindPort), nil
	}
	if !req.bindIP.IsValid() {
		return netip.AddrPortFrom(netip.Addr{}, req.bindPort), nil
	}
	return netip.AddrPortFrom(req.bindIP, req.bindPort), nil
}

func (s *Server) openUpstreamConnected(proto uint8, dest, bind netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	up, err := s.dialUp()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dest.Addr()),
		Protocol:  proto,
		BindIP:    bind.Addr(),
		BindPort:  bind.Port(),
		DestIP:    dest.Addr(),
		DestPort:  dest.Port(),
	})
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	if frame.Action != socketproto.ActionAccept {
		_ = up.Close()
		return nil, netip.AddrPort{}, fmt.Errorf("connect rejected: action=%d payload=%q", frame.Action, string(frame.Payload))
	}
	accept, err := socketproto.DecodeAccept(frame.Payload)
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	return up, socketproto.AddrPort(accept.BindIP, accept.BindPort), nil
}

func (s *Server) addTCPListenerMember(local net.Conn, req connectRequest) (*tcpListenerMember, netip.AddrPort, error) {
	if req.bindPort != 0 && req.bindPort < 1024 && !s.allowLowBind {
		return nil, netip.AddrPort{}, syscall.EACCES
	}
	key := s.nextGroupKey("tcp", req)
	reusable := req.reuseAddr || req.reusePort
	if req.bindPort != 0 {
		key = fmt.Sprintf("tcp-%s-%d", req.bindIP, req.bindPort)
	}

	s.mu.Lock()
	if req.bindPort != 0 {
		if existing := s.tcpGroups[key]; existing != nil {
			if !existing.reusable || !reusable {
				s.mu.Unlock()
				return nil, netip.AddrPort{}, syscall.EADDRINUSE
			}
			member := &tcpListenerMember{
				token:  s.nextToken("tcp-attach-"),
				local:  local,
				group:  existing,
				closed: make(chan struct{}),
			}
			existing.addMemberLocked(member)
			s.tcpMembers[member.token] = member
			reply := existing.replyBind
			s.mu.Unlock()
			return member, reply, nil
		}
	}
	group := &tcpListenerGroup{
		server:      s,
		key:         key,
		requestBind: netip.AddrPortFrom(req.bindIP, req.bindPort),
		reusable:    reusable,
		members:     make(map[string]*tcpListenerMember),
		accepts:     make(map[uint64]*tcpAcceptedConn),
		closed:      make(chan struct{}),
	}
	member := &tcpListenerMember{
		token:  s.nextToken("tcp-attach-"),
		local:  local,
		group:  group,
		closed: make(chan struct{}),
	}
	group.addMemberLocked(member)
	s.tcpGroups[key] = group
	s.tcpMembers[member.token] = member
	s.mu.Unlock()

	if err := group.start(req); err != nil {
		group.close()
		return nil, netip.AddrPort{}, err
	}
	return member, group.replyBind, nil
}

func (g *tcpListenerGroup) start(req connectRequest) error {
	displayIP := req.bindIP
	if !displayIP.IsValid() {
		if req.bindPort == 0 || req.dest.Addr().Is6() {
			displayIP = netip.IPv4Unspecified()
		}
	}
	requestUnspecified := req.bindIP.IsValid() && req.bindIP.IsUnspecified()
	requestLoopback := req.bindIP.IsValid() && req.bindIP.IsLoopback()
	requestSpecific := req.bindIP.IsValid() && !requestUnspecified && !requestLoopback
	if !req.bindIP.IsValid() {
		requestUnspecified = true
	}

	g.allowLoopback = requestUnspecified || requestLoopback
	g.allowTunnel = requestSpecific && g.server.allowBind || requestUnspecified && g.server.allowBind
	if requestLoopback {
		g.allowTunnel = false
	}
	if requestSpecific && !g.server.allowBind {
		g.allowTunnel = false
	}

	port := req.bindPort
	if g.allowLoopback {
		loop, err := listenLoopbackTCP(req.bindIP, port)
		if err != nil {
			return err
		}
		g.loop = loop
		loopBind := addrPortFromNetAddr(loop.Addr())
		port = loopBind.Port()
		if requestUnspecified {
			displayIP = unspecifiedFor(loopBind.Addr())
		} else if requestLoopback {
			displayIP = loopBind.Addr()
		}
		g.replyBind = netip.AddrPortFrom(displayIP, port)
		go g.serveLoopback()
	}
	if g.allowTunnel {
		upstreamBind := normalizeUpstreamBind(req.bindIP, port)
		up, bind, err := g.server.openUpstreamListener(req.proto, upstreamBind)
		if err != nil {
			if g.allowLoopback {
				g.allowTunnel = false
			} else {
				return err
			}
		} else {
			g.up = up
			g.upID = socketproto.ClientIDBase + 1
			if !g.replyBind.IsValid() {
				replyIP := req.bindIP
				if !replyIP.IsValid() {
					replyIP = bind.Addr()
				}
				if req.bindIP.IsValid() && req.bindIP.IsUnspecified() {
					replyIP = unspecifiedFor(bind.Addr())
				}
				g.replyBind = netip.AddrPortFrom(replyIP, bind.Port())
			}
			go g.serveUpstream()
		}
	}
	if !g.replyBind.IsValid() {
		if requestSpecific {
			g.replyBind = netip.AddrPortFrom(req.bindIP, req.bindPort)
		} else {
			port, _ = allocateEphemeralPort(req.bindIP)
			g.replyBind = netip.AddrPortFrom(unspecifiedFor(req.bindIP), port)
		}
		g.dummy = true
	}
	return nil
}

func (s *Server) openUpstreamListener(proto uint8, bind netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	up, err := s.dialUp()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	version := uint8(4)
	if bind.Addr().IsValid() {
		version = socketproto.AddrVersion(bind.Addr())
	}
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: version,
		Protocol:  proto,
		BindIP:    bind.Addr(),
		BindPort:  bind.Port(),
	})
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	if frame.Action != socketproto.ActionAccept {
		_ = up.Close()
		return nil, netip.AddrPort{}, fmt.Errorf("listen rejected: action=%d payload=%q", frame.Action, string(frame.Payload))
	}
	accept, err := socketproto.DecodeAccept(frame.Payload)
	if err != nil {
		_ = up.Close()
		return nil, netip.AddrPort{}, err
	}
	return up, socketproto.AddrPort(accept.BindIP, accept.BindPort), nil
}

func (g *tcpListenerGroup) addMemberLocked(member *tcpListenerMember) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.members[member.token] = member
	g.order = append(g.order, member.token)
}

func (m *tcpListenerMember) watch() {
	_, _ = io.Copy(io.Discard, m.local)
	m.group.removeMember(m.token)
}

func (g *tcpListenerGroup) removeMember(token string) {
	g.server.mu.Lock()
	delete(g.server.tcpMembers, token)
	g.server.mu.Unlock()

	g.mu.Lock()
	member := g.members[token]
	delete(g.members, token)
	for i, current := range g.order {
		if current == token {
			g.order = append(g.order[:i], g.order[i+1:]...)
			break
		}
	}
	remaining := len(g.members)
	activeAccepts := len(g.accepts)
	empty := remaining == 0 && activeAccepts == 0
	g.mu.Unlock()

	if member != nil {
		select {
		case <-member.closed:
		default:
			close(member.closed)
		}
		_ = member.local.Close()
	}
	if empty {
		g.close()
	}
}

func (g *tcpListenerGroup) close() {
	select {
	case <-g.closed:
		return
	default:
		close(g.closed)
	}
	g.server.mu.Lock()
	if current := g.server.tcpGroups[g.key]; current == g {
		delete(g.server.tcpGroups, g.key)
	}
	for token, member := range g.members {
		delete(g.server.tcpMembers, token)
		if member != nil {
			_ = member.local.Close()
		}
	}
	g.server.mu.Unlock()
	if g.up != nil {
		_ = g.up.Close()
	}
	if g.loop != nil {
		_ = g.loop.Close()
	}
	g.mu.Lock()
	for id, accepted := range g.accepts {
		delete(g.accepts, id)
		if accepted.host != nil {
			_ = accepted.host.Close()
		}
		if accepted.attached != nil {
			_ = accepted.attached.Close()
		}
	}
	g.mu.Unlock()
}

func (g *tcpListenerGroup) serveLoopback() {
	for {
		conn, err := g.loop.Accept()
		if err != nil {
			select {
			case <-g.closed:
			default:
				g.close()
			}
			return
		}
		member := g.pickMember()
		if member == nil {
			_ = conn.Close()
			continue
		}
		acceptedID := atomic.AddUint64(&g.next, 1)
		accepted := &tcpAcceptedConn{
			id:     acceptedID,
			member: member,
			remote: addrPortFromNetAddr(conn.RemoteAddr()),
			host:   conn,
		}
		if !g.registerAccepted(accepted) {
			_ = conn.Close()
			continue
		}
		if err := g.notifyAccept(accepted); err != nil {
			g.removeAccepted(acceptedID)
			_ = conn.Close()
			g.removeMember(member.token)
		}
	}
}

func (g *tcpListenerGroup) serveUpstream() {
	for {
		frame, err := socketproto.ReadFrame(g.up, socketproto.DefaultMaxPayload)
		if err != nil {
			select {
			case <-g.closed:
			default:
				g.close()
			}
			return
		}
		switch frame.Action {
		case socketproto.ActionConnect:
			req, err := socketproto.DecodeConnect(frame.Payload)
			if err != nil {
				continue
			}
			member := g.pickMember()
			if member == nil {
				_ = g.sendFrame(socketproto.Frame{ID: frame.ID, Action: socketproto.ActionClose, Payload: []byte("no local listeners")})
				continue
			}
			accepted := &tcpAcceptedConn{
				id:       frame.ID,
				member:   member,
				remote:   netip.AddrPortFrom(req.DestIP, req.DestPort),
				upstream: true,
			}
			if !g.registerAccepted(accepted) {
				_ = g.sendFrame(socketproto.Frame{ID: frame.ID, Action: socketproto.ActionClose, Payload: []byte("duplicate accept")})
				continue
			}
			if err := g.notifyAccept(accepted); err != nil {
				g.removeAccepted(frame.ID)
				g.removeMember(member.token)
			}
		case socketproto.ActionData:
			g.mu.Lock()
			accepted := g.accepts[frame.ID]
			g.mu.Unlock()
			if accepted == nil || accepted.attached == nil {
				g.server.logger.Printf("tcp upstream data before attach id=%d attached=%t", frame.ID, accepted != nil && accepted.attached != nil)
				continue
			}
			if _, err := accepted.attached.Write(frame.Payload); err != nil {
				g.server.logger.Printf("tcp upstream write to local failed id=%d: %v", frame.ID, err)
				g.closeAccepted(frame.ID)
			}
		case socketproto.ActionClose:
			g.closeAccepted(frame.ID)
		}
	}
}

func (g *tcpListenerGroup) pickMember() *tcpListenerMember {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.order) == 0 {
		return nil
	}
	start := int(g.next % uint64(len(g.order)))
	for i := 0; i < len(g.order); i++ {
		token := g.order[(start+i)%len(g.order)]
		member := g.members[token]
		if member == nil {
			continue
		}
		g.next++
		return member
	}
	return nil
}

func (g *tcpListenerGroup) registerAccepted(accepted *tcpAcceptedConn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.accepts[accepted.id]; exists {
		return false
	}
	g.accepts[accepted.id] = accepted
	return true
}

func (g *tcpListenerGroup) notifyAccept(accepted *tcpAcceptedConn) error {
	line := fmt.Sprintf("ACCEPT %s %d %s %d\n", accepted.member.token, accepted.id, accepted.remote.Addr(), accepted.remote.Port())
	_, err := accepted.member.local.Write([]byte(line))
	return err
}

func (g *tcpListenerGroup) attach(id uint64, member *tcpListenerMember, local net.Conn) error {
	g.mu.Lock()
	accepted := g.accepts[id]
	if accepted == nil {
		g.mu.Unlock()
		return syscall.ENOENT
	}
	if accepted.member != member {
		g.mu.Unlock()
		return syscall.EPERM
	}
	if accepted.attached != nil {
		g.mu.Unlock()
		return syscall.EBUSY
	}
	accepted.attached = local
	g.mu.Unlock()

	if _, err := local.Write([]byte("OK\n")); err != nil {
		g.closeAccepted(id)
		return err
	}
	if accepted.upstream {
		if err := g.sendFrame(socketproto.Frame{ID: id, Action: socketproto.ActionAccept}); err != nil {
			g.closeAccepted(id)
			return err
		}
		go g.readAttached(id, local)
		return nil
	}
	go bridgePlain(local, accepted.host, func() { g.closeAccepted(id) })
	return nil
}

func (g *tcpListenerGroup) readAttached(id uint64, local net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			if sendErr := g.sendFrame(socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: append([]byte(nil), buf[:n]...)}); sendErr != nil {
				g.server.logger.Printf("tcp local write to upstream failed id=%d: %v", id, sendErr)
				break
			}
		}
		if err != nil {
			_ = g.sendFrame(socketproto.Frame{ID: id, Action: socketproto.ActionClose})
			break
		}
	}
	g.closeAccepted(id)
}

func (g *tcpListenerGroup) sendFrame(frame socketproto.Frame) error {
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if g.up == nil {
		return net.ErrClosed
	}
	return socketproto.WriteFrame(g.up, frame)
}

func (g *tcpListenerGroup) closeAccepted(id uint64) {
	g.mu.Lock()
	accepted := g.accepts[id]
	delete(g.accepts, id)
	shouldClose := len(g.accepts) == 0 && len(g.members) == 0
	g.mu.Unlock()
	if accepted == nil {
		return
	}
	if accepted.host != nil {
		_ = accepted.host.Close()
	}
	if accepted.attached != nil {
		_ = accepted.attached.Close()
	}
	if shouldClose {
		g.close()
	}
}

func (g *tcpListenerGroup) removeAccepted(id uint64) {
	g.mu.Lock()
	delete(g.accepts, id)
	g.mu.Unlock()
}

func (s *Server) addUDPListenerMember(local net.Conn, req connectRequest) (*udpListenerGroup, string, netip.AddrPort, error) {
	if req.bindPort != 0 && req.bindPort < 1024 && !s.allowLowBind {
		return nil, "", netip.AddrPort{}, syscall.EACCES
	}
	key := s.nextGroupKey("udp", req)
	reusable := req.reuseAddr || req.reusePort
	if req.bindPort != 0 {
		key = fmt.Sprintf("udp-%s-%d", req.bindIP, req.bindPort)
	}

	s.mu.Lock()
	if req.bindPort != 0 {
		if existing := s.udpGroups[key]; existing != nil {
			if !existing.reusable || !reusable {
				s.mu.Unlock()
				return nil, "", netip.AddrPort{}, syscall.EADDRINUSE
			}
			token := s.nextToken("udp-member-")
			existing.addMemberLocked(token, local)
			reply := existing.replyBind
			s.mu.Unlock()
			return existing, token, reply, nil
		}
	}
	group := &udpListenerGroup{
		server:      s,
		key:         key,
		requestBind: netip.AddrPortFrom(req.bindIP, req.bindPort),
		reusable:    reusable,
		members:     make(map[string]net.Conn),
		peerOwner:   make(map[string]string),
		closed:      make(chan struct{}),
	}
	token := s.nextToken("udp-member-")
	group.addMemberLocked(token, local)
	s.udpGroups[key] = group
	s.mu.Unlock()

	if err := group.start(req); err != nil {
		group.close()
		return nil, "", netip.AddrPort{}, err
	}
	return group, token, group.replyBind, nil
}

func (g *udpListenerGroup) addMemberLocked(token string, local net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.members[token] = local
	g.order = append(g.order, token)
}

func (g *udpListenerGroup) start(req connectRequest) error {
	if req.bindPort != 0 && req.bindPort < 1024 && !g.server.allowLowBind {
		return syscall.EACCES
	}
	requestUnspecified := req.bindIP.IsValid() && req.bindIP.IsUnspecified()
	requestLoopback := req.bindIP.IsValid() && req.bindIP.IsLoopback()
	requestSpecific := req.bindIP.IsValid() && !requestUnspecified && !requestLoopback
	if !req.bindIP.IsValid() {
		requestUnspecified = true
	}
	g.allowLoopback = requestUnspecified || requestLoopback
	g.allowTunnel = true

	port := req.bindPort
	displayIP := req.bindIP
	if g.allowLoopback {
		loop, err := listenLoopbackUDP(req.bindIP, port)
		if err != nil {
			return err
		}
		g.loop = loop
		loopBind := addrPortFromNetAddr(loop.LocalAddr())
		port = loopBind.Port()
		if requestUnspecified {
			displayIP = unspecifiedFor(loopBind.Addr())
		} else if requestLoopback {
			displayIP = loopBind.Addr()
		}
		g.replyBind = netip.AddrPortFrom(displayIP, port)
		go g.serveLoopback()
	}

	upstreamBind := udpBindForUpstream(req.bindIP, port, g.server.allowBind)
	up, bind, err := g.server.openUpstreamListener(listenerProtoUDP, upstreamBind)
	if err != nil {
		if !g.allowLoopback {
			return err
		}
		g.allowTunnel = false
	} else {
		g.up = up
		g.upID = socketproto.ClientIDBase + 1
		if !g.replyBind.IsValid() {
			replyIP := req.bindIP
			if requestUnspecified {
				replyIP = unspecifiedFor(bind.Addr())
			} else if !replyIP.IsValid() {
				replyIP = bind.Addr()
			}
			g.replyBind = netip.AddrPortFrom(replyIP, bind.Port())
		}
		go g.serveUpstream()
	}
	if !g.replyBind.IsValid() {
		port, _ = allocateEphemeralPort(req.bindIP)
		g.replyBind = netip.AddrPortFrom(unspecifiedFor(req.bindIP), port)
	}
	_ = requestSpecific
	return nil
}

func (g *udpListenerGroup) serveMember(token string, local net.Conn) {
	defer g.removeMember(token)
	for {
		packet, err := readLocalPacket(local)
		if err != nil {
			return
		}
		dgram, err := socketproto.DecodeUDPDatagram(packet)
		if err != nil {
			continue
		}
		remote := netip.AddrPortFrom(dgram.RemoteIP, dgram.RemotePort)
		g.recordPeerOwner(remote, token)
		if remote.Addr().IsLoopback() && g.loop != nil {
			if _, err := g.loop.WriteTo(dgram.Payload, net.UDPAddrFromAddrPort(remote)); err != nil {
				return
			}
			continue
		}
		if g.up == nil {
			continue
		}
		payload, err := socketproto.EncodeUDPDatagram(dgram)
		if err != nil {
			continue
		}
		g.writeMu.Lock()
		err = socketproto.WriteFrame(g.up, socketproto.Frame{ID: g.upID, Action: socketproto.ActionUDPDatagram, Payload: payload})
		g.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (g *udpListenerGroup) serveLoopback() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := g.loop.ReadFrom(buf)
		if err != nil {
			select {
			case <-g.closed:
			default:
				g.close()
			}
			return
		}
		remote := addrPortFromNetAddr(addr)
		if !remote.IsValid() {
			continue
		}
		g.dispatchDatagram(remote, append([]byte(nil), buf[:n]...), true)
	}
}

func (g *udpListenerGroup) serveUpstream() {
	for {
		frame, err := socketproto.ReadFrame(g.up, socketproto.DefaultMaxPayload)
		if err != nil {
			select {
			case <-g.closed:
			default:
				g.close()
			}
			return
		}
		switch frame.Action {
		case socketproto.ActionUDPDatagram:
			dgram, err := socketproto.DecodeUDPDatagram(frame.Payload)
			if err != nil {
				continue
			}
			remote := netip.AddrPortFrom(dgram.RemoteIP, dgram.RemotePort)
			g.dispatchDatagram(remote, dgram.Payload, false)
		case socketproto.ActionClose:
			select {
			case <-g.closed:
			default:
				g.close()
			}
			return
		}
	}
}

func (g *udpListenerGroup) dispatchDatagram(remote netip.AddrPort, payload []byte, fromLoopback bool) {
	token := g.ownerFor(remote)
	if token == "" {
		if !fromLoopback {
			return
		}
		token = g.randomMemberToken()
	}
	if token == "" {
		return
	}
	g.mu.Lock()
	local := g.members[token]
	g.mu.Unlock()
	if local == nil {
		return
	}
	packet, err := socketproto.EncodeUDPDatagram(socketproto.UDPDatagram{
		IPVersion:  socketproto.AddrVersion(remote.Addr()),
		RemoteIP:   remote.Addr(),
		RemotePort: remote.Port(),
		Payload:    payload,
	})
	if err != nil {
		return
	}
	if err := writeLocalPacket(local, packet); err != nil {
		g.removeMember(token)
	}
}

func (g *udpListenerGroup) randomMemberToken() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.order) == 0 {
		return ""
	}
	for i := 0; i < len(g.order); i++ {
		token := g.order[rand.IntN(len(g.order))]
		if g.members[token] != nil {
			return token
		}
	}
	return ""
}

func (g *udpListenerGroup) recordPeerOwner(remote netip.AddrPort, token string) {
	g.mu.Lock()
	g.peerOwner[remote.String()] = token
	g.mu.Unlock()
}

func (g *udpListenerGroup) ownerFor(remote netip.AddrPort) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peerOwner[remote.String()]
}

func (g *udpListenerGroup) removeMember(token string) {
	g.server.mu.Lock()
	if current := g.server.udpGroups[g.key]; current == g && len(g.order) == 1 && g.order[0] == token {
		delete(g.server.udpGroups, g.key)
	}
	g.server.mu.Unlock()

	g.mu.Lock()
	local := g.members[token]
	delete(g.members, token)
	for i, current := range g.order {
		if current == token {
			g.order = append(g.order[:i], g.order[i+1:]...)
			break
		}
	}
	for peer, owner := range g.peerOwner {
		if owner == token {
			delete(g.peerOwner, peer)
		}
	}
	remaining := len(g.members)
	empty := remaining == 0
	g.mu.Unlock()
	if local != nil {
		_ = local.Close()
	}
	if empty {
		g.close()
	}
}

func (g *udpListenerGroup) close() {
	select {
	case <-g.closed:
		return
	default:
		close(g.closed)
	}
	g.server.mu.Lock()
	if current := g.server.udpGroups[g.key]; current == g {
		delete(g.server.udpGroups, g.key)
	}
	g.server.mu.Unlock()
	if g.up != nil {
		_ = g.up.Close()
	}
	if g.loop != nil {
		_ = g.loop.Close()
	}
	g.mu.Lock()
	for token, local := range g.members {
		delete(g.members, token)
		_ = local.Close()
	}
	g.mu.Unlock()
}

func normalizeUpstreamBind(ip netip.Addr, port uint16) netip.AddrPort {
	if ip.IsValid() && ip.IsUnspecified() {
		return netip.AddrPortFrom(netip.Addr{}, port)
	}
	return netip.AddrPortFrom(ip, port)
}

func udpBindForUpstream(ip netip.Addr, port uint16, allowBind bool) netip.AddrPort {
	if ip.IsValid() && ip.IsLoopback() {
		return netip.AddrPortFrom(netip.Addr{}, 0)
	}
	if !allowBind {
		return netip.AddrPortFrom(netip.Addr{}, port)
	}
	return normalizeUpstreamBind(ip, port)
}

func unspecifiedFor(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func loopbackFor(ip netip.Addr) netip.Addr {
	if ip.IsValid() && ip.Is6() {
		return netip.MustParseAddr("::1")
	}
	return netip.MustParseAddr("127.0.0.1")
}

func listenLoopbackTCP(bindIP netip.Addr, port uint16) (net.Listener, error) {
	ip := loopbackFor(bindIP)
	network := "tcp4"
	if ip.Is6() {
		network = "tcp6"
	}
	var lc net.ListenConfig
	return lc.Listen(context.Background(), network, netip.AddrPortFrom(ip, port).String())
}

func listenLoopbackUDP(bindIP netip.Addr, port uint16) (net.PacketConn, error) {
	ip := loopbackFor(bindIP)
	network := "udp4"
	if ip.Is6() {
		network = "udp6"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, netip.AddrPortFrom(ip, port).String())
}

func allocateEphemeralPort(bindIP netip.Addr) (uint16, error) {
	ln, err := listenLoopbackTCP(bindIP, 0)
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return addrPortFromNetAddr(ln.Addr()).Port(), nil
}

func parseConnectRequest(fields []string) (connectRequest, error) {
	if len(fields) != 4 && len(fields) != 6 && len(fields) != 8 {
		return connectRequest{}, fmt.Errorf("want 4, 6, or 8 fields")
	}
	req := connectRequest{}
	switch strings.ToLower(fields[1]) {
	case "tcp":
		req.proto = listenerProtoTCP
		req.protoName = "tcp"
	case "udp":
		req.proto = listenerProtoUDP
		req.protoName = "udp"
	default:
		return connectRequest{}, fmt.Errorf("unsupported proto %q", fields[1])
	}
	ip, err := netip.ParseAddr(fields[2])
	if err != nil {
		return connectRequest{}, err
	}
	port, err := parseUint16(fields[3])
	if err != nil {
		return connectRequest{}, err
	}
	req.dest = netip.AddrPortFrom(ip, port)
	if len(fields) >= 6 {
		req.bindIP, err = netip.ParseAddr(fields[4])
		if err != nil {
			return connectRequest{}, err
		}
		req.bindPort, err = parseUint16(fields[5])
		if err != nil {
			return connectRequest{}, err
		}
	}
	if len(fields) == 8 {
		req.reuseAddr = parseBoolField(fields[6])
		req.reusePort = parseBoolField(fields[7])
	}
	return req, nil
}

func parseListenRequest(fields []string) (connectRequest, error) {
	if len(fields) != 4 && len(fields) != 6 {
		return connectRequest{}, fmt.Errorf("want 4 or 6 fields")
	}
	req := connectRequest{}
	switch strings.ToLower(fields[1]) {
	case "tcp":
		req.proto = listenerProtoTCP
		req.protoName = "tcp"
	case "udp":
		req.proto = listenerProtoUDP
		req.protoName = "udp"
	default:
		return connectRequest{}, fmt.Errorf("unsupported proto %q", fields[1])
	}
	ip, err := netip.ParseAddr(fields[2])
	if err != nil {
		return connectRequest{}, err
	}
	req.bindIP = ip
	req.bindPort, err = parseUint16(fields[3])
	if err != nil {
		return connectRequest{}, err
	}
	if len(fields) == 6 {
		req.reuseAddr = parseBoolField(fields[4])
		req.reusePort = parseBoolField(fields[5])
	}
	return req, nil
}

func parseUint16(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

func parseBoolField(s string) bool {
	return s == "1" || strings.EqualFold(s, "true") || strings.EqualFold(s, "yes")
}

func bridgeTCP(local net.Conn, up net.Conn, id uint64) {
	errc := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if werr := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: append([]byte(nil), buf[:n]...)}); werr != nil {
					break
				}
			}
			if err != nil {
				_ = socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionClose})
				break
			}
		}
		_ = up.Close()
		errc <- struct{}{}
	}()
	go func() {
		defer func() {
			_ = local.Close()
			errc <- struct{}{}
		}()
		for {
			frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
			if err != nil {
				break
			}
			switch frame.Action {
			case socketproto.ActionData:
				if _, err := local.Write(frame.Payload); err != nil {
					return
				}
			case socketproto.ActionClose:
				return
			}
		}
	}()
	<-errc
}

func bridgeUDPConnected(local net.Conn, up net.Conn, id uint64) {
	errc := make(chan struct{}, 2)
	go func() {
		for {
			payload, err := readLocalPacket(local)
			if err != nil {
				_ = socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionClose})
				break
			}
			if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: payload}); err != nil {
				break
			}
		}
		_ = up.Close()
		errc <- struct{}{}
	}()
	go func() {
		defer func() {
			_ = local.Close()
			errc <- struct{}{}
		}()
		for {
			frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
			if err != nil {
				return
			}
			switch frame.Action {
			case socketproto.ActionData:
				if err := writeLocalPacket(local, frame.Payload); err != nil {
					return
				}
			case socketproto.ActionClose:
				return
			}
		}
	}()
	<-errc
}

func bridgePlain(a, b net.Conn, onClose func()) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	if onClose != nil {
		onClose()
	}
}

func (s *Server) handleDNS(c *net.UnixConn, fd int, fields []string) {
	if len(fields) != 2 {
		_ = c.Close()
		s.logger.Printf("bad DNS request %q", strings.Join(fields, " "))
		return
	}
	sizeMode := fields[1]
	if sizeMode != "16" && sizeMode != "32" {
		_ = c.Close()
		s.logger.Printf("bad DNS size mode %q: only 16/32 bits are supported", fields[1])
		return
	}
	largePrefix := sizeMode == "32"

	local, closeControl, ok := s.localConn(c, fd)
	if !ok {
		return
	}
	defer closeControl()
	defer local.Close()

	up, err := s.dialUp()
	if err != nil {
		s.logger.Printf("api socket: %v", err)
		return
	}
	defer up.Close()

	if _, err := c.Write([]byte("OK\n")); err != nil {
		return
	}

	errc := make(chan struct{}, 2)
	go func() {
		for {
			var payload []byte
			var err error
			if largePrefix {
				payload, err = readLocalPacket(local)
			} else {
				payload, err = readUInt16LocalPacket(local)
			}
			if err != nil {
				break
			}
			if err := socketproto.WriteFrame(up, socketproto.Frame{ID: socketproto.ClientIDBase + 2, Action: socketproto.ActionDNS, Payload: payload}); err != nil {
				break
			}
		}
		_ = up.Close()
		errc <- struct{}{}
	}()
	go func() {
		defer func() {
			_ = local.Close()
			errc <- struct{}{}
		}()
		for {
			frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
			if err != nil {
				return
			}
			if frame.Action != socketproto.ActionDNS || frame.ID != socketproto.ClientIDBase+2 {
				continue
			}
			payload := frame.Payload
			if len(payload) > 65535 {
				payload = payload[:65535]
			}
			if largePrefix {
				if err := writeLocalPacket(local, payload); err != nil {
					return
				}
			} else {
				if err := writeUint16LocalPacket(local, payload); err != nil {
					return
				}
			}
		}
	}()
	<-errc
}

func addrPortFromNetAddr(addr net.Addr) netip.AddrPort {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err == nil {
		return ap
	}
	return netip.AddrPort{}
}

func readLocalPacket(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > socketproto.DefaultMaxPayload {
		return nil, socketproto.ErrFrameTooLarge
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func writeLocalPacket(w io.Writer, p []byte) error {
	if len(p) > socketproto.DefaultMaxPayload {
		return socketproto.ErrFrameTooLarge
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readUInt16LocalPacket(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func writeUint16LocalPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 {
		return socketproto.ErrFrameTooLarge
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(p)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func recvRequest(c *net.UnixConn) (string, int, error) {
	data := make([]byte, 4096)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(data, oob)
	if err != nil {
		return "", -1, err
	}
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return "", -1, err
		}
		for _, msg := range msgs {
			fds, err := syscall.ParseUnixRights(&msg)
			if err != nil {
				continue
			}
			if len(fds) > 0 {
				return strings.TrimSpace(string(data[:n])), fds[0], nil
			}
		}
	}
	line := strings.TrimSpace(string(data[:n]))
	if line == "" {
		return "", -1, fmt.Errorf("empty request")
	}
	return line, -1, nil
}
