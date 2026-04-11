// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package fdproxy exposes a small Unix-socket manager used by the experimental
// LD_PRELOAD wrapper. It translates local manager fds into the HTTP-upgraded
// raw socket protocol served by uwgsocks.
package fdproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
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

type Server struct {
	ln          *net.UnixListener
	api         string
	path        string
	token       string
	logger      *log.Logger
	nextAttach  uint64
	mu          sync.Mutex
	tcpListener map[string]*tcpListenerBridge
}

type tcpListenerBridge struct {
	token  string
	up     net.Conn
	local  net.Conn
	write  sync.Mutex
	mu     sync.Mutex
	locals map[uint64]net.Conn
	closed chan struct{}
}

// Listen creates a manager socket using the API server's /v1/socket endpoint.
func Listen(path, api, token string, logger *log.Logger) (*Server, error) {
	return ListenWithSocketPath(path, api, token, "/v1/socket", logger)
}

// ListenWithSocketPath creates a manager socket for a configurable upstream
// upgrade path. /uwg/socket is useful when the upstream is an HTTP proxy Unix
// listener rather than the API server itself.
func ListenWithSocketPath(path, api, token, socketPath string, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "uwgfdproxy: ", log.LstdFlags)
	}
	path = strings.TrimPrefix(strings.TrimPrefix(path, "unix://"), "unix:")
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
	return &Server{ln: ln, api: api, path: socketPath, token: token, logger: logger, tcpListener: make(map[string]*tcpListenerBridge)}, nil
}

func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

func (s *Server) Close() error {
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
	case "CONNECT":
		s.handleConnect(c, fd, fields)
	case "LISTEN":
		s.handleListen(c, fd, fields)
	case "ATTACH":
		s.handleAttach(c, fd, fields)
	default:
		_ = c.Close()
		s.logger.Printf("bad request %q", line)
	}
}

// handleConnect serves destination-fixed TCP and UDP sockets. TCP is bridged as
// a byte stream; UDP uses length-prefixed packets on the manager fd so datagram
// boundaries survive the Unix stream transport.
func (s *Server) handleConnect(c *net.UnixConn, fd int, fields []string) {
	if len(fields) != 4 {
		_ = c.Close()
		s.logger.Printf("bad CONNECT request %q", strings.Join(fields, " "))
		return
	}
	local, closeControl, ok := s.localConn(c, fd)
	if !ok {
		return
	}
	defer closeControl()
	defer local.Close()
	proto := fields[1]
	ip, err := netip.ParseAddr(fields[2])
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad IP %q: %v", fields[2], err)
		return
	}
	port64, err := strconv.ParseUint(fields[3], 10, 16)
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad port %q: %v", fields[3], err)
		return
	}

	up, err := s.dialUp()
	if err != nil {
		s.logger.Printf("api socket: %v", err)
		return
	}
	defer up.Close()

	sp := socketproto.ProtoTCP
	if strings.HasPrefix(proto, "udp") {
		sp = socketproto.ProtoUDP
	}
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(ip),
		Protocol:  sp,
		DestIP:    ip,
		DestPort:  uint16(port64),
	})
	if err != nil {
		s.logger.Printf("encode connect: %v", err)
		return
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		s.logger.Printf("connect frame: %v", err)
		return
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		s.logger.Printf("accept frame: %v", err)
		return
	}
	if frame.Action != socketproto.ActionAccept {
		s.logger.Printf("connect rejected: action=%d payload=%q", frame.Action, string(frame.Payload))
		return
	}
	if _, err := c.Write([]byte("OK\n")); err != nil {
		return
	}
	if sp == socketproto.ProtoUDP {
		bridgeUDPConnected(local, up, id)
		return
	}
	bridgeTCP(local, up, id)
}

// handleListen creates a tunnel-side listener through the raw socket API. UDP
// listener fds exchange length-prefixed udp_datagram payloads. TCP listener fds
// stay open as an event stream and emit ACCEPT lines that the preload wrapper
// turns into accept(2) results via ATTACH.
func (s *Server) handleListen(c *net.UnixConn, fd int, fields []string) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	if len(fields) != 4 {
		_ = c.Close()
		s.logger.Printf("bad LISTEN request %q", strings.Join(fields, " "))
		return
	}
	proto := fields[1]
	ip, err := netip.ParseAddr(fields[2])
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad listen IP %q: %v", fields[2], err)
		return
	}
	port64, err := strconv.ParseUint(fields[3], 10, 16)
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad listen port %q: %v", fields[3], err)
		return
	}
	sp := socketproto.ProtoTCP
	if strings.HasPrefix(proto, "udp") {
		sp = socketproto.ProtoUDP
	}
	up, err := s.dialUp()
	if err != nil {
		_ = c.Close()
		s.logger.Printf("api socket: %v", err)
		return
	}
	bindIP := ip
	if ip.Is4() && ip == netip.IPv4Unspecified() || ip.Is6() && ip == netip.IPv6Unspecified() {
		bindIP = netip.Addr{}
	}
	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(ip),
		Protocol:  sp,
		BindIP:    bindIP,
		BindPort:  uint16(port64),
	})
	if err != nil {
		_ = c.Close()
		_ = up.Close()
		s.logger.Printf("encode listen: %v", err)
		return
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		_ = c.Close()
		_ = up.Close()
		s.logger.Printf("listen frame: %v", err)
		return
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		_ = c.Close()
		_ = up.Close()
		s.logger.Printf("listen accept frame: %v", err)
		return
	}
	if frame.Action != socketproto.ActionAccept {
		_ = c.Close()
		_ = up.Close()
		s.logger.Printf("listen rejected: action=%d payload=%q", frame.Action, string(frame.Payload))
		return
	}
	if sp == socketproto.ProtoUDP {
		if _, err := c.Write([]byte("OKUDP\n")); err != nil {
			_ = c.Close()
			_ = up.Close()
			return
		}
		bridgeUDPListener(c, up, id)
		return
	}
	token := strconv.FormatUint(atomic.AddUint64(&s.nextAttach, 1), 36)
	l := &tcpListenerBridge{token: token, up: up, local: c, locals: make(map[uint64]net.Conn), closed: make(chan struct{})}
	s.mu.Lock()
	s.tcpListener[token] = l
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tcpListener, token)
		s.mu.Unlock()
		l.close()
	}()
	if _, err := c.Write([]byte("OKLISTEN " + token + "\n")); err != nil {
		return
	}
	l.serve()
}

// handleAttach connects a newly-created manager fd to a pending TCP accept from
// a tunnel-side listener.
func (s *Server) handleAttach(c *net.UnixConn, fd int, fields []string) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	if len(fields) != 3 {
		_ = c.Close()
		s.logger.Printf("bad ATTACH request %q", strings.Join(fields, " "))
		return
	}
	id, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		_ = c.Close()
		s.logger.Printf("bad attach ID %q: %v", fields[2], err)
		return
	}
	s.mu.Lock()
	l := s.tcpListener[fields[1]]
	s.mu.Unlock()
	if l == nil {
		_ = c.Close()
		s.logger.Printf("unknown attach token %q", fields[1])
		return
	}
	if err := l.attach(id, c); err != nil {
		_ = c.Close()
		s.logger.Printf("attach failed: %v", err)
	}
}

// localConn keeps compatibility with the earlier SCM_RIGHTS/socketpair bridge.
// When no fd was passed, the accepted Unix connection itself is the managed fd.
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

func bridgeUDPListener(local net.Conn, up net.Conn, id uint64) {
	errc := make(chan struct{}, 2)
	go func() {
		for {
			payload, err := readLocalPacket(local)
			if err != nil {
				_ = socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionClose})
				break
			}
			if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionUDPDatagram, Payload: payload}); err != nil {
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
			case socketproto.ActionUDPDatagram:
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

// tcpListenerBridge owns one raw socket API TCP listener. The listener's
// manager fd carries only ACCEPT control lines; each accepted stream gets its
// own manager connection attached by handleAttach.
func (l *tcpListenerBridge) serve() {
	for {
		frame, err := socketproto.ReadFrame(l.up, socketproto.DefaultMaxPayload)
		if err != nil {
			return
		}
		switch frame.Action {
		case socketproto.ActionConnect:
			req, err := socketproto.DecodeConnect(frame.Payload)
			if err != nil {
				continue
			}
			line := fmt.Sprintf("ACCEPT %s %d %s %d\n", l.token, frame.ID, req.DestIP, req.DestPort)
			if _, err := l.local.Write([]byte(line)); err != nil {
				return
			}
		case socketproto.ActionData:
			if c := l.localFor(frame.ID); c != nil {
				_, _ = c.Write(frame.Payload)
			}
		case socketproto.ActionClose:
			l.closeLocal(frame.ID)
		}
	}
}

func (l *tcpListenerBridge) attach(id uint64, c net.Conn) error {
	l.mu.Lock()
	if _, exists := l.locals[id]; exists {
		l.mu.Unlock()
		return fmt.Errorf("connection %d is already attached", id)
	}
	l.locals[id] = c
	l.mu.Unlock()
	if _, err := c.Write([]byte("OK\n")); err != nil {
		l.closeLocal(id)
		return err
	}
	if err := l.send(socketproto.Frame{ID: id, Action: socketproto.ActionAccept}); err != nil {
		l.closeLocal(id)
		return err
	}
	go l.readAccepted(id, c)
	return nil
}

func (l *tcpListenerBridge) readAccepted(id uint64, c net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if werr := l.send(socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: append([]byte(nil), buf[:n]...)}); werr != nil {
				break
			}
		}
		if err != nil {
			_ = l.send(socketproto.Frame{ID: id, Action: socketproto.ActionClose})
			break
		}
	}
	l.closeLocal(id)
}

func (l *tcpListenerBridge) send(f socketproto.Frame) error {
	l.write.Lock()
	defer l.write.Unlock()
	return socketproto.WriteFrame(l.up, f)
}

func (l *tcpListenerBridge) localFor(id uint64) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locals[id]
}

func (l *tcpListenerBridge) closeLocal(id uint64) {
	l.mu.Lock()
	c := l.locals[id]
	delete(l.locals, id)
	l.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (l *tcpListenerBridge) close() {
	select {
	case <-l.closed:
		return
	default:
		close(l.closed)
	}
	_ = l.up.Close()
	_ = l.local.Close()
	l.mu.Lock()
	for id, c := range l.locals {
		delete(l.locals, id)
		_ = c.Close()
	}
	l.mu.Unlock()
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
