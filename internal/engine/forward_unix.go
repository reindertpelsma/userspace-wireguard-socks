// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

const unixMessageChunkBytes = 60 * 1024

func frameBytesForForward(f config.Forward) int {
	if f.FrameBytes == 2 {
		return 2
	}
	return 4
}

func prepareUnixSocketPath(path string) error {
	if path == "" || strings.HasPrefix(path, "@") {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func listenUnixEndpoint(ep config.ForwardEndpoint) (net.Listener, error) {
	if err := prepareUnixSocketPath(ep.Address); err != nil {
		return nil, err
	}
	return net.Listen(ep.Network(), ep.Address)
}

func listenUnixDatagram(ep config.ForwardEndpoint) (*net.UnixConn, error) {
	if err := prepareUnixSocketPath(ep.Address); err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket(ep.Network(), ep.Address)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UnixConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("listen %s %q did not return *net.UnixConn", ep.Network(), ep.Address)
	}
	return uc, nil
}

func dialUnixEndpoint(ep config.ForwardEndpoint) (net.Conn, error) {
	switch ep.Kind {
	case config.ForwardEndpointUnixStream, config.ForwardEndpointUnixSeqpacket:
		return net.Dial(ep.Network(), ep.Address)
	case config.ForwardEndpointUnixDgram:
		return dialConnectedUnixDatagram(ep.Address)
	default:
		return nil, fmt.Errorf("unsupported unix endpoint kind %v", ep.Kind)
	}
}

func dialConnectedUnixDatagram(target string) (net.Conn, error) {
	remote := &net.UnixAddr{Name: target, Net: "unixgram"}
	local, cleanup, err := nextEphemeralUnixDatagramAddr()
	if err != nil {
		return nil, err
	}
	c, err := net.DialUnix("unixgram", local, remote)
	if err != nil {
		_ = cleanup()
		return nil, err
	}
	return &cleanupConn{Conn: c, cleanup: cleanup}, nil
}

func nextEphemeralUnixDatagramAddr() (*net.UnixAddr, func() error, error) {
	suffix, err := randomHexSuffix()
	if err != nil {
		return nil, nil, err
	}
	if runtime.GOOS == "linux" {
		name := "@uwgsocks-" + suffix
		return &net.UnixAddr{Name: name, Net: "unixgram"}, func() error { return nil }, nil
	}
	path := filepath.Join(os.TempDir(), "uwgsocks-"+suffix+".sock")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	return &net.UnixAddr{Name: path, Net: "unixgram"}, func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}, nil
}

func randomHexSuffix() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

type cleanupConn struct {
	net.Conn
	once    sync.Once
	cleanup func() error
}

func (c *cleanupConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.cleanup != nil {
			_ = c.cleanup()
		}
	})
	return err
}

type framedUnixMessageConn struct {
	net.Conn
	frameBytes int
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuf    bytes.Buffer
}

func wrapFramedUnixMessageConn(c net.Conn, f config.Forward) net.Conn {
	return &framedUnixMessageConn{Conn: c, frameBytes: frameBytesForForward(f)}
}

func (c *framedUnixMessageConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.readBuf.Len() == 0 {
		buf := make([]byte, unixMessageChunkBytes+8)
		n, err := c.Conn.Read(buf)
		if err != nil {
			return 0, err
		}
		payload, err := decodeUnixFrame(buf[:n], c.frameBytes)
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		c.readBuf.Write(payload)
	}
	return c.readBuf.Read(p)
}

func (c *framedUnixMessageConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	maxPayload := unixMessageChunkBytes
	if c.frameBytes == 2 && maxPayload > 0xffff {
		maxPayload = 0xffff
	}
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		frame := make([]byte, c.frameBytes+len(chunk))
		switch c.frameBytes {
		case 2:
			binary.BigEndian.PutUint16(frame[:2], uint16(len(chunk)))
		default:
			binary.BigEndian.PutUint32(frame[:4], uint32(len(chunk)))
		}
		copy(frame[c.frameBytes:], chunk)
		n, err := c.Conn.Write(frame)
		if err != nil {
			return total, err
		}
		if n != len(frame) {
			return total, io.ErrShortWrite
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func decodeUnixFrame(frame []byte, frameBytes int) ([]byte, error) {
	if len(frame) < frameBytes {
		return nil, fmt.Errorf("unix message frame too short")
	}
	var want int
	switch frameBytes {
	case 2:
		want = int(binary.BigEndian.Uint16(frame[:2]))
	default:
		want = int(binary.BigEndian.Uint32(frame[:4]))
	}
	payload := frame[frameBytes:]
	if want != len(payload) {
		return nil, fmt.Errorf("unix message frame length %d does not match payload %d", want, len(payload))
	}
	return payload, nil
}

type unixDatagramSessionConn struct {
	pc     *net.UnixConn
	remote *net.UnixAddr

	incoming chan []byte
	closed   chan struct{}
	once     sync.Once
	onClose  func()

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newUnixDatagramSessionConn(pc *net.UnixConn, remote *net.UnixAddr, onClose func()) *unixDatagramSessionConn {
	return &unixDatagramSessionConn{
		pc:       pc,
		remote:   remote,
		incoming: make(chan []byte, 32),
		closed:   make(chan struct{}),
		onClose:  onClose,
	}
}

func (c *unixDatagramSessionConn) enqueue(payload []byte) bool {
	select {
	case <-c.closed:
		return false
	case c.incoming <- payload:
		return true
	}
}

func (c *unixDatagramSessionConn) Read(p []byte) (int, error) {
	payload, err := c.waitForPayload()
	if err != nil {
		return 0, err
	}
	if len(payload) == 0 {
		return 0, nil
	}
	return copy(p, payload), nil
}

func (c *unixDatagramSessionConn) waitForPayload() ([]byte, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	if deadline.IsZero() {
		select {
		case <-c.closed:
			return nil, net.ErrClosed
		case payload := <-c.incoming:
			return payload, nil
		}
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return nil, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case payload := <-c.incoming:
		return payload, nil
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (c *unixDatagramSessionConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	return c.pc.WriteToUnix(p, c.remote)
}

func (c *unixDatagramSessionConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *unixDatagramSessionConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *unixDatagramSessionConn) RemoteAddr() net.Addr { return c.remote }

func (c *unixDatagramSessionConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *unixDatagramSessionConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *unixDatagramSessionConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (e *Engine) runTCPForwardConn(src net.Conn, f config.Forward) {
	defer src.Close()
	aclSrc := addrPortFromNetAddr(src.RemoteAddr())
	bindSrc := netip.AddrPort{}
	srcConn := net.Conn(src)
	if f.ProxyProtocol != "" {
		_ = src.SetReadDeadline(time.Now().Add(10 * time.Second))
		wrapped, pp, err := parseProxyProtocolConn(src, f.ProxyProtocol)
		_ = src.SetReadDeadline(time.Time{})
		if err != nil {
			e.log.Printf("tcp forward %s PROXY header failed: %v", f.Listen, err)
			return
		}
		srcConn = wrapped
		if pp.Source.IsValid() {
			aclSrc = pp.Source
			bindSrc = pp.Source
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dst, err := e.dialTunnelOnlyWithBind(ctx, "tcp", f.Target, aclSrc, bindSrc)
	if err != nil {
		e.log.Printf("tcp forward %s -> %s failed: %v", f.Listen, f.Target, err)
		return
	}
	defer dst.Close()
	proxyBothIdle(srcConn, dst, e.tcpIdleTimeout())
}

func (e *Engine) proxyUDPForwardConn(local, remote net.Conn, f config.Forward) {
	var (
		timer *time.Timer
		mu    sync.Mutex
	)
	idle := e.udpIdleTimeout()
	touch := func() {
		if idle <= 0 {
			return
		}
		mu.Lock()
		if timer != nil {
			timer.Reset(idle)
		}
		mu.Unlock()
	}
	if idle > 0 {
		timer = time.AfterFunc(idle, func() {
			_ = local.Close()
			_ = remote.Close()
		})
		defer timer.Stop()
	}
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			payload := buf[:n]
			if f.ProxyProtocol != "" {
				stripped, _, err := stripProxyProtocolDatagram(payload, f.ProxyProtocol)
				if err != nil {
					e.log.Printf("udp forward %s PROXY header failed: %v", f.Listen, err)
					done <- struct{}{}
					return
				}
				payload = stripped
			}
			touch()
			if _, err := remote.Write(payload); err != nil {
				done <- struct{}{}
				return
			}
			touch()
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			touch()
			if _, err := local.Write(buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
			touch()
		}
	}()
	<-done
}

func unixAddrKey(addr *net.UnixAddr) string {
	if addr == nil || addr.Name == "" {
		return ""
	}
	return addr.Net + ":" + addr.Name
}

func (e *Engine) startTCPUnixForward(name string, f config.Forward, ep config.ForwardEndpoint) error {
	if ep.Kind == config.ForwardEndpointUnixDgram {
		return e.startTCPUnixDgramForward(name, f, ep)
	}
	ln, err := listenUnixEndpoint(ep)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("tcp forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			if ep.UsesMessages() {
				c = wrapFramedUnixMessageConn(c, f)
			}
			go e.runTCPForwardConn(c, f)
		}
	}()
	return nil
}

func (e *Engine) startTCPUnixDgramForward(name string, f config.Forward, ep config.ForwardEndpoint) error {
	pc, err := listenUnixDatagram(ep)
	if err != nil {
		return err
	}
	e.addPacketConn(name, pc)
	go func() {
		var mu sync.Mutex
		sessions := make(map[string]*unixDatagramSessionConn)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFromUnix(buf)
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("tcp forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			if addr == nil {
				continue
			}
			key := unixAddrKey(addr)
			if key == "" && !f.AllowUnnamedDGRAM {
				continue
			}
			payload := append([]byte(nil), buf[:n]...)
			mu.Lock()
			sess := sessions[key]
			if sess == nil {
				sess = newUnixDatagramSessionConn(pc, addr, func() {
					if key == "" {
						return
					}
					mu.Lock()
					delete(sessions, key)
					mu.Unlock()
				})
				if key != "" {
					sessions[key] = sess
				}
				go e.runTCPForwardConn(wrapFramedUnixMessageConn(sess, f), f)
			}
			mu.Unlock()
			_ = sess.enqueue(payload)
		}
	}()
	return nil
}

func (e *Engine) startUDPUnixForward(name string, f config.Forward, ep config.ForwardEndpoint) error {
	if ep.Kind == config.ForwardEndpointUnixDgram {
		return e.startUDPUnixDgramForward(name, f, ep)
	}
	ln, err := listenUnixEndpoint(ep)
	if err != nil {
		return err
	}
	e.addListener(name, ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("udp forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			go e.handleUDPUnixPacketForwardConn(c, f)
		}
	}()
	return nil
}

func (e *Engine) handleUDPUnixPacketForwardConn(local net.Conn, f config.Forward) {
	defer local.Close()
	buf := make([]byte, 64*1024)
	_ = local.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := local.Read(buf)
	_ = local.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	payload := append([]byte(nil), buf[:n]...)
	source := addrPortFromNetAddr(local.RemoteAddr())
	bindSrc := netip.AddrPort{}
	if f.ProxyProtocol != "" {
		stripped, pp, err := stripProxyProtocolDatagram(payload, f.ProxyProtocol)
		if err != nil {
			e.log.Printf("udp forward %s PROXY header failed: %v", f.Listen, err)
			return
		}
		payload = stripped
		if pp.Source.IsValid() {
			source = pp.Source
			bindSrc = pp.Source
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	remote, err := e.dialTunnelOnlyWithBind(ctx, "udp", f.Target, source, bindSrc)
	cancel()
	if err != nil {
		e.log.Printf("udp forward %s -> %s failed: %v", f.Listen, f.Target, err)
		return
	}
	defer remote.Close()
	if _, err := remote.Write(payload); err != nil {
		return
	}
	e.proxyUDPForwardConn(local, remote, f)
}

func (e *Engine) startUDPUnixDgramForward(name string, f config.Forward, ep config.ForwardEndpoint) error {
	pc, err := listenUnixDatagram(ep)
	if err != nil {
		return err
	}
	e.addPacketConn(name, pc)
	go func() {
		var mu sync.Mutex
		sessions := make(map[string]*unixDatagramSessionConn)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFromUnix(buf)
			if err != nil {
				if !isClosedErr(err) {
					e.log.Printf("udp forward %s stopped: %v", f.Listen, err)
				}
				return
			}
			if addr == nil {
				continue
			}
			key := unixAddrKey(addr)
			if key == "" && !f.AllowUnnamedDGRAM {
				continue
			}
			payload := append([]byte(nil), buf[:n]...)
			source := netip.AddrPort{}
			bindSrc := netip.AddrPort{}
			if f.ProxyProtocol != "" {
				stripped, pp, err := stripProxyProtocolDatagram(payload, f.ProxyProtocol)
				if err != nil {
					e.log.Printf("udp forward %s PROXY header failed: %v", f.Listen, err)
					continue
				}
				payload = stripped
				if pp.Source.IsValid() {
					source = pp.Source
					bindSrc = pp.Source
				}
			}
			mu.Lock()
			sess := sessions[key]
			if sess == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				remote, err := e.dialTunnelOnlyWithBind(ctx, "udp", f.Target, source, bindSrc)
				cancel()
				if err != nil {
					mu.Unlock()
					e.log.Printf("udp forward %s -> %s failed: %v", f.Listen, f.Target, err)
					continue
				}
				sess = newUnixDatagramSessionConn(pc, addr, func() {
					if key == "" {
						return
					}
					mu.Lock()
					delete(sessions, key)
					mu.Unlock()
				})
				if key != "" {
					sessions[key] = sess
				}
				go func(local net.Conn, remote net.Conn) {
					defer remote.Close()
					e.proxyUDPForwardConn(local, remote, f)
				}(sess, remote)
			}
			mu.Unlock()
			_ = sess.enqueue(payload)
		}
	}()
	return nil
}
