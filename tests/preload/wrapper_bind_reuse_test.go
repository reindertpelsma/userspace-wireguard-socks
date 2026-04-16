// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
)

func TestUWGWrapperSourceBindAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	for index, transport := range []string{"preload", "preload-and-ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			fdSock := startSharedWrapperFDProxy(t, httpSock, true, false)
			tcpListenPort := 18210 + index
			udpListenPort := 18220 + index
			tcpSourcePort := 19210 + index*2
			udpSourcePort := tcpSourcePort + 1

			tcpLn, err := serverEng.ListenTCP(netip.AddrPortFrom(netip.MustParseAddr("100.64.94.1"), uint16(tcpListenPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer tcpLn.Close()
			tcpSeen := make(chan netip.AddrPort, 1)
			go func() {
				conn, err := tcpLn.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				tcpSeen <- addrPortFromNetAddr(conn.RemoteAddr())
				_, _ = io.Copy(conn, conn)
			}()

			udpPC, err := serverEng.ListenUDP(netip.AddrPortFrom(netip.MustParseAddr("100.64.94.1"), uint16(udpListenPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer udpPC.Close()
			udpSeen := make(chan netip.AddrPort, 1)
			go func() {
				buf := make([]byte, 2048)
				n, addr, err := udpPC.ReadFrom(buf)
				if err != nil {
					return
				}
				udpSeen <- addrPortFromNetAddr(addr)
				_, _ = udpPC.WriteTo(buf[:n], addr)
			}()

			tcpEnv := map[string]string{"UWGS_STUB_BIND": fmt.Sprintf("100.64.94.2:%d", tcpSourcePort)}
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.1", fmt.Sprintf("%d", tcpListenPort), "tcp-source-bind", "tcp-no-poll"},
				wrapperRunOptions{
					env:         tcpEnv,
					timeout:     60 * time.Second,
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
				})
			if normalizedOutput(out) != "tcp-source-bind" {
				t.Fatalf("unexpected TCP output %q", out)
			}
			select {
			case seen := <-tcpSeen:
				if int(seen.Port()) != tcpSourcePort {
					t.Fatalf("TCP source port = %d, want %d", seen.Port(), tcpSourcePort)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for TCP source bind observation")
			}

			udpEnv := map[string]string{"UWGS_STUB_BIND": fmt.Sprintf("100.64.94.2:%d", udpSourcePort)}
			out = runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.1", fmt.Sprintf("%d", udpListenPort), "udp-source-bind", "udp-no-poll"},
				wrapperRunOptions{
					env:         udpEnv,
					timeout:     60 * time.Second,
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
				})
			if normalizedOutput(out) != "udp-source-bind" {
				t.Fatalf("unexpected UDP output %q", out)
			}
			select {
			case seen := <-udpSeen:
				if int(seen.Port()) != udpSourcePort {
					t.Fatalf("UDP source port = %d, want %d", seen.Port(), udpSourcePort)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for UDP source bind observation")
			}

			out = runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.1", "18081", "udp-unconnected-source-bind", "udp-unconnected-no-poll"},
				wrapperRunOptions{
					env:         udpEnv,
					timeout:     60 * time.Second,
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
				})
			if normalizedOutput(out) != "udp-unconnected-source-bind" {
				t.Fatalf("unexpected UDP unconnected output %q", out)
			}
		})
	}
}

func TestUWGWrapperBindDisabledFallbacks(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	for index, transport := range []string{"preload", "preload-and-ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			fdSock := startSharedWrapperFDProxy(t, httpSock, false, false)
			localPort := 19310 + index*10
			dummyPort := localPort + 1
			udpSourcePort := localPort + 2

			opts := wrapperRunOptions{
				wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
				timeout:     60 * time.Second,
				env: map[string]string{
					"UWGS_STUB_REPLY": "loopback-only",
				},
			}
			cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"0.0.0.0", fmt.Sprintf("%d", localPort), "ignored", "listen-tcp"}, opts)

			expectTunnelDialFailure(t, serverEng, fmt.Sprintf("100.64.94.2:%d", localPort))
			reply := roundTripHostTCP(t, fmt.Sprintf("127.0.0.1:%d", localPort), "ping")
			if reply != "loopback-only" {
				t.Fatalf("loopback-only reply = %q", reply)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("loopback-only listener failed: %v\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				killProcessGroup(cmd)
				<-done
				t.Fatalf("loopback-only listener did not exit\nstderr=%s", stderr.String())
			}

			cmd, stderr, done = startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.2", fmt.Sprintf("%d", dummyPort), "ignored", "listen-tcp"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
				})
			expectTunnelDialFailure(t, serverEng, fmt.Sprintf("100.64.94.2:%d", dummyPort))
			killProcessGroup(cmd)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("dummy listener did not exit after kill\nstderr=%s", stderr.String())
			}

			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.1", "18081", "udp-bind-disabled", "udp-unconnected-no-poll"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
					env: map[string]string{
						"UWGS_STUB_BIND": fmt.Sprintf("100.64.94.2:%d", udpSourcePort),
					},
				})
			if normalizedOutput(out) != "udp-bind-disabled" {
				t.Fatalf("unexpected bind-disabled UDP output %q", out)
			}
		})
	}
}

func TestUWGWrapperReuseAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	for index, transport := range []string{"preload", "preload-and-ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			fdSock := startSharedWrapperFDProxy(t, httpSock, true, false)
			tcpPort := 19410 + index*10
			udpPort := tcpPort + 1

			aCmd, aStderr, aDone := startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.2", fmt.Sprintf("%d", tcpPort), "ignored", "listen-tcp"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
					env: map[string]string{
						"UWGS_STUB_REUSE": "1",
						"UWGS_STUB_REPLY": "tcp-a",
					},
				})
			defer killProcessGroup(aCmd)
			bCmd, bStderr, bDone := startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"100.64.94.2", fmt.Sprintf("%d", tcpPort), "ignored", "listen-tcp"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
					env: map[string]string{
						"UWGS_STUB_REUSE": "1",
						"UWGS_STUB_REPLY": "tcp-b",
					},
				})
			defer killProcessGroup(bCmd)

			first := roundTripTunnelTCP(t, serverEng, fmt.Sprintf("100.64.94.2:%d", tcpPort), "ping")
			second := roundTripTunnelTCP(t, serverEng, fmt.Sprintf("100.64.94.2:%d", tcpPort), "ping")
			if !((first == "tcp-a" && second == "tcp-b") || (first == "tcp-b" && second == "tcp-a")) {
				t.Fatalf("TCP reuse replies = %q, %q", first, second)
			}
			waitAllListenersExit(t, aDone, aStderr, bDone, bStderr)

			if transport == "ptrace-only" {
				return
			}

			aCmd, aStderr, aDone = startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"0.0.0.0", fmt.Sprintf("%d", udpPort), "ignored", "listen-udp"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
					env: map[string]string{
						"UWGS_STUB_REUSE":        "1",
						"UWGS_STUB_REPLY":        "udp-a",
						"UWGS_STUB_LISTEN_COUNT": "64",
					},
				})
			defer killProcessGroup(aCmd)
			bCmd, bStderr, bDone = startWrappedListenerProcess(t, art, httpSock, transport, art.stub,
				[]string{"0.0.0.0", fmt.Sprintf("%d", udpPort), "ignored", "listen-udp"},
				wrapperRunOptions{
					wrapperArgs: []string{"--spawn-fdproxy=false", "--listen", fdSock},
					timeout:     60 * time.Second,
					env: map[string]string{
						"UWGS_STUB_REUSE":        "1",
						"UWGS_STUB_REPLY":        "udp-b",
						"UWGS_STUB_LISTEN_COUNT": "64",
					},
				})
			defer killProcessGroup(bCmd)

			seenUDP := map[string]bool{}
			for i := 0; i < 40 && !(seenUDP["udp-a"] && seenUDP["udp-b"]); i++ {
				seenUDP[roundTripHostUDP(t, fmt.Sprintf("127.0.0.1:%d", udpPort), "ping")] = true
			}
			if !seenUDP["udp-a"] || !seenUDP["udp-b"] {
				t.Fatalf("UDP reuse replies did not reach both listeners: %v", seenUDP)
			}
			killProcessGroup(aCmd)
			killProcessGroup(bCmd)
			waitListenerStopped(t, aDone, aStderr)
			waitListenerStopped(t, bDone, bStderr)
		})
	}
}

func roundTripHostTCP(t *testing.T, address, payload string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func roundTripTunnelTCP(t *testing.T, eng interface {
	DialTunnelContext(context.Context, string, string) (net.Conn, error)
}, address, payload string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := eng.DialTunnelContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func roundTripHostUDP(t *testing.T, address, payload string) string {
	t.Helper()
	conn, err := net.DialTimeout("udp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func expectTunnelDialFailure(t *testing.T, eng interface {
	DialTunnelContext(context.Context, string, string) (net.Conn, error)
}, address string) {
	t.Helper()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		conn, err := eng.DialTunnelContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Write([]byte("probe"))
			var buf [1]byte
			_, readErr := conn.Read(buf[:])
			_ = conn.Close()
			if readErr == nil {
				t.Fatalf("unexpected tunnel echo success to %s", address)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitAllListenersExit(t *testing.T, aDone chan error, aStderr *bytes.Buffer, bDone chan error, bStderr *bytes.Buffer) {
	t.Helper()
	for i := 0; i < 2; i++ {
		select {
		case err := <-aDone:
			if err != nil {
				t.Fatalf("listener A failed: %v\nstderr=%s", err, aStderr.String())
			}
		case err := <-bDone:
			if err != nil {
				t.Fatalf("listener B failed: %v\nstderr=%s", err, bStderr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for listeners to exit")
		}
	}
}

func waitListenerStopped(t *testing.T, done chan error, stderr *bytes.Buffer) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for listener to stop\nstderr=%s", stderr.String())
	}
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

func startSharedWrapperFDProxy(t *testing.T, httpSock string, allowBind, allowLowBind bool) string {
	t.Helper()
	fdSock := filepath.Join(t.TempDir(), "fd.sock")
	server, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:         fdSock,
		API:          "unix:" + httpSock,
		SocketPath:   "/uwg/socket",
		Logger:       log.New(testWriter{t}, "", 0),
		AllowBind:    allowBind,
		AllowLowBind: allowLowBind,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { _ = server.Close() })
	waitPath(t, fdSock)
	return fdSock
}
