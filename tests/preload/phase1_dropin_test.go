// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"log"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
)

// TestPhase1DropInLegacyTCP validates that preload/uwgpreload-phase1.so
// can replace the legacy preload/uwgpreload.c monolith in the LD_PRELOAD-
// only flow, with NO uwgwrapper / UWGS_TRACE_SECRET / seccomp filter
// involvement. The shim_libc layer interposes libc symbols directly,
// so the kernel-level filter from uwgwrapper isn't needed for
// correctness — only as a belt-and-braces against raw asm syscalls.
//
// This is the smallest test that asserts shim_libc actually works
// end-to-end. It runs the C stub_client with LD_PRELOAD=phase1.so
// + UWGS_FDPROXY=fdsock, exactly the way the legacy preload tests
// invoke it. If the shim doesn't override libc's connect/read/write
// (e.g. wrong symbol name, wrong signature, wrong return convention),
// this either hangs (libc's connect goes direct to the kernel and
// fails on a non-routable IP) or the bytes round-trip wrong.
func TestPhase1DropInLegacyTCP(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	stubBin := filepath.Join(tmp, "stub_client")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", stubBin, "tests/preload/testdata/stub_client.c")

	phase1So := filepath.Join(tmp, "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.94.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(tmp, "api.sock")
	httpSock := filepath.Join(tmp, "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.94.2/32"}
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"100.64.94.1/32"},
		PersistentKeepalive: 1,
	}}
	_ = mustStart(t, clientCfg)
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go serveUDPEcho(udp)

	fdSock := filepath.Join(tmp, "fdproxy.sock")
	proxy, err := fdproxy.ListenWithSocketPath(fdSock, "unix:"+httpSock, "", "/uwg/socket", log.New(testWriter{t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Close() })
	waitPath(t, fdSock)

	// Mirror TestLDPreloadManagedTCPUDPConnect's runPreloadStub-driven
	// shape coverage but with phase1.so as the LD_PRELOAD'd preload.
	// Each case is the legacy test's exact assertion, just with the
	// .so swapped — so a green run confirms phase1.so really is a
	// behavioural drop-in for the existing preload tests.
	type stubCase struct {
		name   string
		args   []string
		env    []string
		expect string
	}
	cases := []stubCase{
		{name: "tcp", expect: "phase1-dropin-tcp"},
		{name: "tcp_dup", args: []string{"tcp", "dup"}, expect: "phase1-dropin-tcp-dup"},
		{name: "tcp_fork", args: []string{"tcp", "fork"}, expect: "phase1-dropin-tcp-fork"},
		// "tcp exec" relies on libc-symbol re-interposition across exec
		// (the new image gets LD_PRELOAD'd again by the kernel). shim_libc
		// supports it natively without uwgwrapper. Confirms drop-in is a
		// true superset of the legacy LD_PRELOAD-only behaviour.
		{name: "tcp_exec", args: []string{"tcp", "exec"}, expect: "phase1-dropin-tcp-exec"},
		{name: "tcp_msg", args: []string{"tcp", "msg"}, expect: "phase1-dropin-tcp-msg"},
		{name: "tcp_iov", args: []string{"tcp", "iov"}, expect: "phase1-dropin-tcp-iov"},
		{name: "tcp_select", args: []string{"tcp", "select"}, expect: "phase1-dropin-tcp-sel"},
		{name: "tcp_pselect", args: []string{"tcp", "pselect"}, expect: "phase1-dropin-tcp-psel"},
		{name: "tcp_recv_peek", args: []string{"tcp", "recv-peek"}, expect: "phase1-dropin-tcp-peek"},
		{name: "tcp_syscall_surface", args: []string{"syscall-surface"}, expect: "phase1-dropin-tcp-surf"},
		{name: "tcp_syscall_surface_extra", args: []string{"syscall-surface-extra"}, expect: "phase1-dropin-tcp-surfx"},
		{name: "udp", args: []string{"udp"}, expect: "phase1-dropin-udp"},
		{name: "udp_msg", args: []string{"udp", "msg"}, expect: "phase1-dropin-udp-msg"},
		{name: "udp_iov", args: []string{"udp", "iov"}, expect: "phase1-dropin-udp-iov"},
		{name: "udp_mmsg", args: []string{"mmsg"}, expect: "phase1-dropin-udp-mmsg"},
		{name: "udp_no_poll", args: []string{"udp-no-poll"}, expect: "phase1-dropin-udp-np"},
		{name: "udp_unconnected", args: []string{"udp-unconnected"}, expect: "phase1-dropin-udp-unc"},
		{name: "udp_unconnected_no_poll", args: []string{"udp-unconnected-no-poll"}, expect: "phase1-dropin-udp-unp"},
		{name: "udp_unconnected_bound", args: []string{"udp-unconnected"},
			env: []string{"UWGS_STUB_BIND=100.64.94.2:19091"}, expect: "phase1-dropin-udp-bound"},
		{name: "udp_connect_probe", args: []string{"udp-connect-probe"}, expect: "phase1-dropin-udp-probe"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			port := "18080"
			if strings.HasPrefix(tc.name, "udp") {
				port = "18081"
			}
			args := append([]string{"100.64.94.1", port, tc.expect}, tc.args...)
			var out []byte
			if len(tc.env) > 0 {
				out = runPreloadStubWithEnv(t, phase1So, fdSock, stubBin, tc.env, args...)
			} else {
				out = runPreloadStub(t, phase1So, fdSock, stubBin, args...)
			}
			if strings.TrimSpace(string(out)) != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, out)
			}
		})
	}

	// TCP listener via tunnel dial — the "real" listener flow that
	// the legacy preload's runPreloadTCPListener exercises. Validates
	// uwg_listen / uwg_managed_accept work in drop-in mode too.
	t.Run("tcp_listener", func(t *testing.T) {
		runPreloadTCPListener(t, phase1So, fdSock, stubBin, serverEng, "19193")
	})
	// NOTE: the legacy "listen-tcp + exec" pattern needs the shared-
	// state mmap to survive across execve so the child process can see
	// the parent's KIND_TCP_LISTENER state on the inherited fd. In
	// drop-in mode (no UWGS_SHARED_STATE_PATH), the child's fresh BSS
	// table loses that state and accept() on the unix-socketpair fd
	// fails. The Phase 2 bootstrap supervisor will close this gap by
	// re-arming preload across execve and replaying state. For now,
	// the listener-exec case is supported only when uwgwrapper sets
	// UWGS_SHARED_STATE_PATH — which the existing wrapper-mediated
	// TestPhase1SeccompPreloadTCPListener already exercises.
}
