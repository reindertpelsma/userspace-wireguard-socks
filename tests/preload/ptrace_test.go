// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
)

type wrapperArtifacts struct {
	wrapper      string
	preload      string
	stub         string
	mixed        string
	raw          string
	rawmixLib    string
	rawmixClient string
	nnpProbe     string
}

type traceStats struct {
	Syscalls map[string]uint64 `json:"syscalls"`
}

type wrapperRunOptions struct {
	env         map[string]string
	wrapperArgs []string
	timeout     time.Duration
}

func TestUWGWrapperPtraceSeccompRawGoTCPUDP(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "ptrace-seccomp", art.raw, "tcp", "100.64.94.1", "18080", "ptrace-seccomp-tcp")
	if normalizedOutput(out) != "ptrace-seccomp-tcp" {
		t.Fatalf("unexpected ptrace+seccomp tcp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace-seccomp", art.raw, "udp", "100.64.94.1", "18081", "ptrace-seccomp-udp")
	if normalizedOutput(out) != "ptrace-seccomp-udp" {
		t.Fatalf("unexpected ptrace+seccomp udp output %q", out)
	}
}

func TestUWGWrapperPtraceRawGoTCPUDP(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "ptrace", art.raw, "tcp", "100.64.94.1", "18080", "ptrace-tcp")
	if normalizedOutput(out) != "ptrace-tcp" {
		t.Fatalf("unexpected ptrace tcp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace", art.raw, "udp", "100.64.94.1", "18081", "ptrace-udp")
	if normalizedOutput(out) != "ptrace-udp" {
		t.Fatalf("unexpected ptrace udp output %q", out)
	}
}

func TestUWGWrapperBothMixedInterop(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	_, baseline := runWrappedTargetWithStats(t, art, httpSock, "both", art.rawmixClient,
		[]string{"print-only", "0.0.0.0", "0", "both-baseline"}, wrapperRunOptions{})

	out, stats := runWrappedTargetWithStats(t, art, httpSock, "both", art.rawmixClient,
		[]string{"raw-socket-libc-connect-dynamic-only", "100.64.94.1", "18080", "both-raw-open-dynamic"}, wrapperRunOptions{})
	if normalizedOutput(out) != "both-raw-open-dynamic" {
		t.Fatalf("unexpected both raw-open dynamic output %q", out)
	}
	assertSyscallCount(t, stats, "socket", 1)
	assertSyscallCount(t, stats, "connect", 0)
	assertSyscallDelta(t, baseline, stats, "write", 0)
	assertSyscallDelta(t, baseline, stats, "read", 0)

	out, stats = runWrappedTargetWithStats(t, art, httpSock, "both", art.rawmixClient,
		[]string{"raw-socket-libc-connect-stdio-only", "100.64.94.1", "18080", "both-raw-open-stdio"}, wrapperRunOptions{})
	if normalizedOutput(out) != "both-raw-open-stdio" {
		t.Fatalf("unexpected both raw-open stdio output %q", out)
	}
	assertSyscallCount(t, stats, "socket", 1)
	assertSyscallCount(t, stats, "connect", 0)
	assertSyscallDelta(t, baseline, stats, "write", 0)
	assertSyscallDelta(t, baseline, stats, "read", 0)

	out = runWrappedTarget(t, art, httpSock, "both", art.rawmixClient,
		"raw-socket-libc-connect", "100.64.94.1", "18080", "both-raw-open")
	if normalizedOutput(out) != "both-raw-open" {
		t.Fatalf("unexpected both raw-open output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "both", art.rawmixClient,
		"libc-socket-raw-connect", "100.64.94.1", "18080", "both-raw-connect")
	if normalizedOutput(out) != "both-raw-connect" {
		t.Fatalf("unexpected both raw-connect output %q", out)
	}
}

func TestUWGWrapperBothStress(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTargetWithOptions(t, art, httpSock, "both", art.rawmixClient,
		[]string{"stress", "100.64.94.1", "18080", "both-stress", "2", "2"},
		wrapperRunOptions{timeout: 90 * time.Second})
	if strings.TrimSpace(string(out)) != "rawmix-stress-ok" {
		t.Fatalf("unexpected mixed stress output %q", out)
	}
}

func TestUWGWrapperBothExecAndFork(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "both", art.mixed, "100.64.94.1", "18080", "both-exec", "exec")
	if normalizedOutput(out) != "both-exec" {
		t.Fatalf("unexpected both exec output %q", out)
	}

	out = runWrappedTargetWithOptions(t, art, httpSock, "both", art.stub,
		[]string{"100.64.94.1", "18080", "both-fork", "tcp", "fork"},
		wrapperRunOptions{timeout: 60 * time.Second})
	if normalizedOutput(out) != "both-fork" {
		t.Fatalf("unexpected both fork output %q", out)
	}

	if _, err := exec.LookPath("curl"); err == nil {
		ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18083"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "curl-over-wrapper")
			}))
		}()
		out = runWrappedTargetWithOptions(t, art, httpSock, "both", "curl",
			[]string{"--max-time", "15", "-fsS", "http://100.64.94.1:18083/"},
			wrapperRunOptions{timeout: 90 * time.Second})
		if normalizedOutput(out) != "curl-over-wrapper" {
			t.Fatalf("unexpected curl output %q", out)
		}
	}
}

func TestUWGWrapperPtraceSeccompTCPListener(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "ptrace-seccomp", art.stub,
			[]string{"100.64.94.2", "19190", "ptrace-seccomp-listener", "listen-tcp"}, wrapperRunOptions{})

		runErr := func() error {
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19190")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ptrace-seccomp-listener")); err != nil {
				return fmt.Errorf("listener write failed: %w\nstderr=%s", err, stderr.String())
			}
			buf := make([]byte, len("ptrace-seccomp-listener"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("listener read failed: %w\nstderr=%s", err, stderr.String())
			}
			if string(buf) != "ptrace-seccomp-listener" {
				return fmt.Errorf("listener echo mismatch %q\nstderr=%s", buf, stderr.String())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				return fmt.Errorf("listener wrapper did not exit\nstderr=%s", stderr.String())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying ptrace+seccomp listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}

func TestUWGWrapperPreloadOnlyTCPUDPAndListener(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "preload", art.stub, "100.64.94.1", "18080", "preload-tcp", "tcp")
	if normalizedOutput(out) != "preload-tcp" {
		t.Fatalf("unexpected preload tcp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "preload", art.stub, "100.64.94.1", "18081", "preload-udp", "udp")
	if normalizedOutput(out) != "preload-udp" {
		t.Fatalf("unexpected preload udp output %q", out)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "preload", art.stub,
			[]string{"100.64.94.2", "19191", "preload-listener", "listen-tcp"}, wrapperRunOptions{})

		runErr := func() error {
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19191")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("preload-listener")); err != nil {
				return fmt.Errorf("preload listener write failed: %w\nstderr=%s", err, stderr.String())
			}
			buf := make([]byte, len("preload-listener"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("preload listener read failed: %w\nstderr=%s", err, stderr.String())
			}
			if string(buf) != "preload-listener" {
				return fmt.Errorf("preload listener echo mismatch %q\nstderr=%s", buf, stderr.String())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("preload listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				killProcessGroup(cmd)
				<-done
				return fmt.Errorf("preload listener wrapper did not exit\nstderr=%s", stderr.String())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying preload listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}

func TestUWGWrapperNoNewPrivilegesDefaultAndOverride(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "preload", art.nnpProbe)
	if normalizedOutput(out) != "1" {
		t.Fatalf("expected preload default no_new_privs=1, got %q", out)
	}

	out = runWrappedTargetWithOptions(t, art, httpSock, "preload", art.nnpProbe, nil, wrapperRunOptions{
		wrapperArgs: []string{"--no-new-privileges=false"},
	})
	if normalizedOutput(out) != "0" {
		t.Fatalf("expected preload override no_new_privs=0, got %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace", art.nnpProbe)
	if normalizedOutput(out) != "1" {
		t.Fatalf("expected ptrace default no_new_privs=1, got %q", out)
	}

	out = runWrappedTargetWithOptions(t, art, httpSock, "ptrace", art.nnpProbe, nil, wrapperRunOptions{
		wrapperArgs: []string{"--no-new-privileges=false"},
	})
	if normalizedOutput(out) != "0" {
		t.Fatalf("expected ptrace override no_new_privs=0, got %q", out)
	}
}

func requireWrapperToolchain(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("wrapper tests are linux/amd64 only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for wrapper integration tests")
	}
}

func buildWrapperArtifacts(t *testing.T) wrapperArtifacts {
	t.Helper()
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	art := wrapperArtifacts{
		wrapper:      filepath.Join(tmp, "uwgwrapper"),
		preload:      filepath.Join(tmp, "uwgpreload.so"),
		stub:         filepath.Join(tmp, "stub_client"),
		mixed:        filepath.Join(tmp, "mixed_client"),
		raw:          filepath.Join(tmp, "raw_client"),
		rawmixLib:    filepath.Join(tmp, "librawmix_helpers.so"),
		rawmixClient: filepath.Join(tmp, "rawmix_client"),
		nnpProbe:     filepath.Join(tmp, "nnp_probe"),
	}
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", art.preload, "preload/uwgpreload.c", "-ldl", "-pthread")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.stub, "tests/preload/testdata/stub_client.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.mixed, "tests/preload/testdata/mixed_client.c")
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", art.rawmixLib, "tests/preload/testdata/rawmix_helpers.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-I", "tests/preload/testdata", "-L", tmp, "-Wl,-rpath,$ORIGIN", "-o", art.rawmixClient, "tests/preload/testdata/rawmix_client.c", "-lrawmix_helpers")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.nnpProbe, "tests/preload/testdata/nnp_probe.c")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.raw, "tests/preload/testdata/raw_client.go")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.wrapper, "./cmd/uwgwrapper")
	return art
}

func setupWrapperNetwork(t *testing.T) (*engine.Engine, string) {
	t.Helper()

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

	apiSock := filepath.Join(t.TempDir(), "api.sock")
	httpSock := filepath.Join(t.TempDir(), "http.sock")
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
	clientEng := mustStart(t, clientCfg)
	_ = clientEng
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go serveUDPEcho(udp)

	return serverEng, httpSock
}

func wrappedCommand(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) *exec.Cmd {
	t.Helper()
	listenSock := filepath.Join(t.TempDir(), fmt.Sprintf("fdproxy-%s.sock", strings.ReplaceAll(transport, "/", "_")))
	cmdArgs := []string{"--transport=" + transport, "--listen", listenSock, "--api", "unix:" + httpSock, "--socket-path", "/uwg/socket"}
	if os.Getenv("UWGS_TEST_DEBUG") != "" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	if os.Getenv("UWGS_TEST_DEBUG_STRESS") != "" && len(args) > 0 && args[0] == "stress" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	cmdArgs = append(cmdArgs, opts.wrapperArgs...)
	if transportUsesPreload(transport) {
		cmdArgs = append(cmdArgs, "--preload", art.preload)
	}
	cmdArgs = append(cmdArgs, "--", target)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(art.wrapper, cmdArgs...)
	cmd.Env = append([]string{}, os.Environ()...)
	for key, value := range opts.env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}

func startWrappedListenerProcess(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) (*exec.Cmd, *bytes.Buffer, chan error) {
	t.Helper()
	var lastErr error
	var lastStderr string
	for attempt := 0; attempt < 3; attempt++ {
		cmd := wrappedCommand(t, art, httpSock, transport, target, args, opts)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		reader := bufio.NewReader(stdout)
		type readyResult struct {
			line string
			err  error
		}
		readyCh := make(chan readyResult, 1)
		go func() {
			line, err := reader.ReadString('\n')
			readyCh <- readyResult{line: line, err: err}
		}()

		var ready string
		select {
		case res := <-readyCh:
			ready, err = res.line, res.err
		case <-time.After(10 * time.Second):
			killProcessGroup(cmd)
			<-done
			err = fmt.Errorf("listener did not become ready before timeout")
		}
		if err == nil && strings.TrimSpace(ready) == "READY" {
			return cmd, &stderr, done
		}
		lastErr = err
		lastStderr = stderr.String()
		killProcessGroup(cmd)
		<-done
		if retryableWrappedFailure(stderr.Bytes(), nil) {
			t.Logf("retrying wrapped listener after startup failure: %s %v", target, args)
			continue
		}
		if err != nil {
			t.Fatalf("listener did not become ready: %v\nstderr=%s", err, stderr.String())
		}
		t.Fatalf("listener readiness = %q\nstderr=%s", ready, stderr.String())
	}
	t.Fatalf("listener did not become ready after retries: %v\nstderr=%s", lastErr, lastStderr)
	return nil, nil, nil
}

func runWrappedTarget(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args ...string) []byte {
	t.Helper()
	return runWrappedTargetWithOptions(t, art, httpSock, transport, target, args, wrapperRunOptions{})
}

func runWrappedTargetWithOptions(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) []byte {
	t.Helper()
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	var lastOut []byte
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		base := wrappedCommand(t, art, httpSock, transport, target, args, opts)
		cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
		cmd.Env = append([]string{}, base.Env...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		out, err := cmd.CombinedOutput()
		cancel()
		if err == nil {
			return out
		}
		lastOut = out
		lastErr = err
		if ctx.Err() == context.DeadlineExceeded {
			killProcessGroup(cmd)
			if attempt < 2 && retryableWrappedTimeout(target) {
				t.Logf("retrying wrapped target after timeout: %s %v", target, args)
				continue
			}
			t.Fatalf("wrapped target %s %v timed out\n%s", target, args, out)
		}
		killProcessGroup(cmd)
		if attempt < 2 && retryableWrappedFailure(out, err) {
			t.Logf("retrying wrapped target after transient failure: %s %v (%v)", target, args, err)
			continue
		}
		t.Fatalf("wrapped target %s %v failed: %v\n%s", target, args, err, out)
	}
	t.Fatalf("wrapped target %s %v failed after retries: %v\n%s", target, args, lastErr, lastOut)
	return nil
}

func runWrappedTargetWithStats(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) ([]byte, traceStats) {
	t.Helper()
	statsPath := filepath.Join(t.TempDir(), "trace-stats.json")
	if opts.env == nil {
		opts.env = make(map[string]string)
	}
	opts.env["UWGS_TRACE_STATS_PATH"] = statsPath
	out := runWrappedTargetWithOptions(t, art, httpSock, transport, target, args, opts)
	data, err := os.ReadFile(statsPath)
	if err != nil {
		t.Fatalf("read trace stats: %v", err)
	}
	var stats traceStats
	if err := json.Unmarshal(data, &stats); err != nil {
		t.Fatalf("decode trace stats: %v\n%s", err, data)
	}
	if stats.Syscalls == nil {
		stats.Syscalls = make(map[string]uint64)
	}
	return out, stats
}

func transportUsesPreload(transport string) bool {
	switch transport {
	case "both", "combo-only", "preload+seccomp", "preload-plus-seccomp", "preload", "preload-only":
		return true
	default:
		return false
	}
}

func assertSyscallCount(t *testing.T, stats traceStats, name string, want uint64) {
	t.Helper()
	got := stats.Syscalls[name]
	if got != want {
		t.Fatalf("expected traced syscall %s=%d, got %d (all=%v)", name, want, got, stats.Syscalls)
	}
}

func assertSyscallDelta(t *testing.T, baseline, stats traceStats, name string, want int64) {
	t.Helper()
	got := int64(stats.Syscalls[name]) - int64(baseline.Syscalls[name])
	if got != want {
		t.Fatalf("expected traced syscall delta %s=%d, got %d (baseline=%v current=%v)", name, want, got, baseline.Syscalls, stats.Syscalls)
	}
}

func normalizedOutput(out []byte) string {
	lines := strings.Split(string(out), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "uwgwrapper:"):
			continue
		case strings.HasPrefix(trimmed, "connect fd="):
			continue
		case strings.HasPrefix(trimmed, "send fd="):
			continue
		case strings.HasPrefix(trimmed, "write fd="):
			continue
		case strings.HasPrefix(trimmed, "recv fd="):
			continue
		case strings.HasPrefix(trimmed, "read fd="):
			continue
		case strings.HasPrefix(trimmed, "manager_connect "):
			continue
		case strings.HasPrefix(trimmed, "manager_request "):
			continue
		case strings.HasPrefix(trimmed, "proxy_connect "):
			continue
		default:
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "\n")
}

func retryableWrappedFailure(out []byte, err error) bool {
	if bytes.Contains(out, []byte("cannot read file data: Error 38")) {
		return true
	}
	if bytes.Contains(out, []byte("ptrace mode failed: no such process")) {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 141 {
		return true
	}
	return false
}

func retryableWrappedTimeout(target string) bool {
	base := filepath.Base(target)
	return base == "rawmix_client" || base == "mixed_client" || base == "raw_client" || base == "curl"
}

func buildWithEnv(t *testing.T, dir string, env map[string]string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, os.Environ()...)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
