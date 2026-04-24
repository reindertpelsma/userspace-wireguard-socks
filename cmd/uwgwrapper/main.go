//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/socketproto"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgtrace"
)

//go:embed assets/uwgpreload.so
var embeddedPreload []byte

func main() {
	var mode string
	var api string
	var apiToken string
	var socketPath string
	var preloadPath string
	var listenPath string
	var dnsMode string
	var transport string
	var forceLoopbackDNS bool
	var spawnFDProxy bool
	var noNewPrivileges bool
	var allowBind bool
	var allowLowBind bool
	var stdioConnect string
	var verbose bool

	flag.StringVar(&mode, "mode", getenv("UWGS_WRAPPER_MODE", "launch"), "mode: launch, fdproxy, or stdio")
	flag.StringVar(&api, "api", getenv("UWGS_API", "http://127.0.0.1:9090"), "uwgsocks API endpoint")
	flag.StringVar(&apiToken, "token", os.Getenv("UWGS_API_TOKEN"), "uwgsocks API bearer token")
	flag.StringVar(&socketPath, "socket-path", getenv("UWGS_SOCKET_PATH", "/uwg/socket"), "upstream socket upgrade path")
	flag.StringVar(&preloadPath, "preload", os.Getenv("UWGS_PRELOAD"), "path to preload shared library; defaults to embedded copy extracted to /tmp")
	flag.StringVar(&listenPath, "listen", getenv("UWGS_FDPROXY", ""), "Unix socket path exposed to the preload wrapper")
	flag.StringVar(&dnsMode, "dns-mode", getenv("UWGS_DNS_MODE", "full"), "DNS handling mode: full, libc, none")
	flag.StringVar(&transport, "transport", getenv("UWGS_WRAPPER_TRANSPORT", "auto"), "transport mode: auto, preload-and-ptrace, preload, ptrace, ptrace-seccomp, ptrace-only, preload-with-optional-ptrace")
	flag.BoolVar(&forceLoopbackDNS, "force-loopback-dns", getenv("UWGS_DISABLE_LOOPBACK_DNS53", "") == "", "force loopback TCP/UDP port 53 to DNS proxy (default true)")
	flag.BoolVar(&spawnFDProxy, "spawn-fdproxy", getenv("UWGS_WRAPPER_SPAWN_FDPROXY", "") != "0", "launch built-in fdproxy daemon automatically in launch mode")
	flag.BoolVar(&noNewPrivileges, "no-new-privileges", getenv("UWGS_WRAPPER_NO_NEW_PRIVILEGES", "1") != "0", "set PR_SET_NO_NEW_PRIVS before launching the wrapped program (default true)")
	flag.BoolVar(&allowBind, "allow-bind", getenv("UWGS_FDPROXY_ALLOW_BIND", "1") != "0", "allow fdproxy-managed tunnel bind/listen requests")
	flag.BoolVar(&allowLowBind, "allow-lowbind", getenv("UWGS_FDPROXY_ALLOW_LOWBIND", "0") != "0", "allow fdproxy-managed ports below 1024")
	flag.StringVar(&stdioConnect, "stdio-connect", getenv("UWGS_STDIO_CONNECT", ""), "connect a tunnel TCP target and bridge stdin/stdout; useful as SSH ProxyCommand")
	flag.BoolVar(&verbose, "v", false, "enable wrapper diagnostics")
	flag.Parse()

	switch mode {
	case "launch":
		if stdioConnect != "" {
			if err := runStdioConnect(api, apiToken, socketPath, stdioConnect, os.Stdin, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		}
		runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, allowBind, allowLowBind, verbose)
	case "fdproxy":
		runFDProxy(api, apiToken, socketPath, listenPath, allowBind, allowLowBind, verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != "")
	case "stdio":
		target, err := stdioConnectTarget(stdioConnect, flag.Args())
		if err != nil {
			log.Fatal(err)
		}
		if err := runStdioConnect(api, apiToken, socketPath, target, os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "exec-helper":
		if err := runExecHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	case "tracee-helper":
		if err := uwgtrace.RunTraceeHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported mode %q, expected launch, fdproxy, stdio, exec-helper, or tracee-helper", mode)
	}
}

func runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport string, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, allowBind, allowLowBind, verbose bool) {
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "usage: uwgwrapper [flags] -- program [args...]\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	prog := flag.Arg(0)
	progArgs := flag.Args()[1:]

	if preloadPath == "" {
		var err error
		preloadPath, err = ensureEmbeddedPreload()
		if err != nil {
			log.Fatalf("materialize embedded preload library: %v", err)
		}
	}
	if preloadPath == "" {
		log.Fatal("no preload library configured")
	}

	if listenPath == "" {
		listenPath = filepath.Join(os.TempDir(), fmt.Sprintf("uwgfdproxy-%d.sock", os.Getpid()))
	}
	debug := verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != ""

	var fdproxyCmd *exec.Cmd
	if spawnFDProxy {
		_ = os.Remove(listenPath)
		fdproxyCmd = exec.Command(os.Args[0], fdproxySpawnArgs(listenPath, api, socketPath, allowBind, allowLowBind, apiToken, debug)...)
		fdproxyCmd.Stdout = os.Stderr
		fdproxyCmd.Stderr = os.Stderr
		fdproxyCmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := fdproxyCmd.Start(); err != nil {
			log.Fatalf("start built-in uwgfdproxy: %v", err)
		}
		defer cleanupSpawnedFDProxy(fdproxyCmd, listenPath)
		if err := waitFDProxyReady(listenPath, 5*time.Second); err != nil {
			log.Fatalf("uwgfdproxy did not become ready: %v", err)
		}
	} else {
		if err := waitFDProxyReady(listenPath, 5*time.Second); err != nil {
			log.Fatalf("existing uwgfdproxy socket %s not ready: %v", listenPath, err)
		}
	}

	target, err := exec.LookPath(prog)
	if err != nil {
		log.Fatalf("resolve target %q: %v", prog, err)
	}

	if verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != "" {
		log.Printf("mode=launch target=%s transport=%s preload=%s listen=%s api=%s socketPath=%s spawnFDProxy=%t",
			target, transport, preloadPath, listenPath, api, socketPath, spawnFDProxy)
	}

	env := os.Environ()
	env = setEnv(env, "UWGS_FDPROXY", listenPath)
	env = setEnv(env, "UWGS_API", api)
	env = setEnv(env, "UWGS_SOCKET_PATH", socketPath)
	env = setEnv(env, "UWGS_DNS_MODE", dnsMode)
	if forceLoopbackDNS {
		env = setEnv(env, "UWGS_DISABLE_LOOPBACK_DNS53", "0")
	} else {
		env = setEnv(env, "UWGS_DISABLE_LOOPBACK_DNS53", "1")
	}
	if apiToken != "" {
		env = setEnv(env, "UWGS_API_TOKEN", apiToken)
	}
	shared, err := prepareSharedState()
	if err != nil {
		log.Fatalf("prepare shared state: %v", err)
	}
	env = setEnv(env, "UWGS_SHARED_STATE_PATH", shared.Path())
	env = setEnv(env, "UWGS_TRACE_SECRET", fmt.Sprintf("%d", shared.Secret()))
	env = setEnv(env, "UWGS_TRACE_NO_NEW_PRIVS", boolString(noNewPrivileges))
	statsPath := os.Getenv("UWGS_TRACE_STATS_PATH")

	traceRun := func(seccompMode uwgtrace.SeccompMode, withPreload bool) error {
		traceEnv := append([]string{}, env...)
		if withPreload {
			traceEnv = prependEnvPath(traceEnv, "LD_PRELOAD", preloadPath)
		}
		code, err := uwgtrace.Run(uwgtrace.Options{
			Args:            append([]string{target}, progArgs...),
			Env:             traceEnv,
			FDProxy:         listenPath,
			SeccompMode:     seccompMode,
			NoNewPrivileges: noNewPrivileges,
			Verbose:         debug,
			Shared:          shared,
			StatsPath:       statsPath,
		})
		if err != nil {
			return err
		}
		_ = shared.Close(true)
		os.Exit(code)
		return nil
	}

	preloadRun := func() {
		if preloadPath == "" {
			log.Fatal("no preload library configured")
		}
		envPreload := prependEnvPath(append([]string{}, env...), "LD_PRELOAD", preloadPath)
		_ = shared.Close(false)
		cmdArgs := append([]string{"--mode=exec-helper", "--", target}, progArgs...)
		cmd := exec.Command(os.Args[0], cmdArgs...)
		cmd.Env = envPreload
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					if status.Exited() {
						os.Exit(status.ExitStatus())
					}
					if status.Signaled() {
						os.Exit(128 + int(status.Signal()))
					}
				}
			}
			log.Fatalf("run %s: %v", target, err)
		}
		os.Exit(0)
	}

	combo := func() error {
		if preloadPath == "" {
			return errors.New("preload-and-ptrace transport requires preload")
		}
		return traceRun(uwgtrace.SeccompSecret, true)
	}
	traceSimple := func() error {
		return traceRun(uwgtrace.SeccompSimple, false)
	}
	traceNoSeccomp := func() error {
		return traceRun(uwgtrace.SeccompNone, false)
	}

	switch transport {
	case "preload":
		preloadRun()
	case "preload-and-ptrace":
		if err := combo(); err != nil {
			log.Fatalf("both mode failed: %v", err)
		}
	case "ptrace-seccomp":
		if err := traceSimple(); err != nil {
			log.Fatalf("ptrace+seccomp mode failed: %v", err)
		}
	case "ptrace-only":
		if err := traceNoSeccomp(); err != nil {
			log.Fatalf("ptrace mode failed: %v", err)
		}
	case "ptrace":
		if err := traceSimple(); err == nil {
			return
		}
		if err := traceNoSeccomp(); err != nil {
			log.Fatalf("ptrace mode failed: %v", err)
		}
	case "preload-with-optional-ptrace":
		if err := combo(); err == nil {
			return
		}
		preloadRun()
	case "auto":
		if err := combo(); err == nil {
			return
		}
		if err := traceSimple(); err == nil {
			return
		}
		if err := traceNoSeccomp(); err == nil {
			return
		}
		preloadRun()
	default:
		log.Fatalf("unsupported transport %q, supported auto, preload, preload-and-ptrace, ptrace-seccomp, ptrace-only, ptrace, preload-with-optional-ptrace", transport)
	}
}

func fdproxySpawnArgs(listenPath, api, socketPath string, allowBind, allowLowBind bool, apiToken string, debug bool) []string {
	args := []string{
		"--mode=fdproxy",
		"--listen", listenPath,
		"--api", api,
		"--socket-path", socketPath,
		fmt.Sprintf("--allow-bind=%t", allowBind),
		fmt.Sprintf("--allow-lowbind=%t", allowLowBind),
	}
	if debug {
		args = append(args, "-v")
	}
	if apiToken != "" {
		args = append(args, "--token", apiToken)
	}
	return args
}

func runExecHelper(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("exec helper requires target program")
	}
	if os.Getenv("UWGS_TRACE_NO_NEW_PRIVS") != "0" {
		if err := uwgtrace.SetNoNewPrivileges(); err != nil {
			return err
		}
	}
	target, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(target, args, os.Environ())
}

func runFDProxy(api, apiToken, socketPath, listenPath string, allowBind, allowLowBind, verbose bool) {
	if listenPath == "" {
		listenPath = "/tmp/uwgfdproxy.sock"
	}
	server, err := fdproxy.ListenWithOptions(fdproxy.Options{
		Path:         listenPath,
		API:          api,
		Token:        apiToken,
		SocketPath:   socketPath,
		Logger:       log.Default(),
		AllowBind:    allowBind,
		AllowLowBind: allowLowBind,
		Verbose:      verbose,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}

func stdioConnectTarget(flagValue string, args []string) (string, error) {
	if flagValue != "" {
		if len(args) != 0 {
			return "", fmt.Errorf("stdio mode accepts either --stdio-connect or one positional target, not both")
		}
		return flagValue, nil
	}
	if len(args) != 1 {
		return "", fmt.Errorf("stdio mode requires a single target like 100.64.0.2:22")
	}
	return args[0], nil
}

func parseStdioConnectTarget(raw string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse stdio target %q: %w", raw, err)
	}
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid stdio target %q", raw)
	}
	return ap, nil
}

func runStdioConnect(api, apiToken, socketPath, target string, stdin io.Reader, stdout io.Writer) error {
	dest, err := parseStdioConnectTarget(target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	up, err := socketproto.DialHTTP(ctx, api, apiToken, socketPath)
	if err != nil {
		return err
	}
	defer up.Close()

	payload, err := socketproto.EncodeConnect(socketproto.Connect{
		IPVersion: socketproto.AddrVersion(dest.Addr()),
		Protocol:  socketproto.ProtoTCP,
		DestIP:    dest.Addr(),
		DestPort:  dest.Port(),
	})
	if err != nil {
		return err
	}
	id := socketproto.ClientIDBase + 1
	if err := socketproto.WriteFrame(up, socketproto.Frame{ID: id, Action: socketproto.ActionConnect, Payload: payload}); err != nil {
		return err
	}
	frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
	if err != nil {
		return err
	}
	if frame.ID != id {
		return fmt.Errorf("unexpected socket response id %d", frame.ID)
	}
	switch frame.Action {
	case socketproto.ActionAccept:
		if _, err := socketproto.DecodeAccept(frame.Payload); err != nil {
			return err
		}
	case socketproto.ActionClose:
		if len(frame.Payload) != 0 {
			return fmt.Errorf("connect rejected: %s", string(frame.Payload))
		}
		return errors.New("connect rejected")
	default:
		return fmt.Errorf("unexpected socket response action %d", frame.Action)
	}
	return proxyStdioSocket(up, id, stdin, stdout)
}

func proxyStdioSocket(up net.Conn, id uint64, stdin io.Reader, stdout io.Writer) error {
	var writeMu sync.Mutex
	writeFrame := func(frame socketproto.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return socketproto.WriteFrame(up, frame)
	}

	sendErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				if werr := writeFrame(socketproto.Frame{ID: id, Action: socketproto.ActionData, Payload: payload}); werr != nil {
					sendErr <- werr
					return
				}
			}
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				sendErr <- nil
				return
			}
			sendErr <- err
			return
		}
	}()

	for {
		frame, err := socketproto.ReadFrame(up, socketproto.DefaultMaxPayload)
		if err != nil {
			var sendErrValue error
			select {
			case sendErrValue = <-sendErr:
			default:
			}
			if sendErrValue != nil {
				return sendErrValue
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if frame.ID != id {
			continue
		}
		switch frame.Action {
		case socketproto.ActionData:
			if _, err := stdout.Write(frame.Payload); err != nil {
				return err
			}
		case socketproto.ActionClose:
			select {
			case send := <-sendErr:
				if send != nil {
					return send
				}
			default:
			}
			return nil
		default:
			return fmt.Errorf("unexpected socket action %d", frame.Action)
		}
	}
}

func cleanupSpawnedFDProxy(cmd *exec.Cmd, listenPath string) {
	_ = os.Remove(listenPath)
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func waitUnixSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := os.Stat(path)
		if err == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", path)
}

func waitFDProxyReady(path string, timeout time.Duration) error {
	if err := waitUnixSocket(path, timeout); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write([]byte("PING\n")); err != nil {
			_ = conn.Close()
			time.Sleep(25 * time.Millisecond)
			continue
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if err == nil && strings.TrimSpace(line) == "PONG" {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for fdproxy readiness on %s", path)
}

func ensureEmbeddedPreload() (string, error) {
	if len(embeddedPreload) == 0 {
		return "", errors.New("embedded preload payload missing")
	}
	sum := sha256.Sum256(embeddedPreload)
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("uwgwrapper-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("uwgpreload-%x.so", sum[:8]))
	if data, err := os.ReadFile(path); err == nil {
		if sha256.Sum256(data) == sum {
			return path, nil
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, embeddedPreload, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

func prepareSharedState() (*uwgshared.Table, error) {
	var secret uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &secret); err != nil {
		return nil, err
	}
	if secret == 0 {
		secret = 1
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("uwgwrapper-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, "shared-state-*.bin")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	_ = file.Close()
	return uwgshared.Create(path, secret)
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func prependEnvPath(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			cur := strings.TrimPrefix(entry, prefix)
			if cur == "" {
				env[i] = prefix + value
			} else if !containsPath(cur, value) {
				env[i] = prefix + value + ":" + cur
			}
			return env
		}
	}
	return append(env, prefix+value)
}

func containsPath(list, value string) bool {
	for _, part := range strings.Split(list, ":") {
		if part == value {
			return true
		}
	}
	return false
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func boolString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func init() {
	log.SetFlags(0)
	log.SetPrefix("uwgwrapper: ")
}
