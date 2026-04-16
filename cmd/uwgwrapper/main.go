// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
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
	var verbose bool

	flag.StringVar(&mode, "mode", getenv("UWGS_WRAPPER_MODE", "launch"), "mode: launch or fdproxy")
	flag.StringVar(&api, "api", getenv("UWGS_API", "http://127.0.0.1:9090"), "uwgsocks API endpoint")
	flag.StringVar(&apiToken, "token", os.Getenv("UWGS_API_TOKEN"), "uwgsocks API bearer token")
	flag.StringVar(&socketPath, "socket-path", getenv("UWGS_SOCKET_PATH", "/uwg/socket"), "upstream socket upgrade path")
	flag.StringVar(&preloadPath, "preload", os.Getenv("UWGS_PRELOAD"), "path to preload shared library; defaults to embedded copy extracted to /tmp")
	flag.StringVar(&listenPath, "listen", getenv("UWGS_FDPROXY", ""), "Unix socket path exposed to the preload wrapper")
	flag.StringVar(&dnsMode, "dns-mode", getenv("UWGS_DNS_MODE", "full"), "DNS handling mode: full, libc, none")
	flag.StringVar(&transport, "transport", getenv("UWGS_WRAPPER_TRANSPORT", "both"), "transport mode: both, ptrace-seccomp, ptrace, preload")
	flag.BoolVar(&forceLoopbackDNS, "force-loopback-dns", getenv("UWGS_DISABLE_LOOPBACK_DNS53", "") == "", "force loopback TCP/UDP port 53 to DNS proxy (default true)")
	flag.BoolVar(&spawnFDProxy, "spawn-fdproxy", getenv("UWGS_WRAPPER_SPAWN_FDPROXY", "") != "0", "launch built-in fdproxy daemon automatically in launch mode")
	flag.BoolVar(&noNewPrivileges, "no-new-privileges", getenv("UWGS_WRAPPER_NO_NEW_PRIVILEGES", "1") != "0", "set PR_SET_NO_NEW_PRIVS before launching the wrapped program (default true)")
	flag.BoolVar(&verbose, "v", false, "enable wrapper diagnostics")
	flag.Parse()

	switch mode {
	case "launch":
		runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, verbose)
	case "fdproxy":
		runFDProxy(api, apiToken, socketPath, listenPath)
	case "exec-helper":
		if err := runExecHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	case "tracee-helper":
		if err := uwgtrace.RunTraceeHelper(flag.Args()); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported mode %q, expected launch, fdproxy, exec-helper, or tracee-helper", mode)
	}
}

func runLaunch(api, apiToken, socketPath, preloadPath, listenPath, dnsMode, transport string, forceLoopbackDNS, spawnFDProxy, noNewPrivileges, verbose bool) {
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

	var fdproxyCmd *exec.Cmd
	if spawnFDProxy {
		_ = os.Remove(listenPath)
		fdproxyCmd = exec.Command(os.Args[0],
			"--mode=fdproxy",
			"--listen", listenPath,
			"--api", api,
			"--socket-path", socketPath,
		)
		if apiToken != "" {
			fdproxyCmd.Args = append(fdproxyCmd.Args, "--token", apiToken)
		}
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
			Verbose:         verbose || os.Getenv("UWGS_WRAPPER_DEBUG") != "",
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
			return errors.New("combo transport requires preload")
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
	case "preload", "preload-only":
		preloadRun()
	case "both", "combo-only", "preload+seccomp", "preload-plus-seccomp":
		if err := combo(); err != nil {
			log.Fatalf("both mode failed: %v", err)
		}
	case "ptrace-seccomp", "ptrace-only-with-seccomp", "trace-only-with-seccomp":
		if err := traceSimple(); err != nil {
			log.Fatalf("ptrace+seccomp mode failed: %v", err)
		}
	case "ptrace", "ptrace-only", "trace-only", "ptrace-only-no-seccomp", "trace-only-no-seccomp":
		if err := traceNoSeccomp(); err != nil {
			log.Fatalf("ptrace mode failed: %v", err)
		}
	default:
		log.Fatalf("unsupported transport %q", transport)
	}
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

func runFDProxy(api, apiToken, socketPath, listenPath string) {
	if listenPath == "" {
		listenPath = "/tmp/uwgfdproxy.sock"
	}
	server, err := fdproxy.ListenWithSocketPath(listenPath, api, apiToken, socketPath, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	if err := server.Serve(); err != nil {
		log.Fatal(err)
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
