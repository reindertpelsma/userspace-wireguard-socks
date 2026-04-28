//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPhase1HeadlessChromeSmoke is the chromium-class workload validation
// for the SIGSYS+seccomp preload. It mirrors TestUWGWrapperNodeHeadlessChromeSmoke
// but swaps in preload/uwgpreload-phase1.so instead of the legacy
// preload/uwgpreload.c monolith. Chromium is the canonical hostile
// workload — multi-process zygote, lots of fd-passing, mixed
// blocking/non-blocking IO, libuv inside V8's worker pool — so passing
// it under the new architecture is the strongest single signal that
// we're not regressing real-world behaviour.
//
// Gated by UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE=1 so it doesn't run
// in normal unit-test flow. Needs a chromium/headless_shell binary
// in UWGS_CHROME_BIN and node on $PATH.
func TestPhase1HeadlessChromeSmoke(t *testing.T) {
	if os.Getenv("UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE") == "" {
		t.Skip("set UWGS_RUN_PHASE1_HEADLESS_CHROME_SMOKE=1 to run the phase1 headless Chrome smoke")
	}
	requirePhase1Toolchain(t)
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for the phase1 headless Chrome smoke test")
	}
	chromeBin := strings.TrimSpace(os.Getenv("UWGS_CHROME_BIN"))
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to a Chromium/headless_shell binary to run this smoke test")
	}

	art := buildPhase1Artifacts(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	phase1So := filepath.Join(t.TempDir(), "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}
	art.preload = phase1So

	pair := setupWrapperHTTPPair(t)
	transport := strings.TrimSpace(os.Getenv("UWGS_BROWSER_SMOKE_TRANSPORT"))
	if transport == "" {
		// Default to systrap-supervised: the supervisor handles
		// chromium's zygote + renderer fork+exec model, which
		// means we no longer need --no-zygote or
		// UWGS_DISABLE_SECCOMP=1 for chromium-class workloads.
		// The previous default `systrap` (no ptrace) relied on
		// --no-zygote to avoid the static-child interception gap;
		// supervised eliminates that gap.
		transport = "systrap-supervised"
	}
	serverScript := filepath.Join(repo, "tests/preload/testdata/node_http_server.js")
	markFile := filepath.Join(t.TempDir(), "phase1-chrome-post.txt")

	// UWGS_DNS_MODE=libc keeps the DNS path simple — chromium's
	// parallel DNS bursts can race our forced-DNS path; libc
	// resolver gives consistent passes. The test URL is an IP
	// literal anyway, so DNS isn't load-bearing here.
	wrapperEnv := wrapperRunOptions{
		timeout: 360 * time.Second,
		env: map[string]string{
			"UWGS_DNS_MODE": "libc",
		},
	}
	serverCmd, serverStderr, serverDone := startWrappedListenerProcess(t, art, pair.serverHTTPSock, transport, "node",
		[]string{serverScript, "100.64.94.1", "18090", markFile},
		wrapperEnv)
	defer func() {
		killProcessGroup(serverCmd)
		<-serverDone
	}()

	// Minimum chromium flag set under systrap-supervised. The
	// supervisor lets us drop --no-zygote (chromium's zygote IS
	// the fork+exec model the supervisor handles), and the
	// chromium-supervised real-internet test (TestChromiumSystrap
	// SupervisedRealInternet) confirmed --disable-features=DBus,
	// VizDisplayCompositor and --disable-software-rasterizer are
	// also unnecessary. --no-sandbox stays (setuid sandbox
	// conflicts with ptrace; future hardening pass for
	// fdproxy/sandbox-cooperation tackles this); --disable-gpu
	// stays (no GPU on test hosts); --disable-dev-shm-usage stays
	// defensively for stripped containers.
	browserArgs := []string{
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--virtual-time-budget=5000",
		"--dump-dom",
		"http://100.64.94.1:18090/",
	}
	out, stderr := runPhase1WrappedBrowser(t, art, pair.clientHTTPSock, transport, chromeBin, browserArgs, wrapperEnv)
	if !strings.Contains(string(out), "script-ok:204") {
		t.Fatalf("phase1 headless chrome smoke failed\nout=%s\nbrowser stderr=%s\nserver stderr=%s", out, stderr, serverStderr.String())
	}
	waitForFileContent(t, markFile, "chrome-post-ok")
}

// runPhase1WrappedBrowser is the env-aware variant of runWrappedTargetBrowser
// — it threads opts (specifically UWGS_DISABLE_SECCOMP) through to the
// wrapped child so chromium-class workloads can run in shim-only mode.
func runPhase1WrappedBrowser(t *testing.T, art wrapperArtifacts, httpSock, transport, target string,
	args []string, opts wrapperRunOptions) ([]byte, []byte) {
	t.Helper()
	if opts.timeout == 0 {
		opts.timeout = 300 * time.Second
	}
	base := wrappedCommand(t, art, httpSock, transport, target, args, opts)
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPath := filepath.Join(t.TempDir(), "browser.out")
	stderrPath := filepath.Join(t.TempDir(), "browser.err")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutFile.Close()
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	runErr := cmd.Run()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	stdout, _ := os.ReadFile(stdoutPath)
	stderrBytes, _ := os.ReadFile(stderrPath)
	killProcessGroup(cmd)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("wrapped browser %s %v timed out\n%s", target, args, stderrBytes)
	}
	if runErr != nil {
		t.Fatalf("wrapped browser %s %v failed: %v\nstdout=%s\nstderr=%s", target, args, runErr, stdout, stderrBytes)
	}
	return stdout, stderrBytes
}
