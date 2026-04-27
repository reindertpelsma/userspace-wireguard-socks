//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		transport = "preload"
	}
	serverScript := filepath.Join(repo, "tests/preload/testdata/node_http_server.js")
	markFile := filepath.Join(t.TempDir(), "phase1-chrome-post.txt")

	serverCmd, serverStderr, serverDone := startWrappedListenerProcess(t, art, pair.serverHTTPSock, transport, "node",
		[]string{serverScript, "100.64.94.1", "18090", markFile},
		wrapperRunOptions{timeout: 360 * time.Second})
	defer func() {
		killProcessGroup(serverCmd)
		<-serverDone
	}()

	out, stderr := runWrappedTargetBrowser(t, art, pair.clientHTTPSock, transport, chromeBin,
		[]string{
			"--headless",
			"--no-sandbox",
			"--disable-gpu",
			"--disable-features=DBus,VizDisplayCompositor",
			"--disable-software-rasterizer",
			"--disable-dev-shm-usage",
			"--no-zygote",
			"--virtual-time-budget=5000",
			"--dump-dom",
			"http://100.64.94.1:18090/",
		})
	if !strings.Contains(string(out), "script-ok:204") {
		t.Fatalf("phase1 headless chrome smoke failed\nout=%s\nbrowser stderr=%s\nserver stderr=%s", out, stderr, serverStderr.String())
	}
	waitForFileContent(t, markFile, "chrome-post-ok")
}
