//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumSystrapSupervisedRealInternet is the "Final Boss"
// test: wrap headless Chromium under transport=systrap-supervised
// and navigate to a real-internet URL through a uwgsocks-hosted
// HTTP proxy. Chromium spawns dozens of threads, has its own
// internal seccomp-bpf sandboxes, and uses fork+exec heavily to
// spawn child renderer / GPU / network processes — every one of
// those execve boundaries must be re-armed by our supervisor.
//
// Goals:
//   - No UWGS_DISABLE_SECCOMP=1 workaround (the entire point of the
//     supervisor is that this is no longer needed).
//   - Use the minimum number of --disable-* chromium flags. The
//     existing tests carry a kitchen-sink list; here we trim it
//     to what's actually required for headless on a stripped
//     Linux + ptrace + LD_PRELOAD environment.
//   - Real-internet target (example.com first, then a JS-heavy
//     site like wikipedia.org) — proves DNS, TLS, JS engine,
//     fork+exec re-arm, and zygote handling all coexist.
//
// Gated by UWGS_RUN_CHROMIUM_SUPERVISED=1.
func TestChromiumSystrapSupervisedRealInternet(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumSupervised {
		t.Skip("set UWGS_RUN_CHROMIUM_SUPERVISED=1 or -uwgs-chromium-supervised to run the supervised-chromium real-internet smoke")
	}
	requirePhase1Toolchain(t)

	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		for _, candidate := range []string{
			"chromium", "chromium-browser", "google-chrome", "headless_shell",
		} {
			if path, err := exec.LookPath(candidate); err == nil {
				chromeBin = path
				break
			}
		}
	}
	if chromeBin == "" {
		t.Skip("no chromium binary found")
	}

	// Pick a free TCP port for the proxy listener.
	proxyPort := freeTCPPort(t)

	// Spawn a proxy-only uwgsocks: HTTP listener + fallback_direct
	// so outbound requests go straight to the host's network.
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)

	art := buildPhase1Artifacts(t)

	// Build the freestanding blob (the supervisor needs it for any
	// static descendants chromium might exec — chromium's helper
	// processes are dynamic in practice, but the supervisor is
	// supposed to handle either case).
	tmp := t.TempDir()
	repo := filepath.Clean(filepath.Join("..", ".."))
	build := exec.Command("bash", filepath.Join("preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh: %v\n%s", err, out)
	}
	blob := filepath.Join(tmp, "uwgpreload-static-amd64.so")
	if _, err := os.Stat(blob); err != nil {
		// arm64 build produces uwgpreload-static-arm64.so; guess
		// from the filename.
		blob = filepath.Join(tmp, "uwgpreload-static-arm64.so")
		if _, err := os.Stat(blob); err != nil {
			t.Fatalf("static blob not produced in %s", tmp)
		}
	}

	for _, tc := range []struct {
		name, url, mustContain string
	}{
		{"example.com", "https://example.com/", "Example Domain"},
		// Wikipedia is JS-heavy and triggers chromium's renderer
		// fork. Asserts a string that's stable across language
		// editions of the index page.
		{"wikipedia.org", "https://www.wikipedia.org/", "Wikipedia"},
		// YouTube is the deepest JS + IPC + media stack the
		// open web exposes. The homepage doesn't require login
		// or a specific video; we just look for "YouTube" in
		// the rendered DOM as a presence check. If the
		// supervisor breaks anywhere in chromium's helper-
		// process tree, this is where it'll surface.
		{"youtube.com", "https://www.youtube.com/", "YouTube"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// MINIMAL chromium flag set. We start with the
			// kitchen sink and document each flag we drop.
			//
			//   --headless                 required (no display)
			//   --no-sandbox               required: chromium's
			//     setuid sandbox helper needs CAP_SYS_ADMIN to
			//     unshare user/PID namespaces; under systrap-
			//     supervised we also can't ptrace into a setuid-
			//     sandboxed child. Hardening pass for
			//     fdproxy/sandbox-cooperation is a separate
			//     follow-up.
			//   --disable-gpu              required without a GPU
			//   --disable-dev-shm-usage    required: snap +
			//     stripped containers have a tiny /dev/shm tmpfs
			//     that chromium's IPC SharedMemory can't fit
			//     into. (Was --disable-dev-shm-usage)
			//
			// Dropping (vs. existing chromium_realinet_test.go):
			//   - --disable-features=DBus,VizDisplayCompositor:
			//       drop and see what happens. dbus retry loop
			//       eats startup time in stripped containers but
			//       we time out at 60s anyway.
			//   - --disable-software-rasterizer: drop; software
			//       fallback should be fine for static pages.
			//   - --no-zygote: drop! The zygote IS the fork+exec
			//       model the supervisor is meant to handle. If
			//       --no-zygote was load-bearing before, that's
			//       what systrap-supervised exists to remove.
			//   - --virtual-time-budget=10000: keep at 8000;
			//       gives JS a moment to settle.
			args := []string{
				"--headless",
				"--no-sandbox",
				"--disable-gpu",
				"--disable-dev-shm-usage",
				"--virtual-time-budget=8000",
				fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", proxyPort),
				"--dump-dom",
				tc.url,
			}

			// We don't have a tunnel-side network for chromium
			// to bind on — chromium just dials outbound through
			// the proxy. So we use systrap-supervised purely
			// for the kernel-trap path, no fdproxy listen
			// required. The wrapper still starts fdproxy
			// internally for the Phase 1 trap dispatcher; we
			// tell it the api endpoint so socket() etc.
			// resolves cleanly.
			httpSock := filepath.Join(tmp, "uwgsocks.sock")
			// Bring up a separate uwgsocks instance with a Unix
			// HTTP listener for fdproxy to talk to (the proxy
			// listener above is for chromium; this one is for
			// the wrapper's internal socket-API calls).
			cfg2 := config.Default()
			cfg2.WireGuard.PrivateKey = mustKey(t).String()
			cfg2.WireGuard.Addresses = []string{"100.64.99.2/32"}
			cfg2.API.Listen = "unix:" + filepath.Join(tmp, "uwgsocks-api.sock")
			cfg2.API.AllowUnauthenticatedUnix = true
			cfg2.Proxy.HTTPListeners = []string{"unix:" + httpSock}
			cfg2.SocketAPI.Bind = true
			_ = mustStart(t, cfg2)
			waitPath(t, httpSock)

			wrapperArgs := []string{
				"--transport=systrap-supervised",
				"--listen", filepath.Join(tmp, "fdproxy.sock"),
				"--api", "unix:" + httpSock,
				"--socket-path", "/uwg/socket",
				"--", chromeBin,
			}
			wrapperArgs = append(wrapperArgs, args...)

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
			cmd.Env = append(os.Environ(), "UWGS_STATIC_BLOB="+blob)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			out, err := runCommandCombinedFileBacked(t, cmd)
			t.Logf("=== chromium under systrap-supervised: %s ===\n%s\n=== end (%d bytes, err=%v) ===",
				tc.url, abbrev(out, 800), len(out), err)

			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("chromium under systrap-supervised timed out fetching %s", tc.url)
			}
			if err != nil {
				t.Fatalf("chromium under systrap-supervised exited non-zero for %s: %v", tc.url, err)
			}
			if !strings.Contains(string(out), tc.mustContain) {
				t.Fatalf("expected %q in DOM for %s; not found", tc.mustContain, tc.url)
			}
		})
	}
}

func abbrev(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max/2]) + "\n…\n" + string(b[len(b)-max/2:])
}

// Reuse waitPath / runCommandCombinedFileBacked / freeTCPPort /
// waitTCPPort / mustKey / mustStart from existing helpers.
var _ = net.Listen
