// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestPhase2NaturalExitDiag runs the static HTTP server in its
// "natural exit" variant (no explicit os.Exit) and, when the server
// fails to exit within a short window after serving its quota, dumps
// the kernel-side state of every thread in the tracee process via
// /proc/PID/task/*/{status,syscall,stack,wchan}. The dump goes to
// stderr; the test still fails (the natural-exit hang is a known
// issue tracked in memory) but with concrete diagnostic data.
//
// Skipped by default (UWG_PHASE2_DIAG=1 to enable) — this test is for
// manual investigation, not CI.
func TestPhase2NaturalExitDiag(t *testing.T) {
	if !testconfig.Get().Phase2Diag {
		t.Skip("set UWG_PHASE2_DIAG=1 or -uwgs-phase2-diag to run natural-exit hang diagnostic")
	}
	requirePhase1Toolchain(t)
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("phase2 only on amd64+arm64 (got %s)", runtime.GOARCH)
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	build := exec.Command("bash", filepath.Join("preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh: %v\n%s", err, out)
	}

	server := filepath.Join(tmp, "static_http_server_natural")
	gobuild := exec.Command("go", "build", "-tags=netgo,osusergo",
		"-ldflags=-extldflags=-static",
		"-o", server,
		filepath.Join(repo, "tests", "preload", "testdata", "static_http_server_natural.go"))
	gobuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := gobuild.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	art := buildPhase1Artifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	const (
		concurrent = 20
		perWorker  = 5
	)
	totalReq := concurrent * perWorker

	wrapperArgs := []string{
		"--transport=systrap-static",
		"--listen", filepath.Join(tmp, "fdproxy.sock"),
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--", server, "100.64.94.2", "19500", fmt.Sprintf("%d", totalReq),
	}

	cmd := exec.Command(art.wrapper, wrapperArgs...)
	cmd.Env = append(os.Environ(), "UWGS_STATIC_BLOB="+filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer killProcessGroup(cmd)

	br := bufio.NewReader(stdout)
	readyLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read READY: %v", err)
	}
	t.Logf("server: %s", strings.TrimSpace(readyLine))

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return serverEng.DialTunnelContext(ctx, "tcp", "100.64.94.2:19500")
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var wg sync.WaitGroup
	errs := make(chan error, totalReq)
	for w := 0; w < concurrent; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				path := fmt.Sprintf("/w%d-r%d", workerID, j)
				resp, err := client.Get("http://diag" + path)
				if err != nil {
					errs <- fmt.Errorf("w%d r%d: %w", workerID, j, err)
					return
				}
				_, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	t.Logf("%d/%d reqs done", totalReq, totalReq)

	// Drain client connections to encourage the server-side keep-alive
	// goroutines to finish (this is what we suspect is the cause of
	// the hang). If this releases the hang, the diagnosis is "ln.Close
	// alone doesn't drop active conns; client-side disconnect does".
	tr.CloseIdleConnections()
	t.Logf("client idle conns closed; waiting 3s to see if natural exit completes")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Logf("EXITED CLEANLY (err=%v) — diagnosis: client-side close is sufficient",
			err)
		return
	case <-time.After(3 * time.Second):
		// Hang. Find the wrapped child PID and dump its threads.
	}

	// Dump per-thread state for both the wrapper and the wrapped server.
	dumpThreads := func(label string, pid int) {
		t.Logf("=== /proc dump: %s pid=%d ===", label, pid)
		taskDir := fmt.Sprintf("/proc/%d/task", pid)
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			t.Logf("  read %s: %v", taskDir, err)
			return
		}
		for _, e := range entries {
			tid := e.Name()
			t.Logf("  --- tid %s ---", tid)
			for _, field := range []string{"status", "syscall", "stack", "wchan", "comm"} {
				path := filepath.Join(taskDir, tid, field)
				b, err := os.ReadFile(path)
				if err != nil {
					t.Logf("    %s: %v", field, err)
					continue
				}
				out := strings.TrimSpace(string(b))
				if field == "status" {
					// status is multi-line; pick the interesting fields.
					interesting := []string{}
					for _, line := range strings.Split(out, "\n") {
						for _, want := range []string{"State:", "Pid:", "PPid:", "Tgid:", "VmSize:", "Threads:", "SigQ:", "SigPnd:", "SigBlk:", "SigCgt:"} {
							if strings.HasPrefix(line, want) {
								interesting = append(interesting, line)
								break
							}
						}
					}
					t.Logf("    status:\n      %s", strings.Join(interesting, "\n      "))
				} else if field == "stack" {
					// stack can be very long; first 8 lines is enough.
					lines := strings.Split(out, "\n")
					if len(lines) > 8 {
						lines = lines[:8]
					}
					t.Logf("    stack:\n      %s", strings.Join(lines, "\n      "))
				} else {
					t.Logf("    %s: %s", field, out)
				}
			}
		}
	}

	wrapperPid := cmd.Process.Pid
	dumpThreads("wrapper", wrapperPid)

	// The wrapped server is the only child of the wrapper.
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(wrapperPid)).CombinedOutput()
	for _, line := range strings.Fields(string(out)) {
		pid, _ := strconv.Atoi(line)
		if pid > 0 {
			dumpThreads("wrapped-server", pid)
		}
	}

	t.Fatalf("natural-exit hang reproduced — see /proc dump above")
}
