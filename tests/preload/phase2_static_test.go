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
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestPhase2StaticBinaryEchoTCP wraps a CGO_ENABLED=0 Go static binary
// through transport=preload-static. The binary is the simplest possible
// tunnel client: dials a TCP address, writes a sentinel message,
// reads it back, prints it.
//
// Validates the Phase 2 ptrace-injection pipeline end-to-end:
//   1. uwgwrapper detects static binary, fork+execs with PTRACE_TRACEME
//   2. Supervisor parses the freestanding blob
//   3. Supervisor remote-mmaps + POKEDATAs the segments
//   4. Supervisor jumps to uwg_static_init with the tracee's real envp
//   5. uwg_core_init installs SIGSYS + seccomp + connects to fdproxy
//   6. Supervisor detaches; tracee runs full-speed
//   7. Tracee's connect() → SIGSYS → uwg_connect → fdproxy → tunnel
//   8. Tracee gets the echo back, prints it, exits 0
func TestPhase2StaticBinaryEchoTCP(t *testing.T) {
	requirePhase1Toolchain(t)
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("phase2 static-blob injection only on amd64 + arm64 (got %s)", runtime.GOARCH)
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build the freestanding blob.
	blob := filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so")
	build := exec.Command("bash", filepath.Join("preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(blob); err != nil {
		t.Fatalf("blob not produced at %s: %v", blob, err)
	}

	// Build a glibc-static C client. The rt_sigaction-protection in
	// the seccomp filter (uwg_dispatch's SYS_rt_sigaction case)
	// also makes Go static binaries work — Go's runtime tries to
	// override SIGSYS during early init but our handler intercepts
	// the rt_sigaction call and silently no-ops it for SIGSYS. The
	// C variant is the simpler test target; a Go-static stress test
	// follows in TestPhase2StaticGoConcurrency.
	client := filepath.Join(tmp, "stub_static")
	gccCmd := exec.Command("gcc", "-static", "-O2",
		"-o", client,
		filepath.Join(repo, "tests", "preload", "testdata", "stub_client.c"))
	if out, err := gccCmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc -static failed: %v\n%s", err, out)
	}
	// Confirm it really is statically linked. `file` is missing in
	// some minimal containers (e.g. golang:alpine without the file
	// package); treat its absence as "trust gcc -static did its job"
	// rather than failing the test.
	if _, fileErr := exec.LookPath("file"); fileErr == nil {
		fileOut, _ := exec.Command("file", client).CombinedOutput()
		if !strings.Contains(string(fileOut), "statically linked") &&
			!strings.Contains(string(fileOut), "static-pie linked") {
			t.Fatalf("client isn't statically linked: %s", fileOut)
		}
		t.Logf("client: %s", strings.TrimSpace(string(fileOut)))
	} else {
		t.Logf("client: %s (file(1) unavailable; trusting gcc -static)", client)
	}

	// Build wrapper artifacts (we need uwgwrapper + a tunnel server).
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	// Run the static client through transport=preload-static. The
	// stub_client takes "<ip> <port> <message> [tcp|udp|...]"; tcp
	// mode connects, writes, reads, prints.
	args := []string{"100.64.94.1", "18080", "phase2-static-tcp", "tcp"}
	wrapperArgs := []string{
		"--transport=preload-static",
		"--listen", filepath.Join(tmp, "fdproxy.sock"),
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--", client,
	}
	wrapperArgs = append(wrapperArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = append(os.Environ(), "UWGS_STATIC_BLOB="+blob)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("timed out waiting for static client")
	}
	if err != nil {
		t.Fatalf("wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "phase2-static-tcp") {
		t.Fatalf("expected sentinel %q in output; got %q", "phase2-static-tcp", out)
	}
}

// TestPhase2StaticGoBinaryEchoTCP wraps a CGO_ENABLED=0 Go static
// binary through transport=preload-static. This validates Go runtime
// compatibility: Go installs its own SIGSYS handler during early
// init, but the rt_sigaction-protection in the seccomp filter
// silently no-ops sigaction(SIGSYS, ...) so our handler stays intact.
func TestPhase2StaticGoBinaryEchoTCP(t *testing.T) {
	requirePhase1Toolchain(t)
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("phase2 only on amd64 + arm64 (got %s)", runtime.GOARCH)
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()

	// Build the freestanding blob — wrapper picks it up via embed
	// once we materialize it; here we re-build to ensure the latest
	// source compiles.
	build := exec.Command("bash", filepath.Join("preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh: %v\n%s", err, out)
	}

	// Build CGO_ENABLED=0 Go static client.
	client := filepath.Join(tmp, "static_http_client")
	gobuild := exec.Command("go", "build", "-tags=netgo,osusergo",
		"-ldflags=-extldflags=-static",
		"-o", client,
		filepath.Join(repo, "tests", "preload", "testdata", "static_http_client.go"))
	gobuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := gobuild.CombinedOutput(); err != nil {
		t.Fatalf("go build static client: %v\n%s", err, out)
	}

	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	args := []string{"100.64.94.1", "18080", "phase2-go-static-tcp"}
	wrapperArgs := []string{
		"--transport=preload-static",
		"--listen", filepath.Join(tmp, "fdproxy.sock"),
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--", client,
	}
	wrapperArgs = append(wrapperArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.Env = append(os.Environ(), "UWGS_STATIC_BLOB="+filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== output ===\n%s\n=== end ===", out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("timed out")
	}
	if err != nil {
		t.Fatalf("wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "phase2-go-static-tcp") {
		t.Fatalf("expected sentinel in output; got %q", out)
	}
}

// TestPhase2StaticGoConcurrencyStress runs a Go-static HTTP server
// under transport=preload-static, listening on a tunnel address, and
// hammers it with N concurrent clients dispatched from the WireGuard
// server-side engine. Validates:
//   - listener flow (uwg_listen + uwg_accept + uwg_managed_accept)
//   - per-fd cache scaling under thousands of accept'd KIND_TCP_STREAM fds
//   - rt_sigaction-protect under Go's runtime spawning many M's
//   - end-to-end tunnel round-trip per request
func TestPhase2StaticGoConcurrencyStress(t *testing.T) {
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

	server := filepath.Join(tmp, "static_http_server")
	gobuild := exec.Command("go", "build", "-tags=netgo,osusergo",
		"-ldflags=-extldflags=-static",
		"-o", server,
		filepath.Join(repo, "tests", "preload", "testdata", "static_http_server.go"))
	gobuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := gobuild.CombinedOutput(); err != nil {
		t.Fatalf("go build static server: %v\n%s", err, out)
	}

	art := buildPhase1Artifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	const (
		concurrent = 100
		perWorker  = 10
	)
	totalReq := concurrent * perWorker

	wrapperArgs := []string{
		"--transport=preload-static",
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
		t.Fatalf("start wrapped server: %v", err)
	}
	defer killProcessGroup(cmd)

	// Wait for "READY <ip>:<port>" line.
	br := bufio.NewReader(stdout)
	readyLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read READY: %v", err)
	}
	t.Logf("server: %s", strings.TrimSpace(readyLine))
	if !strings.HasPrefix(readyLine, "READY ") {
		t.Fatalf("unexpected first line: %q", readyLine)
	}

	// Tunnel-side HTTP client that dials via serverEng.
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
				resp, err := client.Get("http://stress" + path)
				if err != nil {
					errs <- fmt.Errorf("w%d r%d: %w", workerID, j, err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != path {
					errs <- fmt.Errorf("w%d r%d: body=%q want=%q", workerID, j, body, path)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	failed := 0
	for e := range errs {
		failed++
		if failed <= 5 {
			t.Logf("err: %v", e)
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d requests failed", failed, totalReq)
	}
	t.Logf("%d concurrent workers × %d requests = %d req successful",
		concurrent, perWorker, totalReq)

	// Wait for server to exit cleanly.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Logf("server exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		killProcessGroup(cmd)
		t.Fatalf("server didn't exit after %d responses", totalReq)
	}
}
