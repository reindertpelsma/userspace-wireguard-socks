// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestPhase1SeccompPreloadConcurrent fires N wrapped stub_client
// processes in parallel — each one independently does a full TCP
// connect/echo/close cycle through the SIGSYS preload + fdproxy
// path. The point is to surface any races in shared_state's rwlock
// or in fdproxy's listener registration.
//
// 16 parallel workers is comfortable on commodity CI runners (we
// build phase1.so once, then dispatch the spawn loop). Bumping to
// 64 surfaces a kernel-side EAGAIN that's irrelevant to phase1.
func TestPhase1SeccompPreloadConcurrent(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	phase1So := filepath.Join(t.TempDir(), "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}
	art.preload = phase1So

	const workers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sentry := "phase1-stress-" + itoa(idx)
			args := []string{"100.64.94.1", "18080", sentry, "tcp"}
			base := wrappedCommand(t, art, httpSock, "preload", art.stub, args, wrapperRunOptions{})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
			cmd.Env = append([]string{}, base.Env...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			out, err := runCommandCombinedFileBacked(t, cmd)
			if ctx.Err() == context.DeadlineExceeded {
				errCh <- &workerErr{idx: idx, msg: "timeout: " + string(out)}
				return
			}
			if err != nil {
				errCh <- &workerErr{idx: idx, msg: "exec: " + err.Error() + " out=" + string(out)}
				return
			}
			if !strings.Contains(string(out), sentry) {
				errCh <- &workerErr{idx: idx, msg: "no sentry: out=" + string(out)}
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	var failures []string
	for e := range errCh {
		failures = append(failures, e.Error())
	}
	if len(failures) > 0 {
		t.Fatalf("%d/%d workers failed:\n%s", len(failures), workers, strings.Join(failures, "\n"))
	}
}

type workerErr struct {
	idx int
	msg string
}

func (e *workerErr) Error() string {
	return "worker " + itoa(e.idx) + ": " + e.msg
}
