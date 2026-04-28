// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Note: UDP-listener server-side tests aren't viable in this harness:
// fdproxy's udpListenerGroup.dispatchDatagram drops upstream datagrams
// that arrive before the wrapped member has sent at least once
// (recordPeerOwner is what populates ownerFor). The same limitation
// applies to the legacy preload — it's architectural in fdproxy, not
// a phase1 bug. The unconnected-UDP client side (stub sends first,
// then recvfrom) is covered by TestPhase1SeccompPreload/udp_unconnected
// in phase1_smoke_test.go and exercises the same encode/decode paths.

// TestPhase1SeccompPreloadTCPListener exercises the TCP listener flow
// (bind + listen + accept) under the SIGSYS+seccomp preload. Mirrors
// TestUWGWrapperPreloadAccept4Listener exactly except for the .so swap
// — which lets us pin the exact regression if phase1 misbehaves where
// legacy doesn't.
func TestPhase1SeccompPreloadTCPListener(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	phase1So := filepath.Join(t.TempDir(), "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}
	art.preload = phase1So

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "systrap", art.stub,
			[]string{"100.64.94.2", "19196", "phase1-listener", "listen-tcp"}, wrapperRunOptions{})

		runErr := func() error {
			drainAndDump := func() string {
				killProcessGroup(cmd)
				<-done
				return stderr.String()
			}
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19196")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("phase1-listener")); err != nil {
				return fmt.Errorf("listener write failed: %w\nstderr=%s", err, drainAndDump())
			}
			buf := make([]byte, len("phase1-listener"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("listener read failed: %w\nstderr=%s", err, drainAndDump())
			}
			if string(buf) != "phase1-listener" {
				return fmt.Errorf("listener echo mismatch %q\nstderr=%s", buf, drainAndDump())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("listener wrapper did not exit\nstderr=%s", drainAndDump())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying phase1 listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}
