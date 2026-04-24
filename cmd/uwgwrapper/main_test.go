//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import "testing"

func TestFDProxySpawnArgsKeepTokenReachable(t *testing.T) {
	args := fdproxySpawnArgs("/tmp/fd.sock", "http://127.0.0.1:9090", "/uwg/socket", true, false, "demo-token", true)
	want := []string{
		"--mode=fdproxy",
		"--listen", "/tmp/fd.sock",
		"--api", "http://127.0.0.1:9090",
		"--socket-path", "/uwg/socket",
		"--allow-bind=true",
		"--allow-lowbind=false",
		"-v",
		"--token", "demo-token",
	}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d: %v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; args=%v", i, args[i], want[i], args)
		}
	}
}
