// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build (!linux || (!amd64 && !arm64)) && (!android || !arm64)

package uwgtrace

import (
	"errors"
	"runtime"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
	"golang.org/x/sys/unix"
)

var (
	ErrPtraceUnavailable  = errors.New("ptrace tracing unavailable")
	ErrSeccompUnavailable = errors.New("seccomp trace filter unavailable")
)

type Options struct {
	Args            []string
	Env             []string
	FDProxy         string
	SeccompMode     SeccompMode
	NoNewPrivileges bool
	Verbose         bool
	Shared          *uwgshared.Table
	StatsPath       string
}

type SeccompMode int

const (
	SeccompNone SeccompMode = iota
	SeccompSimple
	SeccompSecret
)

func Run(opts Options) (int, error) {
	_ = opts
	return 0, ErrPtraceUnavailable
}

func RunTraceeHelper(args []string) error {
	_ = args
	return ErrPtraceUnavailable
}

func SetNoNewPrivileges() error {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	}
	return ErrPtraceUnavailable
}
