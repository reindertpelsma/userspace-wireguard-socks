// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !linux || !amd64

package uwgtrace

import "errors"

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
	return ErrPtraceUnavailable
}
