// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build (linux || android) && arm64

package uwgtrace

import "golang.org/x/sys/unix"

var secretBypassSyscalls = []uint32{
	unix.SYS_SOCKET,
	unix.SYS_CONNECT,
	unix.SYS_BIND,
	unix.SYS_LISTEN,
	unix.SYS_ACCEPT,
	unix.SYS_ACCEPT4,
	unix.SYS_CLOSE,
	unix.SYS_READ,
	unix.SYS_WRITE,
	unix.SYS_READV,
	unix.SYS_WRITEV,
	unix.SYS_SENDMSG,
	unix.SYS_RECVMSG,
	unix.SYS_SENDMMSG,
	unix.SYS_RECVMMSG,
	unix.SYS_DUP,
	unix.SYS_DUP3,
	unix.SYS_GETSOCKNAME,
	unix.SYS_GETPEERNAME,
	unix.SYS_SHUTDOWN,
	unix.SYS_FCNTL,
	unix.SYS_GETSOCKOPT,
	unix.SYS_SETSOCKOPT,
	unix.SYS_PPOLL,
}

var alwaysTraceSyscalls = []uint32{
	unix.SYS_SENDTO,
	unix.SYS_RECVFROM,
	// arm64 does not have a native select(2) syscall; libc reaches the kernel
	// through pselect6/ppoll instead.
	unix.SYS_PSELECT6,
}

func syscallUsesPassthroughSecret(nr int64) bool {
	return syscallInSet(nr, secretBypassSyscalls)
}
