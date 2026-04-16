// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package uwgshared

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	MaxTrackedFD  = 65536
	SharedMagic   = 0x55574753
	SharedVersion = 3
	MaxGuardSlots = 256

	KindNone         = 0
	KindTCPStream    = 1
	KindUDPConnected = 2
	KindUDPListener  = 3
	KindTCPListener  = 4
)

type TrackedFD struct {
	Active       int32
	Domain       int32
	Type         int32
	Protocol     int32
	Proxied      int32
	Kind         int32
	HotReady     int32
	Bound        int32
	BindFamily   int32
	BindPort     uint16
	BindIP       [46]byte
	RemoteFamily int32
	RemotePort   uint16
	RemoteIP     [46]byte
	SavedFL      int32
	SavedFDFL    int32
}

type rwLock struct {
	Readers  uint32
	Writer   uint32
	Reserved uint32
}

type guardLock struct {
	Readers    uint32
	Writer     uint32
	WriterTID  int32
	Reserved   uint32
	ReaderTIDs [MaxGuardSlots]int32
}

type sharedState struct {
	Magic   uint32
	Version uint32
	Secret  uint64
	Lock    rwLock
	Guard   guardLock
	Tracked [MaxTrackedFD]TrackedFD
}

type GuardDisposition int

const (
	GuardUnlocked GuardDisposition = iota
	GuardOwnedBySelf
	GuardOwnedByOther
)

type Table struct {
	path  string
	file  *os.File
	data  []byte
	state *sharedState
}

func Create(path string, secret uint64) (*Table, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	size := int(unsafe.Sizeof(sharedState{}))
	if err := file.Truncate(int64(size)); err != nil {
		_ = file.Close()
		return nil, err
	}
	data, err := unix.Mmap(int(file.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	state := (*sharedState)(unsafe.Pointer(&data[0]))
	*state = sharedState{}
	state.Magic = SharedMagic
	state.Version = SharedVersion
	state.Secret = secret
	return &Table{path: path, file: file, data: data, state: state}, nil
}

func Open(path string) (*Table, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	size := int(unsafe.Sizeof(sharedState{}))
	data, err := unix.Mmap(int(file.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	state := (*sharedState)(unsafe.Pointer(&data[0]))
	if state.Magic != SharedMagic || state.Version != SharedVersion {
		_ = unix.Munmap(data)
		_ = file.Close()
		return nil, fmt.Errorf("invalid shared state")
	}
	return &Table{path: path, file: file, data: data, state: state}, nil
}

func (t *Table) Close(removeFile bool) error {
	var firstErr error
	if t == nil {
		return nil
	}
	if len(t.data) > 0 {
		if err := unix.Munmap(t.data); err != nil && firstErr == nil {
			firstErr = err
		}
		t.data = nil
		t.state = nil
	}
	if t.file != nil {
		if err := t.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.file = nil
	}
	if removeFile && t.path != "" {
		if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *Table) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

func (t *Table) Secret() uint64 {
	if t == nil || t.state == nil {
		return 0
	}
	return atomic.LoadUint64(&t.state.Secret)
}

func (t *Table) GuardDisposition(tid int) GuardDisposition {
	if t == nil || t.state == nil || tid <= 0 {
		return GuardUnlocked
	}
	guard := &t.state.Guard
	self := int32(tid)
	writer := atomic.LoadUint32(&guard.Writer)
	writerTID := atomic.LoadInt32(&guard.WriterTID)
	if writerTID == self {
		return GuardOwnedBySelf
	}
	if writer != 0 || writerTID != 0 {
		return GuardOwnedByOther
	}
	hasOther := false
	for i := range guard.ReaderTIDs {
		owner := atomic.LoadInt32(&guard.ReaderTIDs[i])
		if owner == self {
			return GuardOwnedBySelf
		}
		if owner != 0 {
			hasOther = true
		}
	}
	if hasOther {
		return GuardOwnedByOther
	}
	return GuardUnlocked
}

func (t *Table) GuardOwners() (int32, []int32) {
	if t == nil || t.state == nil {
		return 0, nil
	}
	guard := &t.state.Guard
	writer := atomic.LoadInt32(&guard.WriterTID)
	readers := make([]int32, 0, MaxGuardSlots)
	for i := range guard.ReaderTIDs {
		if owner := atomic.LoadInt32(&guard.ReaderTIDs[i]); owner != 0 {
			readers = append(readers, owner)
		}
	}
	return writer, readers
}

func (t *Table) ClearGuardReaderOwner(tid int32) bool {
	if t == nil || t.state == nil || tid == 0 {
		return false
	}
	guard := &t.state.Guard
	for i := range guard.ReaderTIDs {
		if !atomic.CompareAndSwapInt32(&guard.ReaderTIDs[i], tid, 0) {
			continue
		}
		for {
			readers := atomic.LoadUint32(&guard.Readers)
			if readers == 0 {
				return true
			}
			if atomic.CompareAndSwapUint32(&guard.Readers, readers, readers-1) {
				return true
			}
		}
	}
	return false
}

func (t *Table) ClearGuardWriterOwner(tid int32) bool {
	if t == nil || t.state == nil || tid == 0 {
		return false
	}
	guard := &t.state.Guard
	if !atomic.CompareAndSwapInt32(&guard.WriterTID, tid, 0) {
		return false
	}
	atomic.StoreUint32(&guard.Writer, 0)
	return true
}

func (t *Table) WithReadLock(fn func()) {
	if t == nil || t.state == nil {
		fn()
		return
	}
	t.rdlock()
	defer t.rdunlock()
	fn()
}

func (t *Table) WithWriteLock(fn func()) {
	if t == nil || t.state == nil {
		fn()
		return
	}
	t.wrlock()
	defer t.wrunlock()
	fn()
}

func (t *Table) Snapshot(fd int) TrackedFD {
	var entry TrackedFD
	if t == nil || t.state == nil || fd < 0 || fd >= MaxTrackedFD {
		return entry
	}
	t.WithReadLock(func() {
		entry = t.state.Tracked[fd]
	})
	return entry
}

func (t *Table) Update(fd int, fn func(entry *TrackedFD)) {
	if t == nil || t.state == nil || fd < 0 || fd >= MaxTrackedFD {
		return
	}
	t.WithWriteLock(func() {
		fn(&t.state.Tracked[fd])
	})
}

func (t *Table) Clear(fd int) {
	if t == nil || t.state == nil || fd < 0 || fd >= MaxTrackedFD {
		return
	}
	t.Update(fd, func(entry *TrackedFD) {
		*entry = TrackedFD{}
	})
}

func BytesToString(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}

func StringToBytes(dst []byte, value string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, value)
}

func (t *Table) rdlock() {
	lock := &t.state.Lock
	for {
		for atomic.LoadUint32(&lock.Writer) != 0 {
			runtime.Gosched()
		}
		atomic.AddUint32(&lock.Readers, 1)
		if atomic.LoadUint32(&lock.Writer) == 0 {
			return
		}
		atomic.AddUint32(&lock.Readers, ^uint32(0))
	}
}

func (t *Table) rdunlock() {
	atomic.AddUint32(&t.state.Lock.Readers, ^uint32(0))
}

func (t *Table) wrlock() {
	lock := &t.state.Lock
	for !atomic.CompareAndSwapUint32(&lock.Writer, 0, 1) {
		runtime.Gosched()
	}
	for atomic.LoadUint32(&lock.Readers) != 0 {
		runtime.Gosched()
	}
}

func (t *Table) wrunlock() {
	atomic.StoreUint32(&t.state.Lock.Writer, 0)
}
