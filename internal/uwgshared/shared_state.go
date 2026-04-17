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
	MaxTrackedFD    = 65536
	MaxTrackedSlots = 65536
	SharedMagic     = 0x55574753
	SharedVersion   = 6
	MaxGuardSlots   = 256

	KindNone         = 0
	KindTCPStream    = 1
	KindUDPConnected = 2
	KindUDPListener  = 3
	KindTCPListener  = 4
)

const trackedTombstonePID = int32(-1)

type TrackedFD struct {
	Active       int32
	Domain       int32
	Type         int32
	Protocol     int32
	Proxied      int32
	Kind         int32
	HotReady     int32
	Bound        int32
	ReuseAddr    int32
	ReusePort    int32
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
	Readers   uint32
	Writer    uint32
	WriterTID int32
}

type trackedSlot struct {
	OwnerPID int32
	FD       int32
	State    TrackedFD
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
	Tracked [MaxTrackedSlots]trackedSlot
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

func (t *Table) Snapshot(pid, fd int) TrackedFD {
	var entry TrackedFD
	if t == nil || t.state == nil || pid <= 0 || fd < 0 || fd >= MaxTrackedFD {
		return entry
	}
	t.WithReadLock(func() {
		if idx, ok := t.findTrackedSlotLocked(int32(pid), int32(fd), false); ok {
			entry = t.state.Tracked[idx].State
		}
	})
	return entry
}

func (t *Table) Update(pid, fd int, fn func(entry *TrackedFD)) {
	if t == nil || t.state == nil || pid <= 0 || fd < 0 || fd >= MaxTrackedFD {
		return
	}
	t.WithWriteLock(func() {
		idx, found := t.findTrackedSlotLocked(int32(pid), int32(fd), true)
		if idx < 0 {
			return
		}
		slot := &t.state.Tracked[idx]
		if !found {
			slot.OwnerPID = int32(pid)
			slot.FD = int32(fd)
			slot.State = TrackedFD{}
		}
		fn(&slot.State)
		if slot.State == (TrackedFD{}) {
			slot.OwnerPID = trackedTombstonePID
			slot.FD = -1
		}
	})
}

func (t *Table) Clear(pid, fd int) {
	if t == nil || t.state == nil || pid <= 0 || fd < 0 || fd >= MaxTrackedFD {
		return
	}
	t.WithWriteLock(func() {
		if idx, ok := t.findTrackedSlotLocked(int32(pid), int32(fd), false); ok {
			slot := &t.state.Tracked[idx]
			slot.OwnerPID = trackedTombstonePID
			slot.FD = -1
			slot.State = TrackedFD{}
		}
	})
}

func (t *Table) CopyProcess(srcPID, dstPID int) {
	if t == nil || t.state == nil || srcPID <= 0 || dstPID <= 0 || srcPID == dstPID {
		return
	}
	t.WithWriteLock(func() {
		for i := range t.state.Tracked {
			slot := t.state.Tracked[i]
			if slot.OwnerPID != int32(srcPID) {
				continue
			}
			idx, found := t.findTrackedSlotLocked(int32(dstPID), slot.FD, true)
			if idx < 0 {
				continue
			}
			dst := &t.state.Tracked[idx]
			if !found {
				dst.OwnerPID = int32(dstPID)
				dst.FD = slot.FD
			}
			dst.State = slot.State
		}
	})
}

func (t *Table) ClearProcess(pid int) {
	if t == nil || t.state == nil || pid <= 0 {
		return
	}
	t.WithWriteLock(func() {
		for i := range t.state.Tracked {
			if t.state.Tracked[i].OwnerPID != int32(pid) {
				continue
			}
			t.state.Tracked[i].OwnerPID = trackedTombstonePID
			t.state.Tracked[i].FD = -1
			t.state.Tracked[i].State = TrackedFD{}
		}
	})
}

func (t *Table) ProcessFDs(pid int) []int {
	if t == nil || t.state == nil || pid <= 0 {
		return nil
	}
	fds := make([]int, 0)
	t.WithReadLock(func() {
		for i := range t.state.Tracked {
			if t.state.Tracked[i].OwnerPID != int32(pid) {
				continue
			}
			fds = append(fds, int(t.state.Tracked[i].FD))
		}
	})
	return fds
}

func trackedHash(pid, fd int32) uint32 {
	x := uint64(uint32(pid))<<32 | uint64(uint32(fd))
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return uint32(x) & (MaxTrackedSlots - 1)
}

func (t *Table) findTrackedSlotLocked(pid, fd int32, create bool) (int, bool) {
	if t == nil || t.state == nil || pid <= 0 || fd < 0 || fd >= MaxTrackedFD {
		return -1, false
	}
	firstTombstone := -1
	start := trackedHash(pid, fd)
	for probe := 0; probe < MaxTrackedSlots; probe++ {
		idx := int((start + uint32(probe)) & (MaxTrackedSlots - 1))
		slot := &t.state.Tracked[idx]
		switch {
		case slot.OwnerPID == pid && slot.FD == fd:
			return idx, true
		case slot.OwnerPID == 0:
			if !create {
				return -1, false
			}
			if firstTombstone >= 0 {
				return firstTombstone, false
			}
			return idx, false
		case slot.OwnerPID == trackedTombstonePID:
			if firstTombstone < 0 {
				firstTombstone = idx
			}
		}
	}
	if create && firstTombstone >= 0 {
		return firstTombstone, false
	}
	return -1, false
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
	atomic.StoreInt32(&lock.WriterTID, int32(unix.Gettid()))
	for atomic.LoadUint32(&lock.Readers) != 0 {
		runtime.Gosched()
	}
}

func (t *Table) wrunlock() {
	atomic.StoreInt32(&t.state.Lock.WriterTID, 0)
	atomic.StoreUint32(&t.state.Lock.Writer, 0)
}
