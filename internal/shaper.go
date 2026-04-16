package internal

import (
	"container/list"
	"context"
	"hash/fnv"
	"io"
	"net/netip"
	"sync"
	"time"
)

type ShaperConfig struct {
	UploadBps     int64
	DownloadBps   int64
	TargetLatency time.Duration // default 15ms
}

type Shaper struct {
	mu sync.Mutex
	cfg ShaperConfig

	// Upload shaper (from client to tunnel)
	upload *directionShaper
	// Download shaper (from tunnel to client)
	download *directionShaper
}

type directionShaper struct {
	mu sync.Mutex
	bps int64
	target time.Duration

	// Token bucket
	tokens int64
	lastUpdate time.Time
	maxTokens int64

	// FQ-CoDel / CAKE inspired mini-queues
	queues [1024]*packetQueue
}

type packetQueue struct {
	packets *list.List
	// CoDel state
	firstAboveTime time.Time
	dropNext       time.Time
	dropping       bool
	count          int
}

type QueuedPacket struct {
	Data []byte
	Hash uint32
	AddedAt time.Time
	IsECN bool
}

func NewShaper(cfg ShaperConfig) *Shaper {
	if cfg.TargetLatency == 0 {
		cfg.TargetLatency = 15 * time.Millisecond
	}
	s := &Shaper{cfg: cfg}
	if cfg.UploadBps > 0 {
		s.upload = newDirectionShaper(cfg.UploadBps, cfg.TargetLatency)
	}
	if cfg.DownloadBps > 0 {
		s.download = newDirectionShaper(cfg.DownloadBps, cfg.TargetLatency)
	}
	return s
}

func newDirectionShaper(bps int64, target time.Duration) *directionShaper {
	ds := &directionShaper{
		bps: bps,
		target: target,
		lastUpdate: time.Now(),
		// Keep token bucket short: e.g. 100ms worth of traffic
		maxTokens: bps / 10, 
	}
	if ds.maxTokens < 1500 {
		ds.maxTokens = 1500
	}
	for i := range ds.queues {
		ds.queues[i] = &packetQueue{packets: list.New()}
	}
	return ds
}

func (s *Shaper) ShapeUpload(data []byte, hash uint32) (allowed bool, ecn bool) {
	if s == nil || s.upload == nil {
		return true, false
	}
	return s.upload.shape(data, hash)
}

func (s *Shaper) ShapeDownload(data []byte, hash uint32) (allowed bool, ecn bool) {
	if s == nil || s.download == nil {
		return true, false
	}
	return s.download.shape(data, hash)
}

func (ds *directionShaper) shape(data []byte, hash uint32) (bool, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(ds.lastUpdate)
	ds.lastUpdate = now

	// Update tokens
	ds.tokens += int64(float64(ds.bps) * elapsed.Seconds())
	if ds.tokens > ds.maxTokens {
		ds.tokens = ds.maxTokens
	}

	size := int64(len(data))
	if ds.tokens >= size {
		ds.tokens -= size
		return true, false
	}

	// Tail drop if tokens are very negative (burst protection)
	if ds.tokens < -ds.maxTokens {
		return false, false
	}

	// Simple ECN marking if tokens are low
	ds.tokens -= size
	return true, ds.tokens < 0
}

// StreamShaper for TCP backpressure
type StreamShaper struct {
	Shaper *Shaper
}

func (ss *StreamShaper) WaitUpload(ctx context.Context, size int) error {
	if ss == nil || ss.Shaper == nil || ss.Shaper.upload == nil {
		return nil
	}
	return ss.Shaper.upload.wait(ctx, int64(size))
}

func (ss *StreamShaper) WaitDownload(ctx context.Context, size int) error {
	if ss == nil || ss.Shaper == nil || ss.Shaper.download == nil {
		return nil
	}
	return ss.Shaper.download.wait(ctx, int64(size))
}

func (ds *directionShaper) wait(ctx context.Context, size int64) error {
	for {
		ds.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(ds.lastUpdate)
		ds.lastUpdate = now
		ds.tokens += int64(float64(ds.bps) * elapsed.Seconds())
		if ds.tokens > ds.maxTokens {
			ds.tokens = ds.maxTokens
		}

		if ds.tokens >= size {
			ds.tokens -= size
			ds.mu.Unlock()
			return nil
		}
		
		// Need to wait
		needed := size - ds.tokens
		waitDur := time.Duration(float64(needed) / float64(ds.bps) * float64(time.Second))
		if waitDur > 100*time.Millisecond {
			waitDur = 100 * time.Millisecond
		}
		ds.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDur):
		}
	}
}

func HashFlow(src, dst netip.AddrPort) uint32 {
	h := fnv.New32a()
	b1 := src.Addr().AsSlice()
	b2 := dst.Addr().AsSlice()
	// Sort to make it bidirectional
	if src.String() > dst.String() {
		h.Write(b1)
		writeUint16(h, src.Port())
		h.Write(b2)
		writeUint16(h, dst.Port())
	} else {
		h.Write(b2)
		writeUint16(h, dst.Port())
		h.Write(b1)
		writeUint16(h, src.Port())
	}
	return h.Sum32()
}

func writeUint16(h io.Writer, v uint16) {
	var b [2]byte
	b[0] = byte(v >> 8)
	b[1] = byte(v)
	h.Write(b[:])
}
