package internal

import (
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
	TargetLatency time.Duration
}

type Shaper struct {
	cfg      ShaperConfig
	upload   *directionShaper
	download *directionShaper
}

type StreamShaper struct {
	Shaper *Shaper
}

type directionShaper struct {
	mu sync.Mutex

	bps         int64
	target      time.Duration
	maxBurst    int64
	queueBudget int64
	hardDebt    int64
	flowBudget  int64

	tokens int64
	last   time.Time
	flows  [1024]flowState
}

type flowState struct {
	tokens int64
	last   time.Time
}

func NewShaper(cfg ShaperConfig) *Shaper {
	if cfg.TargetLatency <= 0 {
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

func (s *Shaper) Config() ShaperConfig {
	if s == nil {
		return ShaperConfig{}
	}
	return s.cfg
}

func (s *Shaper) Enabled() bool {
	return s != nil && (s.upload != nil || s.download != nil)
}

func (s *Shaper) Stream() *StreamShaper {
	if s == nil || !s.Enabled() {
		return nil
	}
	return &StreamShaper{Shaper: s}
}

func newDirectionShaper(bps int64, target time.Duration) *directionShaper {
	if target <= 0 {
		target = 15 * time.Millisecond
	}
	queueBudget := maxInt64(1500, int64(float64(bps)*target.Seconds()))
	maxBurst := maxInt64(1500, int64(float64(bps)*(50*time.Millisecond).Seconds()))
	flowBudget := maxInt64(1500, queueBudget/8)
	return &directionShaper{
		bps:         bps,
		target:      target,
		maxBurst:    maxBurst,
		queueBudget: queueBudget,
		hardDebt:    queueBudget * 2,
		flowBudget:  flowBudget,
		tokens:      maxBurst,
		last:        time.Now(),
	}
}

func (s *Shaper) ShapeUpload(data []byte, hash uint32) (allowed bool, ecn bool) {
	if s == nil || s.upload == nil {
		return true, false
	}
	return s.upload.shapePacket(int64(len(data)), hash, false)
}

func (s *Shaper) ShapeDownload(data []byte, hash uint32) (allowed bool, ecn bool) {
	if s == nil || s.download == nil {
		return true, false
	}
	return s.download.shapePacket(int64(len(data)), hash, false)
}

func (s *Shaper) ShapeUploadECN(data []byte, hash uint32, ecnCapable bool) (allowed bool, ecn bool) {
	if s == nil || s.upload == nil {
		return true, false
	}
	return s.upload.shapePacket(int64(len(data)), hash, ecnCapable)
}

func (s *Shaper) ShapeDownloadECN(data []byte, hash uint32, ecnCapable bool) (allowed bool, ecn bool) {
	if s == nil || s.download == nil {
		return true, false
	}
	return s.download.shapePacket(int64(len(data)), hash, ecnCapable)
}

func (ds *directionShaper) shapePacket(size int64, hash uint32, ecnCapable bool) (bool, bool) {
	if ds == nil || size <= 0 {
		return true, false
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	now := time.Now()
	ds.refillLocked(now)
	flow := &ds.flows[hash%uint32(len(ds.flows))]
	ds.refillFlowLocked(flow, now)

	projectedGlobal := ds.tokens - size
	projectedFlow := flow.tokens - size
	if projectedFlow < -ds.flowBudget {
		return false, false
	}
	if projectedGlobal < -ds.hardDebt {
		return false, false
	}

	markECN := false
	if projectedGlobal < -ds.queueBudget/2 && ecnCapable {
		markECN = true
	}
	if projectedGlobal < -ds.queueBudget && !markECN {
		return false, false
	}

	ds.tokens = projectedGlobal
	flow.tokens = projectedFlow
	flow.last = now
	return true, markECN
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
	if ds == nil || size <= 0 {
		return nil
	}
	for {
		waitDur := time.Duration(0)

		ds.mu.Lock()
		now := time.Now()
		ds.refillLocked(now)
		if ds.tokens-size >= -ds.queueBudget {
			ds.tokens -= size
			ds.mu.Unlock()
			return nil
		}
		needed := size - (ds.tokens + ds.queueBudget)
		if needed < 1 {
			needed = 1
		}
		waitDur = time.Duration(float64(needed) / float64(ds.bps) * float64(time.Second))
		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}
		if waitDur > 100*time.Millisecond {
			waitDur = 100 * time.Millisecond
		}
		ds.mu.Unlock()

		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (ds *directionShaper) refillLocked(now time.Time) {
	ds.tokens = refillTokenBucket(ds.tokens, ds.bps, ds.last, now, ds.maxBurst)
	ds.last = now
}

func (ds *directionShaper) refillFlowLocked(flow *flowState, now time.Time) {
	if flow.last.IsZero() && flow.tokens == 0 {
		flow.tokens = ds.maxBurst
	}
	flow.tokens = refillTokenBucket(flow.tokens, ds.bps, flow.last, now, ds.maxBurst)
	flow.last = now
}

func refillTokenBucket(tokens, bps int64, last, now time.Time, maxBurst int64) int64 {
	if !last.IsZero() && now.After(last) {
		tokens += int64(float64(bps) * now.Sub(last).Seconds())
	}
	if tokens > maxBurst {
		tokens = maxBurst
	}
	return tokens
}

func HashFlow(src, dst netip.AddrPort) uint32 {
	h := fnv.New32a()
	b1 := src.Addr().AsSlice()
	b2 := dst.Addr().AsSlice()
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

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
