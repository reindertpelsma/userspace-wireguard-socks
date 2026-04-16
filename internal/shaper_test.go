// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package internal

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestStreamShaperWaitsWhenBurstBudgetIsConsumed(t *testing.T) {
	shaper := NewShaper(ShaperConfig{
		UploadBps:     4096,
		TargetLatency: 15 * time.Millisecond,
	})
	stream := shaper.Stream()
	if stream == nil {
		t.Fatal("stream shaper was not created")
	}

	if err := stream.WaitUpload(context.Background(), 3000); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := stream.WaitUpload(context.Background(), 3000); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("second upload wait returned too quickly: %v", elapsed)
	}
}

func TestPacketShaperMarksECNBeforeDropping(t *testing.T) {
	shaper := NewShaper(ShaperConfig{
		UploadBps:     4096,
		TargetLatency: 15 * time.Millisecond,
	})

	packet := make([]byte, 2500)
	allowed, marked := shaper.ShapeUploadECN(packet, 1, true)
	if !allowed || !marked {
		t.Fatalf("first oversized packet = allowed %v marked %v, want allow+mark", allowed, marked)
	}
	allowed, marked = shaper.ShapeUploadECN(packet, 1, false)
	if allowed || marked {
		t.Fatalf("second oversized packet = allowed %v marked %v, want drop", allowed, marked)
	}
}

func TestHashFlowIsBidirectional(t *testing.T) {
	a := netip.MustParseAddrPort("100.64.1.2:1234")
	b := netip.MustParseAddrPort("100.64.1.3:4321")
	if got, want := HashFlow(a, b), HashFlow(b, a); got != want {
		t.Fatalf("hash mismatch: %d != %d", got, want)
	}
}
