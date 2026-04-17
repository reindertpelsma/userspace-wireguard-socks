package uwgshared

import (
	"path/filepath"
	"testing"
)

func TestTableTracksSameFDPerProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.bin")
	table, err := Create(path, 0x1234)
	if err != nil {
		t.Fatalf("create shared table: %v", err)
	}
	defer func() {
		if err := table.Close(true); err != nil {
			t.Fatalf("close shared table: %v", err)
		}
	}()

	table.Update(101, 7, func(entry *TrackedFD) {
		entry.Active = 1
		entry.Kind = KindTCPStream
		entry.BindPort = 1111
	})
	table.Update(202, 7, func(entry *TrackedFD) {
		entry.Active = 1
		entry.Kind = KindUDPListener
		entry.BindPort = 2222
	})

	if got := table.Snapshot(101, 7); got.Kind != KindTCPStream || got.BindPort != 1111 {
		t.Fatalf("unexpected process 101 state: %+v", got)
	}
	if got := table.Snapshot(202, 7); got.Kind != KindUDPListener || got.BindPort != 2222 {
		t.Fatalf("unexpected process 202 state: %+v", got)
	}

	table.CopyProcess(101, 303)
	if got := table.Snapshot(303, 7); got.Kind != KindTCPStream || got.BindPort != 1111 {
		t.Fatalf("unexpected copied state: %+v", got)
	}

	table.Clear(101, 7)
	if got := table.Snapshot(101, 7); got != (TrackedFD{}) {
		t.Fatalf("expected process 101 state to clear, got %+v", got)
	}
	if got := table.Snapshot(202, 7); got.Kind != KindUDPListener || got.BindPort != 2222 {
		t.Fatalf("process 202 state changed after clear: %+v", got)
	}

	table.ClearProcess(303)
	if got := table.Snapshot(303, 7); got != (TrackedFD{}) {
		t.Fatalf("expected copied process to clear, got %+v", got)
	}
}
