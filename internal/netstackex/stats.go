// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package netstackex

// Stats is a small, frozen subset of gVisor's tcpip.Stats. It exists so the
// metrics layer in internal/engine doesn't need to depend on a specific
// gVisor version's stat surface — adding fields here is an explicit choice,
// not a transitive contract.
type Stats struct {
	TCPRetransmits          uint64
	TCPSlowStartRetransmits uint64
	TCPFastRetransmits      uint64
}

// Stats returns a snapshot of selected gVisor netstack counters. Returns nil
// when called on a Net whose stack is not initialised (defensive — should
// not happen in practice for an Engine that has Start()ed successfully).
func (n *Net) Stats() *Stats {
	if n == nil || n.stack == nil {
		return nil
	}
	tcp := n.stack.Stats().TCP
	out := &Stats{}
	if tcp.Retransmits != nil {
		out.TCPRetransmits = tcp.Retransmits.Value()
	}
	if tcp.SlowStartRetransmits != nil {
		out.TCPSlowStartRetransmits = tcp.SlowStartRetransmits.Value()
	}
	if tcp.FastRetransmit != nil {
		out.TCPFastRetransmits = tcp.FastRetransmit.Value()
	}
	return out
}
