// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import "sync/atomic"

// TurnCarrierDropsTotal lives outside the !lite build tag so the engine's
// metrics layer can reference it unconditionally. Lite builds never
// increment it (no TURN carriers exist there), so the gauge stays zero.
var TurnCarrierDropsTotal atomic.Uint64
