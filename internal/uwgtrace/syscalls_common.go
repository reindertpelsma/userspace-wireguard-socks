// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package uwgtrace

func syscallInSet(nr int64, set []uint32) bool {
	if nr < 0 {
		return false
	}
	for _, candidate := range set {
		if int64(candidate) == nr {
			return true
		}
	}
	return false
}
