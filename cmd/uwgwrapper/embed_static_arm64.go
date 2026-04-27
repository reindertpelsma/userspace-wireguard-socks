// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && arm64

package main

import _ "embed"

//go:embed assets/uwgpreload-static-arm64.so
var embeddedStaticBlobARM64 []byte

func pickEmbeddedStaticBlob() []byte { return embeddedStaticBlobARM64 }
