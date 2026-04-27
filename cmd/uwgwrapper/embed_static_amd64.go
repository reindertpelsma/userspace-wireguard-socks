// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package main

import _ "embed"

//go:embed assets/uwgpreload-static-amd64.so
var embeddedStaticBlobAMD64 []byte

func pickEmbeddedStaticBlob() []byte { return embeddedStaticBlobAMD64 }
