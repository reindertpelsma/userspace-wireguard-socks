#!/bin/bash
set -e
export CGO_ENABLED=0
mkdir -p ./cmd/uwgwrapper/assets
gcc -shared -fPIC -O2 -Wall -Wextra -o ./cmd/uwgwrapper/assets/uwgpreload.so preload/uwgpreload.c -ldl
go test ./...
go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
go build -trimpath -ldflags='-s -w' -o uwgwrapper ./cmd/uwgwrapper
echo "COMPILE SUCCEEDED!. Exported uwgsocks binary and uwgwrapper binary"
