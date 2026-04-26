#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# run-matrix.sh: drive run-libc-smoke.sh across a libc matrix and
# print a summary table. Designed to populate the compatibility
# claims in docs/compatibility.md.
#
# Usage:
#   run-matrix.sh [image-list-file]
#
# If no list is given, the default matrix below is used. Each line
# of the list file is one image tag (lines starting with # are
# ignored).

set -u
script_dir="$(cd "$(dirname "$0")" && pwd)"
list="${1:-}"
images=()

if [ -n "$list" ] && [ -f "$list" ]; then
  while IFS= read -r line; do
    case "$line" in
      ''|\#*) continue ;;
      *) images+=("$line") ;;
    esac
  done < "$list"
else
  images=(
    ubuntu:18.04
    ubuntu:20.04
    ubuntu:22.04
    ubuntu:24.04
    ubuntu:25.10
    debian:bullseye
    debian:trixie
    alpine:3.10
    alpine:3.16
    alpine:3.20
    alpine:3.22
  )
fi

arch="$(uname -m)"
echo "===== uwgpreload.so libc matrix ($arch) ====="
echo "image                  libc"
echo "---------------------- -----------------------------------"

pass=0
fail=0
for img in "${images[@]}"; do
  if "$script_dir/run-libc-smoke.sh" "$img"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi
done

echo "----- summary: $pass PASS, $fail FAIL ($arch) -----"
exit "$fail"
