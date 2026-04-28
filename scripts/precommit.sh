#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Project pre-commit hook. Designed to run in ≤ 10 seconds so it
# doesn't break the commit-edit-commit flow. Three sequential
# checks; each is fast on its own and bails on first failure:
#
#   1. gofmt     — formatting catches drift before it lands.
#   2. clang-format — same for the C preload sources.
#   3. doc-link sanity — internal markdown links not broken.
#   4. go test -short ./...  — fast unit tests only; medium-
#      expensive tests skip themselves via testing.Short().
#
# Install with:
#
#   ln -sf ../../scripts/precommit.sh .git/hooks/pre-commit
#
# Or invoke explicitly:
#
#   ./scripts/precommit.sh
#
# Bypass once with `git commit --no-verify` if needed.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

failed=0
fail() {
    echo "✗ $1" >&2
    failed=1
}

# 1. gofmt — only check files actually staged for commit, so we
# don't burn time formatting unrelated tree state.
if command -v gofmt >/dev/null; then
    staged_go=$(git diff --cached --name-only --diff-filter=ACMR | grep -E '\.go$' || true)
    if [ -n "$staged_go" ]; then
        unformatted=$(gofmt -l $staged_go 2>/dev/null || true)
        if [ -n "$unformatted" ]; then
            fail "gofmt: the following files need 'gofmt -w':"
            echo "$unformatted" | sed 's/^/    /' >&2
        fi
    fi
fi

# 2. clang-format — same scope. Tolerate clang-format absence in
# environments that don't have it (CI runs the heavier check).
if command -v clang-format >/dev/null; then
    staged_c=$(git diff --cached --name-only --diff-filter=ACMR | grep -E '\.(c|h)$' || true)
    if [ -n "$staged_c" ]; then
        for f in $staged_c; do
            # Don't reformat; just check.
            if ! clang-format --dry-run --Werror "$f" >/dev/null 2>&1; then
                fail "clang-format: $f needs 'clang-format -i'"
            fi
        done
    fi
fi

# 3. Doc-link sanity — every markdown link of the form
#    [...](relative/path.md) must resolve to a real file. Catches
#    typos / stale references introduced by recent renames (we've
#    had a few).
broken_link_check() {
    local broken=0
    while IFS= read -r line; do
        local file="${line%%:*}"
        local rest="${line#*:}"
        # Extract the link target between (...).
        local target
        target=$(echo "$rest" | sed -n 's/.*](\([^)]*\)).*/\1/p')
        if [ -z "$target" ]; then
            continue
        fi
        # Skip absolute URLs and same-page anchors.
        case "$target" in
            "http://"*|"https://"*|"mailto:"*|"#"*) continue ;;
        esac
        # Strip any anchor for resolution.
        local path="${target%%#*}"
        if [ -z "$path" ]; then
            continue
        fi
        local dir; dir=$(dirname "$file")
        if [ ! -e "$dir/$path" ]; then
            fail "doc-link: $file references missing '$target'"
            broken=$((broken+1))
            if [ $broken -ge 5 ]; then
                echo "    ... (more broken links suppressed; fix the above first)" >&2
                return 1
            fi
        fi
    done < <(git ls-files '*.md' | xargs -r grep -nE '\]\([^)]+\.md[^)]*\)' 2>/dev/null || true)
    return 0
}
broken_link_check

# 4. Fast Go unit tests. -short tells expensive tests to skip
# themselves via testing.Short(). The medium-expensive suite runs
# under default `go test ./...`; the heavy chaos / soak / fuzz
# tests run under the release.yml pipeline only (env-flag gated).
if ! go test -short -count=1 -timeout 30s ./... >/tmp/uwgs-precommit-go.log 2>&1; then
    fail "go test -short failed:"
    tail -40 /tmp/uwgs-precommit-go.log >&2
fi

if [ $failed -ne 0 ]; then
    echo >&2
    echo "Pre-commit checks failed. Use 'git commit --no-verify' to bypass." >&2
    exit 1
fi
echo "✓ pre-commit checks passed"
