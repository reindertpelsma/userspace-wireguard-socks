#!/bin/sh
set -eu

CONFIG_PATH="${UWG_CONFIG_FILE:-/config/uwgsocks.yaml}"

if [ -n "${UWG_CONFIG_B64:-}" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '%s' "$UWG_CONFIG_B64" | base64 -d >"$CONFIG_PATH"
elif [ -n "${UWG_CONFIG_INLINE:-}" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '%s\n' "$UWG_CONFIG_INLINE" >"$CONFIG_PATH"
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "uwgsocks: expected config at $CONFIG_PATH or set UWG_CONFIG_INLINE/UWG_CONFIG_B64" >&2
  exit 64
fi

exec /app/uwgsocks --config "$CONFIG_PATH" "$@"
