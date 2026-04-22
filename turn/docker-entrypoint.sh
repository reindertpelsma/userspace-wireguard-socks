#!/bin/sh
set -eu

CONFIG_PATH="${TURN_CONFIG_FILE:-/config/turn.yaml}"

if [ -n "${TURN_CONFIG_B64:-}" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '%s' "$TURN_CONFIG_B64" | base64 -d >"$CONFIG_PATH"
elif [ -n "${TURN_CONFIG_INLINE:-}" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  printf '%s\n' "$TURN_CONFIG_INLINE" >"$CONFIG_PATH"
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "turn: expected config at $CONFIG_PATH or set TURN_CONFIG_INLINE/TURN_CONFIG_B64" >&2
  exit 64
fi

exec /app/turn -config "$CONFIG_PATH" "$@"
