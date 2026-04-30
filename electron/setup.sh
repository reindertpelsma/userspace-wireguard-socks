#!/usr/bin/env bash
# Quick setup: install deps and launch dev mode.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Installing npm dependencies..."
npm install

echo ""
echo "Starting uwgsocks-ui in dev mode..."
echo "The app will open once Vite is ready (~5s)."
echo ""
npm run dev
