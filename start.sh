#!/bin/sh
set -e

echo "[start] Starting checker in background..."
python3 /app/checker.py &

echo "[start] Starting nginx..."
nginx -g "daemon off;"
