#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SOURCE_LOG="/var/log/open5gs/amf.log"
DEST_LOG="$PROJECT_ROOT/logging/raw_logs/amf.log"

echo "======================================"
echo "      Collecting Open5GS Logs"
echo "======================================"

mkdir -p "$(dirname "$DEST_LOG")"

sudo cp "$SOURCE_LOG" "$DEST_LOG"
sudo chown "$USER:$USER" "$DEST_LOG"

echo "[OK] Log copied successfully."
echo "$DEST_LOG"