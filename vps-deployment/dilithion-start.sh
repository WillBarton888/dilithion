#!/bin/bash
# Dilithion Node Startup Wrapper
# Handles cleanup and ensures clean start every time

set -e

DATADIR="/root/.dilithion-testnet"
NODE_BIN="/root/dilithion/dilithion-node"
LOCK_FILE="$DATADIR/blocks/LOCK"
PORT=18444

echo "========================================"
echo "Dilithion Node Startup Wrapper"
echo "========================================"

# Step 1: Kill any existing dilithion processes
echo "[1/5] Checking for existing processes..."
if pgrep -x "dilithion-node" > /dev/null; then
    echo "  Found existing processes, killing..."
    killall -9 dilithion-node 2>/dev/null || true
    sleep 2
else
    echo "  No existing processes found"
fi

# Step 2: Check if port is still in use
echo "[2/5] Checking port $PORT..."
if ss -tlnp | grep -q ":$PORT "; then
    echo "  Port $PORT still in use, finding and killing process..."
    PORT_PID=$(ss -tlnp | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$PORT_PID" ]; then
        kill -9 $PORT_PID 2>/dev/null || true
        sleep 2
    fi
fi
echo "  Port $PORT is available"

# Step 3: Clean up lock file
echo "[3/5] Cleaning up lock file..."
if [ -f "$LOCK_FILE" ]; then
    rm -f "$LOCK_FILE"
    echo "  Removed stale lock file"
else
    echo "  No lock file to clean"
fi

# Step 4: Ensure data directory exists
echo "[4/5] Verifying data directory..."
mkdir -p "$DATADIR/blocks"
echo "  Data directory ready"

# Step 5: Start the node
echo "[5/5] Starting Dilithion node..."
echo "========================================"

exec "$NODE_BIN" --testnet --datadir="$DATADIR" --port=18444 --rpcport=18332
