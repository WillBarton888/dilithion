#!/bin/bash
# Dilithion Seed Node Restart Script
# Cleanly restarts a seed node with proper cleanup

set -e

NODE_DIR="/root/dilithion"
DATA_DIR="/root/.dilithion-testnet"

echo "======================================="
echo "Dilithion Seed Node Restart"
echo "======================================="
echo "Time: $(date)"
echo ""

# Step 1: Kill any running dilithion-node processes
echo "[1/5] Killing existing processes..."
pkill -9 dilithion-node 2>/dev/null || echo "  No processes to kill"
sleep 3

# Step 2: Remove stale lock files and blockchain data
echo "[2/5] Cleaning blockchain data..."
rm -rf "$DATA_DIR" 2>/dev/null || true
rm -rf "$NODE_DIR/.dilithion-testnet" 2>/dev/null || true
find "$NODE_DIR" -name 'LOCK' -path '*dilithion-testnet*' -delete 2>/dev/null || true

# Step 3: Verify cleanup
echo "[3/5] Verifying cleanup..."
if ps aux | grep -v grep | grep dilithion-node; then
    echo "  ERROR: Processes still running!"
    exit 1
fi
echo "  Clean ✓"

# Step 4: Start node with autostart feature
echo "[4/5] Starting node..."
cd "$NODE_DIR"
nohup ./dilithion-node > node.log 2>&1 &
NODE_PID=$!
echo "  Started with PID: $NODE_PID"

# Step 5: Wait and verify startup
echo "[5/5] Waiting for startup (30s)..."
sleep 30

if ps -p $NODE_PID > /dev/null; then
    echo ""
    echo "✓ Node started successfully!"
    echo "  PID: $NODE_PID"
    echo "  Log: $NODE_DIR/node.log"
    echo ""
    echo "Recent log:"
    tail -20 "$NODE_DIR/node.log"
else
    echo ""
    echo "✗ Node failed to start!"
    echo "Check log: $NODE_DIR/node.log"
    exit 1
fi
