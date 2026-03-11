#!/bin/bash
# Auto-restart wrapper for DilV seed nodes
# Handles BUG #277 auto-rebuild: if the node detects UTXO corruption,
# it writes an auto_rebuild marker and shuts down. This script restarts
# it, and the node's startup code handles the cleanup automatically.
#
# Usage: nohup ./run-dilv-seed.sh > /root/dilv-seed.log 2>&1 &

BINARY="./dilv-node"
FLAGS="--relay-only --public-api"
LOG="/root/dilv-node.log"

echo "$(date): DilV seed node wrapper starting"

while true; do
    echo "$(date): Starting $BINARY $FLAGS"
    $BINARY $FLAGS >> "$LOG" 2>&1
    EXIT_CODE=$?

    echo "$(date): Node exited with code $EXIT_CODE"

    # If auto_rebuild marker exists, the node shut down for recovery
    if [ -f "$HOME/.dilv/auto_rebuild" ]; then
        echo "$(date): Auto-rebuild marker detected — node will clean up on restart"
    fi

    # Brief pause before restart
    echo "$(date): Restarting in 5 seconds..."
    sleep 5
done
