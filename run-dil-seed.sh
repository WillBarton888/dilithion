#!/bin/bash
# Auto-restart wrapper for DIL seed nodes
# Same as run-dilv-seed.sh but for dilithion-node (DIL chain)
#
# Usage: nohup ./run-dil-seed.sh > /root/dil-seed.log 2>&1 &

BINARY="./dilithion-node"
FLAGS="--relay-only --public-api"
LOG="/root/dilithion-node.log"

echo "$(date): DIL seed node wrapper starting"

while true; do
    echo "$(date): Starting $BINARY $FLAGS"
    $BINARY $FLAGS >> "$LOG" 2>&1
    EXIT_CODE=$?

    echo "$(date): Node exited with code $EXIT_CODE"

    if [ -f "$HOME/.dilithion/auto_rebuild" ]; then
        echo "$(date): Auto-rebuild marker detected — node will clean up on restart"
    fi

    echo "$(date): Restarting in 5 seconds..."
    sleep 5
done
