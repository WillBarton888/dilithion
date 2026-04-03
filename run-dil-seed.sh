#!/bin/bash
# Auto-restart wrapper for DIL seed nodes
# Same as run-dilv-seed.sh but for dilithion-node (DIL chain)
#
# Usage: nohup ./run-dil-seed.sh > /root/dil-seed.log 2>&1 &

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/dilithion-node"
LOG="/root/node.log"

# Auto-detect external IP for correct seed ID assignment.
# Without this, all seeds default to seedId=0 and attestations fail.
EXTERNAL_IP=$(hostname -I | awk '{print $1}')
FLAGS="--relay-only --public-api --externalip=${EXTERNAL_IP}"

cd "$SCRIPT_DIR" || exit 1

echo "$(date): DIL seed node wrapper starting (dir=$SCRIPT_DIR, externalip=${EXTERNAL_IP})"

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
