#!/bin/bash
# Monitor 3-node stress test
# Queries RPC every 60 seconds for 15 minutes

END=$(($(date +%s) + 900))
COUNT=0

echo "=== Starting 15-Minute Monitoring ==="
echo "Start time: $(date)"
echo ""

while [ $(date +%s) -lt $END ]; do
    ELAPSED=$((900 - ($END - $(date +%s))))
    ((COUNT++))

    echo "=== Check #$COUNT - Time: ${ELAPSED}s / 900s ==="
    echo "Timestamp: $(date '+%H:%M:%S')"

    # Query each node
    for PORT in 8445 9445 10445; do
        RESPONSE=$(curl -s http://localhost:$PORT -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}' 2>/dev/null)
        HEIGHT=$(echo "$RESPONSE" | grep -o '"blocks":[0-9]*' | cut -d: -f2)
        PEERS=$(echo "$RESPONSE" | grep -o '"connections":[0-9]*' | cut -d: -f2)
        echo "  Node (RPC $PORT): Height=$HEIGHT, Peers=$PEERS"
    done

    echo ""
    sleep 60
done

echo "=== Monitoring Complete ==="
echo "End time: $(date)"
echo ""
echo "Final status check:"
for PORT in 8445 9445 10445; do
    echo "Node on port $PORT:"
    curl -s http://localhost:$PORT -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}' 2>/dev/null | grep -o '"blocks":[0-9]*\|"connections":[0-9]*' | tr '\n' ' '
    echo ""
done
