#!/bin/bash
# Generate network statistics JSON for dilithion.org dashboard
# This script queries the local Dilithion node and outputs network stats

# Configuration
RPC_HOST="localhost"
RPC_PORT="18332"
OUTPUT_FILE="/var/www/html/network-stats.json"
TEMP_FILE="/tmp/network-stats.tmp.json"

# RPC call helper function
rpc_call() {
    local method=$1
    local params=${2:-"[]"}

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"stats-generator\",\"method\":\"$method\",\"params\":$params}" \
        "http://${RPC_HOST}:${RPC_PORT}" 2>/dev/null
}

# Extract result from RPC response
extract_result() {
    echo "$1" | grep -o '"result":[^,}]*' | sed 's/"result"://' | sed 's/"//g'
}

# Get timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Query node for statistics
echo "Querying Dilithion node..."

# Get blockchain info
BLOCKCHAIN_INFO=$(rpc_call "getblockchaininfo" "[]")
BLOCKS=$(echo "$BLOCKCHAIN_INFO" | grep -o '"blocks":[0-9]*' | cut -d':' -f2)
DIFFICULTY=$(echo "$BLOCKCHAIN_INFO" | grep -o '"difficulty":[0-9.]*' | cut -d':' -f2)
BEST_BLOCK_HASH=$(echo "$BLOCKCHAIN_INFO" | grep -o '"bestblockhash":"[^"]*"' | cut -d':' -f2 | tr -d '"')

# Get mining info
MINING_INFO=$(rpc_call "getmininginfo" "[]")
NETWORK_HASHPS=$(echo "$MINING_INFO" | grep -o '"networkhashps":[0-9.]*' | cut -d':' -f2)

# Calculate total supply (simplified - actual calculation done in JavaScript)
# This is approximate: blocks * 50 (not accounting for halvings yet on testnet)
TOTAL_SUPPLY=$((BLOCKS * 50))

# Calculate current block reward (50 DIL on testnet, no halvings yet)
BLOCK_REWARD=50

# Calculate blocks until halving (210,000 block intervals)
HALVING_INTERVAL=210000
BLOCKS_UNTIL_HALVING=$((HALVING_INTERVAL - (BLOCKS % HALVING_INTERVAL)))

# Get network peer count
PEER_INFO=$(rpc_call "getpeerinfo" "[]")
PEER_COUNT=$(echo "$PEER_INFO" | grep -o '"addr"' | wc -l)

# Check if we got valid data
if [ -z "$BLOCKS" ] || [ "$BLOCKS" = "null" ]; then
    echo "Error: Could not fetch blockchain data"
    exit 1
fi

# Generate JSON output
cat > "$TEMP_FILE" << EOF
{
  "timestamp": "$TIMESTAMP",
  "network": "testnet",
  "blockHeight": ${BLOCKS:-0},
  "difficulty": ${DIFFICULTY:-0},
  "networkHashRate": ${NETWORK_HASHPS:-0},
  "totalSupply": ${TOTAL_SUPPLY:-0},
  "blockReward": ${BLOCK_REWARD},
  "blocksUntilHalving": ${BLOCKS_UNTIL_HALVING},
  "peerCount": ${PEER_COUNT:-0},
  "bestBlockHash": "${BEST_BLOCK_HASH:-unknown}",
  "averageBlockTime": 240,
  "status": "live"
}
EOF

# Atomic move to prevent partial reads
mv "$TEMP_FILE" "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"

echo "Network stats updated: $BLOCKS blocks, $PEER_COUNT peers, $(printf "%.2f" $NETWORK_HASHPS) H/s"
