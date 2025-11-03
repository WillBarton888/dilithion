#!/bin/bash
# Robust Network Statistics Generator
# Retries RPC calls and handles failures gracefully

RPC_HOST="localhost"
RPC_PORT="18332"
OUTPUT_FILE="/var/www/html/network-stats.json"
TEMP_FILE="/tmp/network-stats.tmp.json"
MAX_RETRIES=3
RETRY_DELAY=2

# RPC call with retry logic
rpc_call() {
    local method=$1
    local retries=0

    while [ $retries -lt $MAX_RETRIES ]; do
        local response=$(curl -s -m 5 -X POST \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"id\":\"stats\",\"method\":\"$method\",\"params\":[]}" \
            "http://${RPC_HOST}:${RPC_PORT}" 2>/dev/null)

        # Check if we got a valid response (not empty and contains "result")
        if echo "$response" | grep -q '"result"'; then
            echo "$response"
            return 0
        fi

        retries=$((retries + 1))
        if [ $retries -lt $MAX_RETRIES ]; then
            sleep $RETRY_DELAY
        fi
    done

    return 1
}

# Main execution
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Try to fetch blockchain info with retries
BLOCKCHAIN_INFO=$(rpc_call "getblockchaininfo")

if [ $? -ne 0 ] || [ -z "$BLOCKCHAIN_INFO" ]; then
    # RPC not available - create placeholder stats
    cat > "$TEMP_FILE" << EOF
{
  "timestamp": "$TIMESTAMP",
  "network": "testnet",
  "blockHeight": 0,
  "difficulty": 0,
  "networkHashRate": 0,
  "totalSupply": 0,
  "blockReward": 50,
  "blocksUntilHalving": 210000,
  "peerCount": 0,
  "averageBlockTime": 240,
  "status": "starting"
}
EOF
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    chmod 644 "$OUTPUT_FILE"
    exit 0
fi

# Extract data
BLOCKS=$(echo "$BLOCKCHAIN_INFO" | grep -o '"blocks":[0-9]*' | cut -d':' -f2)
DIFFICULTY=$(echo "$BLOCKCHAIN_INFO" | grep -o '"difficulty":[0-9.]*' | cut -d':' -f2)

# Get mining info (optional, may fail)
MINING_INFO=$(rpc_call "getmininginfo")
if [ $? -eq 0 ]; then
    NETWORK_HASHPS=$(echo "$MINING_INFO" | grep -o '"networkhashps":[0-9.]*' | cut -d':' -f2)
else
    NETWORK_HASHPS=0
fi

# Get peer info (optional, may fail)
PEER_INFO=$(rpc_call "getpeerinfo")
if [ $? -eq 0 ]; then
    PEER_COUNT=$(echo "$PEER_INFO" | grep -o '"addr"' | wc -l)
else
    PEER_COUNT=0
fi

# Calculate supply and halving
TOTAL_SUPPLY=$((BLOCKS * 50))
BLOCK_REWARD=50
HALVING_INTERVAL=210000
BLOCKS_UNTIL_HALVING=$((HALVING_INTERVAL - (BLOCKS % HALVING_INTERVAL)))

# Generate JSON
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
  "averageBlockTime": 240,
  "status": "live"
}
EOF

# Atomic move
mv "$TEMP_FILE" "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"
