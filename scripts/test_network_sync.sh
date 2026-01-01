#!/bin/bash
#
# Dilithion Network Sync Test
# Tests that all seed nodes are synchronized and running correctly
#
# Usage: ./scripts/test_network_sync.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Seed nodes
SEED_NYC="134.122.4.164"
SEED_SGP="188.166.255.63"
SEED_LDN="209.97.177.197"

# RPC port
RPC_PORT="8545"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

echo ""
echo -e "${BLUE}=== Dilithion Network Sync Test Suite ===${NC}"
echo ""

#######################################
# Helper functions
#######################################

pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

warn() {
    echo -e "  ${YELLOW}WARN${NC}: $1"
}

rpc_call() {
    local host=$1
    local method=$2
    local params=${3:-"[]"}

    curl -s "http://${host}:${RPC_PORT}" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        --connect-timeout 5 \
        --max-time 10 \
        2>/dev/null
}

get_block_count() {
    local host=$1
    local result=$(rpc_call "$host" "getblockcount")
    echo "$result" | grep -o '"result":[0-9]*' | cut -d: -f2
}

get_block_hash() {
    local host=$1
    local height=$2
    local result=$(rpc_call "$host" "getblockhash" "[$height]")
    echo "$result" | grep -o '"result":"[^"]*"' | cut -d'"' -f4
}

check_node_running() {
    local host=$1
    local name=$2

    if ssh -o ConnectTimeout=5 "root@${host}" "pgrep -x dilithion" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

#######################################
# Test 1: Check all nodes are running
#######################################

echo -e "${BLUE}[1/5] Checking Node Status${NC}"

for node in "NYC:${SEED_NYC}" "SGP:${SEED_SGP}" "LDN:${SEED_LDN}"; do
    name="${node%%:*}"
    ip="${node##*:}"

    if check_node_running "$ip" "$name"; then
        pass "$name node is running ($ip)"
    else
        fail "$name node is NOT running ($ip)"
    fi
done

echo ""

#######################################
# Test 2: Check block heights
#######################################

echo -e "${BLUE}[2/5] Checking Block Heights${NC}"

declare -A heights

for node in "NYC:${SEED_NYC}" "SGP:${SEED_SGP}" "LDN:${SEED_LDN}"; do
    name="${node%%:*}"
    ip="${node##*:}"

    height=$(get_block_count "$ip")

    if [ -n "$height" ] && [ "$height" -gt 0 ]; then
        heights[$name]=$height
        pass "$name height: $height"
    else
        fail "$name: Could not get block height"
        heights[$name]=0
    fi
done

echo ""

#######################################
# Test 3: Check heights are in sync
#######################################

echo -e "${BLUE}[3/5] Checking Height Sync${NC}"

max_height=0
min_height=999999999

for name in "${!heights[@]}"; do
    h=${heights[$name]}
    if [ "$h" -gt "$max_height" ]; then
        max_height=$h
    fi
    if [ "$h" -lt "$min_height" ] && [ "$h" -gt 0 ]; then
        min_height=$h
    fi
done

height_diff=$((max_height - min_height))

if [ "$height_diff" -le 2 ]; then
    pass "All nodes within 2 blocks (diff: $height_diff)"
elif [ "$height_diff" -le 10 ]; then
    warn "Nodes are $height_diff blocks apart (syncing?)"
else
    fail "Nodes are $height_diff blocks apart - sync issue!"
fi

echo ""

#######################################
# Test 4: Check block hashes match
#######################################

echo -e "${BLUE}[4/5] Checking Block Hash Consensus${NC}"

# Use minimum height to compare
if [ "$min_height" -gt 0 ]; then
    compare_height=$((min_height - 1))  # Use a confirmed block

    hash_nyc=$(get_block_hash "$SEED_NYC" "$compare_height")
    hash_sgp=$(get_block_hash "$SEED_SGP" "$compare_height")
    hash_ldn=$(get_block_hash "$SEED_LDN" "$compare_height")

    if [ -n "$hash_nyc" ] && [ "$hash_nyc" = "$hash_sgp" ] && [ "$hash_sgp" = "$hash_ldn" ]; then
        pass "Block $compare_height hash matches on all nodes"
        echo "      Hash: ${hash_nyc:0:16}..."
    else
        fail "Block $compare_height hash MISMATCH!"
        echo "      NYC: ${hash_nyc:-MISSING}"
        echo "      SGP: ${hash_sgp:-MISSING}"
        echo "      LDN: ${hash_ldn:-MISSING}"
    fi
else
    fail "Could not compare hashes - no valid heights"
fi

echo ""

#######################################
# Test 5: Check peer connectivity
#######################################

echo -e "${BLUE}[5/5] Checking Peer Connectivity${NC}"

for node in "NYC:${SEED_NYC}" "SGP:${SEED_SGP}" "LDN:${SEED_LDN}"; do
    name="${node%%:*}"
    ip="${node##*:}"

    peer_count=$(ssh -o ConnectTimeout=5 "root@${ip}" \
        "tail -100 /root/node.log | grep -c 'Connected to' 2>/dev/null || echo 0" 2>/dev/null)

    if [ "$peer_count" -gt 0 ]; then
        pass "$name has recent peer connections"
    else
        warn "$name: No recent peer connections in log"
    fi
done

echo ""

#######################################
# Summary
#######################################

echo -e "${BLUE}=== Test Summary ===${NC}"
echo ""

total=$((TESTS_PASSED + TESTS_FAILED))
echo "  Tests passed: ${TESTS_PASSED}/${total}"
echo "  Tests failed: ${TESTS_FAILED}/${total}"

echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
    exit 0
else
    echo -e "${RED}=== SOME TESTS FAILED ===${NC}"
    exit 1
fi
