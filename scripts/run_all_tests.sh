#!/bin/bash
#
# Dilithion v1.3.9 Comprehensive Test Suite
#
# This script runs all tests for the v1.3.9 release including:
# - Network sync verification
# - Solo mining prevention tests
# - Unit tests (if available)
# - Build verification
#
# Usage: ./scripts/run_all_tests.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Dilithion v1.3.9 Comprehensive Test Suite                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

run_test() {
    local name="$1"
    local script="$2"
    local timeout="${3:-300}"

    ((TOTAL_TESTS++))
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Running: ${name}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if timeout "$timeout" bash "$script" 2>&1; then
        echo ""
        echo -e "${GREEN}✓ ${name}: PASSED${NC}"
        ((PASSED_TESTS++))
        return 0
    else
        echo ""
        echo -e "${RED}✗ ${name}: FAILED${NC}"
        ((FAILED_TESTS++))
        return 1
    fi
}

# ============================================================================
# Test 1: Build Verification
# ============================================================================

echo -e "${BLUE}[1/5] Build Verification${NC}"
echo ""

cd "$PROJECT_DIR"

if [ -f "./dilithion-node" ] || [ -f "./dilithion-node.exe" ]; then
    echo -e "  ${GREEN}✓${NC} dilithion-node binary exists"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} dilithion-node binary not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

if [ -f "./genesis_gen" ] || [ -f "./genesis_gen.exe" ]; then
    echo -e "  ${GREEN}✓${NC} genesis_gen binary exists"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} genesis_gen binary not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

if [ -f "./check-wallet-balance" ] || [ -f "./check-wallet-balance.exe" ]; then
    echo -e "  ${GREEN}✓${NC} check-wallet-balance binary exists"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} check-wallet-balance binary not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

echo ""

# ============================================================================
# Test 2: Network Sync Test
# ============================================================================

echo -e "${BLUE}[2/5] Network Sync Test${NC}"
echo ""

if [ -f "$SCRIPT_DIR/test_network_sync.sh" ]; then
    if bash "$SCRIPT_DIR/test_network_sync.sh"; then
        echo -e "  ${GREEN}✓${NC} Network sync test passed"
        ((PASSED_TESTS++))
    else
        echo -e "  ${RED}✗${NC} Network sync test failed"
        ((FAILED_TESTS++))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} test_network_sync.sh not found, skipping"
fi
((TOTAL_TESTS++))

echo ""

# ============================================================================
# Test 3: Solo Mining Prevention Test
# ============================================================================

echo -e "${BLUE}[3/5] Solo Mining Prevention Test${NC}"
echo ""

if [ -f "$SCRIPT_DIR/test_solo_mining.sh" ]; then
    if bash "$SCRIPT_DIR/test_solo_mining.sh" --quick; then
        echo -e "  ${GREEN}✓${NC} Solo mining prevention test passed"
        ((PASSED_TESTS++))
    else
        echo -e "  ${RED}✗${NC} Solo mining prevention test failed"
        ((FAILED_TESTS++))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} test_solo_mining.sh not found, skipping"
fi
((TOTAL_TESTS++))

echo ""

# ============================================================================
# Test 4: Source Code Verification
# ============================================================================

echo -e "${BLUE}[4/5] Source Code Verification${NC}"
echo ""

# Check for callback pattern
if grep -q "ChainTipUpdateCallback" "$PROJECT_DIR/src/node/block_processing.h" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} ChainTipUpdateCallback defined in block_processing.h"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} ChainTipUpdateCallback not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Check for SetChainTipUpdateCallback
if grep -q "SetChainTipUpdateCallback" "$PROJECT_DIR/src/node/block_processing.cpp" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} SetChainTipUpdateCallback implemented in block_processing.cpp"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} SetChainTipUpdateCallback not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Check for solo mining prevention
if grep -q "SOLO_MINING_GRACE_PERIOD_SECONDS" "$PROJECT_DIR/src/node/dilithion-node.cpp" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Solo mining grace period constant defined"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} Solo mining grace period constant not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

# Check for compact blocks
if grep -q "CBlockHeaderAndShortTxIDs" "$PROJECT_DIR/src/net/blockencodings.h" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} BIP 152 compact blocks implemented"
    ((PASSED_TESTS++))
else
    echo -e "  ${RED}✗${NC} Compact blocks not found"
    ((FAILED_TESTS++))
fi
((TOTAL_TESTS++))

echo ""

# ============================================================================
# Test 5: Seed Node Status (Live)
# ============================================================================

echo -e "${BLUE}[5/5] Seed Node Status (Live)${NC}"
echo ""

SEED_NYC="134.122.4.164"
SEED_SGP="188.166.255.63"
SEED_LDN="209.97.177.197"

for node in "NYC:${SEED_NYC}" "SGP:${SEED_SGP}" "LDN:${SEED_LDN}"; do
    name="${node%%:*}"
    ip="${node##*:}"

    if ssh -o ConnectTimeout=5 -o BatchMode=yes "root@${ip}" "pgrep -x dilithion" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} ${name} seed node is running (${ip})"
        ((PASSED_TESTS++))
    else
        echo -e "  ${RED}✗${NC} ${name} seed node not running or unreachable (${ip})"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
done

echo ""

# ============================================================================
# Summary
# ============================================================================

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     TEST SUMMARY                             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Total tests:  ${TOTAL_TESTS}"
echo -e "  ${GREEN}Passed:${NC}       ${PASSED_TESTS}"
echo -e "  ${RED}Failed:${NC}       ${FAILED_TESTS}"
echo ""

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  ALL TESTS PASSED                            ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║               SOME TESTS FAILED                              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
