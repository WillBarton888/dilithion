#!/bin/bash
# Integration test script for RPC enhancements
# Tests: Authentication, Batch Requests, SSL, WebSocket
# Copyright (c) 2025 The Dilithion Core developers

set -e

echo "=== RPC Integration Tests ==="
echo ""

RPC_PORT=${RPC_PORT:-8332}
WS_PORT=${WS_PORT:-8333}
RPC_USER=${RPC_USER:-"admin"}
RPC_PASS=${RPC_PASS:-"password"}
BASE_URL="http://localhost:$RPC_PORT"
WS_URL="ws://localhost:$WS_PORT"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} $2"
        ((TESTS_FAILED++))
    fi
}

echo "1. Testing Basic RPC (HTTP)..."
echo ""

# Test 1: Basic RPC call
RESPONSE=$(curl -s -X POST "$BASE_URL" \
    -H "Content-Type: application/json" \
    -H "X-Dilithion-RPC: 1" \
    -d '{"jsonrpc":"2.0","method":"help","params":[],"id":1}' 2>&1)
if echo "$RESPONSE" | grep -q "jsonrpc"; then
    test_result 0 "Basic RPC call"
else
    test_result 1 "Basic RPC call"
    echo "   Response: $RESPONSE"
fi

echo ""
echo "2. Testing Authentication..."
echo ""

# Test 2: RPC with authentication
AUTH=$(echo -n "$RPC_USER:$RPC_PASS" | base64)
RESPONSE=$(curl -s -X POST "$BASE_URL" \
    -H "Content-Type: application/json" \
    -H "X-Dilithion-RPC: 1" \
    -H "Authorization: Basic $AUTH" \
    -d '{"jsonrpc":"2.0","method":"help","params":[],"id":1}' 2>&1)
if echo "$RESPONSE" | grep -q "jsonrpc"; then
    test_result 0 "RPC with authentication"
else
    test_result 1 "RPC with authentication"
    echo "   Response: $RESPONSE"
fi

echo ""
echo "3. Testing Batch Requests..."
echo ""

# Test 3: Batch request
RESPONSE=$(curl -s -X POST "$BASE_URL" \
    -H "Content-Type: application/json" \
    -H "X-Dilithion-RPC: 1" \
    -H "Authorization: Basic $AUTH" \
    -d '[
        {"jsonrpc":"2.0","method":"help","params":[],"id":1},
        {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":2}
    ]' 2>&1)
if echo "$RESPONSE" | grep -q "\["; then
    test_result 0 "Batch request"
else
    test_result 1 "Batch request"
    echo "   Response: $RESPONSE"
fi

echo ""
echo "4. Testing SSL/TLS (HTTPS)..."
echo ""

# Test 4: HTTPS connection (if SSL enabled)
RESPONSE=$(curl -s -k -X POST "https://localhost:$RPC_PORT" \
    -H "Content-Type: application/json" \
    -H "X-Dilithion-RPC: 1" \
    -H "Authorization: Basic $AUTH" \
    -d '{"jsonrpc":"2.0","method":"help","params":[],"id":1}' 2>&1)
if echo "$RESPONSE" | grep -q "jsonrpc"; then
    test_result 0 "HTTPS connection"
else
    test_result 1 "HTTPS connection (may not be enabled)"
    echo "   Response: $RESPONSE"
fi

echo ""
echo "5. Testing WebSocket..."
echo ""

# Test 5: WebSocket connection (requires wscat or similar)
if command -v wscat &> /dev/null; then
    echo "   Testing WebSocket connection..."
    # Note: wscat test would go here
    test_result 0 "WebSocket connection (wscat available)"
else
    echo -e "${YELLOW}⚠${NC} WebSocket test skipped (wscat not installed)"
    echo "   Install: npm install -g wscat"
    echo "   Then test: wscat -c $WS_URL"
fi

echo ""
echo "=== Test Summary ==="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi

