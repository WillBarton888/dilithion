#!/bin/bash

echo "=========================================="
echo "Dilithion Comprehensive Test Suite"
echo "=========================================="
echo ""

PASSED=0
FAILED=0
TIMEOUT_COUNT=0

tests=(
    "phase1_test"
    "crypter_tests"
    "timestamp_tests"
    "net_tests"
    "miner_tests"
    "wallet_tests"
    "wallet_persistence_tests"
    "wallet_encryption_integration_tests"
    "tx_validation_tests"
    "tx_relay_tests"
    "rpc_auth_tests"
    "rpc_tests"
    "mining_integration_tests"
    "integration_tests"
)

for test in "${tests[@]}"; do
    echo "Running: $test"
    if timeout 30 ./$test > /tmp/${test}.log 2>&1; then
        echo "  ✅ PASSED"
        ((PASSED++))
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "  ⏱️  TIMEOUT"
            ((TIMEOUT_COUNT++))
        else
            echo "  ❌ FAILED"
            ((FAILED++))
        fi
        # Show last 5 lines of output
        tail -5 /tmp/${test}.log | sed 's/^/     /'
    fi
    echo ""
done

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "✅ Passed:  $PASSED"
echo "❌ Failed:  $FAILED"
echo "⏱️  Timeout: $TIMEOUT_COUNT"
echo "Total:     $((PASSED + FAILED + TIMEOUT_COUNT))"
echo "=========================================="
