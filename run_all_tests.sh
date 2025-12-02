#!/bin/bash
set -u

PASSED=0
FAILED=0

echo "====================================="
echo "Dilithion Comprehensive Test Suite"
echo "====================================="

run_test() {
    local name="$1"
    shift
    local cmd="$*"

    printf "%-40s" "$name"

    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        PASSED=$((PASSED + 1))
        echo "  ✅ PASS"
    else
        FAILED=$((FAILED + 1))
        echo "  ❌ FAIL"
        echo "---- $name output ----"
        cat /tmp/test_output.txt
        echo "----------------------"
    fi
}

# Phase 1: Unit Tests
run_test "phase1_test" ./phase1_test
run_test "crypter_tests" ./crypter_tests
run_test "timestamp_tests" ./timestamp_tests
run_test "rpc_auth_tests" ./rpc_auth_tests

# Phase 2: Security / validation Tests
run_test "tx_validation_tests" "rm -rf .test_utxo_validation && ./tx_validation_tests"
run_test "mining_integration_tests" ./mining_integration_tests
run_test "wallet_encryption_integration_tests" ./wallet_encryption_integration_tests

# Phase 3: Integration Tests
run_test "tx_relay_tests" "timeout 30 ./tx_relay_tests"
run_test "net_tests" ./net_tests
run_test "integration_tests" "timeout 30 ./integration_tests"

# Phase 4: E2E / high-level Tests
run_test "miner_tests" ./miner_tests
run_test "wallet_tests" "timeout 30 ./wallet_tests"
run_test "wallet_persistence_tests" "timeout 30 ./wallet_persistence_tests"
run_test "rpc_tests" "timeout 30 ./rpc_tests"

TOTAL=$((PASSED + FAILED))
echo ""
echo "====================================="
echo "Final Results: $PASSED / $TOTAL tests passed"
echo "====================================="

if [ "$FAILED" -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "⚠️  $FAILED test(s) failed"
    exit 1
fi
