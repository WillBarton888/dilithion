#!/bin/bash
PASSED=0
FAILED=0

echo "====================================="
echo "Dilithion Comprehensive Test Suite"
echo "====================================="

run_test() {
    test_name=
    test_cmd=
    printf "%-40s" ": "
    
    if eval "" > /tmp/test_output.txt 2>&1; then
        PASSED=1
        echo "✅ PASS"
    else
        FAILED=1
        echo "❌ FAIL"
    fi
}

# Phase 1: Unit Tests
run_test "phase1_test" "./phase1_test"
run_test "crypter_tests" "./crypter_tests"
run_test "timestamp_tests" "./timestamp_tests"
run_test "rpc_auth_tests" "./rpc_auth_tests"

# Phase 2: Security Tests  
run_test "tx_validation_tests" "rm -rf .test_utxo_validation && ./tx_validation_tests"
run_test "mining_integration_tests" "./mining_integration_tests"
run_test "wallet_encryption_integration_tests" "./wallet_encryption_integration_tests"

# Phase 3: Integration Tests
run_test "tx_relay_tests" "timeout 30 ./tx_relay_tests"
run_test "net_tests" "./net_tests"
run_test "integration_tests" "timeout 30 ./integration_tests"

# Phase 4: E2E Tests
run_test "miner_tests" "./miner_tests"
run_test "wallet_tests" "timeout 30 ./wallet_tests"
run_test "wallet_persistence_tests" "timeout 30 ./wallet_persistence_tests"
run_test "rpc_tests" "timeout 30 ./rpc_tests"

echo ""
echo "====================================="
echo "Final Results: /14 tests passed"
echo "====================================="
if [  -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
else
    echo "⚠️   test(s) failed"
fi
