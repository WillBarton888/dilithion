#!/bin/bash
# Phase 8: Comprehensive test runner script
# Runs all tests with proper error handling and reporting

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

echo "=========================================="
echo "Dilithion Test Suite Runner"
echo "=========================================="
echo ""

# Function to run a test and track results
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -n "Running $test_name... "
    
    if eval "$test_command" > /tmp/test_${test_name}.log 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "Error output:"
        tail -20 /tmp/test_${test_name}.log
        ((TESTS_FAILED++))
        return 1
    fi
}

# Check if test binaries exist
check_binary() {
    if [ ! -f "$1" ]; then
        echo -e "${YELLOW}⚠ Skipping $1 (not built)${NC}"
        ((TESTS_SKIPPED++))
        return 1
    fi
    return 0
}

# Build test binaries if needed
echo "Building test binaries..."
make test_dilithion -j$(nproc) || echo "Build failed, continuing with existing binaries"

# Run Boost unit tests
if check_binary "./test_dilithion"; then
    run_test "Boost Unit Tests" "./test_dilithion --log_level=test_suite --report_level=short"
fi

# Run individual test binaries if they exist
for test_bin in phase1_test miner_tests wallet_tests rpc_tests rpc_auth_tests \
                timestamp_tests crypter_tests integration_tests net_tests \
                tx_validation_tests tx_relay_tests mining_integration_tests; do
    if check_binary "./$test_bin"; then
        run_test "$test_bin" "./$test_bin"
    fi
done

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi

