#!/bin/bash
#
# Dilithion CLI Wallet - Security Test Suite
# Tests all security validations and protections
#

echo "Dilithion CLI Wallet Security Test Suite"
echo "=========================================="
echo ""

WALLET="./dilithion-wallet"
PASSED=0
FAILED=0

# Test function
test_case() {
    local name="$1"
    local expected="$2"
    shift 2
    
    echo -n "TEST: $name ... "
    
    # Run command and capture exit code
    output=$("$@" 2>&1)
    exit_code=$?
    
    if [ "$expected" = "reject" ] && [ $exit_code -ne 0 ]; then
        echo "PASS (correctly rejected)"
        ((PASSED++))
        return 0
    elif [ "$expected" = "accept" ] && [ $exit_code -eq 0 ]; then
        echo "PASS (correctly accepted)"
        ((PASSED++))
        return 0
    else
        echo "FAIL (expected $expected, got exit code $exit_code)"
        echo "Output: $output"
        ((FAILED++))
        return 1
    fi
}

echo "ADDRESS VALIDATION TESTS"
echo "------------------------"

# Invalid address tests (should reject)
test_case "Reject too short address" reject $WALLET send "DLT" 10
test_case "Reject wrong prefix" reject $WALLET send "ABC1234567890123456789012345678901234567890" 10
test_case "Reject special characters" reject $WALLET send "DLT1@#$%^&*()1234567890123456789012345678" 10
test_case "Reject spaces in address" reject $WALLET send "DLT1 abc 123" 10
test_case "Reject empty address" reject $WALLET send "" 10

echo ""
echo "AMOUNT VALIDATION TESTS"
echo "-----------------------"

# Invalid amount tests (should reject)
test_case "Reject zero amount" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD" 0
test_case "Reject negative amount" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD" -10
test_case "Reject too many decimals" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD" 10.123456789
test_case "Reject non-numeric amount" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD" abc
test_case "Reject excessive amount" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD" 99999999

echo ""
echo "COMMAND INJECTION TESTS"
echo "-----------------------"

# Command injection attempts (should be safely rejected)
test_case "Reject shell command in address" reject $WALLET send 'DLT1";rm -rf /tmp/test;echo"' 10
test_case "Reject backticks in address" reject $WALLET send 'DLT1`whoami`' 10
test_case "Reject dollar expansion" reject $WALLET send 'DLT1$(echo hack)' 10
test_case "Reject JSON injection" reject $WALLET send 'DLT1","amount":0,"exploit":"x' 10

echo ""
echo "ARGUMENT VALIDATION TESTS"
echo "-------------------------"

# Missing arguments (should reject)
test_case "Reject missing address" reject $WALLET send
test_case "Reject missing amount" reject $WALLET send "DLT1abcdefghijklmnopqrstuvwxyz1234567890ABCD"

echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "ALL TESTS PASSED - Security validations working correctly"
    exit 0
else
    echo "SOME TESTS FAILED - Security issues detected"
    exit 1
fi
