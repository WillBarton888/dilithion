#!/bin/bash
#########################################################
# SECURITY FIXES VALIDATION TEST SUITE
# Tests all CRITICAL and HIGH priority security fixes
#########################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC} - $test_name"
        [ -n "$details" ] && echo "         $details"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} - $test_name"
        [ -n "$details" ] && echo "         $details"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  DILITHION SECURITY FIXES VALIDATION TEST SUITE${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

#########################################################
# TEST 1: Command Injection Protection (setup-and-start.sh)
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Command Injection Protection${NC}"
echo ""

# Test 1.1: Check for numeric validation
if grep -q 'grep -q.*\^\[0-9\]' setup-and-start.sh; then
    test_result "Command injection validation exists in setup-and-start.sh" "PASS" "Regex pattern found"
else
    test_result "Command injection validation exists in setup-and-start.sh" "FAIL" "Validation code missing"
fi

# Test 1.2: Check for input sanitization
if grep -q 'Invalid Input' setup-and-start.sh && grep -q 'exit 1' setup-and-start.sh; then
    test_result "Input rejection on invalid data" "PASS" "Error handling found"
else
    test_result "Input rejection on invalid data" "FAIL" "No proper error handling"
fi

# Test 1.3: Check Windows batch file
if [ -f "SETUP-AND-START.bat" ]; then
    if grep -q 'valid=0' SETUP-AND-START.bat && grep -q 'for /L' SETUP-AND-START.bat; then
        test_result "Windows command injection validation" "PASS" "Numeric validation loop found"
    else
        test_result "Windows command injection validation" "FAIL" "Validation missing"
    fi
fi

echo ""

#########################################################
# TEST 2: Environment Variable Validation
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Environment Variable Validation${NC}"
echo ""

# Test 2.1: RPC_HOST validation in Linux wallet
if [ -f "dilithion-wallet" ]; then
    if grep -q 'DILITHION_RPC_HOST.*suspicious' dilithion-wallet; then
        test_result "RPC_HOST validation in Linux wallet" "PASS" "Suspicious character check found"
    else
        test_result "RPC_HOST validation in Linux wallet" "FAIL" "No RPC_HOST validation"
    fi

    # Test 2.2: RPC_PORT validation
    if grep -q 'DILITHION_RPC_PORT.*numeric' dilithion-wallet; then
        test_result "RPC_PORT validation in Linux wallet" "PASS" "Numeric check found"
    else
        test_result "RPC_PORT validation in Linux wallet" "FAIL" "No RPC_PORT validation"
    fi

    # Test 2.3: Remote host warning
    if grep -q 'remote RPC host' dilithion-wallet; then
        test_result "Remote RPC host warning" "PASS" "Warning message found"
    else
        test_result "Remote RPC host warning" "FAIL" "No warning for remote hosts"
    fi
fi

# Test 2.4: Windows TEMP validation
if [ -f "dilithion-wallet.bat" ]; then
    if grep -q 'not defined TEMP' dilithion-wallet.bat; then
        test_result "TEMP variable validation (Windows)" "PASS" "TEMP check found"
    else
        test_result "TEMP variable validation (Windows)" "FAIL" "No TEMP validation"
    fi
fi

echo ""

#########################################################
# TEST 3: Binary Existence Checks
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Binary Existence Checks${NC}"
echo ""

# Test 3.1: start-mining.sh binary check
if grep -q '\[ ! -f "dilithion-node" \]' start-mining.sh; then
    test_result "Binary existence check in start-mining.sh" "PASS" "File existence check found"
else
    test_result "Binary existence check in start-mining.sh" "FAIL" "No binary check"
fi

# Test 3.2: Executable check
if grep -q '\[ ! -x "dilithion-node" \]' start-mining.sh; then
    test_result "Binary executable check in start-mining.sh" "PASS" "Executable check found"
else
    test_result "Binary executable check in start-mining.sh" "FAIL" "No executable check"
fi

# Test 3.3: Windows binary check
if [ -f "START-MINING.bat" ]; then
    if grep -q 'not exist.*dilithion-node.exe' START-MINING.bat; then
        test_result "Binary existence check in START-MINING.bat" "PASS" "Binary check found"
    else
        test_result "Binary existence check in START-MINING.bat" "FAIL" "No binary check"
    fi
fi

echo ""

#########################################################
# TEST 4: Temp File Cleanup Handlers
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Temp File Cleanup${NC}"
echo ""

# Test 4.1: Trap handlers
if [ -f "dilithion-wallet" ]; then
    if grep -q 'trap.*cleanup_temp_files.*EXIT' dilithion-wallet; then
        test_result "Temp file cleanup trap (EXIT)" "PASS" "EXIT trap found"
    else
        test_result "Temp file cleanup trap (EXIT)" "FAIL" "No EXIT trap"
    fi

    if grep -q 'trap.*cleanup_temp_files.*INT' dilithion-wallet; then
        test_result "Temp file cleanup trap (INT)" "PASS" "INT trap found"
    else
        test_result "Temp file cleanup trap (INT)" "FAIL" "No INT trap"
    fi

    if grep -q 'trap.*cleanup_temp_files.*TERM' dilithion-wallet; then
        test_result "Temp file cleanup trap (TERM)" "PASS" "TERM trap found"
    else
        test_result "Temp file cleanup trap (TERM)" "FAIL" "No TERM trap"
    fi
fi

echo ""

#########################################################
# TEST 5: Fresh System Compatibility
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Fresh System Compatibility${NC}"
echo ""

# Test 5.1: curl detection
if grep -q 'command -v curl' start-mining.sh; then
    test_result "curl detection in start-mining.sh" "PASS" "curl check found"
else
    test_result "curl detection in start-mining.sh" "FAIL" "No curl detection"
fi

# Test 5.2: Platform-specific instructions
if grep -q 'apt-get install curl' start-mining.sh; then
    test_result "Debian/Ubuntu curl install instructions" "PASS" "apt-get instructions found"
else
    test_result "Debian/Ubuntu curl install instructions" "FAIL" "No Debian instructions"
fi

if grep -q 'dnf install curl' start-mining.sh; then
    test_result "Fedora curl install instructions" "PASS" "dnf instructions found"
else
    test_result "Fedora curl install instructions" "FAIL" "No Fedora instructions"
fi

# Test 5.3: Homebrew pre-check
if grep -q 'command -v brew' start-mining.sh; then
    test_result "Homebrew pre-check (macOS)" "PASS" "Homebrew check found"
else
    test_result "Homebrew pre-check (macOS)" "FAIL" "No Homebrew check"
fi

# Test 5.4: ldconfig fallback for Alpine
if grep -q 'LEVELDB_FOUND' start-mining.sh; then
    test_result "ldconfig fallback detection" "PASS" "Fallback mechanism found"
else
    test_result "ldconfig fallback detection" "FAIL" "No fallback mechanism"
fi

# Test 5.5: ldconfig permission fix
if grep -q 'ldconfig -p 2>/dev/null' start-mining.sh; then
    test_result "ldconfig permission error suppression" "PASS" "2>/dev/null found"
else
    test_result "ldconfig permission error suppression" "FAIL" "Errors not suppressed"
fi

if grep -q 'ldconfig -p 2>/dev/null' setup-and-start.sh; then
    test_result "ldconfig fix in setup-and-start.sh" "PASS" "2>/dev/null found"
else
    test_result "ldconfig fix in setup-and-start.sh" "FAIL" "Errors not suppressed"
fi

echo ""

#########################################################
# TEST 6: Error Message Quality
#########################################################
echo -e "${YELLOW}TEST CATEGORY: Error Message Quality${NC}"
echo ""

# Test 6.1: Discord support links
if grep -q 'discord.gg/dilithion' start-mining.sh; then
    test_result "Discord support link in errors" "PASS" "Discord link found"
else
    test_result "Discord support link in errors" "FAIL" "No support link"
fi

# Test 6.2: Clear error messages
if grep -q 'Current directory' start-mining.sh; then
    test_result "Helpful context in error messages" "PASS" "Current directory shown"
else
    test_result "Helpful context in error messages" "FAIL" "No context provided"
fi

echo ""

#########################################################
# SUMMARY
#########################################################
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  TEST RESULTS SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total Tests:  ${BLUE}$TESTS_TOTAL${NC}"
echo -e "Passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

PASS_RATE=$((TESTS_PASSED * 100 / TESTS_TOTAL))
echo -e "Pass Rate:    ${BLUE}${PASS_RATE}%${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    echo -e "${GREEN}Security and compatibility fixes validated successfully!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ SOME TESTS FAILED${NC}"
    echo -e "${YELLOW}Review failed tests above and fix issues.${NC}"
    exit 1
fi
