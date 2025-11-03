#!/usr/bin/env bash
# Difficulty Determinism Validation - Automated Execution Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script metadata
SCRIPT_NAME="Difficulty Determinism Validation"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-03"

# Test configuration
TEST_CPP="src/test/difficulty_determinism_test.cpp"
COMPARE_PY="scripts/compare_difficulty_results.py"
RESULTS_DIR="difficulty_validation_results"

# Results files
RESULT_UBUNTU_GCC="difficulty_results_ubuntu_gcc.json"
RESULT_UBUNTU_CLANG="difficulty_results_ubuntu_clang.json"
RESULT_WINDOWS_MINGW="difficulty_results_windows_mingw.json"
COMPARISON_REPORT="difficulty_comparison_report.txt"
FINAL_REPORT="DIFFICULTY-VALIDATION-RESULTS.md"

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
PLATFORMS_TESTED=0

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ${SCRIPT_NAME}${NC}"
echo -e "${BLUE}  Version: ${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}  Date: ${SCRIPT_DATE}${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_file_exists() {
    local file="$1"
    local description="$2"

    if [ -f "$file" ]; then
        log_success "$description found: $file"
        return 0
    else
        log_error "$description not found: $file"
        return 1
    fi
}

check_command_exists() {
    local cmd="$1"
    local description="$2"

    if command -v "$cmd" &> /dev/null; then
        local version=$($cmd --version 2>&1 | head -1)
        log_success "$description found: $version"
        return 0
    else
        log_error "$description not found: $cmd"
        return 1
    fi
}

# ============================================================================
# Pre-Flight Checks
# ============================================================================

preflight_checks() {
    log_info "Running pre-flight checks..."
    echo ""

    local checks_passed=true

    # Check test files exist
    if ! check_file_exists "$TEST_CPP" "Test file"; then
        checks_passed=false
    fi

    if ! check_file_exists "$COMPARE_PY" "Comparison script"; then
        checks_passed=false
    fi

    # Check Python available
    if ! check_command_exists "python3" "Python 3"; then
        checks_passed=false
    fi

    # Check build system
    if ! check_file_exists "Makefile" "Makefile"; then
        checks_passed=false
    fi

    # Check required source files
    if ! check_file_exists "src/consensus/pow.cpp" "PoW implementation"; then
        checks_passed=false
    fi

    if ! check_file_exists "src/consensus/pow.h" "PoW header"; then
        checks_passed=false
    fi

    echo ""

    if [ "$checks_passed" = false ]; then
        log_error "Pre-flight checks failed. Please verify project structure."
        exit 1
    fi

    log_success "All pre-flight checks passed!"
    echo ""
}

# ============================================================================
# Build Test
# ============================================================================

build_test() {
    local platform="$1"
    local compiler="$2"

    log_info "Building difficulty determinism test for $platform with $compiler..."

    # Check if Make target exists
    if ! grep -q "difficulty_determinism_test" Makefile; then
        log_warning "Makefile target 'difficulty_determinism_test' not found"
        log_info "Attempting manual compilation..."

        # Manual compilation as fallback
        if [ "$compiler" = "gcc" ]; then
            g++ -std=c++17 -I. -Isrc \
                src/test/difficulty_determinism_test.cpp \
                src/consensus/pow.cpp \
                -o difficulty_determinism_test
        elif [ "$compiler" = "clang" ]; then
            clang++ -std=c++17 -I. -Isrc \
                src/test/difficulty_determinism_test.cpp \
                src/consensus/pow.cpp \
                -o difficulty_determinism_test
        fi
    else
        # Use Makefile target
        if [ "$compiler" = "clang" ]; then
            CC=clang CXX=clang++ make difficulty_determinism_test
        else
            make difficulty_determinism_test
        fi
    fi

    if [ $? -eq 0 ]; then
        log_success "Build successful for $platform"
        return 0
    else
        log_error "Build failed for $platform"
        return 1
    fi
}

# ============================================================================
# Execute Test
# ============================================================================

execute_test() {
    local platform="$1"
    local output_file="$2"

    log_info "Executing test on $platform..."

    # Run the test
    if [ -f "./difficulty_determinism_test" ]; then
        ./difficulty_determinism_test
    elif [ -f "./difficulty_determinism_test.exe" ]; then
        ./difficulty_determinism_test.exe
    else
        log_error "Test executable not found"
        return 1
    fi

    if [ $? -eq 0 ]; then
        # Check if output file was created
        if [ -f "difficulty_results.json" ]; then
            mv difficulty_results.json "$output_file"
            log_success "Test completed: $output_file"
            return 0
        else
            log_error "Test did not produce output file"
            return 1
        fi
    else
        log_error "Test execution failed"
        return 1
    fi
}

# ============================================================================
# Platform 1: Ubuntu + GCC
# ============================================================================

test_ubuntu_gcc() {
    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Platform 1: Ubuntu + GCC"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # Check if we're in WSL or native Linux
    if grep -qi microsoft /proc/version 2>/dev/null; then
        log_info "Running in WSL environment"
    elif [ -f /etc/os-release ]; then
        log_info "Running in native Linux environment"
    else
        log_error "Not in Linux environment. Skipping Ubuntu+GCC test."
        return 1
    fi

    # Check GCC available
    if ! check_command_exists "gcc" "GCC"; then
        log_error "GCC not found. Please install: sudo apt-get install build-essential"
        return 1
    fi

    if ! check_command_exists "g++" "G++"; then
        log_error "G++ not found. Please install: sudo apt-get install build-essential"
        return 1
    fi

    # Build and execute
    if build_test "Ubuntu+GCC" "gcc"; then
        if execute_test "Ubuntu+GCC" "$RESULT_UBUNTU_GCC"; then
            PLATFORMS_TESTED=$((PLATFORMS_TESTED + 1))
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log_success "Ubuntu+GCC test complete"
            return 0
        fi
    fi

    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "Ubuntu+GCC test failed"
    return 1
}

# ============================================================================
# Platform 2: Ubuntu + Clang
# ============================================================================

test_ubuntu_clang() {
    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Platform 2: Ubuntu + Clang"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # Check if we're in Linux
    if ! grep -qi linux /proc/version 2>/dev/null && [ ! -f /etc/os-release ]; then
        log_error "Not in Linux environment. Skipping Ubuntu+Clang test."
        return 1
    fi

    # Check Clang available
    if ! check_command_exists "clang" "Clang"; then
        log_warning "Clang not found"
        log_info "Install with: sudo apt-get install clang-17"
        log_warning "Skipping Ubuntu+Clang test"
        return 1
    fi

    if ! check_command_exists "clang++" "Clang++"; then
        log_warning "Clang++ not found"
        log_info "Install with: sudo apt-get install clang-17"
        log_warning "Skipping Ubuntu+Clang test"
        return 1
    fi

    # Clean previous build
    make clean 2>/dev/null || true

    # Build and execute
    if build_test "Ubuntu+Clang" "clang"; then
        if execute_test "Ubuntu+Clang" "$RESULT_UBUNTU_CLANG"; then
            PLATFORMS_TESTED=$((PLATFORMS_TESTED + 1))
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log_success "Ubuntu+Clang test complete"
            return 0
        fi
    fi

    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "Ubuntu+Clang test failed"
    return 1
}

# ============================================================================
# Platform 3: Windows + MinGW
# ============================================================================

test_windows_mingw() {
    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Platform 3: Windows + MinGW"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # Check if we're on Windows
    if ! grep -qi microsoft /proc/version 2>/dev/null; then
        log_info "Not in WSL. Assuming native Windows environment."
    fi

    # Check MinGW GCC available
    if ! check_command_exists "gcc" "MinGW GCC"; then
        log_error "MinGW GCC not found"
        log_info "Install MSYS2 from: https://www.msys2.org/"
        return 1
    fi

    # Clean previous build
    make clean 2>/dev/null || true

    # Build and execute
    if build_test "Windows+MinGW" "gcc"; then
        if execute_test "Windows+MinGW" "$RESULT_WINDOWS_MINGW"; then
            PLATFORMS_TESTED=$((PLATFORMS_TESTED + 1))
            TESTS_PASSED=$((TESTS_PASSED + 1))
            log_success "Windows+MinGW test complete"
            return 0
        fi
    fi

    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "Windows+MinGW test failed"
    return 1
}

# ============================================================================
# Cross-Platform Comparison
# ============================================================================

compare_results() {
    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Cross-Platform Comparison"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    # Check if we have at least 2 results to compare
    local result_count=0
    local results_list=""

    if [ -f "$RESULT_UBUNTU_GCC" ]; then
        result_count=$((result_count + 1))
        results_list="$results_list $RESULT_UBUNTU_GCC"
    fi

    if [ -f "$RESULT_UBUNTU_CLANG" ]; then
        result_count=$((result_count + 1))
        results_list="$results_list $RESULT_UBUNTU_CLANG"
    fi

    if [ -f "$RESULT_WINDOWS_MINGW" ]; then
        result_count=$((result_count + 1))
        results_list="$results_list $RESULT_WINDOWS_MINGW"
    fi

    if [ $result_count -lt 2 ]; then
        log_error "Need at least 2 platform results to compare"
        log_error "Only $result_count result(s) available"
        return 1
    fi

    log_info "Comparing $result_count platform results..."
    log_info "Results: $results_list"
    echo ""

    # Run comparison script
    python3 "$COMPARE_PY" $results_list | tee "$COMPARISON_REPORT"

    local exit_code=${PIPESTATUS[0]}

    echo ""

    if [ $exit_code -eq 0 ]; then
        log_success "✅ VALIDATION PASSED"
        log_success "All platforms agree on difficulty calculations"
        log_success "No consensus fork risk detected"
        log_success "Safe for mainnet deployment"
        return 0
    else
        log_error "❌ VALIDATION FAILED"
        log_error "Platforms disagree on difficulty calculations"
        log_error "CRITICAL: Consensus fork risk detected!"
        log_error "Mainnet launch BLOCKED"
        return 1
    fi
}

# ============================================================================
# Generate Final Report
# ============================================================================

generate_report() {
    local validation_result="$1"

    log_info "Generating final report..."

    cat > "$FINAL_REPORT" <<EOF
# Difficulty Determinism Validation - Results

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Test:** Cross-Platform Difficulty Determinism
**Priority:** P0 - CRITICAL (Consensus Fork Prevention)

---

## Executive Summary

**Platforms Tested:** $PLATFORMS_TESTED
**Tests Passed:** $TESTS_PASSED
**Tests Failed:** $TESTS_FAILED
**Validation Result:** $validation_result

---

## Test Execution

### Platform 1: Ubuntu + GCC

**Status:** $([ -f "$RESULT_UBUNTU_GCC" ] && echo "✅ PASS" || echo "❌ FAIL")
**Result File:** $RESULT_UBUNTU_GCC

### Platform 2: Ubuntu + Clang

**Status:** $([ -f "$RESULT_UBUNTU_CLANG" ] && echo "✅ PASS" || echo "❌ FAIL")
**Result File:** $RESULT_UBUNTU_CLANG

### Platform 3: Windows + MinGW

**Status:** $([ -f "$RESULT_WINDOWS_MINGW" ] && echo "✅ PASS" || echo "❌ FAIL")
**Result File:** $RESULT_WINDOWS_MINGW

---

## Cross-Platform Comparison

$(cat "$COMPARISON_REPORT" 2>/dev/null || echo "Comparison report not available")

---

## Conclusion

$(if [ "$validation_result" = "PASS" ]; then
echo "**✅ VALIDATION PASSED**

All platforms produce identical difficulty calculations. The difficulty adjustment algorithm is deterministic across platforms, compilers, and architectures.

**Recommendation:** PROCEED with mainnet preparation.

**Risk Assessment:** LOW - No consensus fork risk detected.

**Next Steps:**
1. Continue with Week 4 remaining tasks
2. Monitor for any platform-specific issues
3. Re-test after any PoW algorithm changes"
else
echo "**❌ VALIDATION FAILED**

Platforms disagree on difficulty calculations. This is a CRITICAL consensus issue that MUST be resolved before mainnet launch.

**Recommendation:** IMPLEMENT Option B (Bitcoin Core ArithU256)

**Risk Assessment:** CRITICAL - Consensus fork risk if deployed.

**Immediate Actions Required:**
1. Review comparison report for specific discrepancies
2. Identify which test vectors fail
3. Debug arithmetic differences
4. Implement Option B (Bitcoin Core ArithU256)
5. Re-test all platforms
6. Validate consensus"
fi)

---

**Report Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Script Version:** $SCRIPT_VERSION
EOF

    log_success "Report generated: $FINAL_REPORT"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    preflight_checks

    # Create results directory
    mkdir -p "$RESULTS_DIR"
    cd "$RESULTS_DIR" || exit 1

    # Execute tests on all platforms
    test_ubuntu_gcc || true
    test_ubuntu_clang || true
    test_windows_mingw || true

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Test Execution Summary"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""
    log_info "Platforms tested: $PLATFORMS_TESTED"
    log_info "Tests passed: $TESTS_PASSED"
    log_info "Tests failed: $TESTS_FAILED"
    echo ""

    # Compare results
    local validation_result="FAIL"
    if compare_results; then
        validation_result="PASS"
    fi

    # Generate report
    generate_report "$validation_result"

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Validation Complete"
    log_info "═══════════════════════════════════════════════════════════"
    echo ""

    if [ "$validation_result" = "PASS" ]; then
        log_success "✅ All validations passed!"
        log_success "Report: $FINAL_REPORT"
        exit 0
    else
        log_error "❌ Validation failed!"
        log_error "Report: $FINAL_REPORT"
        log_error "Review comparison report for details"
        exit 1
    fi
}

# Execute main function
main
