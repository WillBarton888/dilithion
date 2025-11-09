#!/bin/bash
# Test Suite for Resource Monitor (2025-11-10)
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Validate resource monitor parsing and logic
# Usage: ./test-resource-monitor-2025-11-10.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging
log_test() {
  echo -e "${BLUE}[TEST]${NC} $*"
}

log_pass() {
  echo -e "${GREEN}[PASS]${NC} $*"
  TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
  echo -e "${RED}[FAIL]${NC} $*"
  TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

log_info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

# Test helper: assert equals
assert_equals() {
  local expected="$1"
  local actual="$2"
  local test_name="$3"

  TESTS_RUN=$((TESTS_RUN + 1))

  if [ "$expected" = "$actual" ]; then
    log_pass "$test_name"
    return 0
  else
    log_fail "$test_name: expected '$expected', got '$actual'"
    return 1
  fi
}

# Test helper: assert greater than
assert_gt() {
  local value="$1"
  local threshold="$2"
  local test_name="$3"

  TESTS_RUN=$((TESTS_RUN + 1))

  if [ "$value" -gt "$threshold" ]; then
    log_pass "$test_name"
    return 0
  else
    log_fail "$test_name: expected $value > $threshold"
    return 1
  fi
}

# Test helper: assert regex match
assert_matches() {
  local pattern="$1"
  local text="$2"
  local test_name="$3"

  TESTS_RUN=$((TESTS_RUN + 1))

  if echo "$text" | grep -qE "$pattern"; then
    log_pass "$test_name"
    return 0
  else
    log_fail "$test_name: '$text' doesn't match pattern '$pattern'"
    return 1
  fi
}

# Test: CPU parsing with different formats
test_cpu_parsing() {
  log_test "Testing CPU usage parsing..."

  # Source the functions from the monitor script
  source <(grep -A 30 "^get_cpu_usage()" "$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh" | sed 's/^}/}; return/')

  # Test that get_cpu_usage returns a valid integer
  local cpu
  cpu=$(get_cpu_usage)

  if [[ "$cpu" =~ ^[0-9]+$ ]]; then
    log_pass "CPU parsing returns valid integer: $cpu"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "CPU parsing returned non-integer: $cpu"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Memory parsing
test_memory_parsing() {
  log_test "Testing memory usage parsing..."

  # Source the function
  source <(grep -A 20 "^get_memory_usage_mb()" "$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh" | sed 's/^}/}; return/')

  local mem
  mem=$(get_memory_usage_mb)

  if [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -ge 0 ]; then
    log_pass "Memory parsing returns valid integer: ${mem}MB"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Memory parsing returned invalid value: $mem"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Disk usage parsing
test_disk_parsing() {
  log_test "Testing disk usage parsing..."

  # Source the function
  source <(grep -A 15 "^get_disk_usage()" "$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh" | sed 's/^}/}; return/')

  local disk
  disk=$(get_disk_usage)

  if [[ "$disk" =~ ^[0-9]+$ ]] && [ "$disk" -ge 0 ] && [ "$disk" -le 100 ]; then
    log_pass "Disk parsing returns valid percentage: ${disk}%"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Disk parsing returned invalid value: $disk"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Zombie process detection
test_zombie_detection() {
  log_test "Testing zombie process detection..."

  # Source the function
  source <(grep -A 10 "^check_zombie_processes()" "$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh" | sed 's/^}/}; return/')

  local zombies
  zombies=$(check_zombie_processes)

  if [[ "$zombies" =~ ^[0-9]+$ ]] && [ "$zombies" -ge 0 ]; then
    log_pass "Zombie detection returns valid count: $zombies"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Zombie detection returned invalid value: $zombies"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Script syntax validation
test_script_syntax() {
  log_test "Testing script syntax..."

  local script_path="$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh"

  if bash -n "$script_path" 2>/dev/null; then
    log_pass "Script has valid bash syntax"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Script has syntax errors"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Script permissions
test_script_permissions() {
  log_test "Testing script permissions..."

  local script_path="$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh"

  # Make executable if not already
  chmod +x "$script_path" 2>/dev/null || true

  if [ -x "$script_path" ]; then
    log_pass "Script is executable"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Script is not executable"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Required commands exist
test_required_commands() {
  log_test "Testing required commands..."

  local required_commands=("top" "free" "df" "ps" "find" "awk")
  local missing_commands=()

  for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_commands+=("$cmd")
    fi
  done

  if [ ${#missing_commands[@]} -eq 0 ]; then
    log_pass "All required commands available"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Missing commands: ${missing_commands[*]}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# Test: Short execution test (10 seconds)
test_short_execution() {
  log_test "Testing short execution (10 seconds)..."

  local script_path="$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh"
  local test_log="/tmp/resource-monitor-test-$$.log"

  # Run for 10 seconds
  timeout 10 bash "$script_path" > "$test_log" 2>&1 &
  local pid=$!

  sleep 10
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  # Check log output
  if [ -f "$test_log" ] && grep -q "Resource monitor started" "$test_log"; then
    log_pass "Short execution successful"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))

    # Show sample output
    log_info "Sample output:"
    head -5 "$test_log" | sed 's/^/    /'
  else
    log_fail "Short execution failed"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi

  rm -f "$test_log"
}

# Test: Log format validation
test_log_format() {
  log_test "Testing log format..."

  local script_path="$(dirname "$0")/monitor-fuzzer-resources-2025-11-10.sh"
  local test_log="/tmp/resource-monitor-test-format-$$.log"

  # Run for 5 seconds
  timeout 5 bash "$script_path" > "$test_log" 2>&1 || true

  # Check for proper timestamp format
  if grep -qE '\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]' "$test_log"; then
    log_pass "Log format includes valid timestamps"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Log format missing proper timestamps"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi

  # Check for severity levels
  if grep -qE '\[(INFO|WARN|ERROR)\]' "$test_log"; then
    log_pass "Log format includes severity levels"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    log_fail "Log format missing severity levels"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi

  rm -f "$test_log"
}

# Main test execution
main() {
  echo "================================================"
  echo "Resource Monitor Test Suite (2025-11-10)"
  echo "================================================"
  echo ""

  # Run all tests
  test_script_syntax
  test_script_permissions
  test_required_commands
  test_cpu_parsing
  test_memory_parsing
  test_disk_parsing
  test_zombie_detection
  test_log_format
  test_short_execution

  # Print summary
  echo ""
  echo "================================================"
  echo "Test Summary"
  echo "================================================"
  echo "Total tests run: $TESTS_RUN"
  echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
  echo -e "${RED}Failed: $TESTS_FAILED${NC}"
  echo ""

  if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
  else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
  fi
}

main "$@"
