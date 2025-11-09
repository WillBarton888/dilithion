#!/bin/bash
# Dilithion Single Crash Analyzer
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Analyze a single crash file in detail
# Usage: ./analyze-crash-2025-11-10.sh <crash_file>
# Date: 2025-11-10

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Usage
usage() {
  cat <<EOF
Dilithion Single Crash Analyzer

Usage: $0 <crash_file>

Arguments:
  crash_file    Path to crash file to analyze

Options:
  -h, --help    Show this help message
  -j, --json    Output in JSON format

Examples:
  $0 crash-abc123
  $0 --json crash-def456 > crash-analysis.json

EOF
  exit 1
}

# Extract crash type
extract_crash_type() {
  local crash_file="$1"

  if grep -q "heap-use-after-free" "$crash_file" 2>/dev/null; then
    echo "heap-use-after-free"
  elif grep -q "heap-buffer-overflow" "$crash_file" 2>/dev/null; then
    echo "heap-buffer-overflow"
  elif grep -q "stack-buffer-overflow" "$crash_file" 2>/dev/null; then
    echo "stack-buffer-overflow"
  elif grep -q "stack-use-after-scope" "$crash_file" 2>/dev/null; then
    echo "stack-use-after-scope"
  elif grep -q "global-buffer-overflow" "$crash_file" 2>/dev/null; then
    echo "global-buffer-overflow"
  elif grep -q "use-after-poison" "$crash_file" 2>/dev/null; then
    echo "use-after-poison"
  elif grep -q "double-free" "$crash_file" 2>/dev/null; then
    echo "double-free"
  elif grep -q "LeakSanitizer" "$crash_file" 2>/dev/null; then
    echo "memory-leak"
  elif grep -q "TIMEOUT" "$crash_file" 2>/dev/null; then
    echo "timeout"
  elif grep -q "out-of-memory" "$crash_file" 2>/dev/null; then
    echo "out-of-memory"
  elif grep -q "Assertion.*failed" "$crash_file" 2>/dev/null; then
    echo "assertion-failure"
  elif grep -q "SEGV" "$crash_file" 2>/dev/null; then
    echo "segmentation-fault"
  elif grep -q "ABRT" "$crash_file" 2>/dev/null; then
    echo "abort"
  else
    echo "unknown"
  fi
}

# Extract crash location (file:line)
extract_crash_location() {
  local crash_file="$1"

  # Try to extract from ASAN output
  local location
  location=$(grep -oP '(?<= )[a-zA-Z0-9_./]+\.[ch]pp?:[0-9]+' "$crash_file" 2>/dev/null | head -1)

  if [ -z "$location" ]; then
    location="unknown"
  fi

  echo "$location"
}

# Extract stack trace
extract_stack_trace() {
  local crash_file="$1"

  # Extract lines starting with "#" (stack frames)
  grep -E "^    #[0-9]+ " "$crash_file" 2>/dev/null | head -10 || echo "No stack trace found"
}

# Extract function name from top of stack
extract_function_name() {
  local crash_file="$1"

  local function
  function=$(grep -E "^    #0 " "$crash_file" 2>/dev/null | head -1 | awk '{print $3}' | sed 's/+.*//' | sed 's/(.*)//')

  if [ -z "$function" ]; then
    function="unknown"
  fi

  echo "$function"
}

# Determine crash severity
determine_severity() {
  local crash_type="$1"

  case "$crash_type" in
    heap-use-after-free|stack-use-after-scope|double-free)
      echo "CRITICAL"
      ;;
    heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow)
      echo "HIGH"
      ;;
    use-after-poison|assertion-failure|segmentation-fault|abort)
      echo "HIGH"
      ;;
    memory-leak)
      echo "MEDIUM"
      ;;
    timeout|out-of-memory)
      echo "LOW"
      ;;
    *)
      echo "UNKNOWN"
      ;;
  esac
}

# Generate reproduction script
generate_reproduction_script() {
  local crash_file="$1"
  local fuzzer_name="$2"
  local output_file="${crash_file}.reproduce.sh"

  cat > "$output_file" <<EOF
#!/bin/bash
# Crash Reproduction Script
# Generated: $(date)
# Crash file: $crash_file

set -ex

# Run fuzzer with crash input
if [ ! -f "$crash_file" ]; then
  echo "Error: Crash file not found: $crash_file"
  exit 1
fi

# Run with AddressSanitizer
echo "Running fuzzer with crash input..."
./$fuzzer_name "$crash_file"

# If fuzzer doesn't crash, try with GDB
echo "Running with GDB for stack trace..."
gdb --batch --ex run --ex bt --ex quit --args ./$fuzzer_name "$crash_file"
EOF

  chmod +x "$output_file"
  echo "$output_file"
}

# Generate JSON output
generate_json() {
  local crash_file="$1"
  local crash_type="$2"
  local severity="$3"
  local location="$4"
  local function_name="$5"

  cat <<EOF
{
  "crash_file": "$crash_file",
  "analysis_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "crash_type": "$crash_type",
  "severity": "$severity",
  "location": "$location",
  "function": "$function_name",
  "file_size": $(stat -c%s "$crash_file" 2>/dev/null || echo 0),
  "stack_trace": $(extract_stack_trace "$crash_file" | jq -Rs 'split("\n")' 2>/dev/null || echo '[]')
}
EOF
}

# Main analysis function
analyze_crash() {
  local crash_file="$1"
  local json_output="${2:-false}"

  if [ ! -f "$crash_file" ]; then
    log_error "Crash file not found: $crash_file"
    exit 1
  fi

  # Extract crash information
  local crash_type
  crash_type=$(extract_crash_type "$crash_file")

  local severity
  severity=$(determine_severity "$crash_type")

  local location
  location=$(extract_crash_location "$crash_file")

  local function_name
  function_name=$(extract_function_name "$crash_file")

  local fuzzer_name
  fuzzer_name=$(basename "$crash_file" | sed 's/crash-.*/fuzz_unknown/')

  # Output format
  if [ "$json_output" = "true" ]; then
    generate_json "$crash_file" "$crash_type" "$severity" "$location" "$function_name"
  else
    echo ""
    log_info "==================================="
    log_info "Crash Analysis Report"
    log_info "==================================="
    echo ""
    echo "  Crash File:    $crash_file"
    echo "  Crash Type:    $crash_type"
    echo "  Severity:      $severity"
    echo "  Location:      $location"
    echo "  Function:      $function_name"
    echo "  File Size:     $(stat -c%s "$crash_file" 2>/dev/null || echo 0) bytes"
    echo ""
    log_info "Stack Trace:"
    echo ""
    extract_stack_trace "$crash_file" | sed 's/^/  /'
    echo ""

    # Generate reproduction script
    local repro_script
    repro_script=$(generate_reproduction_script "$crash_file" "$fuzzer_name")
    log_success "Reproduction script generated: $repro_script"
  fi
}

# Main execution
main() {
  local json_output=false

  if [ $# -lt 1 ]; then
    log_error "Missing crash file argument"
    usage
  fi

  # Parse arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        ;;
      -j|--json)
        json_output=true
        shift
        ;;
      *)
        crash_file="$1"
        shift
        ;;
    esac
  done

  if [ -z "${crash_file:-}" ]; then
    log_error "No crash file specified"
    usage
  fi

  analyze_crash "$crash_file" "$json_output"
}

main "$@"
