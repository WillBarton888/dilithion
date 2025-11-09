#!/bin/bash
# Dilithion Daily Health Check
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Automated daily health monitoring for all production nodes
# Usage: ./daily-health-check-2025-11-10.sh [--slack-webhook URL]
# Date: 2025-11-10

set -euo pipefail

# Production nodes
declare -A NODES
NODES[singapore]="188.166.255.63"
NODES[nyc]="134.122.4.164"
NODES[london]="209.97.177.197"

# Expected fuzzers per node
declare -A EXPECTED_FUZZERS
EXPECTED_FUZZERS[singapore]="fuzz_difficulty"
EXPECTED_FUZZERS[nyc]="fuzz_transaction"
EXPECTED_FUZZERS[london]="fuzz_sha3"

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

# Configuration
SLACK_WEBHOOK=""
HEALTH_STATUS="HEALTHY"
ISSUES_FOUND=0
REPORT_FILE="/tmp/dilithion-health-$(date +%Y%m%d-%H%M%S).txt"

# Parse arguments
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --slack-webhook)
        SLACK_WEBHOOK="$2"
        shift 2
        ;;
      *)
        log_error "Unknown option: $1"
        exit 1
        ;;
    esac
  done
}

# Start health report
start_report() {
  cat > "$REPORT_FILE" <<EOF
======================================================
Dilithion Testnet - Daily Health Check
======================================================
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Report ID: $(basename "$REPORT_FILE")

EOF
}

# Check node connectivity
check_node_connectivity() {
  local node_name="$1"
  local node_ip="$2"

  log_info "Checking connectivity: $node_name ($node_ip)..."

  if ssh -o ConnectTimeout=5 -o BatchMode=yes root@"$node_ip" "echo 'OK'" >/dev/null 2>&1; then
    log_success "✓ $node_name - Connected"
    echo "✓ $node_name ($node_ip): Connected" >> "$REPORT_FILE"
    return 0
  else
    log_error "✗ $node_name - Connection FAILED"
    echo "✗ $node_name ($node_ip): CONNECTION FAILED" >> "$REPORT_FILE"
    HEALTH_STATUS="DEGRADED"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  fi
}

# Check fuzzer status
check_fuzzer_status() {
  local node_name="$1"
  local node_ip="$2"
  local expected_fuzzer="$3"

  log_info "Checking fuzzer: $expected_fuzzer on $node_name..."

  local fuzzer_ps
  fuzzer_ps=$(ssh root@"$node_ip" "ps aux | grep '$expected_fuzzer' | grep -v grep" 2>/dev/null || echo "")

  if [ -n "$fuzzer_ps" ]; then
    # Extract runtime and CPU usage
    local runtime
    runtime=$(echo "$fuzzer_ps" | awk '{print $10}')
    local cpu
    cpu=$(echo "$fuzzer_ps" | awk '{print $3}')
    local mem
    mem=$(echo "$fuzzer_ps" | awk '{print $6}')

    log_success "✓ $expected_fuzzer - Running (CPU: ${cpu}%, MEM: ${mem}KB, Time: ${runtime})"
    echo "✓ $expected_fuzzer on $node_name: Running" >> "$REPORT_FILE"
    echo "  - CPU: ${cpu}%" >> "$REPORT_FILE"
    echo "  - Memory: ${mem}KB" >> "$REPORT_FILE"
    echo "  - Runtime: ${runtime}" >> "$REPORT_FILE"
    return 0
  else
    log_error "✗ $expected_fuzzer - NOT RUNNING"
    echo "✗ $expected_fuzzer on $node_name: NOT RUNNING" >> "$REPORT_FILE"
    HEALTH_STATUS="CRITICAL"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  fi
}

# Check for crashes
check_for_crashes() {
  local node_name="$1"
  local node_ip="$2"

  log_info "Checking for crashes on $node_name..."

  local crash_count
  crash_count=$(ssh root@"$node_ip" "find /root/dilithion-fuzzers -name 'crash-*' -type f 2>/dev/null | wc -l" 2>/dev/null || echo "0")

  if [ "$crash_count" -eq 0 ]; then
    log_success "✓ $node_name - No crashes detected"
    echo "✓ $node_name: No crashes (0 files)" >> "$REPORT_FILE"
    return 0
  else
    log_warn "⚠ $node_name - $crash_count crash(es) detected"
    echo "⚠ $node_name: $crash_count crash file(s) detected" >> "$REPORT_FILE"

    # List recent crashes
    local recent_crashes
    recent_crashes=$(ssh root@"$node_ip" "find /root/dilithion-fuzzers -name 'crash-*' -type f -mtime -1 2>/dev/null | head -5" 2>/dev/null || echo "")

    if [ -n "$recent_crashes" ]; then
      echo "  Recent crashes (last 24h):" >> "$REPORT_FILE"
      echo "$recent_crashes" | while read -r crash_file; do
        echo "    - $(basename "$crash_file")" >> "$REPORT_FILE"
      done
    fi

    HEALTH_STATUS="ATTENTION_REQUIRED"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  fi
}

# Check resource monitor logs
check_monitor_logs() {
  local node_name="$1"
  local node_ip="$2"

  log_info "Checking resource monitor logs on $node_name..."

  # Check for errors in last 100 lines
  local error_count
  error_count=$(ssh root@"$node_ip" "tail -100 /root/resource-monitor-new.log 2>/dev/null | grep -c '\[ERROR\]'" 2>/dev/null || echo "0")

  local warn_count
  warn_count=$(ssh root@"$node_ip" "tail -100 /root/resource-monitor-new.log 2>/dev/null | grep -c '\[WARN\]'" 2>/dev/null || echo "0")

  if [ "$error_count" -eq 0 ] && [ "$warn_count" -eq 0 ]; then
    log_success "✓ $node_name - Monitor logs clean (0 errors, 0 warnings)"
    echo "✓ $node_name: Monitor logs clean" >> "$REPORT_FILE"
    return 0
  elif [ "$error_count" -gt 0 ]; then
    log_error "✗ $node_name - $error_count error(s) in monitor logs"
    echo "✗ $node_name: $error_count error(s) in last 100 log lines" >> "$REPORT_FILE"

    # Get sample errors
    local sample_errors
    sample_errors=$(ssh root@"$node_ip" "tail -100 /root/resource-monitor-new.log 2>/dev/null | grep '\[ERROR\]' | tail -3" 2>/dev/null || echo "")
    if [ -n "$sample_errors" ]; then
      echo "  Sample errors:" >> "$REPORT_FILE"
      echo "$sample_errors" | while IFS= read -r line; do
        echo "    $line" >> "$REPORT_FILE"
      done
    fi

    HEALTH_STATUS="DEGRADED"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  else
    log_warn "⚠ $node_name - $warn_count warning(s) in monitor logs"
    echo "⚠ $node_name: $warn_count warning(s) in last 100 log lines" >> "$REPORT_FILE"
    return 0
  fi
}

# Check disk space
check_disk_space() {
  local node_name="$1"
  local node_ip="$2"

  log_info "Checking disk space on $node_name..."

  local disk_usage
  disk_usage=$(ssh root@"$node_ip" "df -h / | tail -1 | awk '{print \$5}' | sed 's/%//'" 2>/dev/null || echo "100")

  if [ "$disk_usage" -lt 80 ]; then
    log_success "✓ $node_name - Disk usage: ${disk_usage}%"
    echo "✓ $node_name: Disk usage ${disk_usage}% (healthy)" >> "$REPORT_FILE"
    return 0
  elif [ "$disk_usage" -lt 90 ]; then
    log_warn "⚠ $node_name - Disk usage: ${disk_usage}%"
    echo "⚠ $node_name: Disk usage ${disk_usage}% (WARNING)" >> "$REPORT_FILE"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  else
    log_error "✗ $node_name - Disk usage: ${disk_usage}% (CRITICAL)"
    echo "✗ $node_name: Disk usage ${disk_usage}% (CRITICAL)" >> "$REPORT_FILE"
    HEALTH_STATUS="CRITICAL"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    return 1
  fi
}

# Check corpus growth
check_corpus_growth() {
  local node_name="$1"
  local node_ip="$2"
  local fuzzer="$3"

  log_info "Checking corpus growth for $fuzzer on $node_name..."

  # Extract fuzzer name without fuzz_ prefix
  local corpus_name
  corpus_name=$(echo "$fuzzer" | sed 's/^fuzz_//')

  local corpus_count
  corpus_count=$(ssh root@"$node_ip" "find /root/dilithion-fuzzers/fuzz_corpus/$corpus_name -type f 2>/dev/null | wc -l" 2>/dev/null || echo "0")

  if [ "$corpus_count" -gt 0 ]; then
    log_success "✓ $fuzzer corpus: $corpus_count files"
    echo "✓ $fuzzer corpus on $node_name: $corpus_count files" >> "$REPORT_FILE"
    return 0
  else
    log_warn "⚠ $fuzzer corpus: Empty or not found"
    echo "⚠ $fuzzer corpus on $node_name: Empty or not found" >> "$REPORT_FILE"
    return 1
  fi
}

# Calculate total uptime
calculate_uptime() {
  log_info "Calculating total fuzzing uptime..."

  echo "" >> "$REPORT_FILE"
  echo "=== Fuzzing Statistics ===" >> "$REPORT_FILE"

  for node_name in "${!NODES[@]}"; do
    local node_ip="${NODES[$node_name]}"
    local fuzzer="${EXPECTED_FUZZERS[$node_name]}"

    local uptime
    uptime=$(ssh root@"$node_ip" "ps aux | grep '$fuzzer' | grep -v grep | awk '{print \$10}'" 2>/dev/null || echo "0:00")

    echo "$node_name ($fuzzer): Uptime $uptime" >> "$REPORT_FILE"
  done
}

# Send Slack notification
send_slack_notification() {
  if [ -z "$SLACK_WEBHOOK" ]; then
    return 0
  fi

  local color="good"
  local title="✅ Dilithion Testnet - Health Check PASSED"

  if [ "$HEALTH_STATUS" = "ATTENTION_REQUIRED" ]; then
    color="warning"
    title="⚠️ Dilithion Testnet - Health Check ATTENTION REQUIRED"
  elif [ "$HEALTH_STATUS" = "DEGRADED" ]; then
    color="warning"
    title="⚠️ Dilithion Testnet - Health Check DEGRADED"
  elif [ "$HEALTH_STATUS" = "CRITICAL" ]; then
    color="danger"
    title="🚨 Dilithion Testnet - Health Check FAILED"
  fi

  local report_summary
  report_summary=$(head -20 "$REPORT_FILE")

  local payload
  payload=$(cat <<EOF
{
  "attachments": [{
    "color": "$color",
    "title": "$title",
    "text": "Issues found: $ISSUES_FOUND\n\`\`\`$report_summary\`\`\`",
    "footer": "Dilithion Health Monitor",
    "ts": $(date +%s)
  }]
}
EOF
)

  curl -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1

  if [ $? -eq 0 ]; then
    log_success "Slack notification sent"
  else
    log_warn "Failed to send Slack notification"
  fi
}

# Generate final report
generate_final_report() {
  echo "" >> "$REPORT_FILE"
  echo "======================================================" >> "$REPORT_FILE"
  echo "Health Status: $HEALTH_STATUS" >> "$REPORT_FILE"
  echo "Issues Found: $ISSUES_FOUND" >> "$REPORT_FILE"
  echo "Report Location: $REPORT_FILE" >> "$REPORT_FILE"
  echo "======================================================" >> "$REPORT_FILE"

  log_info ""
  log_info "==========================================="
  if [ "$HEALTH_STATUS" = "HEALTHY" ]; then
    log_success "Health Status: $HEALTH_STATUS ✓"
  elif [ "$HEALTH_STATUS" = "ATTENTION_REQUIRED" ] || [ "$HEALTH_STATUS" = "DEGRADED" ]; then
    log_warn "Health Status: $HEALTH_STATUS ⚠"
  else
    log_error "Health Status: $HEALTH_STATUS ✗"
  fi
  log_info "Issues Found: $ISSUES_FOUND"
  log_info "Report: $REPORT_FILE"
  log_info "==========================================="
}

# Main execution
main() {
  parse_args "$@"

  log_info "==========================================="
  log_info "Dilithion Daily Health Check"
  log_info "==========================================="
  log_info "Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
  echo ""

  start_report

  # Check each node
  for node_name in "${!NODES[@]}"; do
    local node_ip="${NODES[$node_name]}"
    local expected_fuzzer="${EXPECTED_FUZZERS[$node_name]}"

    echo "" >> "$REPORT_FILE"
    echo "--- $node_name ($node_ip) ---" >> "$REPORT_FILE"

    # Connectivity check
    if check_node_connectivity "$node_name" "$node_ip"; then
      # Fuzzer status
      check_fuzzer_status "$node_name" "$node_ip" "$expected_fuzzer"

      # Crashes
      check_for_crashes "$node_name" "$node_ip"

      # Monitor logs
      check_monitor_logs "$node_name" "$node_ip"

      # Disk space
      check_disk_space "$node_name" "$node_ip"

      # Corpus growth
      check_corpus_growth "$node_name" "$node_ip" "$expected_fuzzer"
    fi

    echo ""
  done

  # Calculate uptime
  calculate_uptime

  # Generate final report
  generate_final_report

  # Send notifications
  send_slack_notification

  echo ""
  log_info "Full report available at: $REPORT_FILE"

  # Exit with appropriate code
  if [ "$HEALTH_STATUS" = "CRITICAL" ]; then
    exit 2
  elif [ "$HEALTH_STATUS" = "DEGRADED" ] || [ "$HEALTH_STATUS" = "ATTENTION_REQUIRED" ]; then
    exit 1
  else
    exit 0
  fi
}

main "$@"
