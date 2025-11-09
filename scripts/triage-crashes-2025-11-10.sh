#!/bin/bash
# Dilithion Crash Triage Workflow
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Complete crash triage workflow - collect, deduplicate, analyze, report
# Usage: ./triage-crashes-2025-11-10.sh
# Date: 2025-11-10

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRASH_COLLECT_SCRIPT="${SCRIPT_DIR}/collect-crashes.sh"
DEDUPLICATE_SCRIPT="${SCRIPT_DIR}/deduplicate-crashes-2025-11-10.sh"
ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze-crash-2025-11-10.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BOLD}${BLUE}[STEP]${NC} $*"; }

# Print header
print_header() {
  echo ""
  echo -e "${BOLD}========================================${NC}"
  echo -e "${BOLD}  Dilithion Crash Triage Workflow${NC}"
  echo -e "${BOLD}========================================${NC}"
  echo ""
  echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  Host: $(hostname)"
  echo ""
}

# Step 1: Collect crashes from all nodes
collect_crashes() {
  log_step "1/4: Collecting crashes from all nodes..."
  echo ""

  if [ ! -f "$CRASH_COLLECT_SCRIPT" ]; then
    log_error "Crash collection script not found: $CRASH_COLLECT_SCRIPT"
    exit 1
  fi

  bash "$CRASH_COLLECT_SCRIPT"
  local exit_code=$?

  if [ $exit_code -ne 0 ]; then
    log_error "Crash collection failed with exit code: $exit_code"
    exit 1
  fi

  echo ""
}

# Step 2: Deduplicate crashes
deduplicate_crashes() {
  log_step "2/4: Deduplicating crashes..."
  echo ""

  # Find most recent crash directory
  local crash_dir
  crash_dir=$(find ./fuzzing_crashes -maxdepth 1 -type d -name "20*" 2>/dev/null | sort | tail -1)

  if [ -z "$crash_dir" ]; then
    log_warn "No crash directories found in ./fuzzing_crashes/"
    return 0
  fi

  if [ ! -f "$DEDUPLICATE_SCRIPT" ]; then
    log_error "Deduplication script not found: $DEDUPLICATE_SCRIPT"
    exit 1
  fi

  # Check if there are any crash files
  local crash_count
  crash_count=$(find "$crash_dir" -type f \( -name "crash-*" -o -name "*.crash" -o -name "oom-*" -o -name "leak-*" -o -name "timeout-*" \) 2>/dev/null | wc -l)

  if [ "$crash_count" -eq 0 ]; then
    log_success "No crashes found - all fuzzers running cleanly!"
    exit 0
  fi

  log_info "Found $crash_count crash files in $crash_dir"

  bash "$DEDUPLICATE_SCRIPT" "$crash_dir"
  local exit_code=$?

  if [ $exit_code -ne 0 ]; then
    log_error "Deduplication failed with exit code: $exit_code"
    exit 1
  fi

  echo ""
}

# Step 3: Analyze unique crashes
analyze_unique_crashes() {
  log_step "3/4: Analyzing unique crashes in detail..."
  echo ""

  # Check if crash-groups.json exists
  if [ ! -f "crash-groups.json" ]; then
    log_warn "No crash groups found (crash-groups.json missing)"
    return 0
  fi

  # Parse JSON to get unique crashes
  local unique_count
  unique_count=$(grep -c '"fingerprint"' crash-groups.json 2>/dev/null || echo 0)

  if [ "$unique_count" -eq 0 ]; then
    log_success "No unique crashes to analyze"
    return 0
  fi

  log_info "Analyzing $unique_count unique crash groups..."

  # Create detailed analysis directory
  mkdir -p crash_detailed_analysis

  # Analyze each unique crash (first file from each group)
  local analyzed=0
  while IFS= read -r crash_file; do
    if [ -f "$crash_file" ]; then
      log_info "Analyzing: $crash_file"
      bash "$ANALYZE_SCRIPT" "$crash_file" > "crash_detailed_analysis/$(basename "$crash_file").analysis.txt" 2>&1 || true
      analyzed=$((analyzed + 1))
    fi
  done < <(find crash_analysis_* -type f \( -name "crash-*" -o -name "*.crash" \) 2>/dev/null | sort | head -10)

  log_success "Analyzed $analyzed crashes in detail"
  echo ""
}

# Step 4: Generate GitHub issue templates
generate_github_issues() {
  log_step "4/4: Generating GitHub issue templates..."
  echo ""

  if [ ! -f "crash-groups.json" ]; then
    log_warn "No crash groups found (crash-groups.json missing)"
    return 0
  fi

  mkdir -p github_issues

  # Extract crash information from JSON and create issue templates
  local issue_count=0

  # Read crash groups (simplified parsing without jq dependency)
  while IFS= read -r line; do
    if echo "$line" | grep -q '"fingerprint"'; then
      local fingerprint
      fingerprint=$(echo "$line" | sed 's/.*"fingerprint": "\([^"]*\)".*/\1/')

      local signature
      signature=$(grep -A 1 "\"fingerprint\": \"$fingerprint\"" crash-groups.json | grep '"signature"' | sed 's/.*"signature": "\([^"]*\)".*/\1/' || echo "unknown")

      local severity
      severity=$(grep -A 2 "\"fingerprint\": \"$fingerprint\"" crash-groups.json | grep '"severity"' | sed 's/.*"severity": "\([^"]*\)".*/\1/' || echo "UNKNOWN")

      local count
      count=$(grep -A 3 "\"fingerprint\": \"$fingerprint\"" crash-groups.json | grep '"count"' | sed 's/.*"count": \([0-9]*\).*/\1/' || echo "1")

      # Create GitHub issue template
      local issue_file="github_issues/crash-${fingerprint}.md"

      cat > "$issue_file" <<EOF
---
title: "[CRASH] $signature"
labels: crash, fuzzing, $severity
---

## Crash Report

**Severity:** $severity
**Signature:** \`$signature\`
**Fingerprint:** \`$fingerprint\`
**Occurrences:** $count
**Detected:** $(date '+%Y-%m-%d')

## Description

This crash was automatically detected by the Dilithion continuous fuzzing infrastructure.

## Crash Type

\`\`\`
$signature
\`\`\`

## Reproduction

1. Obtain crash input file from: \`crash_analysis_*/\${fingerprint}/\`
2. Run fuzzer with crash input:
   \`\`\`bash
   ./fuzz_[target] crash-input-file
   \`\`\`
3. Observe crash with AddressSanitizer output

## Stack Trace

See crash files in: \`crash_analysis_*/\${fingerprint}/\`

## Additional Context

- Fuzzing campaign: Phase 5 Continuous Fuzzing
- Detection date: $(date '+%Y-%m-%d %H:%M:%S')
- Nodes: Singapore, NYC, London

## Priority

$(case "$severity" in
  CRITICAL) echo "🔴 **CRITICAL** - Immediate fix required";;
  HIGH) echo "🟠 **HIGH** - Fix in next release";;
  MEDIUM) echo "🟡 **MEDIUM** - Schedule for future release";;
  LOW) echo "🔵 **LOW** - Low priority";;
  *) echo "⚪ **UNKNOWN** - Needs triage";;
esac)

## Checklist

- [ ] Reproduce crash locally
- [ ] Identify root cause
- [ ] Develop fix
- [ ] Add regression test
- [ ] Verify fix with fuzzer
- [ ] Close issue

---
*This issue was automatically generated by the Dilithion crash triage system.*
EOF

      log_success "Created GitHub issue template: $issue_file"
      issue_count=$((issue_count + 1))
    fi
  done < crash-groups.json

  if [ $issue_count -gt 0 ]; then
    log_success "Generated $issue_count GitHub issue templates in ./github_issues/"
  fi

  echo ""
}

# Print summary
print_summary() {
  echo ""
  log_info "========================================="
  log_info "Triage Summary"
  log_info "========================================="
  echo ""

  if [ -f "crash-groups.json" ]; then
    local total
    total=$(grep '"total_crashes"' crash-groups.json | sed 's/.*: \([0-9]*\).*/\1/' || echo 0)

    local unique
    unique=$(grep '"unique_crashes"' crash-groups.json | sed 's/.*: \([0-9]*\).*/\1/' || echo 0)

    local duplicates=$((total - unique))

    echo "  Total crashes:      $total"
    echo "  Unique crashes:     $unique"
    echo "  Duplicate crashes:  $duplicates"
    echo ""
    echo "  📊 HTML Report:     crash-report.html"
    echo "  📄 JSON Data:       crash-groups.json"
    echo "  📁 Analysis:        crash_detailed_analysis/"
    echo "  🐛 GitHub Issues:   github_issues/"
  else
    log_success "✅ No crashes detected - all fuzzers healthy!"
  fi

  echo ""
  log_info "========================================="
  echo ""
}

# Main execution
main() {
  print_header

  # Execute triage workflow
  collect_crashes
  deduplicate_crashes
  analyze_unique_crashes
  generate_github_issues

  # Print summary
  print_summary

  log_success "Crash triage workflow complete!"
}

main "$@"
