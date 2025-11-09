#!/bin/bash
# Dilithion Crash Deduplication Engine
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Deduplicate and analyze fuzzer crashes
# Usage: ./deduplicate-crashes-2025-11-10.sh <crash_directory>
# Date: 2025-11-10

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="crash_analysis_$(date +%Y%m%d_%H%M%S)"
REPORT_HTML="crash-report.html"
REPORT_JSON="crash-groups.json"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

# Usage information
usage() {
  cat <<EOF
Dilithion Crash Deduplication Engine

Usage: $0 <crash_directory>

Arguments:
  crash_directory    Directory containing crash files to analyze

Options:
  -h, --help         Show this help message

Examples:
  $0 ./fuzzing_crashes/2025-11-10/
  $0 /tmp/crashes/

Output:
  - crash-report.html    HTML report with crash groups
  - crash-groups.json    Machine-readable crash data
  - crash_analysis_*/    Organized crash files by signature

EOF
  exit 1
}

# Parse crash file to extract crash signature
extract_crash_signature() {
  local crash_file="$1"
  local signature=""

  # Try to extract ASAN crash signature
  if grep -q "ERROR: AddressSanitizer" "$crash_file" 2>/dev/null; then
    # Extract crash type and function
    local crash_type
    crash_type=$(grep "ERROR: AddressSanitizer:" "$crash_file" | head -1 | sed 's/.*AddressSanitizer: \([^ ]*\).*/\1/')

    local function_name
    function_name=$(grep -E "^    #0 " "$crash_file" | head -1 | awk '{print $3}' | sed 's/+.*//')

    if [ -z "$function_name" ]; then
      function_name="unknown"
    fi

    signature="${crash_type}:${function_name}"

  # Try to extract LeakSanitizer signature
  elif grep -q "ERROR: LeakSanitizer" "$crash_file" 2>/dev/null; then
    local function_name
    function_name=$(grep -E "^    #0 " "$crash_file" | head -1 | awk '{print $3}' | sed 's/+.*//')

    if [ -z "$function_name" ]; then
      function_name="unknown"
    fi

    signature="leak:${function_name}"

  # Try to extract timeout signature
  elif grep -q "TIMEOUT" "$crash_file" 2>/dev/null; then
    signature="timeout:unknown"

  # Try to extract assertion failure
  elif grep -q "Assertion.*failed" "$crash_file" 2>/dev/null; then
    local assertion
    assertion=$(grep "Assertion.*failed" "$crash_file" | head -1 | sed 's/.*Assertion `\(.*\)' failed.*/\1/' | head -c 50)
    signature="assertion:${assertion}"

  # Generic crash
  else
    # Use first line hash as signature
    local first_line
    first_line=$(head -1 "$crash_file" | head -c 100)
    signature="generic:$(echo "$first_line" | sha256sum | cut -c1-16)"
  fi

  echo "$signature"
}

# Extract crash severity
extract_crash_severity() {
  local crash_file="$1"

  if grep -q "heap-use-after-free\|stack-use-after-scope" "$crash_file" 2>/dev/null; then
    echo "CRITICAL"
  elif grep -q "heap-buffer-overflow\|stack-buffer-overflow" "$crash_file" 2>/dev/null; then
    echo "HIGH"
  elif grep -q "LeakSanitizer" "$crash_file" 2>/dev/null; then
    echo "MEDIUM"
  elif grep -q "TIMEOUT" "$crash_file" 2>/dev/null; then
    echo "LOW"
  else
    echo "UNKNOWN"
  fi
}

# Extract fuzzer name from file path
extract_fuzzer_name() {
  local crash_file="$1"
  local fuzzer_name

  # Extract from path like "/fuzzing_crashes/2025-11-10/fuzz_sha3/crash-abc123"
  fuzzer_name=$(echo "$crash_file" | grep -oP 'fuzz_[a-z_]+' | head -1)

  if [ -z "$fuzzer_name" ]; then
    fuzzer_name="unknown"
  fi

  echo "$fuzzer_name"
}

# Generate crash fingerprint (SHA256 hash)
generate_fingerprint() {
  local signature="$1"
  echo -n "$signature" | sha256sum | cut -c1-16
}

# Analyze all crashes and group by signature
analyze_crashes() {
  local crash_dir="$1"

  log_info "Analyzing crashes in: $crash_dir"

  # Create output directory
  mkdir -p "$OUTPUT_DIR"

  # Find all crash files
  local crash_files
  crash_files=$(find "$crash_dir" -type f -name "crash-*" -o -name "*.crash" -o -name "oom-*" -o -name "leak-*" -o -name "timeout-*" 2>/dev/null)

  local total_crashes=0
  local unique_crashes=0

  # Associative array to group crashes
  declare -A crash_groups
  declare -A crash_counts
  declare -A crash_severity
  declare -A crash_files_by_sig

  # Process each crash file
  while IFS= read -r crash_file; do
    if [ ! -f "$crash_file" ]; then
      continue
    fi

    total_crashes=$((total_crashes + 1))

    # Extract crash signature
    local signature
    signature=$(extract_crash_signature "$crash_file")

    local severity
    severity=$(extract_crash_severity "$crash_file")

    local fuzzer
    fuzzer=$(extract_fuzzer_name "$crash_file")

    local fingerprint
    fingerprint=$(generate_fingerprint "$signature")

    # Track crash groups
    if [ -z "${crash_groups[$fingerprint]:-}" ]; then
      crash_groups[$fingerprint]="$signature"
      crash_counts[$fingerprint]=1
      crash_severity[$fingerprint]="$severity"
      crash_files_by_sig[$fingerprint]="$crash_file"
      unique_crashes=$((unique_crashes + 1))
    else
      crash_counts[$fingerprint]=$((${crash_counts[$fingerprint]} + 1))
      crash_files_by_sig[$fingerprint]="${crash_files_by_sig[$fingerprint]}|$crash_file"
    fi

    # Organize crashes by signature
    local sig_dir="$OUTPUT_DIR/$fingerprint"
    mkdir -p "$sig_dir"
    cp "$crash_file" "$sig_dir/"

    log_info "Crash: $(basename "$crash_file") -> Signature: $signature (Fingerprint: $fingerprint, Severity: $severity)"

  done <<< "$crash_files"

  # Generate JSON report
  generate_json_report

  # Generate HTML report
  generate_html_report "$total_crashes" "$unique_crashes"

  log_success "Analysis complete!"
  log_info "Total crashes: $total_crashes"
  log_info "Unique crashes: $unique_crashes"
  log_info "Duplicate crashes: $((total_crashes - unique_crashes))"
  log_info "Report: $REPORT_HTML"
  log_info "Data: $REPORT_JSON"
}

# Generate JSON report
generate_json_report() {
  cat > "$REPORT_JSON" <<EOF
{
  "analysis_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_crashes": $total_crashes,
  "unique_crashes": $unique_crashes,
  "crash_groups": [
EOF

  local first=true
  for fingerprint in "${!crash_groups[@]}"; do
    if [ "$first" = true ]; then
      first=false
    else
      echo "," >> "$REPORT_JSON"
    fi

    cat >> "$REPORT_JSON" <<EOF
    {
      "fingerprint": "$fingerprint",
      "signature": "${crash_groups[$fingerprint]}",
      "count": ${crash_counts[$fingerprint]},
      "severity": "${crash_severity[$fingerprint]}",
      "files": $(echo "${crash_files_by_sig[$fingerprint]}" | sed 's/|/","/g' | sed 's/^/["/' | sed 's/$/"]/')
    }
EOF
  done

  cat >> "$REPORT_JSON" <<EOF

  ]
}
EOF

  log_success "JSON report saved: $REPORT_JSON"
}

# Generate HTML report
generate_html_report() {
  local total="$1"
  local unique="$2"
  local duplicates=$((total - unique))

  cat > "$REPORT_HTML" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dilithion Crash Analysis Report</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 10px;
      margin-bottom: 30px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header h1 {
      margin: 0;
      font-size: 2.5em;
    }
    .header .subtitle {
      opacity: 0.9;
      margin-top: 10px;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stat-number {
      font-size: 2.5em;
      font-weight: bold;
      color: #667eea;
      margin: 10px 0;
    }
    .stat-label {
      color: #666;
      font-size: 0.9em;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .crash-group {
      background: white;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      border-left: 4px solid #667eea;
    }
    .crash-group.critical {
      border-left-color: #e74c3c;
    }
    .crash-group.high {
      border-left-color: #e67e22;
    }
    .crash-group.medium {
      border-left-color: #f39c12;
    }
    .crash-group.low {
      border-left-color: #3498db;
    }
    .crash-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }
    .crash-signature {
      font-family: 'Courier New', monospace;
      font-size: 1.1em;
      font-weight: bold;
      color: #2c3e50;
    }
    .severity-badge {
      padding: 5px 15px;
      border-radius: 20px;
      font-size: 0.8em;
      font-weight: bold;
      text-transform: uppercase;
    }
    .severity-badge.critical {
      background: #e74c3c;
      color: white;
    }
    .severity-badge.high {
      background: #e67e22;
      color: white;
    }
    .severity-badge.medium {
      background: #f39c12;
      color: white;
    }
    .severity-badge.low {
      background: #3498db;
      color: white;
    }
    .crash-count {
      background: #ecf0f1;
      padding: 5px 10px;
      border-radius: 5px;
      margin-left: 10px;
      font-size: 0.9em;
    }
    .crash-details {
      color: #666;
      font-size: 0.9em;
    }
    .file-list {
      margin-top: 10px;
      padding-left: 20px;
      max-height: 200px;
      overflow-y: auto;
    }
    .file-list li {
      margin: 5px 0;
      font-family: 'Courier New', monospace;
      font-size: 0.85em;
    }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding: 20px;
      color: #666;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 Dilithion Crash Analysis</h1>
    <div class="subtitle">Automated Crash Deduplication & Triage Report</div>
    <div class="subtitle">Generated: REPORT_DATE</div>
  </div>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-label">Total Crashes</div>
      <div class="stat-number">TOTAL_CRASHES</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Unique Crashes</div>
      <div class="stat-number">UNIQUE_CRASHES</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Duplicates</div>
      <div class="stat-number">DUPLICATE_CRASHES</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Dedup Rate</div>
      <div class="stat-number">DEDUP_RATE%</div>
    </div>
  </div>

  <h2>Crash Groups</h2>
CRASH_GROUPS_HTML

  <div class="footer">
    <p>Dilithion Continuous Fuzzing Infrastructure</p>
    <p>© 2025 The Dilithion Core Developers</p>
  </div>
</body>
</html>
EOF

  # Calculate deduplication rate
  local dedup_rate=0
  if [ "$total" -gt 0 ]; then
    dedup_rate=$(( (duplicates * 100) / total ))
  fi

  # Replace placeholders
  sed -i "s/REPORT_DATE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g" "$REPORT_HTML"
  sed -i "s/TOTAL_CRASHES/$total/g" "$REPORT_HTML"
  sed -i "s/UNIQUE_CRASHES/$unique/g" "$REPORT_HTML"
  sed -i "s/DUPLICATE_CRASHES/$duplicates/g" "$REPORT_HTML"
  sed -i "s/DEDUP_RATE/$dedup_rate/g" "$REPORT_HTML"

  # Generate crash groups HTML
  local crash_groups_html=""
  for fingerprint in $(printf '%s\n' "${!crash_groups[@]}" | sort); do
    local signature="${crash_groups[$fingerprint]}"
    local count="${crash_counts[$fingerprint]}"
    local severity="${crash_severity[$fingerprint]}"
    local severity_lower=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
    local files="${crash_files_by_sig[$fingerprint]}"

    crash_groups_html+="  <div class=\"crash-group $severity_lower\">\n"
    crash_groups_html+="    <div class=\"crash-header\">\n"
    crash_groups_html+="      <div>\n"
    crash_groups_html+="        <span class=\"crash-signature\">$signature</span>\n"
    crash_groups_html+="        <span class=\"crash-count\">×$count</span>\n"
    crash_groups_html+="      </div>\n"
    crash_groups_html+="      <span class=\"severity-badge $severity_lower\">$severity</span>\n"
    crash_groups_html+="    </div>\n"
    crash_groups_html+="    <div class=\"crash-details\">\n"
    crash_groups_html+="      <strong>Fingerprint:</strong> <code>$fingerprint</code><br>\n"
    crash_groups_html+="      <strong>Files:</strong>\n"
    crash_groups_html+="      <ul class=\"file-list\">\n"

    IFS='|' read -ra FILES <<< "$files"
    for file in "${FILES[@]}"; do
      crash_groups_html+="        <li>$(basename "$file")</li>\n"
    done

    crash_groups_html+="      </ul>\n"
    crash_groups_html+="    </div>\n"
    crash_groups_html+="  </div>\n"
  done

  # Insert crash groups HTML
  sed -i "s|CRASH_GROUPS_HTML|$crash_groups_html|g" "$REPORT_HTML"

  log_success "HTML report saved: $REPORT_HTML"
}

# Main execution
main() {
  # Parse arguments
  if [ $# -lt 1 ]; then
    log_error "Missing crash directory argument"
    usage
  fi

  local crash_dir="$1"

  if [ "$crash_dir" = "-h" ] || [ "$crash_dir" = "--help" ]; then
    usage
  fi

  if [ ! -d "$crash_dir" ]; then
    log_error "Directory does not exist: $crash_dir"
    exit 1
  fi

  log_info "==================================="
  log_info "Dilithion Crash Deduplication"
  log_info "==================================="
  echo ""

  # Run analysis
  analyze_crashes "$crash_dir"

  echo ""
  log_success "Crash deduplication complete!"
  log_info "View report: $REPORT_HTML"
  log_info "View data: $REPORT_JSON"
}

main "$@"
