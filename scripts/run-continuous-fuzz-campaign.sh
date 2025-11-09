#!/bin/bash
# Dilithion Continuous Fuzzing Campaign Orchestrator
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Run long-duration fuzzing campaigns with monitoring and crash collection
# Usage: ./run-continuous-fuzz-campaign.sh [tier1|tier2|tier3]
#
# Tiers:
#   tier1: Consensus-critical (48 hours per fuzzer)
#   tier2: High-priority (24 hours per fuzzer)
#   tier3: Fast fuzzers (12 hours per fuzzer)

set -u
set -o pipefail

# Colors
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[32m'
COLOR_BLUE='\033[34m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'

# Configuration
TIER="${1:-tier2}"
FUZZER_DIR="/root/dilithion-fuzzers"
CORPUS_BASE="$FUZZER_DIR/fuzz_corpus"
CRASH_DIR="/root/fuzz_crashes"
LOG_DIR="/root/fuzz_logs"

# Campaign durations (in seconds)
TIER1_DURATION=$((48 * 3600))  # 48 hours
TIER2_DURATION=$((24 * 3600))  # 24 hours
TIER3_DURATION=$((12 * 3600))  # 12 hours

# Fuzzer tiers
declare -A FUZZER_TIERS
FUZZER_TIERS=(
  # Tier 1: Consensus-critical
  ["tier1"]="fuzz_difficulty fuzz_tx_validation fuzz_utxo fuzz_block fuzz_merkle"

  # Tier 2: High-priority
  ["tier2"]="fuzz_transaction fuzz_subsidy fuzz_network_message fuzz_signature"

  # Tier 3: Fast/utility fuzzers
  ["tier3"]="fuzz_sha3 fuzz_compactsize fuzz_address fuzz_address_encode fuzz_address_validate fuzz_address_bech32 fuzz_address_type fuzz_network_create fuzz_network_checksum fuzz_network_command fuzz_base58"
)

# Get duration for tier
get_duration() {
  case "$1" in
    tier1) echo $TIER1_DURATION ;;
    tier2) echo $TIER2_DURATION ;;
    tier3) echo $TIER3_DURATION ;;
    *) echo $TIER2_DURATION ;;
  esac
}

# Setup directories
mkdir -p "$CORPUS_BASE" "$CRASH_DIR" "$LOG_DIR"

# Print banner
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}Dilithion Continuous Fuzzing Campaign${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  Tier: ${COLOR_YELLOW}$TIER${COLOR_RESET}"
echo -e "  Node: $(hostname)"
echo -e "  Start: $(date)"
echo -e "  Duration: $(get_duration $TIER) seconds per fuzzer"
echo ""

# Get fuzzers for this tier
FUZZERS="${FUZZER_TIERS[$TIER]}"
DURATION=$(get_duration $TIER)

if [ -z "$FUZZERS" ]; then
  echo -e "${COLOR_RED}Error: Unknown tier '$TIER'${COLOR_RESET}"
  echo "Valid tiers: tier1, tier2, tier3"
  exit 1
fi

# Change to fuzzer directory
cd "$FUZZER_DIR"

# Cleanup handler
cleanup() {
  echo ""
  echo -e "${COLOR_YELLOW}Cleaning up fuzzing campaign...${COLOR_RESET}"

  # Kill all fuzzers gracefully
  pkill -TERM -f "fuzz_" || true
  sleep 5
  pkill -KILL -f "fuzz_" || true

  # Collect final crash report
  collect_crashes

  echo -e "${COLOR_GREEN}✓ Campaign terminated${COLOR_RESET}"
  exit 0
}

trap cleanup SIGTERM SIGINT

# Function: Collect crashes
collect_crashes() {
  echo -e "${COLOR_YELLOW}Collecting crashes...${COLOR_RESET}"

  CRASH_COUNT=0
  for PATTERN in "crash-*" "leak-*" "timeout-*"; do
    for CRASH_FILE in $PATTERN; do
      [ -f "$CRASH_FILE" ] || continue

      # Move crash to crash directory
      TIMESTAMP=$(date +%Y%m%d-%H%M%S)
      CRASH_NAME="${CRASH_FILE%.profraw}"
      mv "$CRASH_FILE" "$CRASH_DIR/${TIMESTAMP}-${CRASH_NAME}" 2>/dev/null || true
      ((CRASH_COUNT++))
    done
  done

  if [ $CRASH_COUNT -gt 0 ]; then
    echo -e "${COLOR_RED}⚠️  Found $CRASH_COUNT crash files${COLOR_RESET}"
    echo -e "  Location: $CRASH_DIR"
  else
    echo -e "${COLOR_GREEN}✓ No crashes found${COLOR_RESET}"
  fi
}

# Function: Run single fuzzer
run_fuzzer() {
  local FUZZER=$1
  local DURATION=$2
  local FUZZER_NAME=${FUZZER#fuzz_}
  local CORPUS_DIR="$CORPUS_BASE/$FUZZER_NAME"
  local LOG_FILE="$LOG_DIR/${FUZZER}_$(date +%Y%m%d-%H%M%S).log"

  # Create corpus directory
  mkdir -p "$CORPUS_DIR"

  echo -e "${COLOR_BLUE}[$(date +%H:%M:%S)]${COLOR_RESET} Starting $FUZZER for ${DURATION}s..."

  # Run fuzzer in background with timeout
  timeout $DURATION ./$FUZZER \
    -max_total_time=$DURATION \
    -print_final_stats=1 \
    -detect_leaks=1 \
    -rss_limit_mb=4096 \
    "$CORPUS_DIR" \
    > "$LOG_FILE" 2>&1 &

  local FUZZER_PID=$!

  # Monitor fuzzer
  local CHECK_INTERVAL=300  # Check every 5 minutes
  local ELAPSED=0

  while [ $ELAPSED -lt $DURATION ]; do
    sleep $CHECK_INTERVAL
    ELAPSED=$((ELAPSED + CHECK_INTERVAL))

    # Check if fuzzer is still running
    if ! kill -0 $FUZZER_PID 2>/dev/null; then
      echo -e "${COLOR_YELLOW}⚠️  $FUZZER exited early${COLOR_RESET}"
      break
    fi

    # Print progress
    if [ -f "$LOG_FILE" ]; then
      STATS=$(tail -1 "$LOG_FILE" 2>/dev/null | grep -oP '#[0-9]+' | head -1 || echo "#0")
      echo -e "${COLOR_BLUE}[$(date +%H:%M:%S)]${COLOR_RESET} $FUZZER progress: $STATS (${ELAPSED}/${DURATION}s)"
    fi

    # Collect crashes periodically
    if [ $((ELAPSED % 3600)) -eq 0 ]; then
      collect_crashes
    fi
  done

  # Wait for fuzzer to finish
  wait $FUZZER_PID 2>/dev/null || true

  # Print final stats
  echo -e "${COLOR_GREEN}✓ $FUZZER completed${COLOR_RESET}"
  if [ -f "$LOG_FILE" ]; then
    echo "  Final stats:"
    tail -20 "$LOG_FILE" | grep -E "(#|cov:|corp:|exec/s)" | tail -5 | sed 's/^/    /'
  fi

  # Collect any new crashes
  collect_crashes

  # Sync corpus (basic rotation to prevent disk fill)
  CORPUS_SIZE=$(du -sh "$CORPUS_DIR" 2>/dev/null | awk '{print $1}' || echo "0")
  echo "  Corpus size: $CORPUS_SIZE"

  # If corpus > 1GB, keep only newest 5000 files
  CORPUS_COUNT=$(find "$CORPUS_DIR" -type f | wc -l)
  if [ $CORPUS_COUNT -gt 5000 ]; then
    echo -e "${COLOR_YELLOW}  Rotating corpus (keeping 5000 newest)...${COLOR_RESET}"
    find "$CORPUS_DIR" -type f -printf '%T@ %p\n' | sort -n | head -n -5000 | cut -d' ' -f2- | xargs rm -f
  fi

  echo ""
}

# Main campaign loop
echo -e "${COLOR_YELLOW}Starting fuzzing campaign...${COLOR_RESET}"
echo ""

FUZZER_COUNT=0
for FUZZER in $FUZZERS; do
  if [ ! -f "$FUZZER" ]; then
    echo -e "${COLOR_RED}✗ $FUZZER not found${COLOR_RESET}"
    continue
  fi

  ((FUZZER_COUNT++))
  run_fuzzer "$FUZZER" "$DURATION"
done

# Final summary
echo ""
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ Campaign Complete${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  End: $(date)"
echo -e "  Fuzzers run: $FUZZER_COUNT"
echo -e "  Crash directory: $CRASH_DIR"
echo -e "  Log directory: $LOG_DIR"
echo ""

# Final crash collection
collect_crashes

echo -e "${COLOR_GREEN}✓ All fuzzers completed successfully${COLOR_RESET}"
