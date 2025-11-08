#!/bin/bash
# Dilithion Crash Collection Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Collect crash files from all production nodes
# Usage: ./collect-crashes.sh

set -e

# Configuration
NODES=("188.166.255.63" "134.122.4.164" "209.97.177.197")
LABELS=("Singapore" "NYC" "London")
SSH_KEY="${HOME}/.ssh/id_ed25519_windows"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no"
CRASH_DIR="./fuzzing_crashes/$(date +%Y-%m-%d)"

# Colors
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[32m'
COLOR_BLUE='\033[34m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'

# Create output directory
mkdir -p "$CRASH_DIR"

echo -e "${COLOR_BLUE}=== Dilithion Crash Collection ===${COLOR_RESET}"
echo -e "Output directory: $CRASH_DIR"
echo ""

TOTAL_CRASHES=0

for i in "${!NODES[@]}"; do
  NODE="${NODES[$i]}"
  LABEL="${LABELS[$i]}"

  echo -e "${COLOR_YELLOW}[$LABEL]${COLOR_RESET} Collecting from $NODE..."

  # Create subdirectory for this node
  mkdir -p "$CRASH_DIR/$LABEL"

  # Download all crash files using rsync
  rsync -avz $SSH_OPTS \
    --include="crash-*" \
    --include="leak-*" \
    --include="timeout-*" \
    --exclude="*" \
    root@$NODE:/root/fuzz_crashes/ \
    "$CRASH_DIR/$LABEL/" 2>/dev/null || true

  # Count crashes
  CRASH_COUNT=$(find "$CRASH_DIR/$LABEL" -type f \( -name "crash-*" -o -name "leak-*" -o -name "timeout-*" \) 2>/dev/null | wc -l)
  echo -e "  ${COLOR_GREEN}Found: $CRASH_COUNT crash files${COLOR_RESET}"

  TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
done

echo ""
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ Collection Complete${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  Total crashes: $TOTAL_CRASHES"
echo -e "  Location: $CRASH_DIR"

if [ $TOTAL_CRASHES -gt 0 ]; then
  echo ""
  echo -e "${COLOR_RED}⚠️  CRASHES FOUND - TRIAGE REQUIRED${COLOR_RESET}"
  echo ""
  echo "Next steps:"
  echo "  1. Review crashes: ls -lh $CRASH_DIR/*/"
  echo "  2. Deduplicate: ./scripts/deduplicate-crashes.sh $CRASH_DIR"
  echo "  3. Reproduce crashes with fuzzers"
  echo "  4. Debug with GDB if needed"
  echo "  5. File GitHub issues for unique crashes"
else
  echo ""
  echo -e "${COLOR_GREEN}✓ No crashes found - all fuzzers running cleanly!${COLOR_RESET}"
fi
