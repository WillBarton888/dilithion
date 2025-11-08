#!/bin/bash
# Dilithion Fuzzing Status Monitor
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Real-time monitoring dashboard for fuzzing campaigns across all nodes
# Usage: ./monitor-fuzzing-status.sh

# Configuration
NODES=("188.166.255.63" "134.122.4.164" "209.97.177.197")
LABELS=("Singapore" "NYC" "London")
SSH_KEY="${HOME}/.ssh/id_ed25519_windows"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5"
REFRESH_INTERVAL=60  # seconds

# Colors
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[32m'
COLOR_BLUE='\033[34m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'
COLOR_BOLD='\033[1m'

# Function: Get fuzzer stats from node
get_node_stats() {
  local NODE=$1
  local LABEL=$2

  echo -e "${COLOR_BOLD}[$LABEL - $NODE]${COLOR_RESET}"

  # SSH into node and gather stats
  ssh $SSH_OPTS root@$NODE "
    cd /root/dilithion-fuzzers 2>/dev/null || cd /root || exit 1

    # Count active fuzzers
    ACTIVE=\$(ps aux | grep -c '[f]uzz_')
    echo -e '  ${COLOR_GREEN}Active Fuzzers:${COLOR_RESET} '\$ACTIVE

    # Get latest fuzzer log
    if ls /root/fuzz_logs/*.log 2>/dev/null | head -1 >/dev/null; then
      LATEST_LOG=\$(ls -t /root/fuzz_logs/*.log 2>/dev/null | head -1)
      FUZZER_NAME=\$(basename \$LATEST_LOG .log | sed 's/_[0-9]*-[0-9]*//')
      echo -e '  ${COLOR_BLUE}Latest:${COLOR_RESET} '\$FUZZER_NAME

      # Extract stats
      if [ -f \"\$LATEST_LOG\" ]; then
        STATS=\$(tail -20 \"\$LATEST_LOG\" 2>/dev/null | grep '#' | tail -1)
        if [ -n \"\$STATS\" ]; then
          EXECS=\$(echo \"\$STATS\" | grep -oP '#[0-9]+' | head -1 || echo '#0')
          COV=\$(echo \"\$STATS\" | grep -oP 'cov: [0-9]+' || echo 'cov: 0')
          CORP=\$(echo \"\$STATS\" | grep -oP 'corp: [0-9]+' || echo 'corp: 0')
          EXEC_S=\$(echo \"\$STATS\" | grep -oP 'exec/s: [0-9]+' || echo 'exec/s: 0')

          echo -e '    '\$EXECS' | '\$COV' | '\$CORP' | '\$EXEC_S
        fi
      fi
    else
      echo -e '  ${COLOR_YELLOW}No active fuzzing${COLOR_RESET}'
    fi

    # Check for crashes
    CRASHES=\$(ls /root/fuzz_crashes/ 2>/dev/null | wc -l)
    if [ \"\$CRASHES\" -gt 0 ]; then
      echo -e '  ${COLOR_RED}Crashes:${COLOR_RESET} '\$CRASHES
    else
      echo -e '  ${COLOR_GREEN}Crashes:${COLOR_RESET} 0'
    fi

    # System resources
    CPU_USAGE=\$(top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1)
    MEM_USAGE=\$(free | grep Mem | awk '{printf(\"%.1f%%\", \$3/\$2 * 100.0)}')
    DISK_USAGE=\$(df -h /root | tail -1 | awk '{print \$5}')

    echo -e '  ${COLOR_YELLOW}CPU:${COLOR_RESET} '\${CPU_USAGE}% ' | ${COLOR_YELLOW}RAM:${COLOR_RESET} '\${MEM_USAGE}' | ${COLOR_YELLOW}Disk:${COLOR_RESET} '\${DISK_USAGE}

    # Corpus size
    if [ -d /root/dilithion-fuzzers/fuzz_corpus ]; then
      CORPUS_SIZE=\$(du -sh /root/dilithion-fuzzers/fuzz_corpus 2>/dev/null | awk '{print \$1}' || echo '0')
      echo -e '  ${COLOR_BLUE}Corpus:${COLOR_RESET} '\$CORPUS_SIZE
    fi
  " 2>/dev/null || echo -e "  ${COLOR_RED}ERROR: Cannot connect to $NODE${COLOR_RESET}"

  echo ""
}

# Main monitoring loop
while true; do
  clear

  # Header
  echo -e "${COLOR_BOLD}${COLOR_BLUE}========================================${COLOR_RESET}"
  echo -e "${COLOR_BOLD}${COLOR_BLUE}DILITHION FUZZING DASHBOARD${COLOR_RESET}"
  echo -e "${COLOR_BOLD}${COLOR_BLUE}========================================${COLOR_RESET}"
  echo -e "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "Refresh: ${REFRESH_INTERVAL}s"
  echo ""

  # Collect stats from all nodes
  for i in "${!NODES[@]}"; do
    get_node_stats "${NODES[$i]}" "${LABELS[$i]}"
  done

  # Summary
  echo -e "${COLOR_BOLD}${COLOR_BLUE}========================================${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}Legend:${COLOR_RESET}"
  echo -e "  #N - Total executions"
  echo -e "  cov - Coverage (edges)"
  echo -e "  corp - Corpus size (inputs)"
  echo -e "  exec/s - Executions per second"
  echo ""
  echo -e "${COLOR_YELLOW}Press Ctrl+C to exit${COLOR_RESET}"

  # Wait for next refresh
  sleep $REFRESH_INTERVAL
done
