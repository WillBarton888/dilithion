#!/bin/bash
# Dilithion Fuzzer Resource Monitor
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Monitor and manage fuzzer resource usage
# Usage: nohup ./monitor-fuzzer-resources.sh > /root/resource-monitor.log 2>&1 &

set -u

# Resource limits
MAX_CPU_PERCENT=80
MAX_MEM_GB=6
MAX_DISK_PERCENT=80

# Logging
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Resource monitor started"

while true; do
  # Check CPU usage
  CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'.' -f1)

  if [ "$CPU_USAGE" -gt "$MAX_CPU_PERCENT" ]; then
    log "WARNING: High CPU usage: ${CPU_USAGE}%"
  fi

  # Check memory usage
  MEM_USED=$(free -g | awk '/^Mem:/{print $3}')

  if [ "$MEM_USED" -gt "$MAX_MEM_GB" ]; then
    log "WARNING: High memory usage: ${MEM_USED}GB"
  fi

  # Check disk usage
  DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')

  if [ "$DISK_USAGE" -gt "$MAX_DISK_PERCENT" ]; then
    log "WARNING: High disk usage: ${DISK_USAGE}%"

    # Clean old corpus files (keep only last 7 days)
    log "Cleaning old corpus files..."
    find /root/dilithion-fuzzers/fuzz_corpus -type f -mtime +7 -delete 2>/dev/null || true

    # Clean old logs (keep only last 7 days)
    find /root/fuzz_logs -type f -mtime +7 -delete 2>/dev/null || true
  fi

  # Check for zombie processes
  ZOMBIES=$(ps aux | grep '[f]uzz_' | grep -c 'Z' || echo "0")
  if [ "$ZOMBIES" -gt 0 ]; then
    log "WARNING: Found $ZOMBIES zombie fuzzer processes"
    # Kill zombies
    pkill -9 -f "fuzz_" 2>/dev/null || true
  fi

  # Check for hung fuzzers (no output in last hour)
  if [ -d "/root/fuzz_logs" ]; then
    STALE_LOGS=$(find /root/fuzz_logs -name "*.log" -type f -mmin +60 2>/dev/null | wc -l)
    if [ "$STALE_LOGS" -gt 0 ]; then
      log "INFO: $STALE_LOGS fuzzer log(s) with no updates in 60 minutes"
    fi
  fi

  # Sleep for 5 minutes
  sleep 300
done
