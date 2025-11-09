#!/bin/bash
# Dilithion Fuzzer Resource Monitor (Fixed Version)
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Monitor and manage fuzzer resource usage with robust parsing
# Usage: nohup ./monitor-fuzzer-resources-2025-11-10.sh > /root/resource-monitor.log 2>&1 &
# Date: 2025-11-10
#
# Fixes:
# - Robust CPU parsing (handles decimal points and varying formats)
# - Memory parsing in MB with proper conversion
# - Portable zombie detection
# - Better error handling
# - Structured logging

set -u

# Resource limits
MAX_CPU_PERCENT=80
MAX_MEM_MB=6144  # 6GB in MB
MAX_DISK_PERCENT=80

# Monitoring configuration
CHECK_INTERVAL=300  # 5 minutes
CORPUS_RETENTION_DAYS=7
LOG_RETENTION_DAYS=7
STALE_LOG_MINUTES=60

# Self-monitoring
SCRIPT_START_TIME=$(date +%s)
HEARTBEAT_INTERVAL=3600  # 1 hour

# Logging with severity levels
log() {
  local level="$1"
  shift
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
}

log_info() {
  log "INFO" "$@"
}

log_warn() {
  log "WARN" "$@"
}

log_error() {
  log "ERROR" "$@"
}

# Get CPU usage with robust parsing
get_cpu_usage() {
  # Try multiple methods for compatibility
  local cpu_usage=""

  # Method 1: top -bn1 (most common)
  cpu_usage=$(top -bn1 | grep -i "cpu(s)" | head -1 | awk '{
    # Handle different top formats:
    # Format 1: "Cpu(s):  5.2%us,  2.1%sy, ..."
    # Format 2: "%Cpu(s):  5.2 us,  2.1 sy, ..."
    # Format 3: "Cpu(s): 5.2%us, 2.1%sy, ..."

    for (i=1; i<=NF; i++) {
      if ($i ~ /^[0-9]+\.?[0-9]*%?us/ || $i ~ /^[0-9]+\.?[0-9]*$/) {
        gsub(/%us.*/, "", $i)
        gsub(/us.*/, "", $i)
        print int($i + 0.5)  # Round to nearest integer
        exit
      }
    }
  }')

  # Method 2: mpstat (if available)
  if [ -z "$cpu_usage" ] && command -v mpstat >/dev/null 2>&1; then
    cpu_usage=$(mpstat 1 1 | awk '/Average/ {print int(100 - $NF + 0.5)}')
  fi

  # Method 3: /proc/stat fallback
  if [ -z "$cpu_usage" ] && [ -f /proc/stat ]; then
    cpu_usage=$(awk '/^cpu / {usage=($2+$4)*100/($2+$4+$5); print int(usage + 0.5)}' /proc/stat)
  fi

  # Validate
  if [ -z "$cpu_usage" ] || ! [[ "$cpu_usage" =~ ^[0-9]+$ ]]; then
    log_error "Failed to parse CPU usage, defaulting to 0"
    cpu_usage=0
  fi

  echo "$cpu_usage"
}

# Get memory usage in MB with proper parsing
get_memory_usage_mb() {
  # Use free -m for MB, parse robustly
  local mem_used=""

  # Try different free formats
  mem_used=$(free -m | awk '/^Mem:/ {print $3}')

  # Validate
  if [ -z "$mem_used" ] || ! [[ "$mem_used" =~ ^[0-9]+$ ]]; then
    log_error "Failed to parse memory usage, defaulting to 0"
    mem_used=0
  fi

  echo "$mem_used"
}

# Get disk usage percentage
get_disk_usage() {
  local disk_usage=""

  disk_usage=$(df / | tail -1 | awk '{print $5}' | tr -d '%')

  # Validate
  if [ -z "$disk_usage" ] || ! [[ "$disk_usage" =~ ^[0-9]+$ ]]; then
    log_error "Failed to parse disk usage, defaulting to 0"
    disk_usage=0
  fi

  echo "$disk_usage"
}

# Check for zombie processes (robust detection)
check_zombie_processes() {
  local zombie_count=0

  # Look for zombie processes specifically in STATE column
  zombie_count=$(ps aux | awk '$8 == "Z" && /fuzz_/ {count++} END {print count+0}')

  echo "$zombie_count"
}

# Clean old files with safety checks
clean_old_files() {
  local directory="$1"
  local days="$2"
  local description="$3"

  if [ ! -d "$directory" ]; then
    log_warn "Directory $directory does not exist, skipping cleanup"
    return
  fi

  local file_count
  file_count=$(find "$directory" -type f -mtime +"$days" 2>/dev/null | wc -l)

  if [ "$file_count" -gt 0 ]; then
    log_info "Cleaning $file_count old $description files (>$days days) from $directory"
    find "$directory" -type f -mtime +"$days" -delete 2>/dev/null || log_warn "Some files could not be deleted"
  fi
}

# Check for hung fuzzers
check_stale_logs() {
  local log_dir="/root/fuzz_logs"

  if [ ! -d "$log_dir" ]; then
    return
  fi

  local stale_count
  stale_count=$(find "$log_dir" -name "*.log" -type f -mmin +"$STALE_LOG_MINUTES" 2>/dev/null | wc -l)

  if [ "$stale_count" -gt 0 ]; then
    log_info "$stale_count fuzzer log(s) with no updates in $STALE_LOG_MINUTES minutes"
  fi
}

# Self-monitoring heartbeat
print_heartbeat() {
  local uptime_seconds=$(($(date +%s) - SCRIPT_START_TIME))
  local uptime_hours=$((uptime_seconds / 3600))
  log_info "Heartbeat: Resource monitor has been running for ${uptime_hours} hours"
}

# Main monitoring function
monitor_resources() {
  local iteration=0

  log_info "Resource monitor started (v2025-11-10)"
  log_info "Configuration: CPU<${MAX_CPU_PERCENT}%, MEM<${MAX_MEM_MB}MB, DISK<${MAX_DISK_PERCENT}%"

  while true; do
    iteration=$((iteration + 1))

    # Check CPU usage
    local cpu_usage
    cpu_usage=$(get_cpu_usage)

    if [ "$cpu_usage" -gt "$MAX_CPU_PERCENT" ]; then
      log_warn "High CPU usage: ${cpu_usage}%"
    fi

    # Check memory usage
    local mem_used_mb
    mem_used_mb=$(get_memory_usage_mb)

    if [ "$mem_used_mb" -gt "$MAX_MEM_MB" ]; then
      log_warn "High memory usage: ${mem_used_mb}MB (${MAX_MEM_MB}MB limit)"
    fi

    # Check disk usage
    local disk_usage
    disk_usage=$(get_disk_usage)

    if [ "$disk_usage" -gt "$MAX_DISK_PERCENT" ]; then
      log_warn "High disk usage: ${disk_usage}%"

      # Clean old files
      clean_old_files "/root/dilithion-fuzzers/fuzz_corpus" "$CORPUS_RETENTION_DAYS" "corpus"
      clean_old_files "/root/fuzz_logs" "$LOG_RETENTION_DAYS" "log"
    fi

    # Check for zombie processes
    local zombie_count
    zombie_count=$(check_zombie_processes)

    if [ "$zombie_count" -gt 0 ]; then
      log_warn "Found $zombie_count zombie fuzzer processes"
      # Note: Don't auto-kill, just warn. Zombies are usually harmless and killing might disrupt monitoring
    fi

    # Check for stale logs
    check_stale_logs

    # Heartbeat every hour
    if [ $((iteration % (HEARTBEAT_INTERVAL / CHECK_INTERVAL))) -eq 0 ]; then
      print_heartbeat
    fi

    # Sleep until next check
    sleep "$CHECK_INTERVAL"
  done
}

# Signal handlers for graceful shutdown
cleanup() {
  log_info "Resource monitor shutting down gracefully"
  exit 0
}

trap cleanup SIGTERM SIGINT

# Start monitoring
monitor_resources
