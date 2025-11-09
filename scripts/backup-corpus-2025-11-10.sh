#!/bin/bash
# Dilithion Corpus Backup System
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Backup interesting corpus files from production nodes
# Usage: ./backup-corpus-2025-11-10.sh [--fuzzer NAME] [--dry-run]
# Date: 2025-11-10

set -euo pipefail

# Configuration
BACKUP_DIR="corpus_backups"
BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_PATH="$BACKUP_DIR/$BACKUP_DATE"
MAX_FILES_PER_FUZZER=100
MAX_FILE_SIZE_KB=1024  # 1MB max per file

# Production nodes
declare -A NODES
NODES[singapore]="188.166.255.63"
NODES[nyc]="134.122.4.164"
NODES[london]="209.97.177.197"

# Fuzzer tiers
declare -A FUZZER_NODES
FUZZER_NODES[fuzz_difficulty]="singapore"
FUZZER_NODES[fuzz_transaction]="nyc"
FUZZER_NODES[fuzz_sha3]="london"

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

# Flags
DRY_RUN=false
SPECIFIC_FUZZER=""

# Usage
usage() {
  cat <<EOF
Dilithion Corpus Backup System

Usage: $0 [OPTIONS]

Options:
  --fuzzer NAME     Backup only specific fuzzer (e.g., fuzz_sha3)
  --dry-run         Show what would be backed up without doing it
  -h, --help        Show this help message

Examples:
  $0                           # Backup all fuzzers
  $0 --fuzzer fuzz_sha3        # Backup only fuzz_sha3
  $0 --dry-run                 # Preview backup

Output:
  corpus_backups/YYYY-MM-DD/
    ├── manifest.json          # Metadata about backup
    ├── fuzz_difficulty/       # Top 100 corpus files
    ├── fuzz_transaction/
    └── fuzz_sha3/

EOF
  exit 1
}

# Parse arguments
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --fuzzer)
        SPECIFIC_FUZZER="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      -h|--help)
        usage
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        ;;
    esac
  done
}

# Get interesting corpus files from a node
get_interesting_corpus_files() {
  local node_ip="$1"
  local fuzzer_name="$2"
  local corpus_dir="/root/dilithion-fuzzers/fuzz_corpus/${fuzzer_name#fuzz_}"

  log_info "Querying $fuzzer_name corpus on $node_ip..."

  # Get corpus files sorted by size (smaller = more interesting for coverage)
  # Also check modification time (recently created = new coverage)
  local file_list
  file_list=$(ssh root@"$node_ip" "
    if [ -d '$corpus_dir' ]; then
      find '$corpus_dir' -type f -size -${MAX_FILE_SIZE_KB}k -printf '%s %T@ %p\n' 2>/dev/null | \
      sort -n -k1,1 -k2,2r | \
      head -${MAX_FILES_PER_FUZZER} | \
      awk '{print \$3}'
    fi
  " 2>/dev/null || echo "")

  if [ -z "$file_list" ]; then
    log_warn "No corpus files found for $fuzzer_name on $node_ip"
    return 1
  fi

  local file_count
  file_count=$(echo "$file_list" | wc -l)
  log_success "Found $file_count interesting corpus files for $fuzzer_name"

  echo "$file_list"
}

# Download corpus files from node
download_corpus_files() {
  local node_ip="$1"
  local fuzzer_name="$2"
  local file_list="$3"
  local local_dir="$BACKUP_PATH/$fuzzer_name"

  if [ "$DRY_RUN" = true ]; then
    log_info "[DRY-RUN] Would download $(echo "$file_list" | wc -l) files to $local_dir"
    return 0
  fi

  # Create local directory
  mkdir -p "$local_dir"

  log_info "Downloading corpus files for $fuzzer_name..."

  local downloaded=0
  local failed=0

  while IFS= read -r remote_file; do
    if [ -z "$remote_file" ]; then
      continue
    fi

    local filename
    filename=$(basename "$remote_file")
    local local_file="$local_dir/$filename"

    # Download file
    if scp -q "root@${node_ip}:${remote_file}" "$local_file" 2>/dev/null; then
      downloaded=$((downloaded + 1))
    else
      log_warn "Failed to download: $filename"
      failed=$((failed + 1))
    fi
  done <<< "$file_list"

  log_success "Downloaded $downloaded files for $fuzzer_name (failed: $failed)"
}

# Generate backup manifest
generate_manifest() {
  local manifest_file="$BACKUP_PATH/manifest.json"

  if [ "$DRY_RUN" = true ]; then
    log_info "[DRY-RUN] Would generate manifest: $manifest_file"
    return 0
  fi

  log_info "Generating backup manifest..."

  local total_files=0
  local total_size=0

  # Count files and calculate size
  if [ -d "$BACKUP_PATH" ]; then
    total_files=$(find "$BACKUP_PATH" -type f ! -name "manifest.json" 2>/dev/null | wc -l)
    total_size=$(du -sb "$BACKUP_PATH" 2>/dev/null | awk '{print $1}')
  fi

  cat > "$manifest_file" <<EOF
{
  "backup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_files": $total_files,
  "total_size_bytes": $total_size,
  "max_files_per_fuzzer": $MAX_FILES_PER_FUZZER,
  "max_file_size_kb": $MAX_FILE_SIZE_KB,
  "fuzzers": [
EOF

  local first=true
  for fuzzer in "${!FUZZER_NODES[@]}"; do
    local fuzzer_dir="$BACKUP_PATH/$fuzzer"
    if [ -d "$fuzzer_dir" ]; then
      if [ "$first" = true ]; then
        first=false
      else
        echo "," >> "$manifest_file"
      fi

      local file_count
      file_count=$(find "$fuzzer_dir" -type f 2>/dev/null | wc -l)

      local fuzzer_size
      fuzzer_size=$(du -sb "$fuzzer_dir" 2>/dev/null | awk '{print $1}')

      cat >> "$manifest_file" <<EOF
    {
      "name": "$fuzzer",
      "file_count": $file_count,
      "size_bytes": $fuzzer_size,
      "node": "${FUZZER_NODES[$fuzzer]}"
    }
EOF
    fi
  done

  cat >> "$manifest_file" <<EOF

  ]
}
EOF

  log_success "Manifest generated: $manifest_file"
}

# Compress backup
compress_backup() {
  if [ "$DRY_RUN" = true ]; then
    log_info "[DRY-RUN] Would compress backup to $BACKUP_PATH.tar.gz"
    return 0
  fi

  log_info "Compressing backup..."

  local archive_name="$BACKUP_PATH.tar.gz"

  if tar -czf "$archive_name" -C "$BACKUP_DIR" "$BACKUP_DATE" 2>/dev/null; then
    local archive_size
    archive_size=$(du -h "$archive_name" | awk '{print $1}')
    log_success "Backup compressed: $archive_name ($archive_size)"
  else
    log_error "Failed to compress backup"
    return 1
  fi
}

# Prune old backups
prune_old_backups() {
  local retention_days=30

  if [ "$DRY_RUN" = true ]; then
    log_info "[DRY-RUN] Would prune backups older than $retention_days days"
    return 0
  fi

  log_info "Pruning backups older than $retention_days days..."

  local pruned=0

  # Find and remove old backup directories
  find "$BACKUP_DIR" -maxdepth 1 -type d -name "20*" -mtime +$retention_days 2>/dev/null | while read -r old_dir; do
    log_info "Removing old backup: $(basename "$old_dir")"
    rm -rf "$old_dir"
    pruned=$((pruned + 1))
  done

  # Find and remove old backup archives
  find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" -mtime +$retention_days 2>/dev/null | while read -r old_archive; do
    log_info "Removing old archive: $(basename "$old_archive")"
    rm -f "$old_archive"
    pruned=$((pruned + 1))
  done

  if [ $pruned -gt 0 ]; then
    log_success "Pruned $pruned old backups"
  else
    log_info "No old backups to prune"
  fi
}

# Main backup function
backup_corpus() {
  log_info "==========================================="
  log_info "Dilithion Corpus Backup"
  log_info "==========================================="
  log_info "Date: $BACKUP_DATE"
  log_info "Mode: $([ "$DRY_RUN" = true ] && echo "DRY-RUN" || echo "LIVE")"
  echo ""

  # Create backup directory
  if [ "$DRY_RUN" = false ]; then
    mkdir -p "$BACKUP_PATH"
  fi

  local total_fuzzers=0
  local successful_fuzzers=0

  # Determine which fuzzers to backup
  local fuzzers_to_backup=()
  if [ -n "$SPECIFIC_FUZZER" ]; then
    fuzzers_to_backup=("$SPECIFIC_FUZZER")
  else
    fuzzers_to_backup=("${!FUZZER_NODES[@]}")
  fi

  # Backup each fuzzer
  for fuzzer in "${fuzzers_to_backup[@]}"; do
    total_fuzzers=$((total_fuzzers + 1))

    local node="${FUZZER_NODES[$fuzzer]}"
    local node_ip="${NODES[$node]}"

    log_info "Backing up $fuzzer from $node ($node_ip)..."

    # Get interesting files
    local file_list
    if file_list=$(get_interesting_corpus_files "$node_ip" "$fuzzer"); then
      # Download files
      if download_corpus_files "$node_ip" "$fuzzer" "$file_list"; then
        successful_fuzzers=$((successful_fuzzers + 1))
      fi
    fi

    echo ""
  done

  # Generate manifest
  generate_manifest

  # Compress backup
  compress_backup

  # Prune old backups
  prune_old_backups

  # Print summary
  echo ""
  log_info "==========================================="
  log_info "Backup Summary"
  log_info "==========================================="
  log_info "Date: $BACKUP_DATE"
  log_info "Fuzzers backed up: $successful_fuzzers / $total_fuzzers"
  log_info "Backup location: $BACKUP_PATH"
  if [ "$DRY_RUN" = false ]; then
    if [ -f "$BACKUP_PATH.tar.gz" ]; then
      local size
      size=$(du -h "$BACKUP_PATH.tar.gz" | awk '{print $1}')
      log_info "Archive size: $size"
    fi
  fi
  echo ""

  if [ $successful_fuzzers -eq $total_fuzzers ]; then
    log_success "✓ All fuzzers backed up successfully!"
  else
    log_warn "⚠ Some fuzzers failed to backup"
    exit 1
  fi
}

# Main execution
main() {
  parse_args "$@"

  # Check SSH connectivity
  log_info "Checking node connectivity..."
  for node_name in "${!NODES[@]}"; do
    local node_ip="${NODES[$node_name]}"
    if ssh -o ConnectTimeout=5 -o BatchMode=yes root@"$node_ip" "echo ok" >/dev/null 2>&1; then
      log_success "$node_name ($node_ip) - Connected"
    else
      log_error "$node_name ($node_ip) - Connection failed"
      exit 1
    fi
  done
  echo ""

  # Run backup
  backup_corpus
}

main "$@"
