#!/bin/bash
# Dilithion Corpus Backup Pruning
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Remove old corpus backups to save disk space
# Usage: ./prune-corpus-backup-2025-11-10.sh [--days N] [--dry-run]
# Date: 2025-11-10

set -euo pipefail

# Configuration
BACKUP_DIR="corpus_backups"
RETENTION_DAYS=30

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

# Usage
usage() {
  cat <<EOF
Dilithion Corpus Backup Pruning

Usage: $0 [OPTIONS]

Options:
  --days N       Retention period in days (default: 30)
  --dry-run      Show what would be pruned without deleting
  -h, --help     Show this help message

Examples:
  $0                    # Prune backups older than 30 days
  $0 --days 60          # Prune backups older than 60 days
  $0 --dry-run          # Preview what would be pruned

Safety:
  - Always keeps backups from the last N days
  - Shows detailed list before deletion
  - Supports dry-run mode for safety

EOF
  exit 1
}

# Parse arguments
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --days)
        RETENTION_DAYS="$2"
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

# List all backups
list_backups() {
  log_info "Scanning backups in $BACKUP_DIR..."
  echo ""

  if [ ! -d "$BACKUP_DIR" ]; then
    log_warn "Backup directory does not exist: $BACKUP_DIR"
    return 1
  fi

  local total=0
  local total_size=0

  echo "Backup Date       Files    Size      Age (days)"
  echo "---------------------------------------------------"

  find "$BACKUP_DIR" -maxdepth 1 \( -type d -name "20*" -o -type f -name "*.tar.gz" \) 2>/dev/null | sort -r | while read -r backup_path; do
    local backup_name
    backup_name=$(basename "$backup_path" | sed 's/.tar.gz$//')

    local backup_date
    backup_date=$(echo "$backup_name" | grep -oP '^\d{4}-\d{2}-\d{2}' || echo "$backup_name")

    # Calculate age
    local backup_epoch
    backup_epoch=$(date -d "$backup_date" +%s 2>/dev/null || echo 0)
    local current_epoch
    current_epoch=$(date +%s)
    local age_days=$(( (current_epoch - backup_epoch) / 86400 ))

    # Get size and file count
    local size="N/A"
    local files="N/A"

    if [ -d "$backup_path" ]; then
      size=$(du -sh "$backup_path" 2>/dev/null | awk '{print $1}')
      if [ -f "$backup_path/manifest.json" ]; then
        files=$(grep '"total_files"' "$backup_path/manifest.json" | sed 's/.*: \([0-9]*\).*/\1/' || echo "?")
      fi
    elif [ -f "$backup_path" ]; then
      size=$(du -sh "$backup_path" 2>/dev/null | awk '{print $1}')
      files="archive"
    fi

    printf "%-16s  %-7s  %-8s  %d\n" "$backup_date" "$files" "$size" "$age_days"

    total=$((total + 1))
  done

  echo ""
  log_info "Total backups found: $total"
}

# Find old backups
find_old_backups() {
  local cutoff_date
  cutoff_date=$(date -d "$RETENTION_DAYS days ago" +%Y-%m-%d)

  log_info "Finding backups older than $RETENTION_DAYS days (before $cutoff_date)..."
  echo ""

  local old_backups=()

  # Find old directories
  while IFS= read -r backup_path; do
    local backup_name
    backup_name=$(basename "$backup_path" | sed 's/.tar.gz$//')

    local backup_date
    backup_date=$(echo "$backup_name" | grep -oP '^\d{4}-\d{2}-\d{2}' || echo "$backup_name")

    if [[ "$backup_date" < "$cutoff_date" ]]; then
      old_backups+=("$backup_path")
    fi
  done < <(find "$BACKUP_DIR" -maxdepth 1 \( -type d -name "20*" -o -type f -name "*.tar.gz" \) 2>/dev/null)

  echo "${old_backups[@]}"
}

# Prune old backups
prune_backups() {
  local old_backups
  IFS=' ' read -ra old_backups <<< "$(find_old_backups)"

  if [ ${#old_backups[@]} -eq 0 ]; then
    log_success "No backups to prune"
    return 0
  fi

  log_warn "Found ${#old_backups[@]} backup(s) to prune:"
  echo ""

  local total_size=0

  for backup_path in "${old_backups[@]}"; do
    local size
    size=$(du -sh "$backup_path" 2>/dev/null | awk '{print $1}')
    echo "  - $(basename "$backup_path") ($size)"

    # Calculate total size (convert to bytes for summing)
    local size_bytes
    size_bytes=$(du -sb "$backup_path" 2>/dev/null | awk '{print $1}')
    total_size=$((total_size + size_bytes))
  done

  echo ""
  local total_size_human
  total_size_human=$(numfmt --to=iec --suffix=B $total_size 2>/dev/null || echo "$total_size bytes")
  log_info "Total space to be freed: $total_size_human"
  echo ""

  if [ "$DRY_RUN" = true ]; then
    log_warn "[DRY-RUN] Would delete ${#old_backups[@]} backup(s)"
    return 0
  fi

  # Confirm deletion
  read -p "Delete these backups? (yes/no): " -r
  if [ "$REPLY" != "yes" ]; then
    log_info "Pruning cancelled by user"
    return 0
  fi

  # Delete backups
  local deleted=0
  for backup_path in "${old_backups[@]}"; do
    log_info "Deleting $(basename "$backup_path")..."
    if rm -rf "$backup_path" 2>/dev/null; then
      deleted=$((deleted + 1))
    else
      log_error "Failed to delete: $backup_path"
    fi
  done

  log_success "Pruned $deleted backup(s), freed $total_size_human"
}

# Main execution
main() {
  parse_args "$@"

  log_info "==========================================="
  log_info "Dilithion Corpus Backup Pruning"
  log_info "==========================================="
  log_info "Retention: $RETENTION_DAYS days"
  log_info "Mode: $([ "$DRY_RUN" = true ] && echo "DRY-RUN" || echo "LIVE")"
  echo ""

  # List all backups
  list_backups

  echo ""

  # Prune old backups
  prune_backups

  echo ""
  log_success "✓ Pruning complete!"
}

main "$@"
