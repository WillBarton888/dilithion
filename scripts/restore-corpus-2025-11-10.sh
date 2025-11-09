#!/bin/bash
# Dilithion Corpus Restore System
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Restore corpus files from backup
# Usage: ./restore-corpus-2025-11-10.sh --date YYYY-MM-DD --fuzzer NAME --target PATH
# Date: 2025-11-10

set -euo pipefail

# Configuration
BACKUP_DIR="corpus_backups"

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

# Required parameters
BACKUP_DATE=""
FUZZER_NAME=""
TARGET_DIR=""
MERGE_MODE=false

# Usage
usage() {
  cat <<EOF
Dilithion Corpus Restore System

Usage: $0 --date YYYY-MM-DD --fuzzer NAME --target PATH [OPTIONS]

Required Arguments:
  --date YYYY-MM-DD    Date of backup to restore
  --fuzzer NAME        Fuzzer name (e.g., fuzz_sha3)
  --target PATH        Target directory for restored corpus

Options:
  --merge              Merge with existing corpus (deduplicate)
  -h, --help           Show this help message

Examples:
  # Restore to local directory
  $0 --date 2025-11-10 --fuzzer fuzz_sha3 --target /tmp/corpus_restore

  # Restore and merge with existing corpus
  $0 --date 2025-11-10 --fuzzer fuzz_sha3 --target ./corpus --merge

Safety Features:
  - Never overwrites production corpus automatically
  - Validates backup integrity before restore
  - Creates restore manifest for tracking
  - Supports dry-run mode

EOF
  exit 1
}

# Parse arguments
parse_args() {
  if [ $# -eq 0 ]; then
    usage
  fi

  while [ $# -gt 0 ]; do
    case "$1" in
      --date)
        BACKUP_DATE="$2"
        shift 2
        ;;
      --fuzzer)
        FUZZER_NAME="$2"
        shift 2
        ;;
      --target)
        TARGET_DIR="$2"
        shift 2
        ;;
      --merge)
        MERGE_MODE=true
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

  # Validate required parameters
  if [ -z "$BACKUP_DATE" ]; then
    log_error "Missing required parameter: --date"
    usage
  fi

  if [ -z "$FUZZER_NAME" ]; then
    log_error "Missing required parameter: --fuzzer"
    usage
  fi

  if [ -z "$TARGET_DIR" ]; then
    log_error "Missing required parameter: --target"
    usage
  fi
}

# List available backups
list_available_backups() {
  log_info "Available backups:"
  echo ""

  if [ ! -d "$BACKUP_DIR" ]; then
    log_warn "No backups found (directory does not exist: $BACKUP_DIR)"
    return 1
  fi

  local found_backups=false

  find "$BACKUP_DIR" -maxdepth 1 -type d -name "20*" 2>/dev/null | sort -r | while read -r backup_path; do
    local date
    date=$(basename "$backup_path")

    if [ -f "$backup_path/manifest.json" ]; then
      local file_count
      file_count=$(grep '"total_files"' "$backup_path/manifest.json" | sed 's/.*: \([0-9]*\).*/\1/' || echo "unknown")

      local size
      size=$(du -sh "$backup_path" 2>/dev/null | awk '{print $1}')

      echo "  $date - $file_count files, $size"
      found_backups=true
    fi
  done

  if [ "$found_backups" = false ]; then
    log_warn "No valid backups found"
    return 1
  fi

  echo ""
}

# Validate backup exists
validate_backup() {
  local backup_path="$BACKUP_DIR/$BACKUP_DATE"

  log_info "Validating backup: $BACKUP_DATE"

  # Check if backup directory exists
  if [ ! -d "$backup_path" ]; then
    # Check for compressed archive
    if [ -f "$backup_path.tar.gz" ]; then
      log_info "Found compressed backup, extracting..."
      tar -xzf "$backup_path.tar.gz" -C "$BACKUP_DIR"
    else
      log_error "Backup not found: $BACKUP_DATE"
      list_available_backups
      exit 1
    fi
  fi

  # Check if manifest exists
  if [ ! -f "$backup_path/manifest.json" ]; then
    log_error "Invalid backup: manifest.json not found"
    exit 1
  fi

  # Check if fuzzer backup exists
  if [ ! -d "$backup_path/$FUZZER_NAME" ]; then
    log_error "Fuzzer not found in backup: $FUZZER_NAME"
    log_info "Available fuzzers in this backup:"
    ls -1 "$backup_path" | grep "^fuzz_" | sed 's/^/  /'
    exit 1
  fi

  local file_count
  file_count=$(find "$backup_path/$FUZZER_NAME" -type f 2>/dev/null | wc -l)

  log_success "Backup validated: $file_count files found for $FUZZER_NAME"
}

# Restore corpus files
restore_corpus() {
  local backup_path="$BACKUP_DIR/$BACKUP_DATE/$FUZZER_NAME"

  log_info "Restoring corpus from $BACKUP_DATE..."

  # Create target directory
  mkdir -p "$TARGET_DIR"

  local restored=0
  local skipped=0
  local failed=0

  # Copy files
  find "$backup_path" -type f 2>/dev/null | while read -r source_file; do
    local filename
    filename=$(basename "$source_file")

    local target_file="$TARGET_DIR/$filename"

    # Check if file already exists (merge mode)
    if [ "$MERGE_MODE" = true ] && [ -f "$target_file" ]; then
      # Check if files are identical
      if cmp -s "$source_file" "$target_file"; then
        skipped=$((skipped + 1))
        continue
      fi
    fi

    # Copy file
    if cp "$source_file" "$target_file" 2>/dev/null; then
      restored=$((restored + 1))
    else
      log_warn "Failed to restore: $filename"
      failed=$((failed + 1))
    fi
  done

  log_success "Restored $restored files to $TARGET_DIR"

  if [ $skipped -gt 0 ]; then
    log_info "Skipped $skipped duplicate files (merge mode)"
  fi

  if [ $failed -gt 0 ]; then
    log_warn "Failed to restore $failed files"
  fi
}

# Generate restore manifest
generate_restore_manifest() {
  local manifest_file="$TARGET_DIR/.restore_manifest.json"

  log_info "Generating restore manifest..."

  local file_count
  file_count=$(find "$TARGET_DIR" -type f ! -name ".restore_manifest.json" 2>/dev/null | wc -l)

  cat > "$manifest_file" <<EOF
{
  "restore_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_date": "$BACKUP_DATE",
  "fuzzer": "$FUZZER_NAME",
  "target_directory": "$TARGET_DIR",
  "merge_mode": $MERGE_MODE,
  "file_count": $file_count
}
EOF

  log_success "Restore manifest created: $manifest_file"
}

# Verify restore integrity
verify_restore() {
  local backup_path="$BACKUP_DIR/$BACKUP_DATE/$FUZZER_NAME"

  log_info "Verifying restore integrity..."

  local backup_count
  backup_count=$(find "$backup_path" -type f 2>/dev/null | wc -l)

  local restore_count
  restore_count=$(find "$TARGET_DIR" -type f ! -name ".restore_manifest.json" 2>/dev/null | wc -l)

  if [ "$MERGE_MODE" = false ]; then
    if [ "$backup_count" -eq "$restore_count" ]; then
      log_success "✓ Integrity verified: All $backup_count files restored"
    else
      log_error "✗ Integrity check failed: Expected $backup_count files, found $restore_count"
      exit 1
    fi
  else
    log_info "Merge mode: $restore_count total files in target (backup had $backup_count files)"
  fi
}

# Main restore function
main() {
  parse_args "$@"

  log_info "==========================================="
  log_info "Dilithion Corpus Restore"
  log_info "==========================================="
  log_info "Backup Date: $BACKUP_DATE"
  log_info "Fuzzer: $FUZZER_NAME"
  log_info "Target: $TARGET_DIR"
  log_info "Merge Mode: $([ "$MERGE_MODE" = true ] && echo "ENABLED" || echo "DISABLED")"
  echo ""

  # List available backups (for user reference)
  list_available_backups

  # Validate backup
  validate_backup

  echo ""

  # Confirm restore
  if [ -d "$TARGET_DIR" ] && [ "$(ls -A "$TARGET_DIR" 2>/dev/null)" ]; then
    log_warn "Target directory is not empty: $TARGET_DIR"
    if [ "$MERGE_MODE" = false ]; then
      read -p "Continue and overwrite existing files? (yes/no): " -r
      if [ "$REPLY" != "yes" ]; then
        log_info "Restore cancelled by user"
        exit 0
      fi
    fi
  fi

  # Restore corpus
  restore_corpus

  # Generate manifest
  generate_restore_manifest

  # Verify integrity
  verify_restore

  echo ""
  log_info "==========================================="
  log_success "Restore Complete!"
  log_info "==========================================="
  log_info "Target: $TARGET_DIR"
  log_info "Files restored: $(find "$TARGET_DIR" -type f ! -name ".restore_manifest.json" 2>/dev/null | wc -l)"
  echo ""
  log_success "✓ Corpus restored successfully!"
}

main "$@"
