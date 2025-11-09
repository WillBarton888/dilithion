#!/bin/bash
# Dilithion Automation Setup
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Configure automated daily corpus backups
# Usage: ./setup-automation-2025-11-10.sh
# Date: 2025-11-10

set -euo pipefail

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

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info "==========================================="
log_info "Dilithion Automation Setup"
log_info "==========================================="
log_info "Project root: $PROJECT_ROOT"
echo ""

# Check if backup script exists
if [ ! -f "$SCRIPT_DIR/backup-corpus-2025-11-10.sh" ]; then
  log_error "Backup script not found: $SCRIPT_DIR/backup-corpus-2025-11-10.sh"
  exit 1
fi

log_success "Backup script found"

# Check current crontab
log_info "Checking existing crontab entries..."
if crontab -l 2>/dev/null | grep -q "backup-corpus"; then
  log_warn "Found existing corpus backup cron job:"
  crontab -l 2>/dev/null | grep "backup-corpus"
  echo ""
  read -p "Replace existing cron job? (yes/no): " -r
  if [ "$REPLY" != "yes" ]; then
    log_info "Automation setup cancelled by user"
    exit 0
  fi
  # Remove old backup cron jobs
  crontab -l 2>/dev/null | grep -v "backup-corpus" | crontab -
  log_success "Removed old backup cron jobs"
fi

# Create cron job
log_info "Setting up daily corpus backup..."
echo ""
log_info "Schedule: Daily at 00:00 UTC (midnight)"
log_info "Command: $SCRIPT_DIR/backup-corpus-2025-11-10.sh"
log_info "Log: $PROJECT_ROOT/corpus-backup.log"
echo ""
read -p "Proceed with automation setup? (yes/no): " -r
if [ "$REPLY" != "yes" ]; then
  log_info "Automation setup cancelled by user"
  exit 0
fi

# Add cron job
(crontab -l 2>/dev/null; echo "# Dilithion daily corpus backup (added $(date +%Y-%m-%d))") | crontab -
(crontab -l 2>/dev/null; echo "0 0 * * * cd $PROJECT_ROOT && $SCRIPT_DIR/backup-corpus-2025-11-10.sh >> $PROJECT_ROOT/corpus-backup.log 2>&1") | crontab -

log_success "Cron job added successfully!"
echo ""

# Verify cron job
log_info "Verifying cron job..."
if crontab -l 2>/dev/null | grep -q "backup-corpus-2025-11-10.sh"; then
  log_success "✓ Cron job verified"
  echo ""
  log_info "Current crontab:"
  crontab -l | tail -3
else
  log_error "✗ Cron job verification failed"
  exit 1
fi

echo ""
log_info "==========================================="
log_success "Automation Setup Complete!"
log_info "==========================================="
log_info "Daily backup schedule: 00:00 UTC (midnight)"
log_info "Backup log: $PROJECT_ROOT/corpus-backup.log"
echo ""
log_info "To view backup logs:"
log_info "  tail -f $PROJECT_ROOT/corpus-backup.log"
echo ""
log_info "To view scheduled cron jobs:"
log_info "  crontab -l"
echo ""
log_info "To remove automation:"
log_info "  crontab -e  # Then delete the backup line"
echo ""
log_success "✓ Automation configured successfully!"
