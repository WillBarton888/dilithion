#!/bin/bash
# Dilithion Mainnet Node - Wallet Backup Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/backup-wallet-2025-11-07.sh                         # Interactive backup
#   ./scripts/backup-wallet-2025-11-07.sh --auto                  # Automatic backup
#   ./scripts/backup-wallet-2025-11-07.sh --restore BACKUP_FILE  # Restore from backup
#   ./scripts/backup-wallet-2025-11-07.sh --verify BACKUP_FILE   # Verify backup
#
# Version: 1.0.0
# Created: 2025-11-07
# Mainnet Launch: 2026-01-01 00:00:00 UTC

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-07"

# Default paths
DEFAULT_DATA_DIR="$HOME/.dilithion"
DEFAULT_WALLET_FILE="wallet.dat"
DEFAULT_BACKUP_DIR="$HOME/dilithion-backups"

# Backup configuration
BACKUP_RETAIN_COUNT=10     # Keep last 10 backups
BACKUP_COMPRESS=true        # Compress backups
BACKUP_ENCRYPT=false        # Encrypt backups (requires gpg)
BACKUP_VERIFY=true          # Verify backup integrity

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==============================================================================
# Helper Functions
# ==============================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion Wallet - Backup Script                            ║"
    echo "║   Version: $SCRIPT_VERSION                                         ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
}

# Security warning
print_security_warning() {
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "                  SECURITY WARNING                        "
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    print_warning "Wallet backups contain your private keys!"
    print_warning "Anyone with access to wallet.dat can spend your funds."
    echo ""
    print_info "Security checklist:"
    echo "  ✓ Ensure wallet is encrypted (with strong passphrase)"
    echo "  ✓ Store backups on encrypted storage"
    echo "  ✓ Keep backups offline (USB drive, external HD)"
    echo "  ✓ Never upload backups to cloud without encryption"
    echo "  ✓ Test backup restoration periodically"
    echo "  ✓ Keep multiple backups in different locations"
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
}

# Check if wallet exists
check_wallet_exists() {
    WALLET_PATH="$DATA_DIR/$WALLET_FILE"

    if [ ! -f "$WALLET_PATH" ]; then
        print_error "Wallet not found: $WALLET_PATH"
        print_info "Create a wallet first or specify correct data directory"
        exit 1
    fi

    print_success "Wallet found: $WALLET_PATH"

    # Get wallet size
    WALLET_SIZE=$(du -h "$WALLET_PATH" | cut -f1)
    print_info "Wallet size: $WALLET_SIZE"
}

# Check if wallet is encrypted
check_wallet_encrypted() {
    print_info "Checking wallet encryption..."

    # Try to detect if wallet is encrypted
    # Encrypted wallets typically start with different magic bytes
    # This is a heuristic check - not 100% reliable

    if command -v strings &> /dev/null; then
        if strings "$WALLET_PATH" | grep -q "mkey"; then
            print_success "Wallet appears to be encrypted"
            WALLET_ENCRYPTED=true
        else
            print_warning "WARNING: Wallet may not be encrypted!"
            print_warning "Encrypt your wallet immediately with:"
            print_warning "  curl -X POST http://localhost:8332 \\"
            print_warning "    -H \"Content-Type: application/json\" \\"
            print_warning "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"encryptwallet\",\"params\":[\"STRONG_PASSPHRASE\"],\"id\":1}'"
            WALLET_ENCRYPTED=false

            if [ "$AUTO_MODE" = false ]; then
                read -p "Continue backup anyway? (y/n) " -n 1 -r
                echo ""
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    print_info "Backup cancelled"
                    exit 0
                fi
            fi
        fi
    else
        print_warning "Cannot verify wallet encryption (strings command not found)"
        WALLET_ENCRYPTED="unknown"
    fi
}

# Create backup directory
create_backup_directory() {
    print_info "Creating backup directory: $BACKUP_DIR"

    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"  # Owner-only access

    print_success "Backup directory ready"
}

# Generate backup filename
generate_backup_filename() {
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILENAME="wallet-backup-$TIMESTAMP.dat"

    if [ "$BACKUP_COMPRESS" = true ]; then
        BACKUP_FILENAME="$BACKUP_FILENAME.gz"
    fi

    if [ "$BACKUP_ENCRYPT" = true ]; then
        BACKUP_FILENAME="$BACKUP_FILENAME.gpg"
    fi

    BACKUP_PATH="$BACKUP_DIR/$BACKUP_FILENAME"
}

# Create backup
create_backup() {
    print_info "Creating backup..."

    # Generate backup filename
    generate_backup_filename

    # Copy wallet file
    if [ "$BACKUP_COMPRESS" = true ]; then
        if [ "$BACKUP_ENCRYPT" = true ]; then
            # Compress and encrypt
            print_info "Compressing and encrypting backup..."

            if ! command -v gpg &> /dev/null; then
                print_error "gpg not found. Install gnupg to use encryption."
                exit 1
            fi

            # Prompt for encryption passphrase
            gzip -c "$WALLET_PATH" | gpg --symmetric --cipher-algo AES256 -o "$BACKUP_PATH"
        else
            # Compress only
            print_info "Compressing backup..."
            gzip -c "$WALLET_PATH" > "$BACKUP_PATH"
        fi
    elif [ "$BACKUP_ENCRYPT" = true ]; then
        # Encrypt only
        print_info "Encrypting backup..."

        if ! command -v gpg &> /dev/null; then
            print_error "gpg not found. Install gnupg to use encryption."
            exit 1
        fi

        gpg --symmetric --cipher-algo AES256 -o "$BACKUP_PATH" "$WALLET_PATH"
    else
        # Plain copy
        cp "$WALLET_PATH" "$BACKUP_PATH"
    fi

    # Set restrictive permissions
    chmod 600 "$BACKUP_PATH"

    print_success "Backup created: $BACKUP_PATH"

    # Get backup size
    BACKUP_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)
    print_info "Backup size: $BACKUP_SIZE"
}

# Verify backup integrity
verify_backup() {
    print_info "Verifying backup integrity..."

    VERIFY_FILE="${1:-$BACKUP_PATH}"

    if [ ! -f "$VERIFY_FILE" ]; then
        print_error "Backup file not found: $VERIFY_FILE"
        return 1
    fi

    # Check if file is readable
    if [ ! -r "$VERIFY_FILE" ]; then
        print_error "Cannot read backup file: $VERIFY_FILE"
        return 1
    fi

    # Verify based on backup type
    if [[ "$VERIFY_FILE" == *.gpg ]]; then
        print_info "Verifying encrypted backup..."
        # Try to decrypt to /dev/null to verify
        if gpg --decrypt "$VERIFY_FILE" > /dev/null 2>&1; then
            print_success "Encrypted backup verification: OK"
        else
            print_error "Encrypted backup verification failed"
            print_error "File may be corrupted or wrong passphrase"
            return 1
        fi
    elif [[ "$VERIFY_FILE" == *.gz ]]; then
        print_info "Verifying compressed backup..."
        if gzip -t "$VERIFY_FILE" 2>/dev/null; then
            print_success "Compressed backup verification: OK"
        else
            print_error "Compressed backup verification failed"
            print_error "File may be corrupted"
            return 1
        fi
    else
        # Plain file - check if readable
        if [ -s "$VERIFY_FILE" ]; then
            print_success "Backup verification: OK"
        else
            print_error "Backup verification failed: File is empty"
            return 1
        fi
    fi

    return 0
}

# Calculate checksum
calculate_checksum() {
    print_info "Calculating backup checksum..."

    if command -v sha256sum &> /dev/null; then
        CHECKSUM=$(sha256sum "$BACKUP_PATH" | cut -d' ' -f1)
        print_info "SHA256: $CHECKSUM"

        # Save checksum to file
        echo "$CHECKSUM  $BACKUP_FILENAME" > "$BACKUP_PATH.sha256"
        print_success "Checksum saved: $BACKUP_PATH.sha256"
    else
        print_warning "sha256sum not found. Skipping checksum."
    fi
}

# Rotate old backups
rotate_backups() {
    print_info "Rotating old backups (keeping last $BACKUP_RETAIN_COUNT)..."

    # Count backups
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/wallet-backup-*.dat* 2>/dev/null | wc -l)

    if [ "$BACKUP_COUNT" -gt "$BACKUP_RETAIN_COUNT" ]; then
        print_info "Found $BACKUP_COUNT backups, removing oldest..."

        # Remove oldest backups
        ls -1t "$BACKUP_DIR"/wallet-backup-*.dat* 2>/dev/null | \
            tail -n +$((BACKUP_RETAIN_COUNT + 1)) | \
            while read -r old_backup; do
                print_info "Removing old backup: $(basename "$old_backup")"
                rm -f "$old_backup"
                rm -f "$old_backup.sha256"  # Remove checksum too
            done

        print_success "Old backups removed"
    else
        print_info "Backup count: $BACKUP_COUNT (no rotation needed)"
    fi
}

# List backups
list_backups() {
    print_info "Available backups in: $BACKUP_DIR"
    echo ""

    if [ ! -d "$BACKUP_DIR" ]; then
        print_warning "Backup directory does not exist"
        return
    fi

    # List backups with details
    BACKUPS=$(ls -1t "$BACKUP_DIR"/wallet-backup-*.dat* 2>/dev/null)

    if [ -z "$BACKUPS" ]; then
        print_warning "No backups found"
    else
        printf "%-40s %10s %20s\n" "Filename" "Size" "Date"
        printf "%s\n" "────────────────────────────────────────────────────────────────────"

        echo "$BACKUPS" | while read -r backup; do
            FILENAME=$(basename "$backup")
            SIZE=$(du -h "$backup" | cut -f1)
            DATE=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1,2 | cut -d. -f1)
            printf "%-40s %10s %20s\n" "$FILENAME" "$SIZE" "$DATE"
        done
    fi

    echo ""
}

# Restore backup
restore_backup() {
    RESTORE_FILE="$1"

    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "                  WALLET RESTORE                          "
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    print_warning "This will REPLACE your current wallet with the backup!"
    print_warning "Current wallet will be backed up before restoration."
    echo ""

    if [ -z "$RESTORE_FILE" ]; then
        print_error "No backup file specified"
        print_info "Usage: $0 --restore /path/to/wallet-backup.dat"
        exit 1
    fi

    if [ ! -f "$RESTORE_FILE" ]; then
        print_error "Backup file not found: $RESTORE_FILE"
        exit 1
    fi

    # Verify backup before restoring
    if ! verify_backup "$RESTORE_FILE"; then
        print_error "Backup verification failed. Aborting restore."
        exit 1
    fi

    # Confirm restoration
    echo ""
    read -p "Continue with restoration? (type 'yes' to confirm): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        print_info "Restoration cancelled"
        exit 0
    fi

    # Check if node is running
    if pgrep -x "dilithion-node" > /dev/null || systemctl is-active --quiet dilithion 2>/dev/null; then
        print_error "Node is running. Stop node before restoring wallet."
        print_info "Stop with: sudo systemctl stop dilithion"
        print_info "Or: killall dilithion-node"
        exit 1
    fi

    # Backup current wallet
    if [ -f "$WALLET_PATH" ]; then
        print_info "Backing up current wallet..."
        CURRENT_BACKUP="$BACKUP_DIR/wallet-pre-restore-$(date +%Y%m%d-%H%M%S).dat"
        cp "$WALLET_PATH" "$CURRENT_BACKUP"
        print_success "Current wallet backed up: $CURRENT_BACKUP"
    fi

    # Restore based on backup type
    print_info "Restoring wallet from backup..."

    if [[ "$RESTORE_FILE" == *.gpg ]]; then
        # Decrypt (and decompress if .gz.gpg)
        if [[ "$RESTORE_FILE" == *.gz.gpg ]]; then
            gpg --decrypt "$RESTORE_FILE" | gunzip > "$WALLET_PATH"
        else
            gpg --decrypt "$RESTORE_FILE" > "$WALLET_PATH"
        fi
    elif [[ "$RESTORE_FILE" == *.gz ]]; then
        # Decompress
        gunzip -c "$RESTORE_FILE" > "$WALLET_PATH"
    else
        # Plain copy
        cp "$RESTORE_FILE" "$WALLET_PATH"
    fi

    # Set permissions
    chmod 600 "$WALLET_PATH"

    print_success "Wallet restored successfully"
    echo ""
    print_info "Next steps:"
    echo "  1. Start node: sudo systemctl start dilithion"
    echo "  2. Verify wallet access (may need passphrase)"
    echo "  3. Check balance with RPC"
    echo ""
    print_warning "If restoration failed, current wallet backed up at:"
    print_warning "  $CURRENT_BACKUP"
    echo ""
}

# Export private keys
export_private_keys() {
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "              PRIVATE KEY EXPORT                          "
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    print_warning "DANGER: Private keys allow complete control of funds!"
    print_warning "Store exported keys in secure, offline location."
    echo ""

    read -p "Continue with private key export? (type 'yes' to confirm): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        print_info "Export cancelled"
        exit 0
    fi

    # Generate export filename
    EXPORT_TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    EXPORT_FILE="$BACKUP_DIR/wallet-keys-$EXPORT_TIMESTAMP.txt"

    print_info "Exporting private keys via RPC..."
    print_warning "This requires node to be running and RPC accessible"

    # TODO: Implement RPC call to dump private keys
    print_warning "Private key export via RPC not yet implemented"
    print_info "Manual export:"
    print_info "  curl -X POST http://localhost:8332 \\"
    print_info "    -H \"Content-Type: application/json\" \\"
    print_info "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"dumpprivkey\",\"params\":[\"ADDRESS\"],\"id\":1}'"

    # Recommend encryption
    echo ""
    print_info "Encrypt exported keys with:"
    print_info "  gpg --symmetric --cipher-algo AES256 -o keys.txt.gpg keys.txt"
    print_info "  shred -u keys.txt  # Securely delete plain text"
    echo ""
}

# Print backup summary
print_summary() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Backup Complete!                                            ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    print_success "Wallet backed up successfully"
    echo ""
    print_info "Backup Details:"
    echo "  - Wallet: $WALLET_PATH"
    echo "  - Backup: $BACKUP_PATH"
    echo "  - Size: $BACKUP_SIZE"
    echo "  - Encrypted: $WALLET_ENCRYPTED"
    echo "  - Compressed: $BACKUP_COMPRESS"
    echo "  - Additional encryption: $BACKUP_ENCRYPT"
    echo ""
    print_info "Backup Location:"
    echo "  $BACKUP_PATH"
    echo ""
    print_info "Security Recommendations:"
    echo "  ✓ Copy backup to USB drive or external storage"
    echo "  ✓ Store in secure, offline location"
    echo "  ✓ Keep multiple copies in different locations"
    echo "  ✓ Test restoration periodically"
    echo "  ✓ Never share wallet.dat or private keys"
    echo ""
    print_warning "Remember: Anyone with wallet.dat can access your funds!"
    echo ""
}

# ==============================================================================
# Main Backup Flow
# ==============================================================================

main() {
    # Parse command line arguments
    AUTO_MODE=false
    RESTORE_MODE=false
    VERIFY_MODE=false
    LIST_MODE=false
    EXPORT_KEYS=false
    RESTORE_FILE=""
    VERIFY_FILE=""

    for arg in "$@"; do
        case $arg in
            --auto)
                AUTO_MODE=true
                ;;
            --restore)
                RESTORE_MODE=true
                shift
                RESTORE_FILE="$1"
                ;;
            --verify)
                VERIFY_MODE=true
                shift
                VERIFY_FILE="$1"
                ;;
            --list)
                LIST_MODE=true
                ;;
            --export-keys)
                EXPORT_KEYS=true
                ;;
            --compress)
                BACKUP_COMPRESS=true
                ;;
            --no-compress)
                BACKUP_COMPRESS=false
                ;;
            --encrypt)
                BACKUP_ENCRYPT=true
                ;;
            --datadir=*)
                DATA_DIR="${arg#*=}"
                ;;
            --backup-dir=*)
                BACKUP_DIR="${arg#*=}"
                ;;
            --help)
                echo "Dilithion Wallet - Backup Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --auto                 Automatic backup (no prompts)"
                echo "  --restore FILE         Restore wallet from backup"
                echo "  --verify FILE          Verify backup integrity"
                echo "  --list                 List available backups"
                echo "  --export-keys          Export private keys (dangerous!)"
                echo "  --compress             Compress backup (default)"
                echo "  --no-compress          Don't compress backup"
                echo "  --encrypt              Encrypt backup with GPG"
                echo "  --datadir=PATH         Wallet data directory"
                echo "  --backup-dir=PATH      Backup storage directory"
                echo "  --help                 Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                                        # Interactive backup"
                echo "  $0 --auto --compress --encrypt            # Automatic encrypted backup"
                echo "  $0 --list                                 # List backups"
                echo "  $0 --restore /path/to/wallet-backup.dat   # Restore wallet"
                echo "  $0 --verify /path/to/wallet-backup.dat    # Verify backup"
                echo ""
                exit 0
                ;;
            *)
                print_error "Unknown option: $arg"
                print_info "Run with --help for usage information"
                exit 1
                ;;
        esac
    done

    # Set default data directory
    DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"
    WALLET_FILE="$DEFAULT_WALLET_FILE"
    BACKUP_DIR="${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}"

    # Print banner
    print_banner

    # Handle different modes
    if [ "$RESTORE_MODE" = true ]; then
        restore_backup "$RESTORE_FILE"
        exit 0
    fi

    if [ "$VERIFY_MODE" = true ]; then
        verify_backup "$VERIFY_FILE"
        exit 0
    fi

    if [ "$LIST_MODE" = true ]; then
        list_backups
        exit 0
    fi

    if [ "$EXPORT_KEYS" = true ]; then
        export_private_keys
        exit 0
    fi

    # Normal backup flow
    print_security_warning

    # Confirm backup
    if [ "$AUTO_MODE" = false ]; then
        read -p "Continue with backup? (y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Backup cancelled"
            exit 0
        fi
    fi

    # Check wallet exists
    check_wallet_exists

    # Check wallet encryption
    check_wallet_encrypted

    # Create backup directory
    create_backup_directory

    # Create backup
    create_backup

    # Verify backup
    if [ "$BACKUP_VERIFY" = true ]; then
        verify_backup
    fi

    # Calculate checksum
    calculate_checksum

    # Rotate old backups
    rotate_backups

    # Print summary
    print_summary
}

# Run main function
main "$@"
