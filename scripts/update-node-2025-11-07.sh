#!/bin/bash
# Dilithion Mainnet Node - Safe Update Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/update-node-2025-11-07.sh                     # Check and update
#   ./scripts/update-node-2025-11-07.sh --check-only        # Check version only
#   ./scripts/update-node-2025-11-07.sh --force             # Force update
#   ./scripts/update-node-2025-11-07.sh --rollback          # Rollback to backup
#
# Version: 1.0.0
# Created: 2025-11-07

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-07"

# Installation paths
INSTALL_DIR="/usr/local/bin"
BACKUP_DIR="/var/backups/dilithion"
DATA_DIR="$HOME/.dilithion"

# Update configuration
UPDATE_CHECK_URL="https://api.github.com/repos/your-org/dilithion/releases/latest"
BACKUP_RETAIN_COUNT=3

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
    echo "║   Dilithion Node - Safe Update Script                         ║"
    echo "║   Version: $SCRIPT_VERSION                                         ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        if [ -w "$INSTALL_DIR" ]; then
            print_info "Running as non-root with write access"
        else
            print_error "Root privileges required to update system-wide installation"
            print_info "Run with: sudo $0 $*"
            exit 1
        fi
    fi
}

# Get current version
get_current_version() {
    if [ -f "$INSTALL_DIR/dilithion-node" ]; then
        # Try to get version from binary
        # TODO: Add --version flag to dilithion-node
        CURRENT_VERSION="unknown"
        print_info "Current version: $CURRENT_VERSION"

        # Get binary modification time as version indicator
        CURRENT_BUILD_DATE=$(stat -c %y "$INSTALL_DIR/dilithion-node" 2>/dev/null | cut -d' ' -f1)
        if [ -n "$CURRENT_BUILD_DATE" ]; then
            print_info "Current build date: $CURRENT_BUILD_DATE"
        fi
    else
        print_error "dilithion-node not found at: $INSTALL_DIR/dilithion-node"
        exit 1
    fi
}

# Check for updates
check_for_updates() {
    print_info "Checking for updates..."

    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        print_error "curl not found. Please install curl to check for updates."
        exit 1
    fi

    # Check latest release
    # TODO: Update with actual repository URL
    print_warning "Update check not yet implemented"
    print_info "Manual update check:"
    print_info "  1. Visit: https://github.com/your-org/dilithion/releases"
    print_info "  2. Check for newer version"
    print_info "  3. Download and verify checksums"

    LATEST_VERSION="unknown"
    UPDATE_AVAILABLE=false

    if [ "$LATEST_VERSION" != "$CURRENT_VERSION" ]; then
        UPDATE_AVAILABLE=true
        print_info "Update available: $CURRENT_VERSION → $LATEST_VERSION"
        return 0
    else
        print_success "Already running latest version: $CURRENT_VERSION"
        return 1
    fi
}

# Check node status
check_node_status() {
    print_info "Checking node status..."

    # Check if systemd service exists
    if systemctl list-unit-files | grep -q dilithion.service; then
        NODE_RUNNING=$(systemctl is-active dilithion 2>/dev/null || echo "inactive")
        NODE_MANAGED_BY_SYSTEMD=true

        if [ "$NODE_RUNNING" = "active" ]; then
            print_info "Node status: Running (systemd)"
        else
            print_info "Node status: Stopped"
        fi
    else
        # Check if process is running
        if pgrep -x "dilithion-node" > /dev/null; then
            NODE_RUNNING="active"
            NODE_MANAGED_BY_SYSTEMD=false
            NODE_PID=$(pgrep -x "dilithion-node")
            print_info "Node status: Running (PID: $NODE_PID)"
        else
            NODE_RUNNING="inactive"
            NODE_MANAGED_BY_SYSTEMD=false
            print_info "Node status: Not running"
        fi
    fi
}

# Stop node safely
stop_node() {
    print_info "Stopping node..."

    if [ "$NODE_RUNNING" = "active" ]; then
        if [ "$NODE_MANAGED_BY_SYSTEMD" = true ]; then
            print_info "Stopping systemd service..."
            systemctl stop dilithion

            # Wait for graceful shutdown (up to 60 seconds)
            TIMEOUT=60
            while [ $TIMEOUT -gt 0 ] && systemctl is-active --quiet dilithion; do
                sleep 1
                TIMEOUT=$((TIMEOUT - 1))
            done

            if systemctl is-active --quiet dilithion; then
                print_error "Node did not stop gracefully. Forcing stop..."
                systemctl kill dilithion
                sleep 2
            fi

            print_success "Node stopped"
        else
            print_info "Sending SIGTERM to node (PID: $NODE_PID)..."
            kill -TERM "$NODE_PID"

            # Wait for graceful shutdown
            TIMEOUT=60
            while [ $TIMEOUT -gt 0 ] && kill -0 "$NODE_PID" 2>/dev/null; do
                sleep 1
                TIMEOUT=$((TIMEOUT - 1))
            done

            if kill -0 "$NODE_PID" 2>/dev/null; then
                print_error "Node did not stop gracefully. Forcing stop..."
                kill -KILL "$NODE_PID"
                sleep 2
            fi

            print_success "Node stopped"
        fi
    else
        print_info "Node not running, skipping stop"
    fi
}

# Start node
start_node() {
    print_info "Starting node..."

    if [ "$NODE_MANAGED_BY_SYSTEMD" = true ]; then
        systemctl start dilithion
        sleep 5

        if systemctl is-active --quiet dilithion; then
            print_success "Node started successfully"
        else
            print_error "Node failed to start"
            print_info "Check logs: sudo journalctl -u dilithion -xe"
            return 1
        fi
    else
        print_info "Starting node manually..."
        "$INSTALL_DIR/dilithion-node" --datadir="$DATA_DIR" &
        NODE_PID=$!
        sleep 5

        if kill -0 "$NODE_PID" 2>/dev/null; then
            print_success "Node started successfully (PID: $NODE_PID)"
        else
            print_error "Node failed to start"
            return 1
        fi
    fi

    return 0
}

# Backup current binary
backup_binary() {
    print_info "Backing up current binary..."

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Generate backup filename with timestamp
    BACKUP_TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/dilithion-node-$BACKUP_TIMESTAMP"

    # Copy current binary
    cp "$INSTALL_DIR/dilithion-node" "$BACKUP_FILE"
    chmod +x "$BACKUP_FILE"

    print_success "Binary backed up: $BACKUP_FILE"

    # Clean old backups (keep last N)
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/dilithion-node-* 2>/dev/null | wc -l)
    if [ "$BACKUP_COUNT" -gt "$BACKUP_RETAIN_COUNT" ]; then
        print_info "Cleaning old backups (keeping last $BACKUP_RETAIN_COUNT)..."
        ls -1t "$BACKUP_DIR"/dilithion-node-* | tail -n +$((BACKUP_RETAIN_COUNT + 1)) | xargs rm -f
        print_success "Old backups cleaned"
    fi
}

# Download new version
download_new_version() {
    print_info "Downloading new version..."

    # Create temporary directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    # TODO: Implement actual download
    print_warning "Download not yet implemented"
    print_info "Please download manually:"
    print_info "  1. Visit: https://github.com/your-org/dilithion/releases"
    print_info "  2. Download latest binary"
    print_info "  3. Verify checksums"
    print_info "  4. Place in: $TMP_DIR/dilithion-node"

    # For now, rebuild from source
    print_info "Building from source instead..."

    BUILD_DIR="$HOME/dilithion-build"
    cd "$BUILD_DIR/dilithion"

    # Update source
    git fetch origin
    git checkout main
    git pull origin main

    # Rebuild
    make clean
    make -j$(nproc) CXXFLAGS="-std=c++17 -Wall -Wextra -O3 -march=native"

    # Copy to temp
    cp dilithion-node "$TMP_DIR/dilithion-node"

    print_success "New version ready: $TMP_DIR/dilithion-node"

    NEW_BINARY="$TMP_DIR/dilithion-node"
}

# Verify new binary
verify_new_binary() {
    print_info "Verifying new binary..."

    # Check if file exists
    if [ ! -f "$NEW_BINARY" ]; then
        print_error "New binary not found: $NEW_BINARY"
        return 1
    fi

    # Check if executable
    if [ ! -x "$NEW_BINARY" ]; then
        print_error "New binary is not executable"
        return 1
    fi

    # Test binary
    if "$NEW_BINARY" --help &> /dev/null; then
        print_success "Binary verification: OK"
        return 0
    else
        print_error "Binary verification failed: --help test failed"
        return 1
    fi
}

# Install new binary
install_new_binary() {
    print_info "Installing new binary..."

    # Copy new binary to install directory
    cp "$NEW_BINARY" "$INSTALL_DIR/dilithion-node"
    chmod 755 "$INSTALL_DIR/dilithion-node"

    if [ "$EUID" -eq 0 ]; then
        chown root:root "$INSTALL_DIR/dilithion-node"
    fi

    print_success "New binary installed"
}

# Verify update success
verify_update() {
    print_info "Verifying update..."

    # Test if binary works
    if "$INSTALL_DIR/dilithion-node" --help &> /dev/null; then
        print_success "Update verification: OK"
        return 0
    else
        print_error "Update verification failed"
        return 1
    fi
}

# Rollback to previous version
rollback() {
    print_error "Update failed. Rolling back..."

    # Stop node
    stop_node

    # Find most recent backup
    LATEST_BACKUP=$(ls -1t "$BACKUP_DIR"/dilithion-node-* 2>/dev/null | head -1)

    if [ -z "$LATEST_BACKUP" ]; then
        print_error "No backup found for rollback"
        print_error "Manual intervention required"
        exit 1
    fi

    print_info "Rolling back to: $LATEST_BACKUP"

    # Restore backup
    cp "$LATEST_BACKUP" "$INSTALL_DIR/dilithion-node"
    chmod 755 "$INSTALL_DIR/dilithion-node"

    if [ "$EUID" -eq 0 ]; then
        chown root:root "$INSTALL_DIR/dilithion-node"
    fi

    print_success "Rollback complete"

    # Start node
    start_node

    if [ $? -eq 0 ]; then
        print_success "Node started successfully after rollback"
    else
        print_error "Node failed to start after rollback"
        print_error "Manual intervention required"
        exit 1
    fi
}

# Manual rollback (user requested)
manual_rollback() {
    print_info "Manual rollback requested..."

    # List available backups
    print_info "Available backups:"
    ls -lht "$BACKUP_DIR"/dilithion-node-* 2>/dev/null || print_error "No backups found"

    echo ""
    read -p "Enter backup filename to restore (or press Enter to cancel): " BACKUP_FILE

    if [ -z "$BACKUP_FILE" ]; then
        print_info "Rollback cancelled"
        exit 0
    fi

    BACKUP_PATH="$BACKUP_DIR/$BACKUP_FILE"

    if [ ! -f "$BACKUP_PATH" ]; then
        print_error "Backup not found: $BACKUP_PATH"
        exit 1
    fi

    # Stop node
    check_node_status
    stop_node

    # Restore backup
    print_info "Restoring: $BACKUP_PATH"
    cp "$BACKUP_PATH" "$INSTALL_DIR/dilithion-node"
    chmod 755 "$INSTALL_DIR/dilithion-node"

    if [ "$EUID" -eq 0 ]; then
        chown root:root "$INSTALL_DIR/dilithion-node"
    fi

    print_success "Rollback complete"

    # Start node
    start_node
}

# Print update summary
print_summary() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Update Complete!                                            ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    print_success "Node updated successfully"
    echo ""
    print_info "Update Summary:"
    echo "  - Previous version: $CURRENT_VERSION"
    echo "  - New version: $LATEST_VERSION"
    echo "  - Backup location: $BACKUP_DIR"
    echo ""
    print_info "Post-update checks:"
    echo ""
    echo "  1. Verify node is running:"
    if [ "$NODE_MANAGED_BY_SYSTEMD" = true ]; then
        echo "     sudo systemctl status dilithion"
    else
        echo "     ps aux | grep dilithion-node"
    fi
    echo ""
    echo "  2. Check blockchain sync:"
    echo "     curl -X POST http://localhost:8332 \\"
    echo "       -H \"Content-Type: application/json\" \\"
    echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}'"
    echo ""
    echo "  3. Verify wallet access:"
    echo "     curl -X POST http://localhost:8332 \\"
    echo "       -H \"Content-Type: application/json\" \\"
    echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":[],\"id\":1}'"
    echo ""
    print_info "Rollback:"
    echo "  If issues occur, rollback with:"
    echo "    $0 --rollback"
    echo ""
    print_success "Update complete!"
    echo ""
}

# ==============================================================================
# Main Update Flow
# ==============================================================================

main() {
    # Parse command line arguments
    CHECK_ONLY=false
    FORCE_UPDATE=false
    ROLLBACK_REQUESTED=false

    for arg in "$@"; do
        case $arg in
            --check-only)
                CHECK_ONLY=true
                ;;
            --force)
                FORCE_UPDATE=true
                ;;
            --rollback)
                ROLLBACK_REQUESTED=true
                ;;
            --help)
                echo "Dilithion Node - Safe Update Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --check-only      Check for updates without installing"
                echo "  --force           Force update even if already latest"
                echo "  --rollback        Rollback to previous version"
                echo "  --help            Show this help message"
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

    # Print banner
    print_banner

    # Handle rollback
    if [ "$ROLLBACK_REQUESTED" = true ]; then
        manual_rollback
        exit 0
    fi

    # Check root privileges
    check_root

    # Get current version
    get_current_version

    # Check for updates
    if check_for_updates || [ "$FORCE_UPDATE" = true ]; then
        if [ "$CHECK_ONLY" = true ]; then
            print_info "Update available. Run without --check-only to install."
            exit 0
        fi
    else
        if [ "$FORCE_UPDATE" = false ]; then
            print_success "No update needed"
            exit 0
        fi
    fi

    # Confirm update
    echo ""
    print_warning "This will update dilithion-node"
    print_info "Current version: $CURRENT_VERSION"
    print_info "New version: $LATEST_VERSION"
    read -p "Continue? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Update cancelled"
        exit 0
    fi

    # Check node status
    check_node_status

    # Stop node
    stop_node

    # Backup current binary
    backup_binary

    # Download new version
    download_new_version

    # Verify new binary
    if ! verify_new_binary; then
        print_error "Binary verification failed. Aborting update."
        start_node
        exit 1
    fi

    # Install new binary
    install_new_binary

    # Verify update
    if ! verify_update; then
        rollback
        exit 1
    fi

    # Start node
    if ! start_node; then
        rollback
        exit 1
    fi

    # Print summary
    print_summary
}

# Run main function
main "$@"
