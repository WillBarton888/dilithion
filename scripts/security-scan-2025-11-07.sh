#!/bin/bash
# Dilithion Mainnet - Automated Security Scan
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/security-scan-2025-11-07.sh                    # Full security scan
#   ./scripts/security-scan-2025-11-07.sh --quick            # Quick scan (skip intensive checks)
#   ./scripts/security-scan-2025-11-07.sh --report          # Generate detailed report
#   ./scripts/security-scan-2025-11-07.sh --fix             # Auto-fix fixable issues (with prompts)
#
# Version: 1.0.0
# Created: 2025-11-07

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-07"

# Scan mode
SCAN_MODE="full"  # full, quick
GENERATE_REPORT=false
AUTO_FIX=false

# Paths
DATA_DIR="$HOME/.dilithion"
BINARY_PATH="/usr/local/bin/dilithion-node"
CONFIG_FILE="$DATA_DIR/dilithion.conf"
WALLET_FILE="$DATA_DIR/wallet.dat"

# Scan results
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Report file
REPORT_FILE="security-scan-report-$(date +%Y%m%d-%H%M%S).txt"

# ==============================================================================
# Helper Functions
# ==============================================================================

print_header() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion Security Scan v$SCRIPT_VERSION                           ║"
    echo "║   $(date '+%Y-%m-%d %H:%M:%S %Z')                                       ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    [ "$GENERATE_REPORT" = true ] && echo "[PASS] $1" >> "$REPORT_FILE"
}

check_fail() {
    local severity="$2"  # CRITICAL, HIGH, MEDIUM
    echo -e "${RED}[FAIL]${NC} $1 ${RED}[$severity]${NC}"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$severity" in
        CRITICAL)
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
            ;;
        HIGH)
            HIGH_ISSUES=$((HIGH_ISSUES + 1))
            ;;
        MEDIUM)
            MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
            ;;
    esac

    [ "$GENERATE_REPORT" = true ] && echo "[FAIL] [$severity] $1" >> "$REPORT_FILE"
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNING_CHECKS=$((WARNING_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    [ "$GENERATE_REPORT" = true ] && echo "[WARN] $1" >> "$REPORT_FILE"
}

# ==============================================================================
# Security Checks
# ==============================================================================

# 1. Binary Verification
check_binary_security() {
    print_section "1. Binary Security"

    # Check binary exists
    if [ -f "$BINARY_PATH" ]; then
        check_pass "Binary exists: $BINARY_PATH"
    else
        check_fail "Binary not found: $BINARY_PATH" "CRITICAL"
        return 1
    fi

    # Check binary permissions
    local perms=$(stat -c %a "$BINARY_PATH" 2>/dev/null || stat -f %OLp "$BINARY_PATH" 2>/dev/null)
    if [ "$perms" = "755" ] || [ "$perms" = "555" ]; then
        check_pass "Binary permissions correct: $perms"
    else
        check_warn "Binary permissions unusual: $perms (expected 755 or 555)"
    fi

    # Check binary ownership
    local owner=$(stat -c %U "$BINARY_PATH" 2>/dev/null || stat -f %Su "$BINARY_PATH" 2>/dev/null)
    if [ "$owner" = "root" ] || [ "$owner" = "$USER" ]; then
        check_pass "Binary ownership: $owner"
    else
        check_warn "Binary owned by: $owner (unexpected)"
    fi

    # Check if binary is executable
    if [ -x "$BINARY_PATH" ]; then
        check_pass "Binary is executable"
    else
        check_fail "Binary is not executable" "HIGH"
    fi

    # Test binary execution
    if "$BINARY_PATH" --help &> /dev/null; then
        check_pass "Binary executes successfully"
    else
        check_fail "Binary fails to execute" "CRITICAL"
    fi
}

# 2. Network Configuration
check_network_security() {
    print_section "2. Network Security"

    # Check if node is running
    if pgrep -x "dilithion-node" > /dev/null || systemctl is-active --quiet dilithion 2>/dev/null; then
        check_pass "Node is running"

        # Check listening ports
        if command -v netstat &> /dev/null; then
            # Check P2P port (should be listening)
            if netstat -tuln | grep -q ":8444"; then
                check_pass "P2P port 8444 listening"
            else
                check_warn "P2P port 8444 not listening (node may not accept connections)"
            fi

            # Check RPC port (should be localhost only)
            if netstat -tuln | grep "127.0.0.1:8332" > /dev/null; then
                check_pass "RPC port 8332 bound to localhost only (secure)"
            elif netstat -tuln | grep ":8332" > /dev/null; then
                check_fail "RPC port 8332 exposed to network (INSECURE!)" "CRITICAL"
            else
                check_warn "RPC port 8332 not listening (RPC may be disabled)"
            fi
        else
            check_warn "netstat not available, skipping port checks"
        fi
    else
        check_warn "Node is not running (some checks skipped)"
    fi

    # Check firewall status
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            check_pass "UFW firewall is active"

            # Check if P2P port is allowed
            if ufw status | grep -q "8444"; then
                check_pass "P2P port 8444 allowed in firewall"
            else
                check_warn "P2P port 8444 not explicitly allowed in firewall"
            fi

            # Check if RPC port is blocked
            if ufw status | grep "8332" | grep -q "DENY"; then
                check_pass "RPC port 8332 blocked by firewall (secure)"
            elif ! ufw status | grep -q "8332"; then
                check_pass "RPC port 8332 not in firewall rules (default deny)"
            else
                check_fail "RPC port 8332 allowed in firewall (INSECURE!)" "CRITICAL"
            fi
        else
            check_warn "UFW firewall is inactive"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        if systemctl is-active --quiet firewalld; then
            check_pass "firewalld is active"

            # Check P2P port
            if firewall-cmd --list-ports | grep -q "8444/tcp"; then
                check_pass "P2P port 8444 allowed in firewall"
            else
                check_warn "P2P port 8444 not explicitly allowed in firewall"
            fi
        else
            check_warn "firewalld is inactive"
        fi
    else
        check_warn "No firewall detected (ufw or firewalld)"
    fi
}

# 3. Wallet Security
check_wallet_security() {
    print_section "3. Wallet Security"

    # Check if wallet exists
    if [ -f "$WALLET_FILE" ]; then
        check_pass "Wallet file exists: $WALLET_FILE"

        # Check wallet file permissions
        local perms=$(stat -c %a "$WALLET_FILE" 2>/dev/null || stat -f %OLp "$WALLET_FILE" 2>/dev/null)
        if [ "$perms" = "600" ]; then
            check_pass "Wallet file permissions correct: $perms (owner read/write only)"
        else
            check_fail "Wallet file permissions insecure: $perms (should be 600)" "HIGH"

            if [ "$AUTO_FIX" = true ]; then
                echo "  Fixing: chmod 600 $WALLET_FILE"
                chmod 600 "$WALLET_FILE"
                check_pass "Wallet file permissions fixed"
            fi
        fi

        # Check wallet encryption (heuristic)
        if command -v strings &> /dev/null; then
            if strings "$WALLET_FILE" | grep -q "mkey"; then
                check_pass "Wallet appears to be encrypted"
            else
                check_fail "Wallet may not be encrypted (CRITICAL SECURITY RISK!)" "CRITICAL"
                echo "       Action: Encrypt wallet immediately with RPC command encryptwallet"
            fi
        else
            check_warn "Cannot verify wallet encryption (strings command not available)"
        fi

        # Check for wallet backups
        BACKUP_DIR="$HOME/dilithion-backups"
        if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR"/wallet-backup-* 2>/dev/null | wc -l)" -gt 0 ]; then
            local backup_count=$(ls -1 "$BACKUP_DIR"/wallet-backup-* 2>/dev/null | wc -l)
            check_pass "Wallet backups found: $backup_count backup(s) in $BACKUP_DIR"
        else
            check_warn "No wallet backups found (run scripts/backup-wallet-2025-11-07.sh)"
        fi
    else
        check_warn "Wallet file does not exist (not created yet)"
    fi
}

# 4. Data Directory Security
check_data_directory_security() {
    print_section "4. Data Directory Security"

    # Check if data directory exists
    if [ -d "$DATA_DIR" ]; then
        check_pass "Data directory exists: $DATA_DIR"

        # Check permissions
        local perms=$(stat -c %a "$DATA_DIR" 2>/dev/null || stat -f %OLp "$DATA_DIR" 2>/dev/null)
        if [ "$perms" = "700" ]; then
            check_pass "Data directory permissions correct: $perms (owner access only)"
        else
            check_warn "Data directory permissions: $perms (recommended: 700)"

            if [ "$AUTO_FIX" = true ]; then
                read -p "  Fix permissions to 700? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    chmod 700 "$DATA_DIR"
                    check_pass "Data directory permissions fixed"
                fi
            fi
        fi

        # Check disk space
        local available_gb=$(df -BG "$DATA_DIR" | tail -1 | awk '{print $4}' | sed 's/G//')
        if [ "$available_gb" -ge 20 ]; then
            check_pass "Disk space available: ${available_gb}GB (sufficient)"
        elif [ "$available_gb" -ge 10 ]; then
            check_warn "Disk space available: ${available_gb}GB (low, minimum 20GB recommended)"
        else
            check_fail "Disk space critical: ${available_gb}GB (minimum 10GB required)" "HIGH"
        fi
    else
        check_warn "Data directory does not exist: $DATA_DIR (will be created on first run)"
    fi
}

# 5. RPC Security
check_rpc_security() {
    print_section "5. RPC Security"

    # Check if config file exists
    if [ -f "$CONFIG_FILE" ]; then
        check_pass "Configuration file exists: $CONFIG_FILE"

        # Check for RPC authentication
        if grep -q "rpcuser=" "$CONFIG_FILE" && grep -q "rpcpassword=" "$CONFIG_FILE"; then
            check_pass "RPC authentication configured"

            # Check password strength (basic check)
            local rpc_pass=$(grep "rpcpassword=" "$CONFIG_FILE" | cut -d= -f2)
            if [ ${#rpc_pass} -ge 12 ]; then
                check_pass "RPC password length adequate: ${#rpc_pass} characters"
            else
                check_warn "RPC password short: ${#rpc_pass} characters (recommend 12+)"
            fi
        else
            check_warn "RPC authentication not configured (recommended if RPC enabled)"
        fi

        # Check for RPC bind settings
        if grep -q "rpcbind=0.0.0.0" "$CONFIG_FILE" || grep -q "rpcallowip=" "$CONFIG_FILE"; then
            check_fail "RPC may be exposed to network (rpcbind=0.0.0.0 or rpcallowip set)" "CRITICAL"
            echo "       Action: Remove rpcbind and rpcallowip settings or bind to 127.0.0.1 only"
        else
            check_pass "RPC configuration appears secure (no external binding detected)"
        fi
    else
        check_warn "Configuration file does not exist (using defaults)"
    fi
}

# 6. System Security
check_system_security() {
    print_section "6. System Security"

    # Check if running as root (bad practice)
    if [ "$EUID" -eq 0 ]; then
        check_fail "Running as root (INSECURE! Create dedicated user)" "HIGH"
    else
        check_pass "Not running as root user: $USER"
    fi

    # Check system updates (Debian/Ubuntu)
    if command -v apt-get &> /dev/null; then
        if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
            local days_since_update=$(( ($(date +%s) - $(stat -c %Y /var/lib/apt/periodic/update-success-stamp)) / 86400 ))
            if [ "$days_since_update" -le 7 ]; then
                check_pass "System updates recent (${days_since_update} days ago)"
            else
                check_warn "System updates old (${days_since_update} days ago, run: sudo apt-get update && sudo apt-get upgrade)"
            fi
        else
            check_warn "Cannot determine system update status"
        fi
    fi

    # Check SELinux status (if available)
    if command -v getenforce &> /dev/null; then
        local selinux_status=$(getenforce)
        if [ "$selinux_status" = "Enforcing" ]; then
            check_pass "SELinux is enforcing"
        elif [ "$selinux_status" = "Permissive" ]; then
            check_warn "SELinux is permissive (recommend enforcing)"
        else
            check_warn "SELinux is disabled"
        fi
    fi
}

# 7. Dependency Verification
check_dependencies() {
    print_section "7. Dependencies"

    # Check required libraries
    if command -v ldd &> /dev/null && [ -f "$BINARY_PATH" ]; then
        # Check for RandomX library
        if ldd "$BINARY_PATH" | grep -q "librandomx"; then
            check_pass "RandomX library linked"
        else
            check_warn "RandomX library not detected in ldd output"
        fi

        # Check for LevelDB library
        if ldd "$BINARY_PATH" | grep -q "libleveldb"; then
            check_pass "LevelDB library linked"
        else
            check_fail "LevelDB library not found (required dependency)" "CRITICAL"
        fi
    else
        check_warn "ldd not available or binary not found, skipping library checks"
    fi
}

# 8. Process Security
check_process_security() {
    print_section "8. Process Security"

    # Check if node is running
    if pgrep -x "dilithion-node" > /dev/null; then
        local node_pid=$(pgrep -x "dilithion-node")
        check_pass "Node process running (PID: $node_pid)"

        # Check process limits
        if [ -f "/proc/$node_pid/limits" ]; then
            local max_files=$(grep "Max open files" /proc/$node_pid/limits | awk '{print $4}')
            if [ "$max_files" -ge 4096 ]; then
                check_pass "File descriptor limit adequate: $max_files"
            else
                check_warn "File descriptor limit low: $max_files (recommend 4096+)"
            fi
        fi

        # Check if process is running under systemd
        if systemctl is-active --quiet dilithion 2>/dev/null; then
            check_pass "Node managed by systemd"

            # Check systemd security features
            if systemctl show dilithion -p NoNewPrivileges | grep -q "yes"; then
                check_pass "Systemd: NoNewPrivileges enabled"
            else
                check_warn "Systemd: NoNewPrivileges not enabled"
            fi

            if systemctl show dilithion -p PrivateTmp | grep -q "yes"; then
                check_pass "Systemd: PrivateTmp enabled"
            else
                check_warn "Systemd: PrivateTmp not enabled"
            fi
        else
            check_warn "Node not managed by systemd (manual execution)"
        fi
    else
        check_warn "Node is not running"
    fi
}

# 9. Monitoring Security
check_monitoring_security() {
    print_section "9. Monitoring Security"

    # Check if Prometheus is running and bound correctly
    if pgrep -x "prometheus" > /dev/null; then
        check_pass "Prometheus is running"

        if command -v netstat &> /dev/null; then
            if netstat -tuln | grep "127.0.0.1:9090" > /dev/null; then
                check_pass "Prometheus bound to localhost only (secure)"
            elif netstat -tuln | grep ":9090" > /dev/null; then
                check_warn "Prometheus exposed to network (consider restricting access)"
            fi
        fi
    else
        check_warn "Prometheus not running (monitoring recommended)"
    fi

    # Check if Grafana is running
    if pgrep -x "grafana-server" > /dev/null || pgrep -f "grafana" > /dev/null; then
        check_warn "Grafana is running (ensure authentication is enabled)"
    fi
}

# ==============================================================================
# Report Generation
# ==============================================================================

generate_summary() {
    print_section "Security Scan Summary"

    echo ""
    echo "Total Checks:      $TOTAL_CHECKS"
    echo -e "Passed:            ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Failed:            ${RED}$FAILED_CHECKS${NC}"
    echo -e "Warnings:          ${YELLOW}$WARNING_CHECKS${NC}"
    echo ""
    echo "Issue Severity:"
    echo -e "  Critical:        ${RED}$CRITICAL_ISSUES${NC}"
    echo -e "  High:            ${YELLOW}$HIGH_ISSUES${NC}"
    echo -e "  Medium:          ${YELLOW}$MEDIUM_ISSUES${NC}"
    echo ""

    # Overall assessment
    if [ "$CRITICAL_ISSUES" -eq 0 ] && [ "$HIGH_ISSUES" -eq 0 ]; then
        echo -e "${GREEN}Overall Assessment: PASS${NC}"
        echo "Security posture is good. Address warnings for optimal security."
        OVERALL_STATUS=0
    elif [ "$CRITICAL_ISSUES" -eq 0 ]; then
        echo -e "${YELLOW}Overall Assessment: PASS WITH WARNINGS${NC}"
        echo "Security is acceptable but improvements recommended."
        OVERALL_STATUS=0
    else
        echo -e "${RED}Overall Assessment: FAIL${NC}"
        echo "Critical security issues detected. Address immediately before launch."
        OVERALL_STATUS=1
    fi

    echo ""

    if [ "$GENERATE_REPORT" = true ]; then
        echo "Detailed report saved to: $REPORT_FILE"
    fi

    return $OVERALL_STATUS
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    # Parse arguments
    for arg in "$@"; do
        case $arg in
            --quick)
                SCAN_MODE="quick"
                ;;
            --report)
                GENERATE_REPORT=true
                ;;
            --fix)
                AUTO_FIX=true
                ;;
            --help)
                echo "Dilithion Security Scan v$SCRIPT_VERSION"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --quick       Quick scan (skip intensive checks)"
                echo "  --report      Generate detailed report file"
                echo "  --fix         Auto-fix fixable issues (with prompts)"
                echo "  --help        Show this help message"
                echo ""
                echo "Exit codes:"
                echo "  0 = No critical issues"
                echo "  1 = Critical issues detected"
                echo ""
                exit 0
                ;;
            *)
                echo "Unknown option: $arg"
                echo "Run with --help for usage information"
                exit 1
                ;;
        esac
    done

    # Print header
    print_header

    # Initialize report file
    if [ "$GENERATE_REPORT" = true ]; then
        echo "Dilithion Security Scan Report" > "$REPORT_FILE"
        echo "Date: $(date)" >> "$REPORT_FILE"
        echo "Scan Mode: $SCAN_MODE" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # Run security checks
    check_binary_security || true
    check_network_security || true
    check_wallet_security || true
    check_data_directory_security || true
    check_rpc_security || true
    check_system_security || true
    check_dependencies || true
    check_process_security || true

    if [ "$SCAN_MODE" = "full" ]; then
        check_monitoring_security || true
    fi

    # Generate summary
    if generate_summary; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
