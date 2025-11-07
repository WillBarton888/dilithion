#!/bin/bash
# Dilithion Testnet Node - Automated Installation Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/install-testnet-2025-11-07.sh                  # Interactive install
#   ./scripts/install-testnet-2025-11-07.sh --auto           # Automatic install (defaults)
#   ./scripts/install-testnet-2025-11-07.sh --build-source   # Build from source
#   ./scripts/install-testnet-2025-11-07.sh --systemd        # Install systemd service
#
# Version: 1.0.0
# Created: 2025-11-07
# Purpose: Testnet validation before mainnet launch

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0-testnet"
SCRIPT_DATE="2025-11-07"
NETWORK="testnet"

# Default installation paths
DEFAULT_INSTALL_DIR="/usr/local/bin"
DEFAULT_DATA_DIR="$HOME/.dilithion"
DEFAULT_BUILD_DIR="$HOME/dilithion-build"

# Network configuration (TESTNET)
TESTNET_P2P_PORT=18444
TESTNET_RPC_PORT=18332

# Repository configuration
REPO_URL="https://github.com/your-org/dilithion"  # Update with actual repo
REPO_BRANCH="main"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# ==============================================================================
# Helper Functions
# ==============================================================================

# Print colored message
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

print_testnet() {
    echo -e "${MAGENTA}[TESTNET]${NC} $1"
}

# Print banner
print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion TESTNET Node - Installation Script                ║"
    echo "║   Post-Quantum Cryptocurrency - Testing Environment           ║"
    echo "║                                                                ║"
    echo "║   Version: $SCRIPT_VERSION                                   ║"
    echo "║   Date: $SCRIPT_DATE                                        ║"
    echo "║   Network: TESTNET                                             ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    print_warning "This installs a TESTNET node for testing purposes only"
    print_warning "Not for mainnet use - testnet coins have no real value"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Installation will be system-wide."
        INSTALL_DIR="$DEFAULT_INSTALL_DIR"
        INSTALL_SYSTEMD=true
        RUN_AS_USER="dilithion"
    else
        print_info "Running as non-root. Installation will be user-local."
        INSTALL_DIR="$HOME/.local/bin"
        INSTALL_SYSTEMD=false
        RUN_AS_USER="$USER"
    fi
}

# Detect operating system
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        print_info "Detected OS: $OS $OS_VERSION"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_info "Checking system requirements..."

    # Check CPU cores
    CPU_CORES=$(nproc)
    print_info "CPU cores: $CPU_CORES"
    if [ "$CPU_CORES" -lt 2 ]; then
        print_warning "Minimum 2 CPU cores recommended, found $CPU_CORES"
    fi

    # Check RAM
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    print_info "Total RAM: ${TOTAL_RAM}MB"
    if [ "$TOTAL_RAM" -lt 2000 ]; then
        print_error "Minimum 2GB RAM required, found ${TOTAL_RAM}MB"
        exit 1
    fi

    # Check disk space
    DISK_SPACE=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | sed 's/G//')
    print_info "Available disk space: ${DISK_SPACE}GB"
    if [ "$DISK_SPACE" -lt 50 ]; then
        print_warning "Minimum 50GB disk space recommended, found ${DISK_SPACE}GB"
    fi

    print_success "System requirements check complete"
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."

    case "$OS" in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y \
                build-essential \
                cmake \
                git \
                libssl-dev \
                libboost-all-dev \
                libleveldb-dev \
                libsnappy-dev \
                pkg-config \
                curl \
                wget
            ;;
        centos|rhel|fedora)
            sudo yum install -y \
                gcc \
                gcc-c++ \
                make \
                cmake \
                git \
                openssl-devel \
                boost-devel \
                leveldb-devel \
                snappy-devel \
                curl \
                wget
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Please install dependencies manually"
            exit 1
            ;;
    esac

    print_success "Dependencies installed"
}

# Create dilithion user (if running as root)
create_user() {
    if [ "$EUID" -eq 0 ] && ! id "$RUN_AS_USER" &>/dev/null; then
        print_info "Creating dilithion user..."
        useradd -r -m -s /bin/bash "$RUN_AS_USER"
        print_success "User $RUN_AS_USER created"
    fi
}

# Build from source
build_from_source() {
    print_info "Building Dilithion from source..."

    # Create build directory
    mkdir -p "$DEFAULT_BUILD_DIR"
    cd "$DEFAULT_BUILD_DIR"

    # Clone repository if not exists
    if [ ! -d "dilithion" ]; then
        print_info "Cloning repository from $REPO_URL..."
        git clone "$REPO_URL" dilithion
    fi

    cd dilithion
    git checkout "$REPO_BRANCH"
    git pull

    # Build Dilithium dependency
    print_info "Building Dilithium cryptography library..."
    cd depends/dilithium
    make clean
    make
    cd ../..

    # Build main project
    print_info "Building Dilithion node..."
    make clean
    make -j"$(nproc)"

    # Verify binaries built
    if [ ! -f "dilithiond" ] || [ ! -f "dilithion-cli" ]; then
        print_error "Build failed - binaries not found"
        exit 1
    fi

    print_success "Build completed successfully"

    # Install binaries
    print_info "Installing binaries to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp dilithiond "$INSTALL_DIR/"
    cp dilithion-cli "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/dilithiond"
    chmod +x "$INSTALL_DIR/dilithion-cli"

    print_success "Binaries installed to $INSTALL_DIR"
}

# Configure testnet node
configure_testnet() {
    print_testnet "Configuring testnet node..."

    # Create data directory
    TESTNET_DATA_DIR="$DEFAULT_DATA_DIR/testnet"
    mkdir -p "$TESTNET_DATA_DIR"

    # Set permissions
    if [ "$EUID" -eq 0 ]; then
        chown -R "$RUN_AS_USER:$RUN_AS_USER" "$DEFAULT_DATA_DIR"
    fi
    chmod 700 "$DEFAULT_DATA_DIR"
    chmod 700 "$TESTNET_DATA_DIR"

    # Create configuration file
    CONFIG_FILE="$DEFAULT_DATA_DIR/dilithion.conf"

    print_info "Creating configuration file: $CONFIG_FILE"

    cat > "$CONFIG_FILE" <<EOF
# Dilithion Testnet Configuration
# Generated: $(date)
# Network: TESTNET

# Network settings
testnet=1
listen=1
server=1

# P2P settings
port=$TESTNET_P2P_PORT
maxconnections=125

# RPC settings
rpcport=$TESTNET_RPC_PORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# RPC authentication (CHANGE THESE!)
rpcuser=testnet_user_$(openssl rand -hex 8)
rpcpassword=$(openssl rand -base64 32)

# Logging
debug=0
printtoconsole=0

# Performance
dbcache=300
maxmempool=300

# Testnet specific
# Test mode - lower difficulty, faster blocks for testing
testnet_lowdifficulty=0
EOF

    # Set config file permissions
    chmod 600 "$CONFIG_FILE"
    if [ "$EUID" -eq 0 ]; then
        chown "$RUN_AS_USER:$RUN_AS_USER" "$CONFIG_FILE"
    fi

    print_success "Configuration file created"
    print_testnet "RPC credentials saved to $CONFIG_FILE"
    print_warning "Please review and update configuration as needed"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."

    if command -v ufw >/dev/null 2>&1; then
        print_info "Detected UFW firewall"

        # Allow testnet P2P port
        sudo ufw allow $TESTNET_P2P_PORT/tcp comment "Dilithion Testnet P2P"

        # RPC port is localhost only by default (no firewall rule needed)

        print_success "Firewall configured for testnet"
        print_info "Allowed port: $TESTNET_P2P_PORT/tcp (testnet P2P)"
        print_info "RPC port $TESTNET_RPC_PORT is localhost-only (secure)"
    else
        print_warning "UFW not found. Please configure firewall manually:"
        print_warning "  - Allow inbound TCP port $TESTNET_P2P_PORT (P2P)"
        print_warning "  - Block port $TESTNET_RPC_PORT from external access (RPC)"
    fi
}

# Install systemd service
install_systemd_service() {
    if [ "$INSTALL_SYSTEMD" = false ]; then
        print_info "Skipping systemd service installation (not running as root)"
        return
    fi

    print_info "Installing systemd service..."

    SERVICE_FILE="/etc/systemd/system/dilithion-testnet.service"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Dilithion Testnet Node
After=network.target
Documentation=https://dilithion.org/docs

[Service]
Type=forking
User=$RUN_AS_USER
Group=$RUN_AS_USER

# Start daemon
ExecStart=$INSTALL_DIR/dilithiond -daemon -testnet -conf=$DEFAULT_DATA_DIR/dilithion.conf -datadir=$DEFAULT_DATA_DIR

# Stop daemon
ExecStop=$INSTALL_DIR/dilithion-cli -testnet stop

# Process management
Restart=on-failure
RestartSec=30
TimeoutStartSec=120
TimeoutStopSec=120

# Resource limits
LimitNOFILE=8192
MemoryMax=4G
CPUQuota=200%

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$DEFAULT_DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    print_success "Systemd service installed: dilithion-testnet.service"
    print_info "Enable service: sudo systemctl enable dilithion-testnet"
    print_info "Start service: sudo systemctl start dilithion-testnet"
    print_info "Check status: sudo systemctl status dilithion-testnet"
}

# Start testnet node
start_node() {
    print_testnet "Starting testnet node..."

    if [ "$INSTALL_SYSTEMD" = true ]; then
        # Start via systemd
        systemctl enable dilithion-testnet
        systemctl start dilithion-testnet
        sleep 3
        systemctl status dilithion-testnet --no-pager

        print_success "Testnet node started via systemd"
        print_info "Check logs: sudo journalctl -u dilithion-testnet -f"
    else
        # Start manually
        "$INSTALL_DIR/dilithiond" -daemon -testnet -conf="$DEFAULT_DATA_DIR/dilithion.conf" -datadir="$DEFAULT_DATA_DIR"
        sleep 3

        print_success "Testnet node started"
        print_info "Check logs: tail -f $DEFAULT_DATA_DIR/testnet/debug.log"
    fi
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    sleep 5  # Wait for node to start

    # Check if dilithiond is running
    if pgrep -x "dilithiond" > /dev/null; then
        print_success "dilithiond process is running"
    else
        print_error "dilithiond is not running"
        return 1
    fi

    # Try to connect to RPC
    print_info "Testing RPC connection..."
    if "$INSTALL_DIR/dilithion-cli" -testnet getblockchaininfo &>/dev/null; then
        print_success "RPC connection successful"

        # Get blockchain info
        BLOCK_COUNT=$("$INSTALL_DIR/dilithion-cli" -testnet getblockcount)
        PEER_COUNT=$("$INSTALL_DIR/dilithion-cli" -testnet getconnectioncount)

        print_testnet "Current block: $BLOCK_COUNT"
        print_testnet "Peer connections: $PEER_COUNT"
    else
        print_warning "RPC connection failed (node may still be starting)"
    fi

    print_success "Installation verification complete"
}

# Print post-installation instructions
print_instructions() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion Testnet Node - Installation Complete              ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    print_success "Testnet node installed successfully!"
    echo ""
    print_testnet "IMPORTANT: This is a TESTNET node"
    print_testnet "Testnet coins have NO REAL VALUE"
    print_testnet "Used for testing purposes only"
    echo ""
    print_info "Useful commands:"
    echo ""
    echo "  # Check blockchain info"
    echo "  dilithion-cli -testnet getblockchaininfo"
    echo ""
    echo "  # Check peer connections"
    echo "  dilithion-cli -testnet getconnectioncount"
    echo "  dilithion-cli -testnet getpeerinfo"
    echo ""
    echo "  # Check wallet"
    echo "  dilithion-cli -testnet getwalletinfo"
    echo "  dilithion-cli -testnet getnewaddress"
    echo ""
    if [ "$INSTALL_SYSTEMD" = true ]; then
        echo "  # Service management"
        echo "  sudo systemctl status dilithion-testnet"
        echo "  sudo systemctl stop dilithion-testnet"
        echo "  sudo systemctl start dilithion-testnet"
        echo "  sudo systemctl restart dilithion-testnet"
        echo ""
        echo "  # View logs"
        echo "  sudo journalctl -u dilithion-testnet -f"
    else
        echo "  # Stop node"
        echo "  dilithion-cli -testnet stop"
        echo ""
        echo "  # View logs"
        echo "  tail -f $DEFAULT_DATA_DIR/testnet/debug.log"
    fi
    echo ""
    print_info "Configuration file: $DEFAULT_DATA_DIR/dilithion.conf"
    print_info "Data directory: $DEFAULT_DATA_DIR/testnet/"
    print_info "Testnet P2P port: $TESTNET_P2P_PORT"
    print_info "Testnet RPC port: $TESTNET_RPC_PORT (localhost only)"
    echo ""
    print_info "Next steps:"
    echo "  1. Wait for blockchain to sync (check with getblockchaininfo)"
    echo "  2. Monitor peer connections (should reach 8+ peers)"
    echo "  3. Test wallet functionality"
    echo "  4. Install monitoring stack (Prometheus/Grafana)"
    echo "  5. Run security scan: ./scripts/security-scan-2025-11-07.sh"
    echo ""
    print_success "Happy testing on testnet!"
    echo ""
}

# ==============================================================================
# Main Installation Process
# ==============================================================================

main() {
    # Parse command line arguments
    AUTO_MODE=false
    BUILD_SOURCE=true
    INSTALL_SERVICE=true

    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto)
                AUTO_MODE=true
                shift
                ;;
            --build-source)
                BUILD_SOURCE=true
                shift
                ;;
            --no-systemd)
                INSTALL_SERVICE=false
                shift
                ;;
            --help)
                print_banner
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --auto          Run in automatic mode (no prompts)"
                echo "  --build-source  Build from source (default)"
                echo "  --no-systemd    Skip systemd service installation"
                echo "  --help          Show this help message"
                echo ""
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Display banner
    print_banner

    # Check if running as root
    check_root

    # Detect OS
    detect_os

    # Check system requirements
    check_requirements

    # Confirm installation (if not auto mode)
    if [ "$AUTO_MODE" = false ]; then
        echo ""
        read -p "Proceed with testnet installation? (yes/no): " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi

    # Install dependencies
    install_dependencies

    # Create user if needed
    create_user

    # Build from source
    if [ "$BUILD_SOURCE" = true ]; then
        build_from_source
    fi

    # Configure testnet
    configure_testnet

    # Configure firewall
    configure_firewall

    # Install systemd service
    if [ "$INSTALL_SERVICE" = true ]; then
        install_systemd_service
    fi

    # Start node
    start_node

    # Verify installation
    verify_installation

    # Print instructions
    print_instructions
}

# Run main function
main "$@"
