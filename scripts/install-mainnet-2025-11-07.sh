#!/bin/bash
# Dilithion Mainnet Node - Automated Installation Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/install-mainnet-2025-11-07.sh                  # Interactive install
#   ./scripts/install-mainnet-2025-11-07.sh --auto           # Automatic install (defaults)
#   ./scripts/install-mainnet-2025-11-07.sh --build-source   # Build from source
#   ./scripts/install-mainnet-2025-11-07.sh --systemd        # Install systemd service
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

# Default installation paths
DEFAULT_INSTALL_DIR="/usr/local/bin"
DEFAULT_DATA_DIR="$HOME/.dilithion"
DEFAULT_BUILD_DIR="$HOME/dilithion-build"

# Network configuration
MAINNET_P2P_PORT=8444
MAINNET_RPC_PORT=8332

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Print banner
print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion Mainnet Node - Installation Script                ║"
    echo "║   Post-Quantum Cryptocurrency                                 ║"
    echo "║                                                                ║"
    echo "║   Version: $SCRIPT_VERSION                                         ║"
    echo "║   Date: $SCRIPT_DATE                                        ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Installation will be system-wide."
        INSTALL_DIR="$DEFAULT_INSTALL_DIR"
        INSTALL_SYSTEMD=true
    else
        print_info "Running as non-root. Installation will be user-local."
        INSTALL_DIR="$HOME/.local/bin"
        INSTALL_SYSTEMD=false
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

    # Check CPU
    CPU_CORES=$(nproc)
    print_info "CPU cores: $CPU_CORES"
    if [ "$CPU_CORES" -lt 1 ]; then
        print_error "Minimum 1 CPU core required"
        exit 1
    fi

    # Check RAM
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    print_info "Total RAM: ${TOTAL_RAM}MB"
    if [ "$TOTAL_RAM" -lt 512 ]; then
        print_warning "Less than 512MB RAM detected. Minimum 512MB recommended."
    fi

    # Check disk space
    AVAILABLE_DISK=$(df -BG "$HOME" | tail -1 | awk '{print $4}' | sed 's/G//')
    print_info "Available disk space: ${AVAILABLE_DISK}GB"
    if [ "$AVAILABLE_DISK" -lt 20 ]; then
        print_warning "Less than 20GB disk space available. Minimum 20GB recommended."
    fi

    # Check internet connectivity
    if ping -c 1 8.8.8.8 &> /dev/null; then
        print_success "Internet connectivity: OK"
    else
        print_error "No internet connectivity. Cannot download dependencies."
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."

    case "$OS" in
        ubuntu|debian)
            print_info "Installing packages for Ubuntu/Debian..."
            if [ "$EUID" -eq 0 ]; then
                apt-get update
                apt-get install -y \
                    build-essential \
                    g++ \
                    cmake \
                    make \
                    git \
                    libleveldb-dev \
                    libssl-dev \
                    pkg-config \
                    curl \
                    ca-certificates
            else
                print_warning "Non-root install. Dependencies must be installed manually:"
                print_info "  sudo apt-get update"
                print_info "  sudo apt-get install build-essential g++ cmake make git libleveldb-dev libssl-dev pkg-config curl"
                read -p "Press Enter to continue after installing dependencies..."
            fi
            ;;
        fedora|rhel|centos)
            print_info "Installing packages for Fedora/RHEL/CentOS..."
            if [ "$EUID" -eq 0 ]; then
                dnf install -y \
                    gcc-c++ \
                    cmake \
                    make \
                    git \
                    leveldb-devel \
                    openssl-devel \
                    pkg-config \
                    curl \
                    ca-certificates
            else
                print_warning "Non-root install. Dependencies must be installed manually:"
                print_info "  sudo dnf install gcc-c++ cmake make git leveldb-devel openssl-devel pkg-config curl"
                read -p "Press Enter to continue after installing dependencies..."
            fi
            ;;
        arch|manjaro)
            print_info "Installing packages for Arch Linux..."
            if [ "$EUID" -eq 0 ]; then
                pacman -Sy --noconfirm \
                    base-devel \
                    cmake \
                    git \
                    leveldb \
                    openssl \
                    pkg-config \
                    curl \
                    ca-certificates
            else
                print_warning "Non-root install. Dependencies must be installed manually:"
                print_info "  sudo pacman -Sy base-devel cmake git leveldb openssl pkg-config curl"
                read -p "Press Enter to continue after installing dependencies..."
            fi
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Please install dependencies manually:"
            print_info "  - g++ (C++17 support)"
            print_info "  - cmake"
            print_info "  - make"
            print_info "  - git"
            print_info "  - leveldb development libraries"
            read -p "Press Enter to continue after installing dependencies..."
            ;;
    esac

    print_success "Dependencies installed"
}

# Download source code
download_source() {
    print_info "Downloading Dilithion source code..."

    # Create build directory
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clone repository
    if [ -d "dilithion" ]; then
        print_info "Source directory already exists. Updating..."
        cd dilithion
        git fetch origin
        git checkout main
        git pull origin main
    else
        # TODO: Replace with actual repository URL
        print_warning "Repository URL not configured"
        print_info "Please download source code manually to: $BUILD_DIR/dilithion"
        print_info "Or provide source directory:"
        read -p "Source directory path: " SOURCE_DIR
        if [ -d "$SOURCE_DIR" ]; then
            cp -r "$SOURCE_DIR" "$BUILD_DIR/dilithion"
            print_success "Source copied"
        else
            print_error "Source directory not found: $SOURCE_DIR"
            exit 1
        fi
    fi

    print_success "Source code ready: $BUILD_DIR/dilithion"
}

# Build from source
build_from_source() {
    print_info "Building Dilithion node from source..."

    cd "$BUILD_DIR/dilithion"

    # Build dependencies
    print_info "Building RandomX dependency..."
    cd depends/randomx
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j"$CPU_CORES"
    print_success "RandomX built"

    print_info "Building Dilithium dependency..."
    cd "$BUILD_DIR/dilithion/depends/dilithium/ref"
    make -j"$CPU_CORES"
    print_success "Dilithium built"

    # Build main binary
    print_info "Building dilithion-node..."
    cd "$BUILD_DIR/dilithion"
    make -j"$CPU_CORES" CXXFLAGS="-std=c++17 -Wall -Wextra -O3 -march=native"
    print_success "dilithion-node built"

    # Verify binary
    if [ -f "dilithion-node" ]; then
        print_success "Build successful: $(ls -lh dilithion-node | awk '{print $5}')"

        # Test binary
        if ./dilithion-node --help &> /dev/null; then
            print_success "Binary test: OK"
        else
            print_error "Binary test failed"
            exit 1
        fi
    else
        print_error "Build failed: dilithion-node not found"
        exit 1
    fi
}

# Install binary
install_binary() {
    print_info "Installing dilithion-node to $INSTALL_DIR..."

    # Create installation directory
    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR"
    fi

    # Copy binary
    if [ "$EUID" -eq 0 ]; then
        cp "$BUILD_DIR/dilithion/dilithion-node" "$INSTALL_DIR/dilithion-node"
        chown root:root "$INSTALL_DIR/dilithion-node"
        chmod 755 "$INSTALL_DIR/dilithion-node"
    else
        cp "$BUILD_DIR/dilithion/dilithion-node" "$INSTALL_DIR/dilithion-node"
        chmod 755 "$INSTALL_DIR/dilithion-node"
    fi

    # Copy RandomX library
    print_info "Installing RandomX library..."
    RANDOMX_LIB="$BUILD_DIR/dilithion/depends/randomx/build/librandomx.so"
    if [ -f "$RANDOMX_LIB" ]; then
        if [ "$EUID" -eq 0 ]; then
            cp "$RANDOMX_LIB" /usr/local/lib/
            ldconfig
        else
            print_warning "RandomX library requires root to install to /usr/local/lib"
            print_info "You may need to set LD_LIBRARY_PATH:"
            print_info "  export LD_LIBRARY_PATH=$BUILD_DIR/dilithion/depends/randomx/build:\$LD_LIBRARY_PATH"
        fi
    fi

    # Verify installation
    if command -v dilithion-node &> /dev/null || [ -f "$INSTALL_DIR/dilithion-node" ]; then
        print_success "Binary installed: $INSTALL_DIR/dilithion-node"
    else
        print_error "Installation verification failed"
        exit 1
    fi

    # Add to PATH if needed
    if ! command -v dilithion-node &> /dev/null; then
        print_warning "dilithion-node not in PATH"
        print_info "Add to PATH: export PATH=\$PATH:$INSTALL_DIR"
        echo "export PATH=\$PATH:$INSTALL_DIR" >> "$HOME/.bashrc"
        export PATH="$PATH:$INSTALL_DIR"
    fi
}

# Create data directory
create_data_directory() {
    print_info "Creating data directory: $DATA_DIR..."

    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    print_success "Data directory created: $DATA_DIR"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        print_info "Detected UFW firewall"
        if [ "$EUID" -eq 0 ]; then
            ufw allow "$MAINNET_P2P_PORT"/tcp comment 'Dilithion P2P'
            print_success "UFW rule added: Port $MAINNET_P2P_PORT/tcp"
        else
            print_warning "Firewall configuration requires root"
            print_info "Run manually: sudo ufw allow $MAINNET_P2P_PORT/tcp comment 'Dilithion P2P'"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        print_info "Detected firewalld"
        if [ "$EUID" -eq 0 ]; then
            firewall-cmd --permanent --add-port="$MAINNET_P2P_PORT"/tcp
            firewall-cmd --reload
            print_success "firewalld rule added: Port $MAINNET_P2P_PORT/tcp"
        else
            print_warning "Firewall configuration requires root"
            print_info "Run manually: sudo firewall-cmd --permanent --add-port=$MAINNET_P2P_PORT/tcp"
        fi
    else
        print_warning "No firewall detected. Please configure manually:"
        print_info "  Allow inbound TCP port $MAINNET_P2P_PORT for P2P connections"
        print_info "  Block inbound port $MAINNET_RPC_PORT (RPC should not be exposed)"
    fi
}

# Install systemd service
install_systemd_service() {
    print_info "Installing systemd service..."

    if [ "$EUID" -ne 0 ]; then
        print_warning "Systemd service installation requires root"
        print_info "Run manually: sudo ./scripts/install-mainnet-2025-11-07.sh --systemd"
        return
    fi

    # Check if service file exists
    SERVICE_FILE="$BUILD_DIR/dilithion/deployment/systemd/dilithion-2025-11-07.service"
    if [ ! -f "$SERVICE_FILE" ]; then
        print_warning "Systemd service file not found: $SERVICE_FILE"
        return
    fi

    # Copy service file
    cp "$SERVICE_FILE" /etc/systemd/system/dilithion.service

    # Update service file with actual user
    sed -i "s/%i/$USER/g" /etc/systemd/system/dilithion.service

    # Reload systemd
    systemctl daemon-reload

    print_success "Systemd service installed"
    print_info "Enable service: sudo systemctl enable dilithion"
    print_info "Start service: sudo systemctl start dilithion"
    print_info "Check status: sudo systemctl status dilithion"
}

# Start node
start_node() {
    print_info "Starting Dilithion node..."

    if [ "$INSTALL_SYSTEMD" = true ] && command -v systemctl &> /dev/null; then
        print_info "Starting via systemd..."
        systemctl enable dilithion
        systemctl start dilithion
        sleep 5
        systemctl status dilithion --no-pager
        print_success "Node started via systemd"
    else
        print_info "Starting node manually..."
        print_warning "Node should be run as a background service"
        print_info "Run manually: dilithion-node --datadir=$DATA_DIR &"
    fi
}

# Print post-installation instructions
print_post_install() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Installation Complete!                                      ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    print_success "Dilithion mainnet node installed successfully"
    echo ""
    print_info "Installation Summary:"
    echo "  - Binary: $INSTALL_DIR/dilithion-node"
    echo "  - Data directory: $DATA_DIR"
    echo "  - P2P port: $MAINNET_P2P_PORT"
    echo "  - RPC port: $MAINNET_RPC_PORT (localhost only)"
    echo ""
    print_info "Next Steps:"
    echo ""
    echo "  1. Start the node:"
    if [ "$INSTALL_SYSTEMD" = true ]; then
        echo "     sudo systemctl start dilithion"
        echo "     sudo systemctl enable dilithion  # Auto-start on boot"
    else
        echo "     dilithion-node --datadir=$DATA_DIR &"
    fi
    echo ""
    echo "  2. Check node status:"
    if [ "$INSTALL_SYSTEMD" = true ]; then
        echo "     sudo systemctl status dilithion"
        echo "     sudo journalctl -u dilithion -f  # View logs"
    else
        echo "     ps aux | grep dilithion-node"
    fi
    echo ""
    echo "  3. Create and encrypt wallet:"
    echo "     curl -X POST http://localhost:$MAINNET_RPC_PORT \\"
    echo "       -H \"Content-Type: application/json\" \\"
    echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"encryptwallet\",\"params\":[\"YOUR_PASSPHRASE\"],\"id\":1}'"
    echo ""
    echo "  4. Backup wallet (CRITICAL!):"
    echo "     cp $DATA_DIR/wallet.dat ~/wallet-backup-\$(date +%Y%m%d).dat"
    echo "     Store backup offline in secure location"
    echo ""
    echo "  5. Monitor blockchain sync:"
    echo "     curl -X POST http://localhost:$MAINNET_RPC_PORT \\"
    echo "       -H \"Content-Type: application/json\" \\"
    echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}'"
    echo ""
    print_info "Documentation:"
    echo "  - Node setup: docs/MAINNET-NODE-SETUP-2025-11-07.md"
    echo "  - Mining guide: docs/MAINNET-MINING-GUIDE-2025-11-07.md"
    echo "  - Wallet guide: docs/MAINNET-WALLET-GUIDE-2025-11-07.md"
    echo "  - Troubleshooting: docs/TROUBLESHOOTING-2025-11-07.md"
    echo ""
    print_info "Security Reminders:"
    echo "  - ✅ Encrypt wallet with strong passphrase"
    echo "  - ✅ Backup encrypted wallet to offline storage"
    echo "  - ✅ Never expose RPC port $MAINNET_RPC_PORT to internet"
    echo "  - ✅ Keep node software updated"
    echo "  - ✅ Monitor logs for security events"
    echo ""
    print_success "Installation complete! Welcome to Dilithion mainnet."
    echo ""
}

# ==============================================================================
# Main Installation Flow
# ==============================================================================

main() {
    # Parse command line arguments
    AUTO_MODE=false
    BUILD_SOURCE=true
    INSTALL_SYSTEMD_REQUESTED=false

    for arg in "$@"; do
        case $arg in
            --auto)
                AUTO_MODE=true
                ;;
            --build-source)
                BUILD_SOURCE=true
                ;;
            --systemd)
                INSTALL_SYSTEMD_REQUESTED=true
                ;;
            --help)
                echo "Dilithion Mainnet Node - Installation Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --auto            Automatic installation with defaults"
                echo "  --build-source    Build from source (default)"
                echo "  --systemd         Install systemd service (requires root)"
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

    # Set build directory
    BUILD_DIR="$DEFAULT_BUILD_DIR"
    DATA_DIR="$DEFAULT_DATA_DIR"

    # Print banner
    print_banner

    # Check root
    check_root

    # Detect OS
    detect_os

    # Check requirements
    check_requirements

    # Confirm installation
    if [ "$AUTO_MODE" = false ]; then
        echo ""
        print_warning "This script will install Dilithion mainnet node"
        print_info "Installation directory: $INSTALL_DIR"
        print_info "Data directory: $DATA_DIR"
        read -p "Continue? (y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi

    # Install dependencies
    install_dependencies

    # Download or use existing source
    if [ "$BUILD_SOURCE" = true ]; then
        download_source
        build_from_source
        install_binary
    fi

    # Create data directory
    create_data_directory

    # Configure firewall
    configure_firewall

    # Install systemd service
    if [ "$INSTALL_SYSTEMD_REQUESTED" = true ] || [ "$INSTALL_SYSTEMD" = true ]; then
        install_systemd_service
    fi

    # Print post-installation instructions
    print_post_install
}

# Run main function
main "$@"
