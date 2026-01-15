#!/bin/bash
#########################################################
#  DILITHION MAINNET - ONE-CLICK MINING
#########################################################
#  This script starts mining Dilithion mainnet instantly
#  No configuration needed - just run it!
#########################################################

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

clear
echo -e "${GREEN}"
echo "  ================================================"
echo "    DILITHION MAINNET - QUICK START MINER"
echo "  ================================================"
echo -e "${NC}"
echo ""
echo -e "${BLUE}Starting Dilithion mainnet mining...${NC}"
echo "  - Network: MAINNET (real DIL!)"
echo "  - Seed Nodes: NYC, London, Singapore, Sydney (auto-connect)"
echo "  - Mining: ENABLED (auto-detecting CPU threads)"
echo ""
echo -e "${YELLOW}Mining will start in 3 seconds...${NC}"
echo "Press Ctrl+C to stop mining anytime."
echo ""
sleep 3

echo -e "${GREEN}Starting node...${NC}"
echo ""

# Make executable if not already
chmod +x dilithion-node 2>/dev/null

#########################################################
# SECURITY & COMPATIBILITY: Check system requirements
#########################################################
echo -e "${BLUE}Checking system dependencies...${NC}"
echo ""

# Detect OS
OS_TYPE="$(uname -s)"

# Check if dilithion-node binary exists
if [ ! -f "dilithion-node" ]; then
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}⚠  MISSING BINARY${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "ERROR: dilithion-node binary not found in current directory"
    echo ""
    echo "Please ensure you:"
    echo "  1. Extracted the complete release package"
    echo "  2. Are running this script from the dilithion directory"
    echo "  3. Downloaded the correct package for your OS"
    echo ""
    echo "Current directory: $(pwd)"
    echo ""
    echo "For support: https://discord.gg/dilithion"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 1
fi

# Check if binary is executable
if [ ! -x "dilithion-node" ]; then
    echo -e "${YELLOW}Warning: dilithion-node is not executable, attempting to fix...${NC}"
    chmod +x dilithion-node 2>/dev/null
    if [ ! -x "dilithion-node" ]; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  PERMISSION ERROR${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "ERROR: Cannot make dilithion-node executable"
        echo ""
        echo "Please run: chmod +x dilithion-node"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
fi

# Check for curl (required for wallet operations, optional for mining)
if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}⚠  curl not found (optional for mining, required for wallet operations)${NC}"

    if [ "$OS_TYPE" = "Linux" ]; then
        echo "  Install with:"
        if [ -f /etc/debian_version ]; then
            echo "    sudo apt-get install curl"
        elif [ -f /etc/fedora-release ]; then
            echo "    sudo dnf install curl"
        elif [ -f /etc/arch-release ]; then
            echo "    sudo pacman -S curl"
        else
            echo "    Use your system's package manager to install curl"
        fi
    elif [ "$OS_TYPE" = "Darwin" ]; then
        echo "  curl should be pre-installed on macOS"
        echo "  If missing, install with: brew install curl"
    fi
    echo ""
fi

if [ "$OS_TYPE" = "Linux" ]; then
    # Check for LevelDB on Linux (with fallback for distros without ldconfig)
    LEVELDB_FOUND=0

    # Try ldconfig first (most common method)
    if command -v ldconfig &> /dev/null; then
        if ldconfig -p 2>/dev/null | grep -q libleveldb; then
            LEVELDB_FOUND=1
        fi
    fi

    # Fallback: Check common library paths directly (for Alpine, minimal distros)
    if [ $LEVELDB_FOUND -eq 0 ]; then
        for libpath in /usr/lib /usr/local/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do
            if ls $libpath/libleveldb.so* &> /dev/null; then
                LEVELDB_FOUND=1
                break
            fi
        done
    fi

    if [ $LEVELDB_FOUND -eq 0 ]; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it first:"
        echo ""
        echo "  Ubuntu/Debian:"
        echo "    sudo apt-get update && sudo apt-get install -y libleveldb-dev libsnappy-dev"
        echo ""
        echo "  Fedora/RHEL:"
        echo "    sudo dnf install leveldb-devel snappy-devel"
        echo ""
        echo "  Arch Linux:"
        echo "    sudo pacman -S leveldb snappy"
        echo ""
        echo "  Alpine Linux:"
        echo "    sudo apk add leveldb-dev snappy-dev"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
elif [ "$OS_TYPE" = "Darwin" ]; then
    # Check for Homebrew first on macOS
    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  HOMEBREW NOT INSTALLED${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "Homebrew is required to install dependencies on macOS."
        echo ""
        echo "To install Homebrew:"
        echo "  1. Open Terminal"
        echo "  2. Run this command:"
        echo "     /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
        echo "  3. Follow the on-screen instructions"
        echo "  4. After Homebrew is installed, run:"
        echo "     brew install leveldb"
        echo ""
        echo "  5. Then run this mining script again"
        echo ""
        echo "For support: https://discord.gg/dilithion"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi

    # Check for LevelDB on macOS
    if ! [ -f "/opt/homebrew/lib/libleveldb.dylib" ] && ! [ -f "/usr/local/lib/libleveldb.dylib" ]; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it:"
        echo ""
        echo "  Install LevelDB:"
        echo "     brew install leveldb"
        echo ""
        echo "  If that fails, try updating Homebrew first:"
        echo "     brew update"
        echo "     brew install leveldb"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All dependencies found${NC}"
echo ""

./dilithion-node --mine --threads=auto

# If node exits, show message
echo ""
echo -e "${YELLOW}================================================${NC}"
echo -e "${YELLOW}  Mining stopped${NC}"
echo -e "${YELLOW}================================================${NC}"
echo ""
