#!/bin/bash
#########################################################
#  DILITHION MAINNET - INTERACTIVE SETUP WIZARD
#########################################################
#  First-time setup guide for crypto beginners
#########################################################

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}"
echo "  ========================================================"
echo "    DILITHION MAINNET - FIRST TIME SETUP WIZARD"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  Welcome to Dilithion - Post-Quantum Cryptocurrency!"
echo ""
echo "  This wizard will help you get started mining DIL."
echo "  You are joining the MAINNET - real DIL with real value!"
echo ""
echo "  ========================================================"
echo ""
read -p "Press ENTER to continue..."

clear
echo -e "${BLUE}"
echo "  ========================================================"
echo "    STEP 1: CONFIGURE MINING"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  How many CPU cores would you like to use for mining?"
echo ""
echo -e "${CYAN}Recommendations:${NC}"
echo "    - Leave BLANK for AUTO (recommended for beginners)"
echo "    - Enter 1-2 for light mining (laptop/low power)"
echo "    - Enter 4-8 for medium mining (desktop)"
echo "    - Enter 8+ for maximum mining (powerful PC)"
echo ""
echo "  Your CPU will be auto-detected if you leave this blank."
echo ""
read -p "Enter number of CPU cores (or press ENTER for auto): " threads

#########################################################
# SECURITY: Validate input to prevent command injection
#########################################################
if [ -z "$threads" ]; then
    threads="auto"
    threads_display="Auto-Detect"
elif [ "$threads" = "auto" ] || [ "$threads" = "AUTO" ] || [ "$threads" = "Auto" ]; then
    threads="auto"
    threads_display="Auto-Detect"
elif echo "$threads" | grep -q '^[0-9]\+$' && [ "$threads" -ge 1 ] && [ "$threads" -le 128 ]; then
    # Valid numeric input (1-128)
    threads_display="$threads cores"
else
    clear
    echo -e "${YELLOW}"
    echo "  ========================================================"
    echo "    ERROR: Invalid Input"
    echo "  ========================================================"
    echo -e "${NC}"
    echo ""
    echo "  Please enter either:"
    echo "    - A number between 1 and 128"
    echo "    - 'auto' for automatic detection"
    echo "    - Press ENTER for automatic detection"
    echo ""
    echo "  Your input \"$threads\" is not valid."
    echo ""
    echo "  ========================================================"
    echo ""
    exit 1
fi

clear
echo -e "${BLUE}"
echo "  ========================================================"
echo "    STEP 2: REVIEW CONFIGURATION"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo -e "${GREEN}Your Settings:${NC}"
echo "    - Network:     MAINNET"
echo "    - Seed Nodes:  NYC, London, Singapore, Sydney (auto-connect)"
echo "    - Mining:      ENABLED"
echo "    - CPU Threads: $threads_display"
echo ""
echo "  ========================================================"
echo ""
echo "  Ready to start mining!"
echo ""
read -p "Press ENTER to start..."

clear
echo -e "${GREEN}"
echo "  ========================================================"
echo "    DILITHION MAINNET MINER - STARTING"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  Connecting to seed nodes..."
echo "  Initializing mining with $threads_display..."
echo ""
echo "  The node will start shortly."
echo "  Press Ctrl+C anytime to stop mining."
echo ""
echo "  ========================================================"
echo ""
sleep 2

# Make executable
chmod +x dilithion-node 2>/dev/null

# Check for required dependencies
echo -e "${BLUE}Checking system dependencies...${NC}"

# Detect OS
OS_TYPE="$(uname -s)"

if [ "$OS_TYPE" = "Linux" ]; then
    # Check for LevelDB on Linux
    if ! ldconfig -p 2>/dev/null | grep -q libleveldb; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it first:"
        echo ""
        echo "  Ubuntu/Debian:"
        echo "    sudo apt-get install libleveldb-dev libsnappy-dev"
        echo ""
        echo "  Fedora/RHEL:"
        echo "    sudo dnf install leveldb-devel snappy-devel"
        echo ""
        echo "  Arch Linux:"
        echo "    sudo pacman -S leveldb snappy"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
elif [ "$OS_TYPE" = "Darwin" ]; then
    # Check for LevelDB on macOS
    if ! [ -f "/opt/homebrew/lib/libleveldb.dylib" ] && ! [ -f "/usr/local/lib/libleveldb.dylib" ]; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it first:"
        echo ""
        echo "  1. Install Homebrew (if needed):"
        echo "     /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
        echo "  2. Install LevelDB:"
        echo "     brew install leveldb"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All dependencies found${NC}"
echo ""

# Check if binary exists
if [ ! -f "./dilithion-node" ]; then
    echo -e "${YELLOW}ERROR: dilithion-node binary not found in current directory.${NC}"
    echo "  Make sure you extracted the release package and are running from"
    echo "  inside the extracted folder."
    echo ""
    echo "  Need help? Join us: https://t.me/dilithion"
    exit 1
fi

# Set library path to include bundled libs
if [ -d "./lib" ]; then
    export LD_LIBRARY_PATH="./lib:${LD_LIBRARY_PATH}"
    if [ "$OS_TYPE" = "Darwin" ]; then
        export DYLD_LIBRARY_PATH="./lib:${DYLD_LIBRARY_PATH}"
    fi
fi

# =========================================================================
# BOOTSTRAP: Fast-sync for first-time users
# =========================================================================
# Detect if this is a first run (no existing blockchain data)
DATA_DIR="$HOME/.dilithion"
if [ ! -d "$DATA_DIR/blocks" ] || [ ! -d "$DATA_DIR/chainstate" ]; then
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  FIRST TIME SETUP - Fast Sync Available${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  You can either:"
    echo "    1) Download a blockchain snapshot (~67 MB) for instant sync"
    echo "    2) Sync from scratch (slower, may take a while)"
    echo ""
    read -p "  Download snapshot for fast sync? [Y/n]: " bootstrap_choice

    if [ -z "$bootstrap_choice" ] || [ "$bootstrap_choice" = "Y" ] || [ "$bootstrap_choice" = "y" ]; then
        BOOTSTRAP_URL="https://github.com/dilithion/dilithion/releases/latest/download/bootstrap-mainnet-v3.3.12.tar.gz"
        BOOTSTRAP_FILE="/tmp/dilithion-bootstrap.tar.gz"

        echo ""
        echo "  Downloading blockchain snapshot..."
        if command -v wget >/dev/null 2>&1; then
            wget -q --show-progress -O "$BOOTSTRAP_FILE" "$BOOTSTRAP_URL"
        elif command -v curl >/dev/null 2>&1; then
            curl -L --progress-bar -o "$BOOTSTRAP_FILE" "$BOOTSTRAP_URL"
        else
            echo -e "${YELLOW}  Neither wget nor curl found. Skipping bootstrap.${NC}"
            echo "  The node will sync from scratch instead."
            BOOTSTRAP_FILE=""
        fi

        if [ -n "$BOOTSTRAP_FILE" ] && [ -f "$BOOTSTRAP_FILE" ]; then
            echo "  Extracting snapshot..."
            mkdir -p "$DATA_DIR"
            tar -xzf "$BOOTSTRAP_FILE" -C "$DATA_DIR" --strip-components=1
            rm -f "$BOOTSTRAP_FILE"
            echo -e "${GREEN}  ✓ Blockchain snapshot installed! Node will sync remaining blocks.${NC}"
        fi
    else
        echo "  OK, syncing from scratch. This may take a while."
    fi
    echo ""
fi

echo -e "${BLUE}Starting Dilithion node...${NC}"
echo ""
echo "  NOTE: First sync requires ~2.5 GB RAM for RandomX mining."
echo "  The node may appear to pause briefly while initializing."
echo "  This is normal - please be patient!"
echo ""
echo "  Need help? Join us: https://t.me/dilithion"
echo ""

./dilithion-node --mine --threads="$threads"

echo ""
echo -e "${YELLOW}"
echo "  ========================================================"
echo "    Mining Stopped"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  To start mining again:"
echo "    - Run ./start-mining.sh for quick start"
echo "    - Or run this wizard again"
echo ""
