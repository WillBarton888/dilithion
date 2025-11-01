#!/bin/bash
#########################################################
#  DILITHION TESTNET - ONE-CLICK MINING
#########################################################
#  This script starts mining Dilithion testnet instantly
#  No configuration needed - just run it!
#########################################################

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

clear
echo -e "${GREEN}"
echo "  ================================================"
echo "    DILITHION TESTNET - QUICK START MINER"
echo "  ================================================"
echo -e "${NC}"
echo ""
echo -e "${BLUE}Starting Dilithion testnet mining...${NC}"
echo "  - Network: TESTNET (coins have NO value)"
echo "  - Seed Node: 170.64.203.134:18444"
echo "  - Mining: ENABLED (auto-detecting CPU threads)"
echo ""

# Check for required dependencies
echo -e "${BLUE}Checking system dependencies...${NC}"

# Detect OS
OS_TYPE="$(uname -s)"

if [ "$OS_TYPE" = "Linux" ]; then
    # Check for LevelDB on Linux
    if ! ldconfig -p 2>/dev/null | grep -q libleveldb; then
        echo ""
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it first:"
        echo ""
        echo "  Ubuntu/Debian:"
        echo -e "    ${GREEN}sudo apt-get update && sudo apt-get install -y libleveldb-dev libsnappy-dev${NC}"
        echo ""
        echo "  Fedora/RHEL:"
        echo -e "    ${GREEN}sudo dnf install -y leveldb-devel snappy-devel${NC}"
        echo ""
        echo "  Arch Linux:"
        echo -e "    ${GREEN}sudo pacman -S leveldb snappy${NC}"
        echo ""
        echo "For support, join our Discord: https://discord.gg/dilithion"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
elif [ "$OS_TYPE" = "Darwin" ]; then
    # Check for LevelDB on macOS (should not reach here for Linux package, but included for consistency)
    if ! [ -f "/opt/homebrew/lib/libleveldb.dylib" ] && ! [ -f "/usr/local/lib/libleveldb.dylib" ]; then
        echo ""
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}⚠  MISSING DEPENDENCIES${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "LevelDB library not found. Please install it first:"
        echo ""
        echo "  1. Install Homebrew (if needed):"
        echo "     /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
        echo "  2. Install LevelDB:"
        echo -e "     ${GREEN}brew install leveldb${NC}"
        echo ""
        echo "For support, join our Discord: https://discord.gg/dilithion"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All dependencies found${NC}"
echo ""
echo -e "${YELLOW}Mining will start in 3 seconds...${NC}"
echo "Press Ctrl+C to stop mining anytime."
echo ""
sleep 3

echo -e "${GREEN}Starting node...${NC}"
echo ""

# Make executable if not already
chmod +x dilithion-node 2>/dev/null

./dilithion-node --testnet --addnode=170.64.203.134:18444 --mine --threads=auto

# If node exits, show message
echo ""
echo -e "${YELLOW}================================================${NC}"
echo -e "${YELLOW}  Mining stopped${NC}"
echo -e "${YELLOW}================================================${NC}"
echo ""
