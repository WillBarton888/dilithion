#!/bin/bash
#########################################################
#  DILITHION TESTNET - INTERACTIVE SETUP WIZARD
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
echo "    DILITHION TESTNET - FIRST TIME SETUP WIZARD"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  Welcome to Dilithion - Post-Quantum Cryptocurrency!"
echo ""
echo "  This wizard will help you get started mining testnet DIL."
echo "  Testnet coins have NO monetary value (for testing only)."
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

if [ -z "$threads" ]; then
    threads="auto"
    threads_display="Auto-Detect"
else
    threads_display="$threads cores"
fi

clear
echo -e "${BLUE}"
echo "  ========================================================"
echo "    STEP 2: REVIEW CONFIGURATION"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo -e "${GREEN}Your Settings:${NC}"
echo "    - Network:     TESTNET"
echo "    - Seed Node:   170.64.203.134:18444 (official)"
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
echo "    DILITHION TESTNET MINER - STARTING"
echo "  ========================================================"
echo -e "${NC}"
echo ""
echo "  Connecting to seed node..."
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

./dilithion-node --testnet --addnode=170.64.203.134:18444 --mine --threads=$threads

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
