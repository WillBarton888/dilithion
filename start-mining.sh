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
