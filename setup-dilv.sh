#!/bin/bash
#########################################################
#  DilV MAINNET - FIRST TIME SETUP
#########################################################
#  Interactive first-time setup for DilV node
#########################################################

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/dilv-node"
if [ -f "${SCRIPT_DIR}/run-node.sh" ]; then
    BINARY="${SCRIPT_DIR}/run-node.sh"
fi

clear
echo -e "${BLUE}"
echo "  ========================================================"
echo "    DilV MAINNET - FIRST TIME SETUP"
echo "  ========================================================"
echo -e "${NC}"
echo "  Welcome to DilV — the post-quantum payments chain."
echo ""

# Make binaries executable
chmod +x "${SCRIPT_DIR}/dilv-node" 2>/dev/null
chmod +x "${SCRIPT_DIR}/check-wallet-balance" 2>/dev/null
chmod +x "${SCRIPT_DIR}/run-node.sh" 2>/dev/null

echo -e "${CYAN}  ── WHAT IS DilV? ──────────────────────────────────────${NC}"
echo ""
echo "  DilV is a fast payments cryptocurrency that uses VDF"
echo "  (Verifiable Delay Function) consensus — a provably fair"
echo "  lottery where ANY CPU can participate equally."
echo ""
echo "  • ~45 second block times"
echo "  • 100 DilV per block reward"
echo "  • Post-quantum secure (CRYSTALS-Dilithium signatures)"
echo "  • Native x402 micropayment support"
echo "  • Companion chain to DIL (10 DilV ≈ 1 DIL)"
echo ""

echo -e "${CYAN}  ── HOW TO START ────────────────────────────────────────${NC}"
echo ""
echo "  Option 1: Mine DilV (recommended)"
echo "    ./start-dilv-mining.sh"
echo ""
echo "  Option 2: Run as relay node only (no mining)"
echo "    ./dilv-node --relay-only"
echo ""
echo "  Option 3: Manual control"
echo "    ./dilv-node --mine"
echo "    ./dilv-node --help    (see all options)"
echo ""

echo -e "${CYAN}  ── YOUR WALLET ─────────────────────────────────────────${NC}"
echo ""
echo "  Your DilV wallet is created automatically on first run."
echo "  Data is stored in: ~/.dilv/"
echo ""
echo "  To check your balance at any time:"
echo "    ./check-wallet-balance"
echo ""

echo -e "${CYAN}  ── SEED NODES ──────────────────────────────────────────${NC}"
echo ""
echo "  NYC:       138.197.68.128:9444   (Primary)"
echo "  London:    167.172.56.119:9444"
echo "  Singapore: 165.22.103.114:9444"
echo "  Sydney:    134.199.159.83:9444"
echo ""

echo -e "${GREEN}  Ready! Run ./start-dilv-mining.sh to begin.${NC}"
echo ""
