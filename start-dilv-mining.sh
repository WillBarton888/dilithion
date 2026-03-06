#!/bin/bash
#########################################################
#  DilV MAINNET - ONE-CLICK MINING
#########################################################
#  Starts mining DilV using the VDF lottery consensus.
#  No GPU needed. Any CPU works.
#########################################################

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${GREEN}"
echo "  ================================================"
echo "    DilV MAINNET - VDF MINER"
echo "  ================================================"
echo -e "${NC}"
echo "  Post-Quantum Payments Chain"
echo "  VDF Distribution Consensus"
echo ""
echo -e "${BLUE}  Seed nodes:${NC}"
echo "    NYC:       138.197.68.128:9444"
echo "    London:    167.172.56.119:9444"
echo "    Singapore: 165.22.103.114:9444"
echo "    Sydney:    134.199.159.83:9444"
echo ""
echo -e "${YELLOW}  Note: VDF mining is single-threaded by design.${NC}"
echo -e "${YELLOW}  Your CPU is used sequentially — this is fair for everyone.${NC}"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

# Use wrapper if bundled libs are present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/run-node.sh" ]; then
    exec "${SCRIPT_DIR}/run-node.sh" --mine
else
    exec "${SCRIPT_DIR}/dilv-node" --mine
fi
