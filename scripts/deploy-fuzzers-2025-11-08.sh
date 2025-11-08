#!/bin/bash
# Dilithion Fuzzer Deployment Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Deploy fuzzers to production testnet nodes and run smoke tests
# Targets: Singapore, New York, London testnet nodes
# Date: 2025-11-08
#
# Usage: ./scripts/deploy-fuzzers-2025-11-08.sh [node]
#   node: singapore|newyork|london|all (default: all)

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Colors for output
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[32m'
COLOR_BLUE='\033[34m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FUZZER_DIR="${PROJECT_ROOT}/fuzzer_binaries"

# Production testnet nodes
declare -A NODES=(
    ["singapore"]="188.166.255.63"
    ["newyork"]="134.122.4.164"
    ["london"]="209.97.177.197"
)

# SSH configuration
SSH_USER="root"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
REMOTE_DIR="/root/dilithion-fuzzers"

# Fuzzer list
FUZZERS=(
    "fuzz_sha3"
    "fuzz_transaction"
    "fuzz_block"
    "fuzz_compactsize"
    "fuzz_network_message"
    "fuzz_address"
    "fuzz_difficulty"
    "fuzz_subsidy"
    "fuzz_merkle"
    "fuzz_tx_validation"
    "fuzz_utxo"
)

# Parse arguments
DEPLOY_TARGET="${1:-all}"

# Validate fuzzer directory exists
if [ ! -d "${FUZZER_DIR}" ]; then
    echo -e "${COLOR_RED}Error: Fuzzer directory not found: ${FUZZER_DIR}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Run build script first: ./scripts/build-fuzzers-docker-2025-11-08.sh${COLOR_RESET}"
    exit 1
fi

# Verify all fuzzers exist
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}Dilithion Fuzzer Deployment${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""
echo -e "${COLOR_YELLOW}[1/4] Verifying fuzzer binaries...${COLOR_RESET}"

MISSING_COUNT=0
for fuzzer in "${FUZZERS[@]}"; do
    if [ ! -f "${FUZZER_DIR}/${fuzzer}" ]; then
        echo -e "  ${COLOR_RED}✗${COLOR_RESET} ${fuzzer} - MISSING"
        ((MISSING_COUNT++))
    else
        SIZE=$(ls -lh "${FUZZER_DIR}/${fuzzer}" | awk '{print $5}')
        echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} ${fuzzer} (${SIZE})"
    fi
done

if [ ${MISSING_COUNT} -gt 0 ]; then
    echo -e "${COLOR_RED}Error: ${MISSING_COUNT} fuzzer(s) missing${COLOR_RESET}"
    exit 1
fi
echo ""

# Function: Deploy to a single node
deploy_to_node() {
    local node_name=$1
    local node_ip=$2

    echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
    echo -e "${COLOR_BLUE}Deploying to: ${node_name} (${node_ip})${COLOR_RESET}"
    echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
    echo ""

    # Test SSH connectivity
    echo -e "${COLOR_YELLOW}Testing SSH connection...${COLOR_RESET}"
    if ! ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "echo 'Connection successful'" &> /dev/null; then
        echo -e "${COLOR_RED}Error: Cannot connect to ${node_name} (${node_ip})${COLOR_RESET}"
        return 1
    fi
    echo -e "${COLOR_GREEN}✓ SSH connection established${COLOR_RESET}"
    echo ""

    # Verify GLIBC version
    echo -e "${COLOR_YELLOW}Verifying GLIBC version...${COLOR_RESET}"
    GLIBC_VERSION=$(ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "ldd --version | head -n1" 2>/dev/null || echo "unknown")
    echo -e "  ${GLIBC_VERSION}"
    echo ""

    # Create remote directory
    echo -e "${COLOR_YELLOW}Creating remote directory...${COLOR_RESET}"
    ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "mkdir -p ${REMOTE_DIR}"
    echo -e "${COLOR_GREEN}✓ Directory created: ${REMOTE_DIR}${COLOR_RESET}"
    echo ""

    # Upload fuzzers
    echo -e "${COLOR_YELLOW}Uploading fuzzer binaries...${COLOR_RESET}"
    for fuzzer in "${FUZZERS[@]}"; do
        if scp ${SSH_OPTS} "${FUZZER_DIR}/${fuzzer}" "${SSH_USER}@${node_ip}:${REMOTE_DIR}/" &> /dev/null; then
            echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} ${fuzzer}"
        else
            echo -e "  ${COLOR_RED}✗${COLOR_RESET} ${fuzzer} - UPLOAD FAILED"
            return 1
        fi
    done
    echo ""

    # Set executable permissions
    echo -e "${COLOR_YELLOW}Setting executable permissions...${COLOR_RESET}"
    ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "chmod +x ${REMOTE_DIR}/fuzz_*"
    echo -e "${COLOR_GREEN}✓ Permissions set${COLOR_RESET}"
    echo ""

    # Run 60-second smoke tests
    echo -e "${COLOR_YELLOW}Running 60-second smoke tests...${COLOR_RESET}"
    PASSED_COUNT=0
    FAILED_COUNT=0

    for fuzzer in "${FUZZERS[@]}"; do
        echo -n -e "  Testing ${fuzzer}... "

        # Run fuzzer for 60 seconds
        if ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "cd ${REMOTE_DIR} && timeout 60 ./${fuzzer} 2>&1 | tail -n5" &> /tmp/fuzzer_output_${fuzzer}.log; then
            echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
            ((PASSED_COUNT++))
        else
            # Check if it was a timeout (expected) or a crash (error)
            if grep -q "DONE" /tmp/fuzzer_output_${fuzzer}.log 2>/dev/null || \
               grep -q "NEW" /tmp/fuzzer_output_${fuzzer}.log 2>/dev/null; then
                echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
                ((PASSED_COUNT++))
            else
                # Check for GLIBC errors
                if grep -qi "GLIBC\|GLIBCXX" /tmp/fuzzer_output_${fuzzer}.log 2>/dev/null; then
                    echo -e "${COLOR_RED}FAIL (GLIBC ERROR)${COLOR_RESET}"
                    cat /tmp/fuzzer_output_${fuzzer}.log
                else
                    echo -e "${COLOR_RED}FAIL${COLOR_RESET}"
                fi
                ((FAILED_COUNT++))
            fi
        fi
    done

    echo ""
    echo -e "${COLOR_BLUE}Smoke Test Results for ${node_name}:${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}Passed:${COLOR_RESET} ${PASSED_COUNT}/11"
    echo -e "  ${COLOR_RED}Failed:${COLOR_RESET} ${FAILED_COUNT}/11"
    echo ""

    if [ ${FAILED_COUNT} -eq 0 ]; then
        echo -e "${COLOR_GREEN}✓ ${node_name} deployment successful!${COLOR_RESET}"
        return 0
    else
        echo -e "${COLOR_RED}✗ ${node_name} deployment failed (${FAILED_COUNT} fuzzer(s) failed)${COLOR_RESET}"
        return 1
    fi
}

# Main deployment logic
echo -e "${COLOR_YELLOW}[2/4] Deployment Configuration${COLOR_RESET}"
echo -e "  Target: ${DEPLOY_TARGET}"
echo -e "  Source: ${FUZZER_DIR}"
echo -e "  Remote: ${REMOTE_DIR}"
echo ""

echo -e "${COLOR_YELLOW}[3/4] Deploying to nodes...${COLOR_RESET}"
echo ""

TOTAL_NODES=0
SUCCESSFUL_NODES=0
FAILED_NODES=0

if [ "${DEPLOY_TARGET}" == "all" ]; then
    # Deploy to all nodes
    for node_name in "${!NODES[@]}"; do
        ((TOTAL_NODES++))
        if deploy_to_node "${node_name}" "${NODES[${node_name}]}"; then
            ((SUCCESSFUL_NODES++))
        else
            ((FAILED_NODES++))
        fi
        echo ""
    done
elif [ -n "${NODES[${DEPLOY_TARGET}]}" ]; then
    # Deploy to specific node
    TOTAL_NODES=1
    if deploy_to_node "${DEPLOY_TARGET}" "${NODES[${DEPLOY_TARGET}]}"; then
        SUCCESSFUL_NODES=1
    else
        FAILED_NODES=1
    fi
else
    echo -e "${COLOR_RED}Error: Invalid node '${DEPLOY_TARGET}'${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Valid options: singapore, newyork, london, all${COLOR_RESET}"
    exit 1
fi

# Final summary
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_YELLOW}[4/4] Deployment Summary${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  Total Nodes: ${TOTAL_NODES}"
echo -e "  ${COLOR_GREEN}Successful:${COLOR_RESET} ${SUCCESSFUL_NODES}"
echo -e "  ${COLOR_RED}Failed:${COLOR_RESET} ${FAILED_NODES}"
echo ""

if [ ${FAILED_NODES} -eq 0 ]; then
    echo -e "${COLOR_GREEN}✓ All deployments successful!${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_YELLOW}Next Steps:${COLOR_RESET}"
    echo -e "  1. SSH into a node:"
    echo -e "     ssh root@188.166.255.63"
    echo ""
    echo -e "  2. Run a fuzzer:"
    echo -e "     cd ${REMOTE_DIR}"
    echo -e "     ./fuzz_sha3 -max_total_time=60"
    echo ""
    exit 0
else
    echo -e "${COLOR_RED}✗ ${FAILED_NODES} deployment(s) failed${COLOR_RESET}"
    exit 1
fi
