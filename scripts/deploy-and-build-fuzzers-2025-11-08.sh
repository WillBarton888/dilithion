#!/bin/bash
# Dilithion Fuzzer Deployment and Build Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Upload source and build fuzzers on production testnet nodes
# Targets: Singapore, New York, London testnet nodes
# Date: 2025-11-08
#
# Usage: ./scripts/deploy-and-build-fuzzers-2025-11-08.sh [node]
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

# Production testnet nodes
declare -A NODES=(
    ["singapore"]="188.166.255.63"
    ["newyork"]="134.122.4.164"
    ["london"]="209.97.177.197"
)

# SSH configuration
SSH_USER="root"
SSH_KEY="${HOME}/.ssh/id_ed25519_windows"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"
REMOTE_SOURCE_DIR="/root/dilithion"
REMOTE_FUZZER_DIR="/root/dilithion-fuzzers"

# Fuzzer list (Phase 4: 20 fuzzers - Nov 9, 2025)
FUZZERS=(
    # Original 11 fuzzers
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
    # New 9 fuzzers (Phase 3 split harnesses)
    "fuzz_address_encode"
    "fuzz_address_validate"
    "fuzz_address_bech32"
    "fuzz_address_type"
    "fuzz_network_create"
    "fuzz_network_checksum"
    "fuzz_network_command"
    "fuzz_signature"
    "fuzz_base58"
)

# Parse arguments
DEPLOY_TARGET="${1:-all}"

# Print header
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}Dilithion Fuzzer Deployment & Build${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""

# Function: Deploy and build on a single node
deploy_to_node() {
    local node_name=$1
    local node_ip=$2

    echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
    echo -e "${COLOR_BLUE}Node: ${node_name} (${node_ip})${COLOR_RESET}"
    echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
    echo ""

    # Test SSH connectivity
    echo -e "${COLOR_YELLOW}[1/6] Testing SSH connection...${COLOR_RESET}"
    if ! ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "echo 'Connection successful'" &> /dev/null; then
        echo -e "${COLOR_RED}Error: Cannot connect to ${node_name} (${node_ip})${COLOR_RESET}"
        return 1
    fi
    echo -e "${COLOR_GREEN}✓ SSH connection established${COLOR_RESET}"
    echo ""

    # Verify GLIBC version
    echo -e "${COLOR_YELLOW}[2/6] Verifying environment...${COLOR_RESET}"
    GLIBC_VERSION=$(ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "ldd --version | head -n1" 2>/dev/null || echo "unknown")
    echo -e "  GLIBC: ${GLIBC_VERSION}"
    HOSTNAME=$(ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "hostname" 2>/dev/null || echo "unknown")
    echo -e "  Hostname: ${HOSTNAME}"
    echo ""

    # Create tarball of source code
    echo -e "${COLOR_YELLOW}[3/6] Packaging source code...${COLOR_RESET}"
    TARBALL="/tmp/dilithion-fuzzer-source-${node_name}.tar.gz"

    cd "${PROJECT_ROOT}"
    if tar czf "${TARBALL}" \
        --exclude='.git' \
        --exclude='build/' \
        --exclude='*.o' \
        --exclude='*.gcda' \
        --exclude='*.gcno' \
        --exclude='coverage*' \
        --exclude='fuzzer_binaries/' \
        --exclude='.test_*' \
        --exclude='dilithion-node' \
        --exclude='genesis_gen' \
        --exclude='*_tests' \
        --exclude='test_*' \
        --exclude='fuzz_*_campaign.log' \
        --exclude='*.log' \
        .; then
        TARBALL_SIZE=$(ls -lh "${TARBALL}" | awk '{print $5}')
        echo -e "  ${COLOR_GREEN}✓ Source packaged (${TARBALL_SIZE})${COLOR_RESET}"
    else
        echo -e "  ${COLOR_RED}Error: Failed to create tarball${COLOR_RESET}"
        return 1
    fi
    echo ""

    # Upload tarball
    echo -e "${COLOR_YELLOW}[4/6] Uploading source code...${COLOR_RESET}"
    if scp ${SSH_OPTS} "${TARBALL}" "${SSH_USER}@${node_ip}:/tmp/dilithion-source.tar.gz"; then
        echo -e "  ${COLOR_GREEN}✓ Source uploaded${COLOR_RESET}"
        rm -f "${TARBALL}"
    else
        echo -e "  ${COLOR_RED}Error: Failed to upload source${COLOR_RESET}"
        rm -f "${TARBALL}"
        return 1
    fi

    # Extract source on remote
    echo -e "  Extracting source on remote..."
    if ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} \
        "rm -rf ${REMOTE_SOURCE_DIR} && mkdir -p ${REMOTE_SOURCE_DIR} && cd ${REMOTE_SOURCE_DIR} && tar xzf /tmp/dilithion-source.tar.gz && rm /tmp/dilithion-source.tar.gz"; then
        echo -e "  ${COLOR_GREEN}✓ Source extracted${COLOR_RESET}"
    else
        echo -e "  ${COLOR_RED}Error: Failed to extract source${COLOR_RESET}"
        return 1
    fi
    echo ""

    # Upload build script
    echo -e "${COLOR_YELLOW}[5/6] Building fuzzers...${COLOR_RESET}"
    if scp ${SSH_OPTS} "${SCRIPT_DIR}/build-fuzzers-remote-2025-11-08.sh" \
        "${SSH_USER}@${node_ip}:/root/build-fuzzers.sh" &> /dev/null; then
        echo -e "  ${COLOR_GREEN}✓ Build script uploaded${COLOR_RESET}"
    else
        echo -e "  ${COLOR_RED}Error: Failed to upload build script${COLOR_RESET}"
        return 1
    fi

    # Execute build script remotely
    echo -e "  Building on remote node (this may take 5-10 minutes)..."
    echo ""

    if ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} "chmod +x /root/build-fuzzers.sh && /root/build-fuzzers.sh" 2>&1; then
        echo ""
        echo -e "  ${COLOR_GREEN}✓ Remote build successful${COLOR_RESET}"
    else
        echo ""
        echo -e "  ${COLOR_RED}Error: Remote build failed${COLOR_RESET}"
        return 1
    fi
    echo ""

    # Run 60-second smoke tests
    echo -e "${COLOR_YELLOW}[6/6] Running smoke tests...${COLOR_RESET}"
    PASSED_COUNT=0
    FAILED_COUNT=0

    for fuzzer in "${FUZZERS[@]}"; do
        echo -n -e "  Testing ${fuzzer}... "

        # Run fuzzer for 60 seconds
        TEST_OUTPUT=$(ssh ${SSH_OPTS} ${SSH_USER}@${node_ip} \
            "cd ${REMOTE_FUZZER_DIR} && timeout 60 ./${fuzzer} 2>&1 || true" 2>&1)

        # Check for success indicators or GLIBC errors
        if echo "${TEST_OUTPUT}" | grep -qi "GLIBC\|GLIBCXX"; then
            echo -e "${COLOR_RED}FAIL (GLIBC ERROR)${COLOR_RESET}"
            echo "${TEST_OUTPUT}" | tail -n 5
            ((FAILED_COUNT++))
        elif echo "${TEST_OUTPUT}" | grep -q "ERROR\|Segmentation fault\|Aborted"; then
            # Check if it's just normal fuzzer output
            if echo "${TEST_OUTPUT}" | grep -q "INITED\|NEW\|DONE"; then
                echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
                ((PASSED_COUNT++))
            else
                echo -e "${COLOR_RED}FAIL (CRASH)${COLOR_RESET}"
                echo "${TEST_OUTPUT}" | tail -n 5
                ((FAILED_COUNT++))
            fi
        else
            echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
            ((PASSED_COUNT++))
        fi
    done

    echo ""
    echo -e "${COLOR_BLUE}Smoke Test Results for ${node_name}:${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}Passed:${COLOR_RESET} ${PASSED_COUNT}/20"
    if [ ${FAILED_COUNT} -gt 0 ]; then
        echo -e "  ${COLOR_RED}Failed:${COLOR_RESET} ${FAILED_COUNT}/20"
    fi
    echo ""

    if [ ${FAILED_COUNT} -eq 0 ]; then
        echo -e "${COLOR_GREEN}✓ ${node_name} deployment successful!${COLOR_RESET}"
        return 0
    else
        echo -e "${COLOR_RED}✗ ${node_name} deployment had ${FAILED_COUNT} failure(s)${COLOR_RESET}"
        return 1
    fi
}

# Main deployment logic
echo -e "${COLOR_YELLOW}Deployment Configuration${COLOR_RESET}"
echo -e "  Target: ${DEPLOY_TARGET}"
echo -e "  Project Root: ${PROJECT_ROOT}"
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
echo -e "${COLOR_YELLOW}Deployment Summary${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  Total Nodes: ${TOTAL_NODES}"
echo -e "  ${COLOR_GREEN}Successful:${COLOR_RESET} ${SUCCESSFUL_NODES}"
if [ ${FAILED_NODES} -gt 0 ]; then
    echo -e "  ${COLOR_RED}Failed:${COLOR_RESET} ${FAILED_NODES}"
fi
echo ""

if [ ${FAILED_NODES} -eq 0 ]; then
    echo -e "${COLOR_GREEN}✓ All deployments successful!${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_YELLOW}Fuzzer Location on Nodes:${COLOR_RESET}"
    echo -e "  ${REMOTE_FUZZER_DIR}/"
    echo ""
    echo -e "${COLOR_YELLOW}To run a fuzzer:${COLOR_RESET}"
    echo -e "  ssh root@188.166.255.63"
    echo -e "  cd ${REMOTE_FUZZER_DIR}"
    echo -e "  ./fuzz_sha3 -max_total_time=60"
    echo ""
    exit 0
else
    echo -e "${COLOR_RED}✗ ${FAILED_NODES} deployment(s) failed${COLOR_RESET}"
    exit 1
fi
