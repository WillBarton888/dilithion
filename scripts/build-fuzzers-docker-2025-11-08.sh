#!/bin/bash
# Dilithion Fuzzer Docker Build Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Build all 11 fuzzers in Docker container with GLIBC 2.35 compatibility
# Target: Ubuntu 22.04 LTS container (matches production testnet nodes)
# Date: 2025-11-08
#
# Usage: ./scripts/build-fuzzers-docker-2025-11-08.sh

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
DOCKER_IMAGE="dilithion-fuzzer-builder"
DOCKER_TAG="ubuntu22.04-glibc2.35"
OUTPUT_DIR="${PROJECT_ROOT}/fuzzer_binaries"

# Print header
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}Dilithion Fuzzer Docker Build${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""

# Check Docker availability
echo -e "${COLOR_YELLOW}[1/5] Checking Docker...${COLOR_RESET}"
if ! command -v docker &> /dev/null; then
    echo -e "${COLOR_RED}Error: Docker not found. Please install Docker first.${COLOR_RESET}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${COLOR_RED}Error: Docker daemon not running. Please start Docker.${COLOR_RESET}"
    exit 1
fi
echo -e "${COLOR_GREEN}✓ Docker available${COLOR_RESET}"
echo ""

# Build Docker image
echo -e "${COLOR_YELLOW}[2/5] Building Docker image...${COLOR_RESET}"
echo -e "  Image: ${DOCKER_IMAGE}:${DOCKER_TAG}"
echo -e "  Base: Ubuntu 22.04 (GLIBC 2.35)"
echo ""

cd "${PROJECT_ROOT}"

if docker build -f Dockerfile.fuzzer -t "${DOCKER_IMAGE}:${DOCKER_TAG}" .; then
    echo -e "${COLOR_GREEN}✓ Docker image built successfully${COLOR_RESET}"
else
    echo -e "${COLOR_RED}Error: Docker build failed${COLOR_RESET}"
    exit 1
fi
echo ""

# Extract binaries from container
echo -e "${COLOR_YELLOW}[3/5] Extracting fuzzer binaries...${COLOR_RESET}"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Create temporary container
CONTAINER_ID=$(docker create "${DOCKER_IMAGE}:${DOCKER_TAG}")
echo -e "  Container ID: ${CONTAINER_ID:0:12}"

# Copy binaries
echo -e "  Copying binaries to: ${OUTPUT_DIR}"
if docker cp "${CONTAINER_ID}:/output/." "${OUTPUT_DIR}/"; then
    echo -e "${COLOR_GREEN}✓ Binaries extracted successfully${COLOR_RESET}"
else
    echo -e "${COLOR_RED}Error: Failed to extract binaries${COLOR_RESET}"
    docker rm "${CONTAINER_ID}" &> /dev/null
    exit 1
fi

# Cleanup temporary container
docker rm "${CONTAINER_ID}" &> /dev/null
echo ""

# Verify all 11 fuzzers
echo -e "${COLOR_YELLOW}[4/5] Verifying fuzzer binaries...${COLOR_RESET}"

EXPECTED_FUZZERS=(
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

MISSING_COUNT=0
for fuzzer in "${EXPECTED_FUZZERS[@]}"; do
    if [ -f "${OUTPUT_DIR}/${fuzzer}" ]; then
        SIZE=$(ls -lh "${OUTPUT_DIR}/${fuzzer}" | awk '{print $5}')
        echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} ${fuzzer} (${SIZE})"
    else
        echo -e "  ${COLOR_RED}✗${COLOR_RESET} ${fuzzer} - MISSING"
        ((MISSING_COUNT++))
    fi
done

if [ ${MISSING_COUNT} -gt 0 ]; then
    echo -e "${COLOR_RED}Error: ${MISSING_COUNT} fuzzer(s) missing${COLOR_RESET}"
    exit 1
fi

echo -e "${COLOR_GREEN}✓ All 11 fuzzers verified${COLOR_RESET}"
echo ""

# Display build summary
echo -e "${COLOR_YELLOW}[5/5] Build Summary${COLOR_RESET}"
echo -e "  Docker Image: ${DOCKER_IMAGE}:${DOCKER_TAG}"
echo -e "  GLIBC Version: 2.35 (Ubuntu 22.04)"
echo -e "  Output Directory: ${OUTPUT_DIR}"
echo -e "  Fuzzers Built: 11/11"
echo ""

# Display next steps
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ Build Complete!${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""
echo -e "${COLOR_YELLOW}Next Steps:${COLOR_RESET}"
echo -e "  1. Deploy to production nodes:"
echo -e "     ./scripts/deploy-fuzzers-2025-11-08.sh"
echo ""
echo -e "  2. Or test locally:"
echo -e "     cd ${OUTPUT_DIR}"
echo -e "     ./fuzz_sha3 -max_total_time=60"
echo ""

exit 0
