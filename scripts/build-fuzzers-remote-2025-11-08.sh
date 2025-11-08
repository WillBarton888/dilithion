#!/bin/bash
# Dilithion Fuzzer Remote Build Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Purpose: Build fuzzers directly on production testnet nodes
# This script is uploaded to and executed on the remote nodes
# Date: 2025-11-08
#
# Usage: ./build-fuzzers-remote-2025-11-08.sh

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Colors for output
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[32m'
COLOR_BLUE='\033[34m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'

echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}Dilithion Fuzzer Remote Build${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo ""

# Check environment
echo -e "${COLOR_YELLOW}[1/6] Environment Check${COLOR_RESET}"
echo -e "  Node: $(hostname)"
echo -e "  GLIBC: $(ldd --version | head -n1)"
echo -e "  GCC: $(gcc --version | head -n1 2>/dev/null || echo 'not installed')"
echo -e "  Clang: $(clang --version | head -n1 2>/dev/null || echo 'not installed')"
echo ""

# Install dependencies if needed
echo -e "${COLOR_YELLOW}[2/6] Installing Dependencies${COLOR_RESET}"
if ! command -v clang-14 &> /dev/null; then
    echo -e "  Installing clang-14..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq clang-14 libc++-14-dev libc++abi-14-dev build-essential cmake libleveldb-dev git
    echo -e "${COLOR_GREEN}✓ Dependencies installed${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ Dependencies already installed${COLOR_RESET}"
fi
echo ""

# Navigate to project directory
WORK_DIR="/root/dilithion-fuzzer-build"
echo -e "${COLOR_YELLOW}[3/6] Preparing Build Directory${COLOR_RESET}"
echo -e "  Directory: ${WORK_DIR}"

cd /root
if [ -d "${WORK_DIR}" ]; then
    echo -e "  Cleaning existing directory..."
    rm -rf "${WORK_DIR}"
fi

# Clone or copy source (assume source is already uploaded)
if [ -d "dilithion" ]; then
    echo -e "  Copying from /root/dilithion..."
    cp -r dilithion "${WORK_DIR}"
else
    echo -e "${COLOR_RED}Error: Source directory not found${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Please upload source first:${COLOR_RESET}"
    echo -e "  rsync -avz --exclude='.git' . root@NODE_IP:/root/dilithion/"
    exit 1
fi

cd "${WORK_DIR}"
echo -e "${COLOR_GREEN}✓ Build directory ready${COLOR_RESET}"
echo ""

# Build dependencies
echo -e "${COLOR_YELLOW}[4/6] Building Dependencies${COLOR_RESET}"

echo -e "  Building RandomX..."
cd depends/randomx
rm -rf build
mkdir -p build
cd build
cmake .. > /dev/null
make -j$(nproc) > /dev/null 2>&1
echo -e "${COLOR_GREEN}  ✓ RandomX built${COLOR_RESET}"

cd "${WORK_DIR}"
echo -e "  Building Dilithium..."
cd depends/dilithium/ref
rm -f *.o  # Clean object files
# Build only the object files we need (not the test binaries)
gcc -O2 -DDILITHIUM_MODE=3 -c sign.c -o sign.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c packing.c -o packing.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c polyvec.c -o polyvec.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c poly.c -o poly.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c ntt.c -o ntt.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c reduce.c -o reduce.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c rounding.c -o rounding.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c symmetric-shake.c -o symmetric-shake.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c fips202.c -o fips202.o 2>&1 | tail -n 5
gcc -O2 -DDILITHIUM_MODE=3 -c randombytes.c -o randombytes.o 2>&1 | tail -n 5
echo -e "${COLOR_GREEN}  ✓ Dilithium built${COLOR_RESET}"

cd "${WORK_DIR}"
echo ""

# Build fuzzers
echo -e "${COLOR_YELLOW}[5/6] Building Fuzzers${COLOR_RESET}"
echo -e "  Using clang-14 with libFuzzer..."

export FUZZ_CXX=clang++-14
make clean > /dev/null 2>&1
if make -j$(nproc) fuzz 2>&1 | tee /tmp/fuzzer_build.log; then
    echo -e "${COLOR_GREEN}✓ Fuzzers built successfully${COLOR_RESET}"
else
    echo -e "${COLOR_RED}Error: Fuzzer build failed${COLOR_RESET}"
    tail -n 20 /tmp/fuzzer_build.log
    exit 1
fi
echo ""

# Verify fuzzers
echo -e "${COLOR_YELLOW}[6/6] Verifying Fuzzers${COLOR_RESET}"

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

MISSING_COUNT=0
for fuzzer in "${FUZZERS[@]}"; do
    if [ -f "${fuzzer}" ]; then
        SIZE=$(ls -lh "${fuzzer}" | awk '{print $5}')
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
echo ""

# Copy to final location
OUTPUT_DIR="/root/dilithion-fuzzers"
echo -e "${COLOR_YELLOW}Copying to ${OUTPUT_DIR}...${COLOR_RESET}"
mkdir -p "${OUTPUT_DIR}"
# Only copy fuzzer binaries, not directories
for fuzzer in fuzz_*; do
    if [ -f "${fuzzer}" ]; then
        cp -f "${fuzzer}" "${OUTPUT_DIR}/"
        chmod +x "${OUTPUT_DIR}/${fuzzer}"
    fi
done
echo -e "${COLOR_GREEN}✓ Fuzzers copied${COLOR_RESET}"
echo ""

# Build summary
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ Build Complete!${COLOR_RESET}"
echo -e "${COLOR_BLUE}========================================${COLOR_RESET}"
echo -e "  Output Directory: ${OUTPUT_DIR}"
echo -e "  Fuzzers Built: 20/20"
echo ""
echo -e "${COLOR_YELLOW}Test a fuzzer:${COLOR_RESET}"
echo -e "  cd ${OUTPUT_DIR}"
echo -e "  ./fuzz_sha3 -max_total_time=60"
echo ""

exit 0
