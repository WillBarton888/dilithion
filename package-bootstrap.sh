#!/bin/bash
################################################################
#  DILITHION - PACKAGE BOOTSTRAP
################################################################
#  This script creates a blockchain bootstrap archive from the
#  current node's data directory. Run on a fully synced node.
#
#  The bootstrap allows new users to skip IBD (Initial Block
#  Download) by extracting a pre-synced blocks database.
################################################################

# Configuration
DATA_DIR="${HOME}/.dilithion-testnet"
BLOCKS_DIR="${DATA_DIR}/blocks"
CHAINSTATE_DIR="${DATA_DIR}/chainstate"

# Check if blocks directory exists
if [ ! -d "$BLOCKS_DIR" ]; then
    echo "ERROR: Blocks directory not found at ${BLOCKS_DIR}"
    echo "Make sure you're running this on a synced node."
    exit 1
fi

# Check if chainstate directory exists
if [ ! -d "$CHAINSTATE_DIR" ]; then
    echo "ERROR: Chainstate directory not found at ${CHAINSTATE_DIR}"
    echo "Make sure you're running this on a synced node."
    exit 1
fi

# Get current block height (best effort - read from node or estimate from files)
# We'll include the height in the filename so users know what they're getting
if [ -f "${DATA_DIR}/height.txt" ]; then
    BLOCK_HEIGHT=$(cat "${DATA_DIR}/height.txt")
elif command -v curl &> /dev/null && curl -s http://localhost:8080/info 2>/dev/null | grep -q height; then
    BLOCK_HEIGHT=$(curl -s http://localhost:8080/info | grep -o '"height":[0-9]*' | cut -d: -f2)
else
    # Fallback: use "latest" if we can't determine height
    BLOCK_HEIGHT="latest"
fi

BOOTSTRAP_NAME="bootstrap-testnet-block${BLOCK_HEIGHT}"
OUTPUT_FILE="${BOOTSTRAP_NAME}.tar.gz"

echo ""
echo "================================================================"
echo "  CREATING DILITHION BOOTSTRAP"
echo "================================================================"
echo ""
echo "Data directory: ${DATA_DIR}"
echo "Block height:   ${BLOCK_HEIGHT}"
echo "Output file:    ${OUTPUT_FILE}"
echo ""

# Check for LOCK files - node should ideally be stopped
if ls "${BLOCKS_DIR}"/*.LOCK 1>/dev/null 2>&1 || ls "${BLOCKS_DIR}"/LOCK 1>/dev/null 2>&1; then
    echo "WARNING: LOCK files detected. For best results, stop the node first."
    echo "Continuing anyway (LevelDB should handle this)..."
    echo ""
fi

# Create bootstrap directory
echo "[1/4] Preparing bootstrap directory..."
TEMP_DIR=$(mktemp -d)
mkdir -p "${TEMP_DIR}/bootstrap"

# Copy blocks directory (excluding LOCK files and logs)
echo "[2/4] Copying blocks database (this may take a while)..."
rsync -a --exclude='*.LOCK' --exclude='LOCK' --exclude='LOG*' \
    "${BLOCKS_DIR}/" "${TEMP_DIR}/bootstrap/blocks/"

# Copy chainstate directory (UTXO set - required for fast sync!)
echo "[3/4] Copying chainstate (UTXO set)..."
rsync -a --exclude='*.LOCK' --exclude='LOCK' --exclude='LOG*' \
    "${CHAINSTATE_DIR}/" "${TEMP_DIR}/bootstrap/chainstate/"

# Create the archive
echo "[4/4] Creating compressed archive..."
cd "${TEMP_DIR}"
tar -czf "${OUTPUT_FILE}" bootstrap/

# Move to current directory or releases/
if [ -d "releases" ]; then
    mv "${OUTPUT_FILE}" "releases/${OUTPUT_FILE}"
    FINAL_PATH="releases/${OUTPUT_FILE}"
else
    mv "${OUTPUT_FILE}" "${OLDPWD}/${OUTPUT_FILE}"
    FINAL_PATH="${OLDPWD}/${OUTPUT_FILE}"
fi
cd "${OLDPWD}"

# Cleanup
rm -rf "${TEMP_DIR}"

# Show results
echo ""
echo "================================================================"
echo "  BOOTSTRAP CREATED!"
echo "================================================================"
echo ""
echo "Bootstrap archive: ${FINAL_PATH}"
echo "Archive size:      $(ls -lh "${FINAL_PATH}" | awk '{print $5}')"
echo ""
echo "Upload to GitHub release with:"
echo "  gh release upload vX.X.X ${FINAL_PATH}"
echo ""
echo "Users can extract with:"
echo "  tar -xzf ${OUTPUT_FILE} -C ~/.dilithion-testnet --strip-components=1"
echo ""
