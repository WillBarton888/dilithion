#!/bin/bash
################################################################
#  DILITHION - PACKAGE BOOTSTRAP
################################################################
#  Creates a blockchain bootstrap archive from a synced node.
#  Bootstrap lets new users skip IBD (Initial Block Download).
#
#  Usage:
#    ./package-bootstrap.sh              # mainnet (default)
#    ./package-bootstrap.sh mainnet      # mainnet
#    ./package-bootstrap.sh testnet      # testnet
#    ./package-bootstrap.sh dilv         # DilV chain
################################################################

NETWORK="${1:-mainnet}"

case "$NETWORK" in
    mainnet|main)
        DATA_DIR="${HOME}/.dilithion"
        RPC_PORT=8332
        NETWORK_LABEL="mainnet"
        ;;
    testnet|test)
        DATA_DIR="${HOME}/.dilithion-testnet"
        RPC_PORT=18332
        NETWORK_LABEL="testnet"
        ;;
    dilv)
        DATA_DIR="${HOME}/.dilv"
        RPC_PORT=9332
        NETWORK_LABEL="dilv"
        ;;
    *)
        echo "Usage: $0 [mainnet|testnet|dilv]"
        exit 1
        ;;
esac

BLOCKS_DIR="${DATA_DIR}/blocks"
CHAINSTATE_DIR="${DATA_DIR}/chainstate"
DFMP_DIR="${DATA_DIR}/dfmp_identity"

# Verify directories exist
if [ ! -d "$BLOCKS_DIR" ]; then
    echo "ERROR: Blocks directory not found at ${BLOCKS_DIR}"
    echo "Make sure you're running this on a synced node."
    exit 1
fi

if [ ! -d "$CHAINSTATE_DIR" ]; then
    echo "ERROR: Chainstate directory not found at ${CHAINSTATE_DIR}"
    echo "Make sure you're running this on a synced node."
    exit 1
fi

if [ ! -d "$DFMP_DIR" ]; then
    echo "WARNING: dfmp_identity directory not found at ${DFMP_DIR}"
    echo "Bootstrap will work but MIK rebuild from chain scan will be slower."
    INCLUDE_DFMP=false
else
    INCLUDE_DFMP=true
fi

# Get current block height via RPC
BLOCK_HEIGHT=$(curl -s --max-time 5 --user rpc:rpc \
    -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
    http://127.0.0.1:${RPC_PORT}/ 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"])' 2>/dev/null)

if [ -z "$BLOCK_HEIGHT" ]; then
    echo "WARNING: Could not get height via RPC (port ${RPC_PORT}). Using 'latest'."
    BLOCK_HEIGHT="latest"
fi

OUTPUT_FILE="bootstrap-${NETWORK_LABEL}-${BLOCK_HEIGHT}.tar.gz"

echo ""
echo "================================================================"
echo "  CREATING DILITHION BOOTSTRAP (${NETWORK_LABEL})"
echo "================================================================"
echo ""
echo "Data directory: ${DATA_DIR}"
echo "Block height:   ${BLOCK_HEIGHT}"
echo "Output file:    ${OUTPUT_FILE}"
echo ""

# CRITICAL: Node MUST be stopped for a clean snapshot
# LevelDB corruption WILL occur if you archive while the node is running.
# Use RPC stop or kill -15 (SIGTERM). NEVER use kill -9 or pkill.
if pgrep -f dilithion-node > /dev/null 2>&1 || pgrep -f dilv-node > /dev/null 2>&1; then
    echo "ERROR: Node is still running! LevelDB data will be corrupt."
    echo ""
    echo "Stop gracefully with RPC:"
    echo "  curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \\"
    echo "    --data-binary '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stop\",\"params\":{\"confirm\":true}}' \\"
    echo "    http://127.0.0.1:${RPC_PORT}/"
    echo ""
    echo "Or: kill -15 \$(pgrep -f dilithion-node)  # then WAIT for exit"
    echo ""
    echo "NEVER use kill -9 or pkill — LevelDB WAL won't flush."
    exit 1
fi

# Create archive
# CRITICAL RULES (from past failures):
#   1. Node MUST be stopped (checked above)
#   2. NEVER exclude *.log — LevelDB WAL files (e.g. 000967.log) are DATA, not debug logs
#   3. Only exclude LOCK files
#   4. MUST include dfmp_identity/ — without it, MIK validation fails above dfmpAssumeValidHeight

DIRS_TO_ARCHIVE="blocks/ chainstate/"
if [ "$INCLUDE_DFMP" = true ]; then
    DIRS_TO_ARCHIVE="blocks/ chainstate/ dfmp_identity/"
fi

echo "[1/3] Archiving ${DIRS_TO_ARCHIVE}..."
cd "${DATA_DIR}"
tar -czf "/root/${OUTPUT_FILE}" --exclude='LOCK' ${DIRS_TO_ARCHIVE}

echo "[2/3] Verifying archive integrity..."
# Check archive can be listed (not truncated/corrupt)
DIR_COUNT=$(tar -tzf "/root/${OUTPUT_FILE}" | grep -cE '^(blocks|chainstate|dfmp_identity)/$' || true)
if [ "$INCLUDE_DFMP" = true ] && [ "$DIR_COUNT" -lt 3 ]; then
    echo "ERROR: Archive verification failed! Expected 3 top-level dirs, found ${DIR_COUNT}."
    echo "Contents:"
    tar -tzf "/root/${OUTPUT_FILE}" | head -20
    exit 1
elif [ "$INCLUDE_DFMP" = false ] && [ "$DIR_COUNT" -lt 2 ]; then
    echo "ERROR: Archive verification failed! Expected 2 top-level dirs, found ${DIR_COUNT}."
    exit 1
fi

# Check that LevelDB WAL files are present (the #1 cause of past corruption)
WAL_COUNT=$(tar -tzf "/root/${OUTPUT_FILE}" | grep -c '\.log$' || true)
echo "   LevelDB WAL files in archive: ${WAL_COUNT}"
if [ "$WAL_COUNT" -eq 0 ]; then
    echo "WARNING: No .log (WAL) files found in archive."
    echo "This MAY be fine if LevelDB compacted recently, but verify before uploading."
fi

echo "[3/3] Done!"

# Show results
echo ""
echo "================================================================"
echo "  BOOTSTRAP CREATED!"
echo "================================================================"
echo ""
echo "File:     /root/${OUTPUT_FILE}"
echo "Size:     $(ls -lh "/root/${OUTPUT_FILE}" | awk '{print $5}')"
echo "Contains: ${DIRS_TO_ARCHIVE}"
echo ""
echo "Directories in archive:"
tar -tzf "/root/${OUTPUT_FILE}" | grep -E '^[^/]+/$' | sort -u
echo ""
echo "Upload to GitHub release:"
echo "  gh release upload vX.X.X /root/${OUTPUT_FILE}"
echo ""
echo "Users extract with:"
case "$NETWORK_LABEL" in
    mainnet) echo "  tar -xzf ${OUTPUT_FILE} -C ~/.dilithion/" ;;
    testnet) echo "  tar -xzf ${OUTPUT_FILE} -C ~/.dilithion-testnet/" ;;
    dilv)    echo "  tar -xzf ${OUTPUT_FILE} -C ~/.dilv/" ;;
esac
echo ""
echo "IMPORTANT: Test before uploading!"
echo "  Extract to temp dir, start node, check for corruption errors."
echo ""
