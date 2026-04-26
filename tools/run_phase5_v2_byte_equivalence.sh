#!/bin/bash
# Phase 5 Day 5 V2: byte-level equivalence integration test.
#
# Spins up two regtest binaries:
#   Node A (env-var=0, legacy chain selection, mining)
#   Node B (env-var=1, new chain selection, syncing from A)
# Lets them sync for a fixed window, stops both, hashes their LevelDB
# datadirs via leveldb_state_hash. Byte-equal hashes prove that the new
# chain-selector path produces the same on-disk state as legacy when
# fed the same block stream.
#
# Usage: bash tools/run_phase5_v2_byte_equivalence.sh [SYNC_SECONDS]
#   default SYNC_SECONDS=30
#
# Exit codes:
#   0 — byte-equivalent (PR5.4 unblocked)
#   1 — divergent (investigate before deleting Patch B)
#   2 — infra failure (binary didn't start, ports busy, etc.)

set -u

SYNC_SECONDS="${1:-30}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/dilv-node.exe"
HASHER="$REPO/leveldb_state_hash.exe"

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: dilv-node.exe not found at $BIN" >&2
    exit 2
fi
if [[ ! -x "$HASHER" ]]; then
    echo "ERROR: leveldb_state_hash.exe not found at $HASHER" >&2
    exit 2
fi

# Use Windows-friendly temp paths since this runs under MSYS2.
TMPBASE="${TMPDIR:-/tmp}/phase5_v2_$$"
DA="$TMPBASE/nodeA"
DB="$TMPBASE/nodeB"
mkdir -p "$DA" "$DB"

cleanup() {
    set +e
    [[ -n "${PID_A:-}" ]] && kill "$PID_A" 2>/dev/null
    [[ -n "${PID_B:-}" ]] && kill "$PID_B" 2>/dev/null
    sleep 2
    [[ -n "${PID_A:-}" ]] && kill -9 "$PID_A" 2>/dev/null
    [[ -n "${PID_B:-}" ]] && kill -9 "$PID_B" 2>/dev/null
}
trap cleanup EXIT

echo "=== Phase 5 V2 byte-equivalence ==="
echo "Repo:           $REPO"
echo "Sync window:    ${SYNC_SECONDS}s"
echo "Node A datadir: $DA"
echo "Node B datadir: $DB"
echo

# Node A: legacy path (env-var=0), mining, listening on default regtest p2p port.
echo "[A] Starting node A (legacy path, mining, port 19444)..."
DILITHION_USE_NEW_CHAIN_SELECTOR=0 \
    "$BIN" --regtest --datadir="$DA" --mine --no-upnp \
    --port=19444 --rpcport=19332 \
    >"$TMPBASE/nodeA.log" 2>&1 &
PID_A=$!
sleep 5

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "ERROR: Node A failed to start. Last 20 log lines:" >&2
    tail -20 "$TMPBASE/nodeA.log" >&2
    exit 2
fi
echo "[A] Running (PID $PID_A)"

# Node B: new path (env-var=1), no mining, syncing from A on port 19445.
echo "[B] Starting node B (new path, port 19445, peering with A)..."
DILITHION_USE_NEW_CHAIN_SELECTOR=1 \
    "$BIN" --regtest --datadir="$DB" --no-upnp \
    --port=19445 --rpcport=19333 \
    --addnode=127.0.0.1:19444 \
    >"$TMPBASE/nodeB.log" 2>&1 &
PID_B=$!
sleep 5

if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "ERROR: Node B failed to start. Last 20 log lines:" >&2
    tail -20 "$TMPBASE/nodeB.log" >&2
    exit 2
fi
echo "[B] Running (PID $PID_B)"
echo

echo "Mining + syncing for ${SYNC_SECONDS}s..."
sleep "$SYNC_SECONDS"

echo "Stopping nodes (gentle SIGTERM, 8s grace for clean shutdown)..."
kill "$PID_A" "$PID_B" 2>/dev/null
sleep 8
kill -9 "$PID_A" "$PID_B" 2>/dev/null
# Give the OS time to release LevelDB LOCK files after process death.
sleep 5

echo "Hashing LevelDB datadirs..."
H_A=$("$HASHER" "$DA/blocks" 2>/dev/null) || true
H_B=$("$HASHER" "$DB/blocks" 2>/dev/null) || true

echo "Node A (legacy, env-var=0): $H_A"
echo "Node B (new,    env-var=1): $H_B"
echo

if [[ -z "$H_A" || -z "$H_B" ]]; then
    echo "RESULT: INFRA FAILURE (could not hash one or both datadirs)"
    echo "Node A log tail:"; tail -10 "$TMPBASE/nodeA.log"
    echo "Node B log tail:"; tail -10 "$TMPBASE/nodeB.log"
    exit 2
fi

if [[ "$H_A" == "$H_B" ]]; then
    echo "RESULT: BYTE-EQUIVALENT — PR5.4 (Patch B deletion) unblocked"
    exit 0
else
    echo "RESULT: DIVERGENT — investigate before deleting Patch B"
    echo "Node A log tail:"; tail -20 "$TMPBASE/nodeA.log"
    echo "Node B log tail:"; tail -20 "$TMPBASE/nodeB.log"
    exit 1
fi
