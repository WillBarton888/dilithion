#!/bin/bash
# Phase 5 Day 5 V2: byte-level equivalence integration test.
#
# Spins up two regtest binaries:
#   Node A (env-var=0, legacy chain selection, mining)
#   Node B (env-var=1, new chain selection, syncing from A)
# Mines until BOTH reach height ≥ MIN_HEIGHT, then stops both, hashes
# both LevelDB datadirs (blocks/ AND chainstate/), declares
# BYTE-EQUIVALENT only when:
#   * entry_count is non-trivial (>> regtest genesis state)
#   * both blocks hashes match
#   * both chainstate hashes match
#
# This guards against the 2026-04-26 red-team finding that the original
# script declared "BYTE-EQUIVALENT" on two empty-except-genesis datadirs
# (3 entries each) when the mining window was too short to produce any
# real blocks. (BLOCKER #3 from the deletion-batch audit.)
#
# Usage: bash tools/run_phase5_v2_byte_equivalence.sh [MIN_HEIGHT] [MAX_WAIT_SECONDS]
#   defaults: MIN_HEIGHT=5, MAX_WAIT_SECONDS=180
#
# Exit codes:
#   0 — byte-equivalent at meaningful chain depth
#   1 — divergent (investigate before deleting Patch B / flipping default)
#   2 — infra failure
#   3 — chain too shallow (mining didn't progress; vacuous proof)

set -u

MIN_HEIGHT="${1:-5}"
MAX_WAIT="${2:-180}"
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

# Engage the new chain-selector path on Node B by setting env var; this
# is the OPT-IN signal post-PR5.4 fix (red-team BLOCKER #2).
echo "=== Phase 5 V2 byte-equivalence ==="
echo "Repo:           $REPO"
echo "Min height:     $MIN_HEIGHT blocks"
echo "Max wait:       ${MAX_WAIT}s"
echo "Node A datadir: $DA"
echo "Node B datadir: $DB"
echo

echo "[A] Starting node A (legacy path, mining, port 19444)..."
# --connect=127.0.0.1:0 = no outbound connections. Node A is the
# isolated mining authority for this test; no peering needed (Node B
# explicitly --connects to it).
DILITHION_USE_NEW_CHAIN_SELECTOR=0 \
    "$BIN" --regtest --datadir="$DA" --mine --no-upnp --relay-only --yes \
    --connect=127.0.0.1:0 \
    --port=19444 --rpcport=19332 \
    >"$TMPBASE/nodeA.log" 2>&1 < /dev/null &
PID_A=$!
sleep 5

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "ERROR: Node A failed to start. Last 20 log lines:" >&2
    tail -20 "$TMPBASE/nodeA.log" >&2
    exit 2
fi
echo "[A] Running (PID $PID_A)"

echo "[B] Starting node B (new path, port 19445, exclusively peering with A)..."
# --connect= (exclusive) skips DNS seeds + hardcoded seed connections.
DILITHION_USE_NEW_CHAIN_SELECTOR=1 \
    "$BIN" --regtest --datadir="$DB" --no-upnp --relay-only --yes \
    --connect=127.0.0.1:19444 \
    --port=19445 --rpcport=19333 \
    >"$TMPBASE/nodeB.log" 2>&1 < /dev/null &
PID_B=$!
sleep 5

if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "ERROR: Node B failed to start. Last 20 log lines:" >&2
    tail -20 "$TMPBASE/nodeB.log" >&2
    exit 2
fi
echo "[B] Running (PID $PID_B)"
echo

# Poll RPC for height until BOTH nodes reach MIN_HEIGHT.
# Dilithion RPC uses standard JSON-RPC POST with rpc:rpc auth and the
# X-Dilithion-RPC: 1 header (per CLAUDE.md / RPC reference).
rpc_height() {
    local port=$1
    curl -s --max-time 3 --user rpc:rpc \
        -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
        --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
        "http://127.0.0.1:$port/" 2>/dev/null \
        | grep -o '"blocks":[0-9]*' | head -1 | cut -d: -f2
}

echo "Polling for chain progress (need both nodes to reach height >= $MIN_HEIGHT)..."
elapsed=0
HA=0
HB=0
while (( elapsed < MAX_WAIT )); do
    sleep 5
    elapsed=$(( elapsed + 5 ))
    HA_NEW=$(rpc_height 19332 2>/dev/null || true)
    HB_NEW=$(rpc_height 19333 2>/dev/null || true)
    HA=${HA_NEW:-$HA}
    HB=${HB_NEW:-$HB}
    printf "  [%3ds] node A height: %s, node B height: %s\n" "$elapsed" "${HA:-?}" "${HB:-?}"
    if [[ -n "$HA" && -n "$HB" && "$HA" -ge "$MIN_HEIGHT" && "$HB" -ge "$MIN_HEIGHT" ]]; then
        echo "  Both nodes at height >= $MIN_HEIGHT after ${elapsed}s. Proceeding."
        break
    fi
done

if [[ -z "$HA" || -z "$HB" || "$HA" -lt "$MIN_HEIGHT" || "$HB" -lt "$MIN_HEIGHT" ]]; then
    echo
    echo "RESULT: CHAIN-TOO-SHALLOW after ${MAX_WAIT}s wait"
    echo "  Node A height: ${HA:-unknown}, Node B height: ${HB:-unknown}, MIN_HEIGHT: $MIN_HEIGHT"
    echo "  Mining didn't progress — proof would be vacuous. Exiting (3)."
    echo "Node A log tail:"; tail -10 "$TMPBASE/nodeA.log"
    echo "Node B log tail:"; tail -10 "$TMPBASE/nodeB.log"
    exit 3
fi

echo
echo "Stopping nodes (SIGTERM, 8s grace for clean shutdown)..."
kill "$PID_A" "$PID_B" 2>/dev/null
sleep 8
kill -9 "$PID_A" "$PID_B" 2>/dev/null
sleep 5

echo
echo "Hashing LevelDB datadirs..."
# Capture stdout (hash) AND stderr (entry count) separately.
H_A_BLOCKS=$("$HASHER" "$DA/blocks" 2>"$TMPBASE/nodeA_blocks_meta") || true
H_B_BLOCKS=$("$HASHER" "$DB/blocks" 2>"$TMPBASE/nodeB_blocks_meta") || true
H_A_CHAIN=$("$HASHER" "$DA/chainstate" 2>"$TMPBASE/nodeA_chain_meta") || true
H_B_CHAIN=$("$HASHER" "$DB/chainstate" 2>"$TMPBASE/nodeB_chain_meta") || true

EC_A_BLOCKS=$(grep -o "Entries hashed: [0-9]*" "$TMPBASE/nodeA_blocks_meta" 2>/dev/null | awk '{print $3}')
EC_B_BLOCKS=$(grep -o "Entries hashed: [0-9]*" "$TMPBASE/nodeB_blocks_meta" 2>/dev/null | awk '{print $3}')
EC_A_CHAIN=$(grep -o "Entries hashed: [0-9]*" "$TMPBASE/nodeA_chain_meta" 2>/dev/null | awk '{print $3}')
EC_B_CHAIN=$(grep -o "Entries hashed: [0-9]*" "$TMPBASE/nodeB_chain_meta" 2>/dev/null | awk '{print $3}')

echo
echo "=== Hash comparison ==="
printf "  Node A blocks/      hash: %s  (entries: %s)\n" "$H_A_BLOCKS" "${EC_A_BLOCKS:-?}"
printf "  Node B blocks/      hash: %s  (entries: %s)\n" "$H_B_BLOCKS" "${EC_B_BLOCKS:-?}"
printf "  Node A chainstate/  hash: %s  (entries: %s)\n" "$H_A_CHAIN" "${EC_A_CHAIN:-?}"
printf "  Node B chainstate/  hash: %s  (entries: %s)\n" "$H_B_CHAIN" "${EC_B_CHAIN:-?}"
echo

# Sanity: entry counts should be non-trivial. Genesis only state ≈ 3
# blocks entries + few chainstate entries. We require BOTH > 3 to
# guarantee the proof is not vacuous (BLOCKER #3 fix).
MIN_ENTRIES=4
if [[ -z "$EC_A_BLOCKS" || -z "$EC_B_BLOCKS" || "$EC_A_BLOCKS" -lt "$MIN_ENTRIES" || "$EC_B_BLOCKS" -lt "$MIN_ENTRIES" ]]; then
    echo "RESULT: VACUOUS-PROOF (entry counts too low — likely just genesis state)"
    echo "  Required: blocks entries >= $MIN_ENTRIES on BOTH nodes"
    exit 3
fi

# Both hashes (blocks AND chainstate) must match for byte-equivalence.
if [[ -z "$H_A_BLOCKS" || -z "$H_B_BLOCKS" || -z "$H_A_CHAIN" || -z "$H_B_CHAIN" ]]; then
    echo "RESULT: INFRA-FAILURE (could not hash one or more datadirs)"
    exit 2
fi

if [[ "$H_A_BLOCKS" == "$H_B_BLOCKS" && "$H_A_CHAIN" == "$H_B_CHAIN" ]]; then
    echo "RESULT: BYTE-EQUIVALENT (blocks AND chainstate match at height A=$HA B=$HB)"
    echo "PR5.4 (Patch B deletion) byte-level proof: PASSING"
    exit 0
fi

echo "RESULT: DIVERGENT"
[[ "$H_A_BLOCKS" != "$H_B_BLOCKS" ]] && echo "  blocks/      DIFFER"
[[ "$H_A_CHAIN"  != "$H_B_CHAIN"  ]] && echo "  chainstate/  DIFFER"
echo "Investigate before any further deletion of legacy paths."
echo "Node A log tail:"; tail -20 "$TMPBASE/nodeA.log"
echo "Node B log tail:"; tail -20 "$TMPBASE/nodeB.log"
exit 1
