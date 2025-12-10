# BUG #52 and #53 - RESOLVED

## Date: 2025-11-26

## Summary

Two critical bugs were fixed that were preventing fresh nodes from properly syncing with the network:

- **BUG #52**: Fresh nodes mined their own chain before completing Initial Block Download (IBD)
- **BUG #53**: Headers sent to peers had zero merkle root, causing "Invalid PoW" errors

## BUG #52: Mining Before IBD Complete

### Problem
Fresh nodes would start mining immediately on their own chain, creating incompatible forks with the network.

**Symptoms:**
- Fresh node mines 34 blocks while network has 13
- "Invalid PoW" errors when receiving headers from peers
- Permanent fork between new and existing nodes

### Root Cause
Mining started immediately at `dilithion-node.cpp:2206` without waiting for IBD to complete. Bitcoin Core disables mining during IBD to prevent this exact problem.

### Solution
Implemented Bitcoin-style IsInitialBlockDownload() check:

1. **Added `GetBestPeerHeight()` to CPeerManager** (`peers.h`, `peers.cpp`)
   - Returns highest chain height reported by connected peers
   - Uses existing `start_height` from VERSION messages

2. **Added `IsInitialBlockDownload()` function** (`dilithion-node.cpp`)
   - O(1) check - doesn't verify all blocks
   - Returns true if peers are significantly ahead (6+ blocks)
   - Allows mining during network bootstrap (all nodes at genesis)
   - Checks tip timestamp for stale chains

3. **Modified mining startup** (`dilithion-node.cpp:2250-2277`)
   - Checks IBD before starting mining
   - Waits in loop if syncing needed
   - Shows progress every 10 seconds
   - Starts mining only after sync complete

### Files Changed
- `src/net/peers.h`: Added `GetBestPeerHeight()` declaration
- `src/net/peers.cpp`: Implemented `GetBestPeerHeight()`
- `src/node/dilithion-node.cpp`: Added `IsInitialBlockDownload()` and IBD check

## BUG #53: Zero Merkle Root in Headers

### Problem
When sending headers to peers, the merkle root was all zeros, causing header hash mismatch and "Invalid PoW" errors.

### Root Cause
Block index serialization in `blockchain_storage.cpp` did NOT store the merkle root:
```cpp
// Comment at line 601: "hashMerkleRoot is not stored in the index, will be 0"
```
This was NOT OK - peers need correct merkle root to compute block hash.

### Solution
Added merkle root to block index serialization:

1. **WriteBlockIndex()**: Added merkle root serialization (64 hex chars)
2. **ReadBlockIndex()**: Added merkle root deserialization

### Files Changed
- `src/node/blockchain_storage.cpp`: Added merkle root serialization/deserialization

## Testing Results

### Network Consensus Test
After deploying fixes to all three remote nodes (NYC, Singapore, London):

1. Fresh blockchain data wiped on all nodes
2. Nodes started with `--mine`
3. Singapore and London found block 1 at same time
4. **BOTH NODES HAVE IDENTICAL BLOCK 1 HASH:**
   ```
   0000a442051531aa92bc55edeebe582ae9b7780a04b0874d6ea777fe3ce4ed24
   ```

### IBD Test
NYC node started fresh after Singapore/London had block 1:
- NYC shows `mining: false` (IBD check working!)
- NYC sees peers at height 1
- NYC correctly waits for sync before mining

### No Invalid PoW Errors
Headers exchanged between nodes without "Invalid PoW" errors - merkle root fix working.

## Commit

```
2cde37c fix: BUG #52 #53 - IBD check prevents fork creation, merkle root serialization
```

## Verification Commands

Check block count:
```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
  http://127.0.0.1:18332/
```

Check mining status:
```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getmininginfo","params":[]}' \
  http://127.0.0.1:18332/
```

Get block hash at height:
```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":{"height":1}}' \
  http://127.0.0.1:18332/
```

## Conclusion

Both bugs are now fixed. Fresh nodes will:
1. Wait for sync before mining (BUG #52 fix)
2. Receive valid headers from peers (BUG #53 fix)
3. Join the network consensus without creating forks
