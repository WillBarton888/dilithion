# BUG #118: Slow RandomX Header Validation Blocks IBD

## Priority: HIGH (P1)

## Status: OPEN

## Summary
Header validation during IBD (Initial Block Download) is extremely slow because every `header.GetHash()` call performs a full RandomX hash computation, taking ~1-2 seconds per header. Validating 2000 headers blocks the node for 30-45 minutes.

## Impact
- **Sync time**: A new node takes hours to days to sync instead of minutes
- **Peer disconnections**: Connections time out while headers are being validated
- **Network fragmentation**: Nodes can't maintain stable peer connections during IBD
- **User experience**: Unacceptable for production use

## Root Cause

In `src/primitives/block.cpp:52-72`:
```cpp
uint256 CBlockHeader::GetHash() const {
    // ... serialize header ...

    // RandomX hash (CPU-mining resistant, ASIC-resistant)
    uint256 result;
    randomx_hash_fast(data.data(), data.size(), result.data);  // ~1-2 sec per call!
    return result;
}
```

In `src/net/headers_manager.cpp:281-293`:
```cpp
bool CHeadersManager::ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev)
{
    uint256 hash = header.GetHash();  // Triggers slow RandomX computation

    // 1. Check Proof of Work
    if (!CheckProofOfWork(hash, header.nBits)) {
        return false;
    }
    // ...
}
```

Every header received during IBD triggers:
1. `ProcessHeaders()` calls `ValidateHeader()` for each header
2. `ValidateHeader()` calls `header.GetHash()`
3. `GetHash()` computes full RandomX hash (~1-2 seconds)
4. 2000 headers × 1.5 sec = **50 minutes per batch**

## Observed Behavior

```
[IBD] Received 2000 header(s) from peer 1
[DEBUG-BUG118] Calling ValidateHeader for header 0...
[DEBUG-BUG118] ValidateHeader returned TRUE for header 0
[DEBUG-BUG118] Calling ValidateHeader for header 1...
... (30-45 minutes later) ...
[DEBUG-BUG118] ValidateHeader returned TRUE for header 1999
```

During this time:
- No blocks can be downloaded
- Peer connections time out (90 second timeout)
- Node appears stuck

## Comparison with Bitcoin Core

Bitcoin Core uses SHA256d for block hashes, which computes in microseconds. Dilithion uses RandomX for ASIC-resistance, but this creates a fundamental problem for header validation.

## Proposed Solutions

### Option 1: Cache Header Hashes (Recommended)
Store computed header hashes in the database. On restart, load cached hashes instead of recomputing.

```cpp
uint256 CBlockHeader::GetHash() const {
    // Check cache first
    if (hash_cached && hash_valid) {
        return cached_hash;
    }
    // Compute and cache
    cached_hash = ComputeRandomXHash();
    hash_valid = true;
    return cached_hash;
}
```

**Pros**: Simple, maintains security
**Cons**: Increases storage, cache invalidation complexity

### Option 2: Skip PoW Validation During IBD
During IBD, trust the header chain from peers and only validate PoW for blocks.

```cpp
bool CHeadersManager::ValidateHeader(const CBlockHeader& header, ...) {
    if (IsInIBD() && !fForceValidation) {
        // Skip PoW check during IBD - blocks will be validated later
        return ValidateHeaderStructure(header);
    }
    // Full validation
    return ValidateHeaderWithPoW(header);
}
```

**Pros**: Fastest solution, matches some altcoin approaches
**Cons**: Temporarily trusts peer, requires careful security analysis

### Option 3: Async/Parallel Header Validation
Validate headers in background threads while continuing to receive more.

```cpp
void CHeadersManager::ProcessHeadersAsync(const std::vector<CBlockHeader>& headers) {
    // Queue for background validation
    m_validation_queue.push(headers);
    // Continue receiving without blocking
}
```

**Pros**: Non-blocking, maintains full security
**Cons**: Complex implementation, memory usage

### Option 4: Checkpoint-Based Validation
Hardcode known-good header hashes at checkpoints. Only validate PoW for headers after last checkpoint.

**Pros**: Very fast for historical chain
**Cons**: Requires regular checkpoint updates, centralization concern

## Recommended Fix

**Phase 1 (Immediate)**: Implement Option 2 with guards
- Skip PoW validation during IBD for headers
- Validate full PoW when processing blocks
- Add configuration flag `--validate-headers-pow` for paranoid users

**Phase 2 (Short-term)**: Implement Option 1
- Cache all computed header hashes in LevelDB
- Load cache on startup
- Dramatically reduces restart time

## Test Cases

1. Fresh node sync: Should complete IBD in < 1 hour (not days)
2. Node restart: Should resume sync in < 5 minutes
3. Peer stability: Connections should not timeout during IBD
4. Security: Malicious headers with invalid PoW should be rejected

## Files to Modify

- `src/net/headers_manager.cpp` - Add IBD-aware validation
- `src/net/headers_manager.h` - Add cache structures
- `src/primitives/block.cpp` - Add hash caching
- `src/node/ibd_coordinator.cpp` - Track IBD state

## References

- Bitcoin Core headers-first sync: https://github.com/bitcoin/bitcoin/blob/master/src/headerssync.cpp
- RandomX documentation: https://github.com/tevador/RandomX

## Timeline

- **Identified**: 2025-12-09
- **Assigned**: TBD
- **Target Fix**: Before mainnet launch (CRITICAL)
