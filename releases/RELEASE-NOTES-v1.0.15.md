# Dilithion Testnet v1.0.15 Release Notes

**Release Date:** 2025-11-19
**Critical Release:** YES - All users must upgrade

## Summary

This is a **critical emergency release** that fixes two severe bugs that completely break network functionality:

1. **Bug #32**: Mining template not updating when new blocks arrive
2. **Bug #33**: Initial Block Download (IBD) completely broken - THREE critical bugs

**ALL v1.0.14 AND EARLIER USERS MUST UPGRADE IMMEDIATELY.** These bugs prevent new nodes from syncing and cause blockchain forks.

---

## Critical Bug Fixes

### Bug #32: Mining Template Not Updating (CRITICAL)

**Severity:** CRITICAL - Causes blockchain forks
**Impact:** All mining nodes

**Problem:**
- Mining controller did not detect new blocks arriving from network
- Miners continued mining on stale templates even after network found new blocks
- This caused blockchain forks and wasted hashpower
- The `m_best_block_hash` in mining controller was never updated from network blocks

**Root Cause:**
The mining controller only updated `m_best_block_hash` from its own mined blocks, not from blocks received via P2P. When other nodes mined blocks, the mining controller kept using the old template.

**Fix:**
Added direct callback from blockchain to mining controller in `src/blockchain/blockchain.cpp:535`:
```cpp
// Notify mining controller to update template (Bug #32 fix)
if (m_mining_controller) {
    m_mining_controller->OnNewBlock(block.GetHash());
}
```

This ensures the mining template updates immediately when ANY new block is accepted, whether mined locally or received from peers.

**Files Changed:**
- `src/blockchain/blockchain.cpp`
- `src/blockchain/blockchain.h`

---

### Bug #33: Initial Block Download Completely Broken (CRITICAL)

**Severity:** CRITICAL - IBD does not work at all
**Impact:** All new nodes cannot sync

**Problem:**
IBD failed completely with THREE separate critical bugs that prevented any block synchronization. New nodes could not sync blockchain history from peers.

#### Bug #33-1: Deadlock in Header Processing

**Root Cause:**
`ProcessHeaders()` held `cs_headers` mutex, then called `HaveHeader()` which tried to acquire the same mutex → instant deadlock.

**Fix in `src/p2p/ibd/headers_manager.cpp:290`:**
```cpp
// Check if we already have this header (Bug #33 fix: don't hold cs_headers here)
{
    std::lock_guard<std::mutex> lock(cs_headers);
    if (mapHeaders.find(hash) != mapHeaders.end()) {
        LogDebug("[HeadersManager] Already have header " + hash.ToString().substr(0, 16) + "...");
        continue;
    }
}
```

Changed to check map existence directly in the loop instead of calling `HaveHeader()` which would deadlock.

#### Bug #33-2: Genesis Parent Not Found During First IBD

**Root Cause:**
During first IBD, incoming headers reference genesis block as parent. But genesis only exists in blockchain database (`CBlockIndex`), not in IBD's `mapHeaders`. The lookup `mapHeaders.find(header.hashPrevBlock)` failed, causing headers to be rejected.

**Fix in `src/p2p/ibd/headers_manager.cpp:305`:**
```cpp
// Special case: First header after genesis (Bug #33 fix)
if (mapHeaders.empty() && header.hashPrevBlock == m_blockchain->GetGenesisHash()) {
    LogDebug("[HeadersManager] First header download - parent is genesis block");
    // Don't require parent in mapHeaders for first download
    // Genesis block already exists in blockchain
}
```

Added special handling for the first headers batch that connects to genesis.

#### Bug #33-3: Wrong PoW Validation Using operator<

**Root Cause:**
PoW validation used `operator<` which does lexicographic comparison:
```cpp
if (hash < target) { ... }  // WRONG: treats hashes as little-endian byte arrays
```

This is incorrect because block hashes must be compared as 256-bit big-endian integers.

**Fix in `src/p2p/ibd/headers_manager.cpp:325`:**
```cpp
// Verify proof-of-work (Bug #33 fix: use HashLessThan not operator<)
if (!HashLessThan(hash, target)) {
    LogPrint("[HeadersManager] Invalid PoW for header " + hash.ToString().substr(0, 16) + "...");
    LogPrint("[HeadersManager] ERROR: Invalid header " + hash.ToString().substr(0, 16) + "...");
    return false;
}
```

Changed to use `HashLessThan()` utility function which performs correct big-endian comparison.

**Files Changed:**
- `src/p2p/ibd/headers_manager.cpp`
- `src/p2p/ibd/headers_manager.h`
- `src/util/hash_util.h` (added `HashLessThan` utility)

---

## Testing

All bugs have been verified fixed:

### Bug #32 Testing:
- NYC node mined 5 blocks (heights 1-5)
- Local node synced blocks 1-5 via IBD
- Local node mining template updated correctly to height 5
- Local node successfully mined block 6
- Network accepted block 6 without fork

### Bug #33 Testing:
- Fresh local node with empty blockchain
- Successfully synced 6 blocks from NYC seed node via IBD
- All three bugs verified fixed:
  - No deadlock during header processing ✓
  - Genesis parent correctly recognized ✓
  - PoW validation passed correctly ✓

---

## Deployment Status

All three testnet seed nodes have been upgraded and are running v1.0.15:

- **NYC (134.122.4.164)**: Deployed ✓
- **Singapore (188.166.255.63)**: Deployed ✓
- **London (209.97.177.197)**: Deployed ✓

Current network height: **~6 blocks**

---

## Upgrade Instructions

**CRITICAL: ALL USERS MUST UPGRADE IMMEDIATELY**

### For Current v1.0.14 Users:

1. **Stop your node** (if running)
2. **Download v1.0.15** for your platform (see Downloads below)
3. **WIPE BLOCKCHAIN DATA** - Serialization format changed:
   - Windows: Delete `%USERPROFILE%\.dilithion-testnet\blocks` and `chainstate`
   - Linux/Mac: Delete `~/.dilithion-testnet/blocks` and `chainstate`
4. **Extract new version** and restart node
5. **Node will re-sync** from seed nodes via IBD (now working correctly)

### For New Users:

Simply download and run - IBD now works correctly for initial sync.

---

## Downloads

### Windows x64
- **File:** `dilithion-testnet-v1.0.15-windows-x64.zip` (4.6 MB)
- **SHA256:** `9d9b77d77c1977ded920672c46c0233ee2a3373c4320810b7fa49ad4dcf8453c`

### Linux x64
- **File:** `dilithion-testnet-v1.0.15-linux-x64.tar.gz` (1.1 MB)
- **SHA256:** `f2e9c34469c36d3884d383bd970d8c24492638a1c0712bbd58524688a5e68f03`

### macOS x64
- **File:** `dilithion-testnet-v1.0.15-macos-x64.tar.gz` (3.1 MB)
- **SHA256:** `17c415f071bca40a66bef4b351022c14f54764f74722ace815f1f9588cfe9960`

**Verification:**
```bash
# Download SHA256SUMS file
wget https://github.com/your-org/dilithion/releases/download/v1.0.15/dilithion-testnet-v1.0.15-SHA256SUMS.txt

# Verify checksums
sha256sum -c dilithion-testnet-v1.0.15-SHA256SUMS.txt
```

---

## Known Issues

None currently known.

---

## What's Next (v1.0.16)

With Bug #32 and #33 fixed, the network is now fully functional for basic operations. Future releases will focus on:

- Enhanced network stability
- Performance optimizations
- Additional RPC methods
- Transaction relay improvements

---

## Support

- **Issues:** https://github.com/your-org/dilithion/issues
- **Documentation:** https://docs.dilithion.org

---

**Contributors:** Claude, Will
**Git Tag:** v1.0.15
**Commit:** [Latest main branch]
