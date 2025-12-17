# IBD Issues Diagnostic Analysis & Recommendations

**Date:** 2025-12-14  
**Status:** Research Only - No Code Changes  
**Issues:** 128-block stall + slow post-checkpoint sync

## Executive Summary

Two critical IBD issues identified:
1. **128-block stall**: Heights filtered out before request, causing `mapBlocksInFlight` to fill up
2. **Slow post-checkpoint sync**: `GetBestHeight()` returns 3036 instead of 3567, causing window to stall

## Issue 1: 128-Block Stall (Pre-Checkpoint)

### Root Cause Analysis

The diagnostic report shows that heights 3035-3043 are being filtered out before being requested:

```
[IBD-DEBUG] valid_heights empty for peer 1 chunk_heights.size=9 header_height=3567 chain_height=3034
```

**Filter Logic** (`ibd_coordinator.cpp:506-524`):
```cpp
for (int h : chunk_heights) {
    if (h > header_height) { filter_out_of_range++; continue; }      // Filter 1
    if (h <= chain_height) { filter_already_have++; continue; }      // Filter 2
    
    uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
    if (hash.IsNull()) {
        filter_null_hash++;                                           // Filter 3
        continue;  // No header
    }
    
    CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
    if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
        filter_connected++;                                          // Filter 4
        continue;  // Block is actually connected to chain - skip
    }
    
    valid_heights.push_back(h);
}
```

### Potential Causes

#### 1. Filter 3: `filter_null_hash` - GetRandomXHashAtHeight() Returns Null

**Code Location:** `headers_manager.cpp:611-634`

```cpp
uint256 CHeadersManager::GetRandomXHashAtHeight(int height) const {
    // Get the header(s) at this height
    auto heightIt = mapHeightIndex.find(height);
    if (heightIt == mapHeightIndex.end() || heightIt->second.empty()) {
        return uint256();  // ← Returns null
    }
    
    // Get the first header at this height
    const uint256& storageHash = *heightIt->second.begin();
    auto headerIt = mapHeaders.find(storageHash);
    if (headerIt == mapHeaders.end()) {
        return uint256();  // ← Returns null
    }
    
    // Return RandomX hash (or FastHash if below checkpoint)
    if (headerIt->second.randomXHash.IsNull()) {
        // If randomXHash not set, compute it
        return headerIt->second.header.GetHash();
    }
    return headerIt->second.randomXHash;
}
```

**Problem:** Headers above checkpoint (height > 3000) use `GetHash()` (RandomX) as storage hash, but `GetRandomXHashAtHeight()` might not find them if:
- Headers stored but not added to `mapHeightIndex`
- Headers stored with FastHash but height > checkpoint
- `randomXHash` field not populated for post-checkpoint headers

**Investigation Needed:**
- Check if headers above checkpoint are added to `mapHeightIndex`
- Verify `randomXHash` is populated for post-checkpoint headers
- Check if storage hash mismatch causes lookup failure

#### 2. Filter 4: `filter_connected` - Block Already Connected

**Problem:** Blocks might be marked as `BLOCK_VALID_CHAIN` before they're actually connected, or status flag is incorrect.

**Investigation Needed:**
- Check if `BLOCK_VALID_CHAIN` flag is set prematurely
- Verify block status flags are correct for blocks in validation queue
- Check if async validation sets status flags incorrectly

### Recommendations for Issue 1

1. **Deploy Filter Counter Logging** (Already Done)
   - Log which filter rejects each height
   - Identify the primary cause of filtering

2. **Fix GetRandomXHashAtHeight() for Post-Checkpoint Headers**
   ```cpp
   // In GetRandomXHashAtHeight():
   // For headers above checkpoint, storage hash IS the RandomX hash
   // So we can return storageHash directly if randomXHash is null
   if (headerIt->second.randomXHash.IsNull()) {
       // For post-checkpoint headers, storageHash == RandomX hash
       int checkpointHeight = Dilithion::g_chainParams ?
           Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;
       if (height > checkpointHeight) {
           return storageHash;  // Storage hash IS RandomX hash
       }
       // For pre-checkpoint, compute RandomX hash
       return headerIt->second.header.GetHash();
   }
   ```

3. **Fix BLOCK_VALID_CHAIN Check**
   - Only filter blocks that are ACTUALLY connected, not just have the flag
   - Check if block is at chain tip or in main chain
   - Consider blocks in validation queue as "not connected yet"

4. **Add Debug Logging**
   ```cpp
   if (valid_heights.empty()) {
       std::cout << "[IBD-DEBUG] Filter breakdown: "
                 << "out_of_range=" << filter_out_of_range << ", "
                 << "already_have=" << filter_already_have << ", "
                 << "null_hash=" << filter_null_hash << ", "
                 << "connected=" << filter_connected << std::endl;
       
       // Log first few filtered heights for diagnosis
       for (int h : chunk_heights) {
           uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
           CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
           std::cout << "[IBD-DEBUG] Height " << h << ": "
                     << "hash_null=" << hash.IsNull() << ", "
                     << "pindex=" << (pindex ? "yes" : "no") << ", "
                     << "status=" << (pindex ? pindex->nStatus : 0) << std::endl;
       }
   }
   ```

## Issue 2: Extremely Slow Sync Post-3000 (Post-Checkpoint)

### Root Cause Analysis

**Symptom:** `GetBestHeight()` returns 3036 instead of 3567, even though 533 headers were received.

**Expected:** If LDN started at height 3034 and received 533 headers:
- 3034 + 533 = 3567 ✓

**Actual:** `GetBestHeight()` returns 3036 (only 2 headers processed)

### Code Analysis

**GetBestHeight()** (`headers_manager.cpp:571-575`):
```cpp
int CHeadersManager::GetBestHeight() const {
    std::lock_guard<std::mutex> lock(cs_headers);
    return nBestHeight;  // ← Returns cached value
}
```

**UpdateBestHeader()** (`headers_manager.cpp:883-918`):
```cpp
bool CHeadersManager::UpdateBestHeader(const uint256& hash) {
    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        return false;
    }
    
    // Check if this header has more work than current best
    if (hashBestHeader.IsNull()) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        return true;
    }
    
    auto bestIt = mapHeaders.find(hashBestHeader);
    if (bestIt == mapHeaders.end()) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        return true;
    }
    
    // Compare chain work - only update if MORE work
    if (ChainWorkGreaterThan(it->second.chainWork, bestIt->second.chainWork)) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        return true;
    }
    
    return false;  // ← Doesn't update if chain work is equal or less
}
```

### Potential Causes

#### 1. Chain Work Comparison Fails

**Problem:** `UpdateBestHeader()` only updates `nBestHeight` if the new header has MORE chain work. If:
- Headers processed out of order
- Chain work calculation is incorrect
- Headers have equal chain work (shouldn't happen, but possible)

Then `nBestHeight` won't advance.

**Investigation Needed:**
- Check if headers are processed sequentially
- Verify chain work calculation is correct
- Check if headers above checkpoint have correct chain work

#### 2. Headers Not Stored in mapHeaders

**Problem:** Headers might be rejected during `ProcessHeaders()` if:
- Validation fails (timestamp, PoW, etc.)
- Headers are duplicates
- Headers are orphans

**Investigation Needed:**
- Check if `ProcessHeaders()` returns false for headers above checkpoint
- Verify headers are actually stored in `mapHeaders`
- Check if `AddToHeightIndex()` is called for all headers

#### 3. Storage Hash Mismatch

**Problem:** Headers above checkpoint use `GetHash()` (RandomX) as storage hash, but lookup might fail if:
- Headers stored with FastHash instead
- Hash calculation differs between storage and lookup

**Code Location:** `headers_manager.cpp:68-74`
```cpp
// IBD OPTIMIZATION: Use FastHash for blocks AT or BELOW checkpoint height
uint256 storageHash;
if (expectedHeight <= checkpointHeight) {
    storageHash = header.GetFastHash();  // ← Pre-checkpoint: FastHash
} else {
    storageHash = header.GetHash();     // ← Post-checkpoint: RandomX hash
}
```

**Investigation Needed:**
- Verify headers above checkpoint use RandomX hash for storage
- Check if `expectedHeight` calculation is correct
- Verify `mapHeightIndex` uses correct storage hash

#### 4. Headers Processed But Best Header Not Updated

**Problem:** Headers might be stored but `UpdateBestHeader()` not called, or called but doesn't update due to chain work comparison.

**Investigation Needed:**
- Add logging to `UpdateBestHeader()` to track when it's called and why it doesn't update
- Check if headers are stored but best header hash doesn't advance
- Verify chain work comparison logic

### Recommendations for Issue 2

1. **Add Comprehensive Logging to ProcessHeaders()**
   ```cpp
   bool CHeadersManager::ProcessHeaders(NodeId peer, const std::vector<CBlockHeader>& headers) {
       std::cout << "[HeadersManager] ProcessHeaders: peer=" << peer 
                 << " count=" << headers.size() 
                 << " current_best_height=" << nBestHeight << std::endl;
       
       // ... existing processing ...
       
       // After processing all headers
       std::cout << "[HeadersManager] ProcessHeaders complete: "
                 << "new_best_height=" << nBestHeight 
                 << " headers_stored=" << headers.size() << std::endl;
   }
   ```

2. **Add Logging to UpdateBestHeader()**
   ```cpp
   bool CHeadersManager::UpdateBestHeader(const uint256& hash) {
       auto it = mapHeaders.find(hash);
       if (it == mapHeaders.end()) {
           std::cout << "[UpdateBestHeader] Header not found: " << hash.GetHex().substr(0, 16) << std::endl;
           return false;
       }
       
       int newHeight = it->second.height;
       uint256 newWork = it->second.chainWork;
       
       if (hashBestHeader.IsNull()) {
           std::cout << "[UpdateBestHeader] First header: height=" << newHeight << std::endl;
           hashBestHeader = hash;
           nBestHeight = newHeight;
           return true;
       }
       
       auto bestIt = mapHeaders.find(hashBestHeader);
       if (bestIt == mapHeaders.end()) {
           std::cout << "[UpdateBestHeader] Best header missing, updating: height=" << newHeight << std::endl;
           hashBestHeader = hash;
           nBestHeight = newHeight;
           return true;
       }
       
       uint256 bestWork = bestIt->second.chainWork;
       bool hasMoreWork = ChainWorkGreaterThan(newWork, bestWork);
       
       std::cout << "[UpdateBestHeader] Comparing: "
                 << "current_height=" << nBestHeight << " work=" << bestWork.GetHex().substr(0, 16)
                 << " vs new_height=" << newHeight << " work=" << newWork.GetHex().substr(0, 16)
                 << " hasMoreWork=" << hasMoreWork << std::endl;
       
       if (hasMoreWork) {
           std::cout << "[UpdateBestHeader] Updating best header: " << nBestHeight << " -> " << newHeight << std::endl;
           hashBestHeader = hash;
           nBestHeight = newHeight;
           return true;
       }
       
       std::cout << "[UpdateBestHeader] Not updating: new header has less/equal work" << std::endl;
       return false;
   }
   ```

3. **Fix Chain Work Comparison Issue**
   - If headers are processed sequentially, each header should have MORE chain work than previous
   - If chain work comparison fails, there's a bug in chain work calculation
   - Consider updating best header based on height if chain work is equal (shouldn't happen, but safety check)

4. **Verify Header Storage**
   ```cpp
   // After storing header in ProcessHeaders()
   std::cout << "[HeadersManager] Stored header: height=" << height 
             << " storageHash=" << storageHash.GetHex().substr(0, 16)
             << " chainWork=" << chainWork.GetHex().substr(0, 16) << std::endl;
   
   // Verify it's in mapHeightIndex
   auto heightIt = mapHeightIndex.find(height);
   if (heightIt == mapHeightIndex.end() || heightIt->second.find(storageHash) == heightIt->second.end()) {
       std::cerr << "[HeadersManager] ERROR: Header not in height index!" << std::endl;
   }
   ```

5. **Add Diagnostic Function**
   ```cpp
   void CHeadersManager::DiagnosticDump() const {
       std::lock_guard<std::mutex> lock(cs_headers);
       
       std::cout << "[HeadersManager] Diagnostic Dump:" << std::endl;
       std::cout << "  nBestHeight: " << nBestHeight << std::endl;
       std::cout << "  hashBestHeader: " << hashBestHeader.GetHex().substr(0, 16) << std::endl;
       std::cout << "  mapHeaders.size(): " << mapHeaders.size() << std::endl;
       std::cout << "  mapHeightIndex.size(): " << mapHeightIndex.size() << std::endl;
       
       // Find max height in mapHeightIndex
       int maxHeight = -1;
       for (const auto& pair : mapHeightIndex) {
           maxHeight = std::max(maxHeight, pair.first);
       }
       std::cout << "  Max height in index: " << maxHeight << std::endl;
       
       // Check if best header is in map
       auto bestIt = mapHeaders.find(hashBestHeader);
       if (bestIt != mapHeaders.end()) {
           std::cout << "  Best header height: " << bestIt->second.height << std::endl;
           std::cout << "  Best header work: " << bestIt->second.chainWork.GetHex().substr(0, 16) << std::endl;
       } else {
           std::cout << "  ERROR: Best header hash not found in mapHeaders!" << std::endl;
       }
   }
   ```

## Immediate Action Plan

### Priority 1: Diagnose Issue 1 (128-Block Stall)
1. ✅ Deploy filter counter logging (already done)
2. Review logs to identify which filter is rejecting heights
3. Fix the identified filter issue

### Priority 2: Diagnose Issue 2 (Slow Post-Checkpoint)
1. Add logging to `ProcessHeaders()` and `UpdateBestHeader()`
2. Add diagnostic dump function
3. Verify headers are stored correctly
4. Check chain work calculation

### Priority 3: Fix Both Issues
1. Fix `GetRandomXHashAtHeight()` for post-checkpoint headers
2. Fix `UpdateBestHeader()` chain work comparison
3. Fix `BLOCK_VALID_CHAIN` filter logic
4. Test fixes on LDN/SGP nodes

## Files Requiring Changes

1. **src/net/headers_manager.cpp**
   - `GetRandomXHashAtHeight()` - Fix post-checkpoint hash lookup
   - `UpdateBestHeader()` - Add logging, fix chain work comparison
   - `ProcessHeaders()` - Add logging

2. **src/node/ibd_coordinator.cpp**
   - Filter logic - Fix `BLOCK_VALID_CHAIN` check
   - Add detailed filter counter logging

3. **src/net/headers_manager.h**
   - Add `DiagnosticDump()` function declaration

## Conclusion

Both issues are related to header management and tracking:
- **Issue 1**: Headers stored but not found during block request (hash lookup failure)
- **Issue 2**: Headers stored but best height not updated (chain work comparison failure)

The fixes should focus on:
1. Ensuring headers above checkpoint are stored and indexed correctly
2. Fixing hash lookup for post-checkpoint headers
3. Ensuring best header height advances correctly
4. Fixing filter logic to not reject valid blocks




