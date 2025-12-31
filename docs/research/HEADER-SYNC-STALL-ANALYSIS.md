# Header Sync Stall Bug - Root Cause Analysis

## Problem Summary

After LDN syncs to height 2000 (matching header height), subsequent headers from peers are not stored. The node gets stuck and cannot sync beyond height 2000 to reach the tip at height 4583.

**Observed Behavior:**
- Initial sync works: First 2000 headers (heights 0-1999) are stored successfully
- Subsequent batches fail: After reaching height 2000, new headers are rejected
- UpdateBestHeader shows wrong heights: Incoming headers show height=1, 101, 201... instead of 2001+
- Parent lookup fails: `mapHeaders.find(header.hashPrevBlock)` returns NULL for headers 2001+

## Root Cause: Progressive Processing Parent Lookup Bug

### The Bug

In `ProcessHeadersProgressive()` (lines 1295-1519 in `src/net/headers_manager.cpp`), there is a critical bug in how parent lookup works for headers after the first batch.

**Code Flow:**

1. **Initial Parent Lookup** (lines 1332-1347):
   ```cpp
   auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
   if (parentIt != mapHeaders.end()) {
       startHeight = parentIt->second.height + 1;
       prevHash = headers[0].hashPrevBlock;  // Set prevHash for batch 0
   }
   ```

2. **Batch Processing Loop** (lines 1398-1499):
   ```cpp
   for (size_t batchStart = 0; batchStart < headers.size(); batchStart += BATCH_SIZE) {
       // Find parent for first header in batch
       if (batchStart == 0) {
           // Uses headers[0].hashPrevBlock (already looked up above)
       } else if (!prevHash.IsNull()) {
           auto parentIt = mapHeaders.find(prevHash);  // ⚠️ BUG HERE
           if (parentIt != mapHeaders.end()) {
               pprev = &parentIt->second;
           }
       }
   }
   ```

### The Problem

**For headers 2001+ arriving in a NEW message:**

When a new batch of headers arrives (e.g., headers 2001-2100), `ProcessHeadersProgressive` is called again:

1. Line 1338: Looks up parent for `headers[0]` (which is header 2001)
   - `headers[0].hashPrevBlock` = RandomX hash of header 2000
   - `mapHeaders.find(headers[0].hashPrevBlock)` should find header 2000
   - **BUT**: Header 2000 was stored with key = `storageHash` = `header.GetHash()` (RandomX hash)
   - **AND**: The lookup uses `header.hashPrevBlock` which should also be RandomX hash
   - **SO**: This should work IF header 2000 is in mapHeaders

2. **The Real Issue**: There's a potential race condition or the parent lookup logic for subsequent headers within the same batch is broken.

### Critical Code Path Analysis

**In `ProcessHeadersProgressive`, for headers within a batch (lines 1424-1491):**

```cpp
for (size_t i = 0; i < batchSize; ++i) {
    const CBlockHeader& header = headers[batchStart + i];
    
    // ... validation ...
    
    // Store header
    mapHeaders[storageHash] = headerData;  // storageHash = header.GetHash()
    
    // Update for next iteration
    prevHash = storageHash;  // ⚠️ This is the RandomX hash of CURRENT header
}
```

**The Issue**: When processing header 2001 (i=1 in batch starting at 2000):
- `header.hashPrevBlock` = RandomX hash of header 2000
- But the code doesn't explicitly look up `header.hashPrevBlock` for headers within the batch!
- It relies on `pprev` being set from the batch start lookup
- If `pprev` is NULL (parent not found), `expectedHeight` defaults to 1 (line 69)

### Why Parent Lookup Fails

Looking at the code more carefully:

**Line 1417-1422** (for subsequent batches):
```cpp
} else if (!prevHash.IsNull()) {
    auto parentIt = mapHeaders.find(prevHash);
    if (parentIt != mapHeaders.end()) {
        pprev = &parentIt->second;
    }
}
```

**The Problem**: `prevHash` is set to the RandomX hash of the LAST header from the PREVIOUS batch. But for a NEW message (headers 2001+), there is no previous batch! The `prevHash` variable is local to the function call and starts as NULL.

**Line 1338** should handle this:
```cpp
auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
```

But if this lookup fails (returns NULL), the function returns false at line 1345, so headers 2001+ would never be processed.

### Why Would Parent Lookup Fail?

1. **Hash Mismatch**: `header.hashPrevBlock` (from wire protocol) might not match the RandomX hash used as the key in `mapHeaders`
2. **Timing Issue**: Header 2000 might not be fully stored in `mapHeaders` when header 2001 arrives
3. **Different Hash Types**: Despite comments saying "hashPrevBlock = parent's RandomX hash", there might be a mismatch

### Evidence from Code

**Line 124-126** (ProcessHeaders):
```cpp
// Direct parent lookup (hashPrevBlock = parent's RandomX hash = parent's storage hash)
auto parentIt = mapHeaders.find(header.hashPrevBlock);
```

**Line 539** (headers_manager.h):
```cpp
std::map<uint256, HeaderWithChainWork> mapHeaders;  ///< RandomX hash -> Header mapping
```

**Line 95** (ProcessHeaders):
```cpp
uint256 storageHash = header.GetHash();  // RandomX hash
mapHeaders[storageHash] = headerData;    // Stored by RandomX hash
```

So the assumption is:
- `mapHeaders` key = RandomX hash (from `header.GetHash()`)
- `header.hashPrevBlock` = RandomX hash of parent
- Lookup should work: `mapHeaders.find(header.hashPrevBlock)`

### The Actual Bug

After careful analysis, I believe the issue is in **`ProcessHeadersProgressive`** for headers within a batch:

**Lines 1424-1491**: When processing headers within a batch, the code doesn't explicitly validate that `pprev` is set correctly for each header. It assumes:
- For batch start (i=0): `pprev` is set from batch start lookup
- For subsequent headers (i>0): `pprev` should be the previous header in the batch

But if the batch start lookup fails (line 1412-1415), `pprev` remains NULL, and ALL headers in that batch will have `expectedHeight = 1` (line 69: `int expectedHeight = pprev ? (pprev->height + 1) : 1;`).

### Why Height Shows as 1, 101, 201...

If `pprev` is NULL:
- `expectedHeight = 1` (line 69)
- But the code uses `startHeight + batchStart + i` for `expectedHeight` (line 1426)
- If `startHeight` is wrong or `pprev` is NULL, heights will be calculated incorrectly

Actually, looking at line 1426:
```cpp
int expectedHeight = startHeight + batchStart + i;
```

This doesn't use `pprev` at all! So if `startHeight` is calculated incorrectly, all heights will be wrong.

**Line 1340**: `startHeight = parentIt->second.height + 1;`
- If parent lookup fails, `startHeight` defaults to 1 (line 1336)
- So headers 2001+ would have `expectedHeight = 1 + 0 + 0 = 1` (for first header in batch)

## Conclusion

**Root Cause**: In `ProcessHeadersProgressive`, when a new batch of headers arrives (headers 2001+), the initial parent lookup (line 1338) fails to find header 2000 in `mapHeaders`. This causes:
1. `startHeight` to default to 1
2. All subsequent headers to have incorrect `expectedHeight` (1, 2, 3... instead of 2001, 2002, 2003...)
3. Parent lookup to fail because `header.hashPrevBlock` doesn't match any stored header

**Why Parent Lookup Fails**: The most likely reasons are:
1. **Hash Mismatch**: `header.hashPrevBlock` from NYC doesn't match the RandomX hash stored as the key in `mapHeaders` for header 2000
2. **Race Condition**: Header 2000 isn't fully committed to `mapHeaders` when header 2001 arrives
3. **Async Processing**: Headers are processed asynchronously, and there's a timing issue where the lookup happens before storage completes

## Recommended Investigation Steps

1. **Add Debug Logging**: Log the exact `hashPrevBlock` value from incoming header 2001 and compare with the RandomX hash of header 2000 stored in `mapHeaders`
2. **Verify Hash Computation**: Ensure `header.GetHash()` (RandomX) produces the same hash that NYC puts in `hashPrevBlock`
3. **Check Async Timing**: Verify that header 2000 is fully stored in `mapHeaders` before header 2001 processing begins
4. **Validate Storage**: Add logging to confirm header 2000 is actually stored with the expected RandomX hash key

## Potential Fixes

1. **Fix Parent Lookup**: Ensure `pprev` is correctly set for each header in the batch, not just the first one
2. **Add Validation**: Explicitly check that parent exists before processing each header
3. **Fix Height Calculation**: Use `pprev->height + 1` instead of `startHeight + batchStart + i` to ensure correctness
4. **Add Retry Logic**: If parent lookup fails, wait briefly and retry (to handle async timing issues)







