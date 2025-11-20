# Bug #34: Headers Received But Blocks Never Downloaded

## Summary (Occam's Razor)

**Problem:** v1.0.15 receives headers from network but starts mining instead of downloading blocks first.

**Root Cause:** Headers handler validates headers but never tells BlockFetcher to download them.

**Simple Fix:** After processing headers, queue them for download.

---

## Evidence From Your Test

You ran v1.0.15 and observed:

```
[HeadersManager] Processing 3 headers from peer 1
[HeadersManager] New best header at height 1
[HeadersManager] New best header at height 2

======================================
[OK] BLOCK FOUND!  <-- Started mining immediately
======================================
Block hash: 00007e3e6b65ab4d8f72b8202d2f997fa72d5a32bb75afc482ca17cc1cce4d6a
```

**Expected behavior:** Download blocks 1-3, THEN mine block 4
**Actual behavior:** Mine competing block 1 (creates fork)

Network had blocks 1-7:
- NYC: 5 blocks
- Singapore: 7 blocks
- London: 7 blocks

---

## Code Analysis

### File: `src/node/dilithion-node.cpp`

**Line 1462-1477: SetHeadersHandler callback**

```cpp
message_processor.SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
    if (headers.empty()) {
        return;
    }

    std::cout << "[IBD] Received " << headers.size() << " header(s) from peer " << peer_id << std::endl;

    // Pass headers to headers manager for validation and storage
    if (g_headers_manager->ProcessHeaders(peer_id, headers)) {
        // Headers were valid and processed successfully
        int bestHeight = g_headers_manager->GetBestHeight();
        uint256 bestHash = g_headers_manager->GetBestHeaderHash();

        std::cout << "[IBD] Headers processed successfully" << std::endl;
        std::cout << "[IBD] Best header height: " << bestHeight << std::endl;
        std::cout << "[IBD] Best header hash: " << bestHash.GetHex().substr(0, 16) << "..." << std::endl;

        // BUG: MISSING CODE HERE TO QUEUE BLOCKS FOR DOWNLOAD!
    }
});
```

**What's missing:** After line 1477, should call:
```cpp
g_block_fetcher->QueueBlockForDownload(hash, height);
```

### Components That Exist But Aren't Used:

1. **`CBlockFetcher`** (`src/net/block_fetcher.h`) - Ready to use
2. **`g_block_fetcher`** (line 93) - Initialized at line 921
3. **`QueueBlockForDownload()`** method - Available but never called

---

## The Fix (Simple)

After headers are validated (line 1470-1477), add code to queue blocks:

```cpp
if (g_headers_manager->ProcessHeaders(peer_id, headers)) {
    // Headers were valid and processed successfully
    int bestHeight = g_headers_manager->GetBestHeight();
    uint256 bestHash = g_headers_manager->GetBestHeaderHash();

    std::cout << "[IBD] Headers processed successfully" << std::endl;
    std::cout << "[IBD] Best header height: " << bestHeight << std::endl;
    std::cout << "[IBD] Best header hash: " << bestHash.GetHex().substr(0, 16) << "..." << std::endl;

    // BUG #34 FIX: Queue the received blocks for download
    if (g_block_fetcher) {
        for (const auto& header : headers) {
            uint256 hash = header.GetHash();
            // Get height from headers manager
            int height = /* need to determine height for this header */;
            g_block_fetcher->QueueBlockForDownload(hash, height);
            std::cout << "[IBD] Queued block " << hash.GetHex().substr(0, 16) << "... for download" << std::endl;
        }
    }
}
```

**Note:** Need to determine how to get the height for each header. HeadersManager must track this.

---

## Why This Wasn't Caught Earlier

- Bug #33 fixes made headers processing work
- But the code to trigger block download was never implemented
- Headers are validated and stored, but BlockFetcher is never notified

---

## Next Steps

1. Find how to get height for each header from HeadersManager
2. Add the missing QueueBlockForDownload() calls
3. Test that blocks are actually downloaded before mining starts
4. Package as v1.0.16

---

**Status:** Bug identified, fix understood, ready to implement when you're back.
