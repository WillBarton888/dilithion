# Bug #39 - Peer Not Responding to GETDATA Requests During IBD
**Date:** 2025-11-20
**Status:** 🔴 CRITICAL - Blocks IBD
**Priority:** P0 - Must fix before v1.0.16 release

---

## Executive Summary

During E2E testing of Bug #38 fix, a new critical bug was discovered: **peers do not respond to GETDATA requests for blocks during IBD**, preventing fresh nodes from downloading blocks even after successfully receiving headers.

**Impact:** Fresh nodes cannot complete Initial Block Download, rendering the network unusable for new nodes joining.

---

## Bug Description

### What Works ✅
1. Fresh node connects to seed successfully
2. Handshake completes correctly
3. Headers are received and processed (Bug #38 FIX VERIFIED)
4. IBD loop triggers correctly when headers ahead of chain
5. Blocks are queued for download
6. GETDATA requests are sent to peer

### What Fails ❌
**Peer never sends the requested blocks back to the requesting node.**

The requesting node:
- Sends GETDATA for specific block hashes
- Waits for response
- Times out after 30 seconds
- Retries the request
- Times out again
- Peer is marked as "stalled"
- Blocks never arrive

---

## Technical Details

### Test Environment
- **Local Node:** Windows, fresh blockchain (genesis only), commit ff4020d
- **NYC Seed:** 134.122.4.164:18444, height 2, commit a854055
- **Test:** Fresh IBD from genesis

### Evidence from Logs

**Local Node (Requester):**
```
[P2P] Handshake complete with peer 1
[P2P] Received 2 headers from peer 1
[HeadersManager] New best header at height 2
[IBD] Headers ahead of chain - downloading blocks (header=2 chain=1)
[BlockFetcher] Selected peer 1 for download (score: 1090)
[IBD] Sent GETDATA for block 000004f84425c344... (height 1) to peer 1
[BlockFetcher] Selected peer 1 for download (score: 1040)
[IBD] Sent GETDATA for block 0000ed64acc098e0... (height 2) to peer 1

... [30 seconds pass] ...

[BlockFetcher] Found 2 timed-out block requests
[BlockFetcher] Block request timed out: peer=1 height=1 hash=000004f84425c344... retries=0
[BlockFetcher] Peer 1 stalled (total stalls: 2)
[BlockFetcher] Block request timed out: peer=1 height=2 hash=0000ed64acc098e0... retries=0
[BlockFetcher] Peer 1 stalled (total stalls: 4)
```

**Expected:** Peer should respond with BLOCK messages containing the requested blocks
**Actual:** No response, requests timeout

---

## Root Cause - CONFIRMED ✅

**Location:** src/net/net.cpp:498-501

**Issue:** Block serving logic is NOT IMPLEMENTED

```cpp
else if (inv.type == NetProtocol::MSG_BLOCK_INV) {
    // Existing block handling (keep as-is)
    // Block serving logic would go here
}
```

When a GETDATA request is received for a block:
1. ✅ Message is parsed correctly
2. ✅ Block hash is extracted
3. ❌ **NO CODE to fetch block from database**
4. ❌ **NO CODE to create BLOCK message**
5. ❌ **NO CODE to send block to requesting peer**

The function just has a comment where the implementation should be.

**This is a missing feature, not a bug in existing code.**

---

## Reproduction Steps

1. Start seed node with at least 2 blocks (height ≥ 1)
2. Start fresh node from genesis
3. Connect fresh node to seed
4. Observe:
   - Headers are received ✅
   - GETDATA sent ✅
   - Blocks never received ❌
   - Request times out ❌

---

## Impact Assessment

**Severity:** CRITICAL (P0)

**User Impact:**
- Fresh nodes cannot join network
- Network cannot onboard new participants
- IBD completely broken

**Release Blocker:** YES - This must be fixed before v1.0.16 release

**Related Bugs:**
- Bug #38 (FIXED) - Allowed headers to be received
- Bug #39 (THIS BUG) - Blocks not served after headers received

---

## Next Steps

1. ✅ Bug #38 verified FIXED
2. ❌ Bug #39 discovered and documented
3. ⏳ Investigate GETDATA handling in src/net/net.cpp
4. ⏳ Check `ProcessGetDataMessage()` implementation
5. ⏳ Verify block lookup and serving logic
6. ⏳ Fix and test

---

**Report Generated:** 2025-11-20
**Test:** E2E IBD Test (120 seconds)
**Outcome:** Bug #38 FIXED, Bug #39 DISCOVERED
