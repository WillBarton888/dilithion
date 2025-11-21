# Bug #40 - HeadersManager Not Updating with New Blocks

**Date:** 2025-11-21
**Severity:** HIGH
**Status:** Identified during E2E testing
**Impact:** Header-based IBD fails, nodes cannot sync via GETHEADERS/HEADERS protocol

---

## Summary

The HeadersManager component is not being notified when new blocks are added to the blockchain (via mining or IBD). This prevents nodes from serving headers to peers requesting them via GETHEADERS messages.

---

## Reproduction

1. Start Node A with a clean blockchain (genesis only)
2. Node A mines block 1 or receives it via IBD
3. Start Node B and connect to Node A
4. Node B sends GETHEADERS to Node A
5. **Expected:** Node A sends headers for genesis + block 1
6. **Actual:** Node A sends 0 headers

---

## Evidence

From E2E test logs (e2e-multi-node-test.log):
```
[P2P] Handshake complete with peer 1
[P2P] Requesting headers from peer 1
[HeadersManager] RequestHeaders for peer 1
[HeadersManager] Empty locator, peer will send from genesis
[HeadersManager] Sent GETHEADERS to peer 1
[P2P] Received GETHEADERS from peer 1 (locator size: 0)
[IBD] Peer 1 requested headers (locator size: 0)
[IBD] Empty locator - sending from genesis
[IBD] Sending 0 header(s) to peer 1    <-- BUG: Should send at least genesis header
```

---

## Root Cause

The `HeadersManager` maintains an in-memory list of block headers for serving to peers. When a new block is added to the blockchain:

1. **Mining path:** `CBlockchain::ProcessBlock()` → chain tip updated → HeadersManager NOT notified
2. **IBD path:** `CBlockchain::ProcessBlock()` → chain tip updated → HeadersManager NOT notified

The HeadersManager only initializes its headers list during construction, never updating it afterward.

---

## Impact Assessment

### What Works

✅ **Block propagation via INV/GETDATA** - Nodes can broadcast mined blocks and peers can request them
✅ **Direct block transfer** - Blocks received via GETDATA are processed correctly
✅ **Chain validation** - Blockchain integrity checks pass

### What Doesn't Work

❌ **Header-based IBD** - Fresh nodes cannot discover blockchain height from peers
❌ **Fast sync** - Headers-first sync protocol is non-functional
❌ **Network topology discovery** - Nodes cannot determine best peer for syncing

---

## Workaround

Block propagation via INV/GETDATA works correctly. Mined blocks are broadcast immediately and received by all peers. This is sufficient for small networks but doesn't scale well.

---

## Affected Components

### src/net/headers_manager.h
- `CHeadersManager` class - Needs notification mechanism

### src/blockchain/blockchain.cpp
- `CBlockchain::ProcessBlock()` - Should notify HeadersManager after adding block to chain
- `CBlockchain::ActivateBestChain()` - Should notify HeadersManager when tip changes

### src/node/dilithion-node.cpp
- Block serving handler (lines 1097-1118) - Works correctly
- IBD GETHEADERS handler - Returns 0 headers when it should return chain headers

---

## Proposed Fix

### Option 1: Callback Notification (Recommended)
```cpp
// In blockchain.h
class CBlockchain {
    using HeadersUpdateCallback = std::function<void(const CBlockIndex*)>;
    std::vector<HeadersUpdateCallback> m_headersCallbacks;

public:
    void RegisterHeadersCallback(HeadersUpdateCallback callback);
    void NotifyHeadersUpdate(const CBlockIndex* pindex);
};

// In ProcessBlock()
if (pindex becomes new tip) {
    NotifyHeadersUpdate(pindex);
}

// In dilithion-node.cpp
blockchain.RegisterHeadersCallback([&headers_manager](const CBlockIndex* pindex) {
    headers_manager.AddHeader(pindex->GetBlockHeader(), pindex->GetBlockHash());
});
```

### Option 2: Polling (Fallback)
Headers Manager periodically checks blockchain tip and updates its header list.

---

## Test Plan

1. **Unit Test:** Verify HeadersManager receives notifications when blocks are added
2. **Integration Test:** Mine block on Node A, verify Node B can retrieve headers
3. **E2E Test:** Fresh node syncs via headers-first protocol
4. **Regression Test:** Verify INV/GETDATA still works after fix

---

## Priority

**HIGH** - This bug prevents proper IBD scaling. Current workaround (INV/GETDATA) works but is inefficient for networks with >10 nodes or chains with >1000 blocks.

---

## Related Issues

- Bug #36: BlockFetcher not registered (RESOLVED - commit 0c8c126)
- Bug #39: Genesis mismatch causing block rejection (RESOLVED - operational fix)

---

## Discovery Context

Found during E2E testing on 2025-11-21 while verifying multi-node block propagation. All three seed nodes received blocks via INV/GETDATA but could not serve headers to requesting peers.
