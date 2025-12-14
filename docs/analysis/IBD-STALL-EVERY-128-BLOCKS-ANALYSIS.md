# IBD Stall Every 128 Blocks - Comprehensive Analysis

**Date:** 2025-01-XX  
**Status:** Research Only - No Code Changes  
**Issue:** Node stalls every 128 blocks during IBD, then eventually restarts

## Executive Summary

The Dilithion node successfully syncs the first 256 blocks (2 batches of 128), then stalls when requesting the third batch (257-384). The `mapBlocksInFlight` stays permanently at size 128, preventing new block requests. However, GETDATA requests ARE being sent, NYC IS sending blocks, but LDN is not receiving/processing them. The node eventually recovers and continues, suggesting this is a temporary stall rather than a permanent freeze.

## Key Observations from Debug Report

### Working Behavior (Blocks 1-256)
- Blocks 1-128: Requested, received, erased from map ✓
- Blocks 129-256: Requested, received, erased from map ✓
- `mapBlocksInFlight` correctly cycles: 0→128→0→128→0

### Stalled Behavior (Blocks 257+)
- Blocks 257-384: Added to `mapBlocksInFlight` (size goes to 128)
- **NEVER removed** - no `mapBlocksInFlight.erase` calls
- No `[DEBUG] Tracked block received` messages
- GETDATA requests ARE being sent
- NYC IS receiving GETDATAs and sending blocks
- LDN socket shows empty buffers (Recv-Q = 0)
- LDN message handler IS running
- **No block messages being logged on LDN**

## Critical Code Path Analysis

### Block Request Flow (Working)
```
1. IBD Coordinator requests chunk (257-384)
2. CBlockFetcher::RequestBlock() called for each block
3. CPeerManager::MarkBlockAsInFlight() adds to mapBlocksInFlight
4. GETDATA message sent to NYC peer
5. NYC receives GETDATA, sends block
6. LDN receives block → ProcessBlockMessage() → block handler
7. Block handler calls MarkBlockReceived() → CPeerManager::MarkBlockAsReceived()
8. mapBlocksInFlight.erase() removes block
```

### Block Receive Flow (Stalled)
```
1. GETDATA sent ✓
2. NYC sends block ✓
3. LDN socket: Recv-Q = 0 (no data waiting) ✗
4. ProcessBlockMessage() never called ✗
5. MarkBlockReceived() never called ✗
6. mapBlocksInFlight stays at 128 ✗
```

## Hypothesis: Window/Chunk Tracking Issue

The fact that this happens **every 128 blocks** (exactly the window size) suggests a window tracking issue. The download window is 128 blocks, and when it fills up, something might be preventing new blocks from being processed.

### Window Tracking Code (block_fetcher.h:346-388)

```cpp
class CDownloadWindow {
    static constexpr int WINDOW_SIZE = 128;
    
    void AdvanceWindow() {
        // Advance window_start past received blocks
        while (m_window_start <= m_target_height) {
            bool can_advance = false;
            
            // Check if height is not pending, not received, and not in-flight
            if (m_pending.count(m_window_start) == 0 &&
                m_received.count(m_window_start) == 0 &&
                !is_in_flight) {
                can_advance = true;
            }
            // Also advance if height is received but queued for validation
            else if (m_received.count(m_window_start) > 0 && is_height_queued_callback) {
                if (is_height_queued_callback(m_window_start)) {
                    can_advance = true;
                    m_received.erase(m_window_start);
                }
            }
            
            if (can_advance) {
                m_window_start++;
            } else {
                break;  // Can't advance - height is still being processed
            }
        }
        
        // Add new heights to pending to fill window
        int window_end = std::min(m_window_start + WINDOW_SIZE - 1, m_target_height);
        for (int h = m_window_start; h <= window_end; h++) {
            if (m_pending.count(h) == 0 && m_received.count(h) == 0) {
                m_pending.insert(h);
            }
        }
    }
};
```

### Potential Issue: Window Not Advancing

If the window doesn't advance past height 256, then:
1. Heights 257-384 are added to `mapBlocksInFlight` (requested)
2. Blocks arrive but window thinks they're "out of window"
3. Blocks might be ignored or not processed
4. Window stays stuck at 256, preventing new blocks from being requested

### Window Advancement Conditions

The window advances when:
1. Height is not in `m_pending`, not in `m_received`, and not in-flight
2. OR height is in `m_received` but queued for validation

The window **doesn't advance** when:
1. Height is in `m_pending` (still being fetched)
2. Height is in `m_received` but NOT queued for validation (stuck)
3. Height is in-flight (being fetched)

## Potential Root Causes

### 1. Window Stuck at Height 256

**Scenario:**
- Window processes blocks 1-256 successfully
- Window advances to 256
- Blocks 257-384 are requested and added to `mapBlocksInFlight`
- Blocks arrive but window doesn't advance past 256
- New blocks can't be added to window because it's "full" (128 blocks pending)
- Window stays stuck until timeout/recovery mechanism kicks in

**Evidence:**
- Happens exactly every 128 blocks (window size)
- Eventually recovers (suggesting timeout/recovery mechanism)
- Blocks are being sent but not received (window might be rejecting them)

### 2. Chunk Tracking Desync

**Scenario:**
- First chunk (1-128) completes successfully
- Second chunk (129-256) completes successfully
- Third chunk (257-384) is assigned but blocks never arrive
- `mapHeightToPeer` still has heights 257-384 mapped to peer
- When blocks arrive, `OnChunkBlockReceived()` can't find them in active chunks
- Blocks are ignored or not processed

**Code Location:** `block_fetcher.cpp:759-872`

```cpp
NodeId CBlockFetcher::OnChunkBlockReceived(int height) {
    // Find which peer had this height assigned
    auto it = mapHeightToPeer.find(height);
    if (it == mapHeightToPeer.end()) {
        return -1;  // Height not tracked
    }
    
    NodeId peer_id = it->second;
    
    // Check active chunk
    auto chunk_it = mapActiveChunks.find(peer_id);
    if (chunk_it != mapActiveChunks.end()) {
        PeerChunk& chunk = chunk_it->second;
        if (height >= chunk.height_start && height <= chunk.height_end) {
            // Process block...
        }
    }
    
    // Check cancelled chunks...
}
```

**Issue:** If chunk was cancelled or completed before blocks arrived, `OnChunkBlockReceived()` might not process them correctly.

### 3. Socket Read Buffer Issue

**Scenario:**
- Blocks are being sent by NYC
- LDN socket shows Recv-Q = 0 (no data waiting)
- But blocks might be stuck in kernel buffer or not being read
- Message handler runs but doesn't extract block messages

**Evidence:**
- Socket is ESTABLISHED
- Recv-Q = 0 (no data in receive queue)
- Send-Q = 0 (no data in send queue)
- Message handler IS running
- But no block messages are being processed

**Possible Causes:**
- TCP receive window is full (flow control)
- Blocks are being sent but TCP ACKs are not being sent
- Socket read buffer is full but not being drained
- Message parsing is failing silently

### 4. Message Handler Blocking

**Scenario:**
- Message handler processes first 256 blocks successfully
- After 256 blocks, something changes in the handler
- Handler might be blocking on a lock or operation
- Subsequent block messages are queued but not processed

**Code Location:** `connman.cpp:570-612`

```cpp
for (const auto& pending : pending_messages) {
    CNetMessage message(pending.msg.command, pending.msg.data);
    
    bool success = false;
    if (m_msg_processor) {
        success = m_msg_processor->ProcessMessage(pending.node_id, message);
    }
    // ...
}
```

**Issue:** If `ProcessMessage()` blocks indefinitely on the 257th block, the loop never continues.

### 5. Block Handler Early Return

**Scenario:**
- Block handler receives blocks 257-384
- But handler has an early return condition that's triggered
- Blocks are received but not processed
- `MarkBlockReceived()` is never called

**Code Location:** `dilithion-node.cpp:1882-2180`

**Potential Early Returns:**
- Block already in chainstate (line 1927-1943)
- Block already in database (line 1972-1997)
- Block is orphan (line 2016-2113)
- Block validation fails (line 1914-1918)

**Issue:** If blocks 257-384 match one of these conditions, they might be skipped without calling `MarkBlockReceived()`.

## Connection to Previous Freeze Issue

This stall issue is **different** from the complete freeze issue:

1. **Complete Freeze:** Node freezes after processing 1 block, 0% CPU, all threads blocked
2. **Periodic Stall:** Node stalls every 128 blocks, eventually recovers, blocks are sent but not received

However, they might share a common root cause:
- **Lock contention** in block processing
- **Window/chunk tracking** issues
- **Message handler** blocking

## Recommended Investigation Steps

### 1. Add Window State Logging

```cpp
void CDownloadWindow::AdvanceWindow() {
    std::cout << "[WINDOW] AdvanceWindow: start=" << m_window_start 
              << " pending=" << m_pending.size() 
              << " received=" << m_received.size()
              << " in_flight=" << m_in_flight.size() << std::endl;
    // ... existing code ...
}
```

### 2. Add Chunk State Logging

```cpp
NodeId CBlockFetcher::OnChunkBlockReceived(int height) {
    std::cout << "[CHUNK] OnChunkBlockReceived: height=" << height 
              << " mapHeightToPeer.count=" << mapHeightToPeer.count(height)
              << " active_chunks=" << mapActiveChunks.size() << std::endl;
    // ... existing code ...
}
```

### 3. Add Socket Buffer Monitoring

```cpp
// In message handler loop
void CConnman::ThreadMessageHandler() {
    // Check socket buffer state
    for (auto& node : m_nodes) {
        int recv_q = GetSocketRecvQueue(node->sock);
        int send_q = GetSocketSendQueue(node->sock);
        if (recv_q > 0 || send_q > 0) {
            std::cout << "[SOCKET] peer=" << node->id 
                      << " Recv-Q=" << recv_q 
                      << " Send-Q=" << send_q << std::endl;
        }
    }
}
```

### 4. Add Block Handler Entry/Exit Logging

```cpp
message_processor.SetBlockHandler([&blockchain](int peer_id, const CBlock& block) {
    uint256 blockHash = block.GetHash();
    std::cout << "[BLOCK-HANDLER] ENTER height=" << g_chainstate.GetHeight() 
              << " hash=" << blockHash.GetHex().substr(0, 16) << std::endl;
    
    // ... existing code ...
    
    std::cout << "[BLOCK-HANDLER] EXIT hash=" << blockHash.GetHex().substr(0, 16) << std::endl;
});
```

### 5. Check for Window Advancement Blocking

Review `CDownloadWindow::AdvanceWindow()` to identify why it might not advance past height 256:
- Are heights 257-384 stuck in `m_pending`?
- Are heights 257-384 stuck in `m_received`?
- Is `is_height_in_flight_callback` returning true incorrectly?

## Files Requiring Deep Analysis

1. **src/net/block_fetcher.cpp:759-872** - `OnChunkBlockReceived()` chunk tracking
2. **src/net/block_fetcher.h:346-388** - `CDownloadWindow::AdvanceWindow()` window advancement
3. **src/net/block_fetcher.cpp:1198-1230** - `OnWindowBlockConnected()` window updates
4. **src/net/connman.cpp:570-612** - Message handler loop
5. **src/node/dilithion-node.cpp:1882-2180** - Block handler (early returns)
6. **src/net/net.cpp:874-918** - `ProcessBlockMessage()` message parsing

## Conclusion

The periodic stall every 128 blocks is most likely caused by a **window/chunk tracking issue** where:

1. The download window fills up after 256 blocks (2 windows of 128)
2. Window doesn't advance past height 256
3. Blocks 257-384 are requested but window thinks they're "out of window"
4. Blocks arrive but are ignored or not processed
5. `mapBlocksInFlight` stays at 128, preventing new requests
6. Eventually, a timeout/recovery mechanism kicks in and window advances

**Next Steps:**
1. Add comprehensive logging to window/chunk tracking
2. Verify window advancement logic
3. Check for early returns in block handler that skip `MarkBlockReceived()`
4. Monitor socket buffer states during stall
5. Review chunk cancellation/cleanup logic
