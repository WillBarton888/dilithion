# BUG #147: IBD Block Download Optimization Plan

## Problem Statement
During IBD (Initial Block Download), block download is extremely slow (~1-7 blocks/minute instead of 100+).

## Root Causes Identified
1. **Exponential backoff during IBD** - When peer selection fails once, backs off 1→30 seconds
2. **Single GETDATA per block** - 16 network messages instead of 1 batched
3. **Low in-flight limit** - 16 blocks vs Bitcoin Core's 128
4. **Synchronous block validation** - Blocks P2P thread during validation

---

## Phase 1: Quick Wins (COMPLETED)

### Fix 1.1: Disable Exponential Backoff During IBD
**File**: `src/node/ibd_coordinator.cpp:113-129`
- During `BLOCKS_DOWNLOAD` state: fixed 1-second interval
- Outside IBD: exponential backoff (1, 2, 4, 8, 16, 30s)

### Fix 1.2: Batch GETDATA Messages
**File**: `src/node/ibd_coordinator.cpp:177-232`
- Group blocks by peer
- Send ONE batched GETDATA per peer (not per block)

### Fix 1.3: Increase In-Flight Limits
**File**: `src/net/block_fetcher.h:359-361`
- `MAX_BLOCKS_IN_FLIGHT`: 16 → 128
- `MAX_BLOCKS_PER_PEER`: 8 → 16

---

## Phase 2: Async Block Validation

### Current Problem
Block processing in `dilithion-node.cpp:1866-2170` is synchronous:
- Block arrives → PoW check → DB write → **ActivateBestChain() (50-500ms)** → Next block
- P2P thread blocks during validation, can't receive more blocks

### Proposed Architecture
```
P2P Thread (fast)          Validation Worker (slow)
─────────────────          ────────────────────────
Receive block
PoW check (cheap)
Save to DB
Queue block ─────────────► Process queue (height order)
Return immediately         ActivateBestChain()
Continue receiving         UTXO validation
```

### Phase 2.1: Create CBlockValidationQueue Class (~1-2h)

**New file**: `src/node/block_validation_queue.h`

```cpp
class CBlockValidationQueue {
public:
    struct QueuedBlock {
        CBlock block;
        int peer_id;
        uint256 hash;
        int expected_height;
        int64_t queued_time;

        bool operator<(const QueuedBlock& other) const {
            return expected_height > other.expected_height;  // Min-heap by height
        }
    };

    struct Stats {
        size_t queue_depth;
        size_t total_queued;
        size_t total_validated;
        size_t total_rejected;
        double avg_validation_time_ms;
        int last_validated_height;
    };

    explicit CBlockValidationQueue(CChainState& chainstate, CBlockchainDB& db);
    ~CBlockValidationQueue();

    bool Start();
    void Stop();
    bool IsRunning() const;

    // Queue block for async validation (returns immediately)
    bool QueueBlock(int peer_id, const CBlock& block, int expected_height);

    // Wait for specific block to be validated
    bool WaitForBlock(const uint256& hash, std::chrono::milliseconds timeout);

    int GetLastValidatedHeight() const;
    Stats GetStats() const;

private:
    void ValidationWorker();
    bool ProcessBlock(const QueuedBlock& block);
    void NotifyBlockValidated(const uint256& hash, bool success);

    CChainState& m_chainstate;
    CBlockchainDB& m_db;

    std::priority_queue<QueuedBlock> m_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<int> m_last_validated_height{-1};

    std::map<uint256, std::promise<bool>> m_pending_notifications;
    std::mutex m_notify_mutex;

    Stats m_stats{};
    std::mutex m_stats_mutex;
};
```

### Phase 2.2: Modify Block Handler (~30m)

**File**: `src/node/dilithion-node.cpp` (block handler callback)

Change from:
```cpp
// Full synchronous validation
g_chainstate.ActivateBestChain(pindex, block, reorg);
```

To:
```cpp
// Cheap checks only (PoW, duplicate, parent exists)
// Then queue for async validation
if (g_node_context.validation_queue && g_node_context.validation_queue->IsRunning()) {
    g_node_context.validation_queue->QueueBlock(peer_id, block, expected_height);
} else {
    // Fallback to synchronous
    ProcessBlockSynchronous(...);
}
```

### Phase 2.3: Update NodeContext (~10m)

**File**: `src/core/node_context.h`

```cpp
class CBlockValidationQueue;  // Forward declaration

struct NodeContext {
    // ... existing members ...
    std::unique_ptr<CBlockValidationQueue> validation_queue;
};
```

### Phase 2.4: Initialize Queue on Startup (~15m)

**File**: `src/node/dilithion-node.cpp` (initialization)

```cpp
g_node_context.validation_queue = std::make_unique<CBlockValidationQueue>(
    g_chainstate, blockchain);
g_node_context.validation_queue->Start();
```

### Phase 2.5: Move Orphan Processing to Worker (~30m)

Move orphan child processing from P2P callback to validation worker thread.

### Phase 2.6: IBD Backpressure (~20m)

**File**: `src/node/ibd_coordinator.cpp`

```cpp
bool CIbdCoordinator::ShouldAttemptDownload() const {
    // ... existing checks ...

    // Backpressure: slow down if validation queue is full
    if (m_node_context.validation_queue) {
        auto stats = m_node_context.validation_queue->GetStats();
        if (stats.queue_depth > 50) {
            return false;  // Let validation catch up
        }
    }
    return true;
}
```

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Race conditions | Single validation worker thread |
| Memory usage | Queue depth limit (100 blocks max) |
| Block ordering | Priority queue by height, only process if parent validated |
| Orphan handling | Process orphans in validation worker |
| Error propagation | Peer misbehavior scoring in worker |
| Non-IBD operation | Fallback to sync for single blocks |

---

## Testing Strategy

1. **Unit Tests**: Queue ordering, backpressure, stats
2. **Integration**: IBD from 1000+ blocks behind
3. **Stress**: Queue at max capacity, rapid arrivals

---

## Reference Files

- `src/net/async_broadcaster.cpp` - Existing worker thread pattern
- `src/consensus/chain.cpp` - ActivateBestChain (thread-safe with cs_main)
- Bitcoin Core PR #16175 - Async ProcessNewBlock
