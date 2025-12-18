# IBD Architecture Redesign - Detailed Handoff Document

## Executive Summary

This document provides all context needed to continue the IBD (Initial Block Download) architecture redesign for Dilithion. The redesign addresses fundamental performance and reliability issues discovered during testnet sync.

**Goal**: Make IBD simple, fast, efficient, and reliable by:
1. Never blocking the message handler (all expensive operations async)
2. Single source of truth for tracking (eliminate desync bugs)
3. Checkpoint-aware pipeline (trust blocks below checkpoint)
4. Simple state machine (clear states, deterministic transitions)

**Plan Status**: APPROVED by user, ready for implementation
**Plan Location**: `C:\Users\will\.claude\plans\compressed-coalescing-lemon.md`

---

## Background: Why This Redesign Is Needed

### Root Cause Analysis

During testnet sync, we discovered that **headers processing blocks the message handler for 100+ seconds**:

```
2000 headers × 75ms RandomX hash computation = 150 seconds blocking
```

This causes a cascade of problems:
- Block messages queue up and aren't processed
- Peers timeout waiting for responses
- IBD stalls repeatedly
- Complex workarounds created more bugs

### Bugs That Led to This Redesign

| Bug | Description | Root Cause |
|-----|-------------|------------|
| BUG #158 | Fork detection lag | Only detects after 5 ticks of no progress |
| BUG #165 | vBlocksInFlight desync | Multiple sources of truth |
| BUG #166 | Permanent peer stall | In-flight tracking desync |
| BUG #167 | Message queue starvation | Headers processing blocks message handler |
| IBD STUCK #3 | Orphan accumulation | Reactive orphan scan every 10 seconds |

### Temporary Fixes Applied (Still in codebase)

In `src/net/connman.cpp` (lines 532-600), we added:
1. Per-node message limit: 20 messages per node per batch
2. Headers throttling: Max 1 headers message per batch
3. Global batch limit: 200 messages total

These are **band-aids**, not solutions. The redesign replaces them with proper async architecture.

---

## Approved Architecture: "Pipeline IBD"

### Core Design Principle

**Everything is a pipeline stage. Nothing blocks. Everything flows.**

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NETWORK LAYER                                      │
│  Socket → ExtractMessages → Classify Message Type                           │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                    │                    │
                    ▼                    ▼                    ▼
         ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
         │  HEADERS QUEUE  │  │   BLOCK QUEUE   │  │  CONTROL QUEUE  │
         │   (async)       │  │    (async)      │  │    (sync)       │
         └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
                  │                    │                    │
                  ▼                    │                    ▼
┌─────────────────────────────────┐    │         ┌──────────────────────┐
│     HEADERS PIPELINE            │    │         │  Processed inline    │
│                                 │    │         │  (version, verack,   │
│  ┌─────────────────────────┐   │    │         │   ping, pong, etc.)  │
│  │ Structure Validation    │   │    │         └──────────────────────┘
│  │ (~10ms for 2000 headers)│   │    │
│  └───────────┬─────────────┘   │    │
│              ▼                 │    │
│  ┌─────────────────────────┐   │    │
│  │ Hash Computer Pool      │   │    │
│  │ (N threads = CPU cores) │   │    │
│  │ ~37s for 2000 headers   │   │    │
│  └───────────┬─────────────┘   │    │
│              ▼                 │    │
│  ┌─────────────────────────┐   │    │
│  │ Ready Headers Map       │◄──┼────┘
│  │ (height → hash)         │   │
│  └───────────┬─────────────┘   │
└──────────────┼─────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLOCK DOWNLOAD PIPELINE                              │
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   PENDING    │───▶│  IN-FLIGHT   │───▶│   RECEIVED   │                   │
│  │  (heights)   │    │ (height,peer │    │  (heights)   │                   │
│  │              │    │   timeout)   │    │              │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│         ▲                   │                    │                          │
│         │                   │                    ▼                          │
│         │            (timeout)         ┌──────────────────┐                 │
│         └────────────────────          │  VALIDATION      │                 │
│                                        │  ≤checkpoint:    │                 │
│                                        │    fast path     │                 │
│                                        │  >checkpoint:    │                 │
│                                        │    full validate │                 │
│                                        └────────┬─────────┘                 │
└─────────────────────────────────────────────────┼───────────────────────────┘
                                                  │
                                                  ▼
                                        ┌──────────────────┐
                                        │     CHAIN        │
                                        │  (connected tip) │
                                        └──────────────────┘
```

### Thread Model

| Thread | Purpose | Current | New |
|--------|---------|---------|-----|
| Main/Event | UI, timers, signals | Same | Same |
| SocketHandler | Network I/O | Same | Same |
| MessageHandler | Process messages | **BLOCKS for 100+s** | **Routes only (~1ms)** |
| HeadersHash1-N | Compute RandomX | N/A | **NEW: N = CPU cores** |
| BlockValidator | Validate & connect | Same | Same (checkpoint-aware) |

### User-Selected Configuration

| Setting | Choice | Rationale |
|---------|--------|-----------|
| Hash threads | Match CPU cores | Maximum throughput |
| Implementation | Incremental | Lower risk, test between phases |
| Checkpoint validation | Structure + parent link | Balance of speed and safety |

---

## Implementation Phases

### Phase 1: Async Message Dispatch (1-2 hours)

**Goal**: Message handler never blocks. Headers and blocks routed to async queues.

**File**: `src/net/connman.cpp`

**Current Code Location**: `ThreadMessageHandler()` at line 510-682

**Changes Required**:

1. Add new async queues in `connman.h`:
```cpp
// New: Async queues for headers and blocks
std::queue<std::pair<int, CProcessedMsg>> m_headers_queue;  // (node_id, msg)
std::queue<std::pair<int, CProcessedMsg>> m_blocks_queue;
std::mutex m_headers_queue_mutex;
std::mutex m_blocks_queue_mutex;
std::condition_variable m_headers_cv;
std::condition_variable m_blocks_cv;

// New threads
std::thread m_headers_worker_thread;
std::thread m_blocks_worker_thread;
```

2. Modify `ThreadMessageHandler()` to route instead of process:
```cpp
void CConnman::ThreadMessageHandler() {
    while (!flagInterruptMsgProc.load()) {
        // Collect messages (same as current)
        std::vector<PendingMessage> pending_messages;
        // ... collection code ...

        // NEW: Route by type instead of processing
        for (const auto& pending : pending_messages) {
            if (pending.msg.command == "headers") {
                std::lock_guard<std::mutex> lock(m_headers_queue_mutex);
                m_headers_queue.push({pending.node_id, pending.msg});
                m_headers_cv.notify_one();
            } else if (pending.msg.command == "block") {
                std::lock_guard<std::mutex> lock(m_blocks_queue_mutex);
                m_blocks_queue.push({pending.node_id, pending.msg});
                m_blocks_cv.notify_one();
            } else {
                // Control messages (version, verack, ping, pong, etc.) - process inline
                ProcessControlMessage(pending.node_id, pending.msg);
            }
        }
    }
}
```

3. Add new worker threads:
```cpp
void CConnman::HeadersWorkerThread() {
    while (!flagInterruptMsgProc.load()) {
        std::pair<int, CProcessedMsg> item;
        {
            std::unique_lock<std::mutex> lock(m_headers_queue_mutex);
            m_headers_cv.wait(lock, [this] {
                return !m_headers_queue.empty() || flagInterruptMsgProc.load();
            });
            if (flagInterruptMsgProc.load()) break;
            item = std::move(m_headers_queue.front());
            m_headers_queue.pop();
        }
        // Process headers (calls into headers_manager)
        ProcessHeadersMessage(item.first, item.second);
    }
}

void CConnman::BlocksWorkerThread() {
    while (!flagInterruptMsgProc.load()) {
        std::pair<int, CProcessedMsg> item;
        {
            std::unique_lock<std::mutex> lock(m_blocks_queue_mutex);
            m_blocks_cv.wait(lock, [this] {
                return !m_blocks_queue.empty() || flagInterruptMsgProc.load();
            });
            if (flagInterruptMsgProc.load()) break;
            item = std::move(m_blocks_queue.front());
            m_blocks_queue.pop();
        }
        // Process block (calls into block validation)
        ProcessBlockMessage(item.first, item.second);
    }
}
```

4. Start/stop workers in `Start()` and `Stop()`.

**Test Checkpoint**: Headers and blocks no longer block message handler. Verify with logging that control messages (version, verack) are processed immediately even when headers are queued.

---

### Phase 2: Async Headers Pipeline (2-3 hours)

**Goal**: Headers processing is fully async. Structure validation is fast, hash computation is parallel.

**Files**: `src/net/headers_manager.cpp`, `src/net/headers_manager.h`

**Current Code Location**: Need to explore `CHeadersManager` class

**New Data Structures**:
```cpp
class CHeadersManager {
    // ... existing ...

    // NEW: Async hash computation
    struct PendingHeader {
        CBlockHeader header;
        int height;
        int peer_id;
    };

    std::queue<PendingHeader> m_pending_headers;     // Awaiting hash computation
    std::map<int, uint256> m_ready_headers;          // Height → RandomX hash (ready for download)
    std::mutex m_headers_mutex;
    std::condition_variable m_hash_work_cv;
    std::vector<std::thread> m_hash_workers;
    std::atomic<bool> m_hash_workers_running{false};
};
```

**New Methods**:
```cpp
// Called from message handler - FAST, non-blocking (~10ms for 2000 headers)
void QueueHeadersForProcessing(const std::vector<CBlockHeader>& headers, int peer_id) {
    std::lock_guard lock(m_headers_mutex);

    for (const auto& header : headers) {
        // Quick structure validation only (no hash computation)
        if (!QuickValidateStructure(header)) continue;

        // Determine height from parent link
        int height = GetHeightFromParent(header.hashPrevBlock) + 1;

        // Queue for async hash computation
        m_pending_headers.push({header, height, peer_id});
    }

    m_hash_work_cv.notify_all();  // Wake up hash workers
}

// Hash computer thread (run N of these in parallel where N = CPU cores)
void HashComputerThread() {
    while (m_hash_workers_running.load()) {
        PendingHeader pending;
        {
            std::unique_lock lock(m_headers_mutex);
            m_hash_work_cv.wait(lock, [&] {
                return !m_hash_workers_running.load() || !m_pending_headers.empty();
            });
            if (!m_hash_workers_running.load()) break;
            if (m_pending_headers.empty()) continue;

            pending = std::move(m_pending_headers.front());
            m_pending_headers.pop();
        }

        // Compute hash OUTSIDE the lock (expensive but non-blocking)
        uint256 hash = pending.header.GetHash();  // RandomX computation

        // Store result
        {
            std::lock_guard lock(m_headers_mutex);
            StoreHeaderWithHash(pending.header, hash, pending.height);
            m_ready_headers[pending.height] = hash;
        }

        // Notify download queue that this height is ready
        NotifyHeightReady(pending.height);
    }
}

// Query methods for block fetcher
uint256 GetHashAtHeight(int height) {
    std::lock_guard lock(m_headers_mutex);
    auto it = m_ready_headers.find(height);
    return (it != m_ready_headers.end()) ? it->second : uint256();
}

bool IsHeightReady(int height) {
    std::lock_guard lock(m_headers_mutex);
    return m_ready_headers.count(height) > 0;
}
```

**Key Points**:
- Structure validation: ~10ms for 2000 headers (fast)
- Hash computation: ~75ms per header, but parallel across N threads
- With 4 threads: 2000 × 75ms / 4 = ~37 seconds (in background, doesn't block)
- Block download can start as soon as first hashes are ready (pipelined)

**Test Checkpoint**: Headers processed in background, download queue populates progressively.

---

### Phase 3: Simple Block Window (1-2 hours)

**Goal**: Single source of truth for in-flight tracking. Simple round-robin peer assignment.

**Files**: `src/net/block_fetcher.cpp`, `src/net/block_fetcher.h`

**Replace `CBlockDownloadWindow` with**:
```cpp
class CSimpleBlockWindow {
    std::mutex m_mutex;
    std::set<int> m_pending;                              // Heights waiting to be requested
    std::map<int, std::pair<int, std::chrono::steady_clock::time_point>> m_in_flight;  // height → (peer_id, request_time)
    std::set<int> m_received;                             // Heights downloaded, awaiting connection

public:
    void AddPending(int height) {
        std::lock_guard lock(m_mutex);
        if (m_in_flight.count(height) == 0 && m_received.count(height) == 0) {
            m_pending.insert(height);
        }
    }

    void RequestBlocks(const std::vector<int>& peer_ids, std::function<void(int peer, int height)> send_getdata) {
        std::lock_guard lock(m_mutex);

        std::vector<int> pending_vec(m_pending.begin(), m_pending.end());
        size_t peer_idx = 0;

        for (int height : pending_vec) {
            // Find peer with capacity (round-robin, max 16 per peer)
            for (size_t i = 0; i < peer_ids.size(); ++i) {
                int peer = peer_ids[(peer_idx + i) % peer_ids.size()];
                if (GetInFlightForPeerLocked(peer) < 16) {
                    send_getdata(peer, height);
                    m_in_flight[height] = {peer, std::chrono::steady_clock::now()};
                    m_pending.erase(height);
                    peer_idx = (peer_idx + i + 1) % peer_ids.size();
                    break;
                }
            }
        }
    }

    void OnBlockReceived(int height) {
        std::lock_guard lock(m_mutex);
        m_in_flight.erase(height);
        m_received.insert(height);
    }

    void OnBlockConnected(int height) {
        std::lock_guard lock(m_mutex);
        m_received.erase(height);
    }

    void TimeoutCheck(std::chrono::seconds timeout = std::chrono::seconds(30)) {
        std::lock_guard lock(m_mutex);
        auto now = std::chrono::steady_clock::now();

        std::vector<int> timed_out;
        for (const auto& [height, info] : m_in_flight) {
            if (now - info.second > timeout) {
                timed_out.push_back(height);
            }
        }

        for (int height : timed_out) {
            m_in_flight.erase(height);
            m_pending.insert(height);  // Return to pending for retry
        }
    }

    void OnPeerDisconnected(int peer_id) {
        std::lock_guard lock(m_mutex);

        std::vector<int> heights_to_return;
        for (const auto& [height, info] : m_in_flight) {
            if (info.first == peer_id) {
                heights_to_return.push_back(height);
            }
        }

        for (int height : heights_to_return) {
            m_in_flight.erase(height);
            m_pending.insert(height);
        }
    }

    void Reset(int from_height) {
        std::lock_guard lock(m_mutex);
        m_pending.clear();
        m_in_flight.clear();
        m_received.clear();
        // Will be repopulated by caller
    }

private:
    int GetInFlightForPeerLocked(int peer_id) {
        int count = 0;
        for (const auto& [height, info] : m_in_flight) {
            if (info.first == peer_id) count++;
        }
        return count;
    }
};
```

**Key Points**:
- **Single source of truth**: Only `CSimpleBlockWindow` tracks in-flight blocks
- **Remove** tracking from: `CPeerManager::mapBlocksInFlight`, `CPeer::nBlocksInFlight`
- Round-robin assignment: Simple, fair, no complex scoring
- Timeout handling: Return timed-out blocks to pending for retry
- Peer disconnect: Immediately return their blocks to pending

**Test Checkpoint**: Blocks download correctly, no tracking desync, peer disconnects handled cleanly.

---

### Phase 4: Checkpoint-Aware Validation (1-2 hours)

**Goal**: Fast path for blocks at/below checkpoint (height 3000 on testnet).

**File**: `src/node/block_validation_queue.cpp`

**Changes**:
```cpp
void OnBlockReceived(const CBlock& block, int height) {
    constexpr int CHECKPOINT_HEIGHT = 3000;  // Testnet checkpoint

    if (height <= CHECKPOINT_HEIGHT) {
        // FAST PATH: Trust block, just verify structure + parent link
        if (!ValidateBlockStructure(block)) {
            RejectBlock(block, "bad-structure");
            return;
        }
        if (!ValidateParentLink(block, height)) {
            RejectBlock(block, "bad-parent");
            return;
        }
        // Skip PoW check, skip script validation
        StoreBlock(block);
        ConnectBlock(height);
        return;
    }

    // Above checkpoint: full validation
    if (!ValidatePoW(block)) {
        RejectBlock(block, "bad-pow");
        return;
    }

    // Queue for full validation (scripts, UTXOs)
    m_validation_queue.push({block, height});
}
```

**Fast Path Validation** (for checkpoint):
- Structure validation: Block format is valid
- Parent link: `block.hashPrevBlock` matches expected parent at `height - 1`
- NO PoW validation (trusted by checkpoint)
- NO script validation (trusted by checkpoint)

**Full Validation** (above checkpoint):
- RandomX PoW verification
- Script validation
- UTXO validation
- Connect to chain

**Test Checkpoint**: Blocks ≤3000 connect fast (no PoW check), blocks >3000 fully validated.

---

### Phase 5: Simple IBD Coordinator (1 hour)

**Goal**: Explicit state machine with logged transitions.

**Files**: `src/node/ibd_coordinator.cpp`, `src/node/ibd_coordinator.h`

**State Machine**:
```cpp
enum class IBDState {
    IDLE,               // Not syncing
    CONNECTING,         // Finding peers
    HEADERS_SYNC,       // Downloading headers
    BLOCKS_DOWNLOAD,    // Downloading blocks (can overlap with HEADERS_SYNC)
    BLOCKS_VALIDATE,    // Validating blocks above checkpoint
    COMPLETE            // Fully synced
};

class CIBDCoordinator {
    IBDState m_state = IBDState::IDLE;
    std::chrono::steady_clock::time_point m_state_entered_time;

    void TransitionTo(IBDState new_state) {
        LogPrintf("[IBD] State: %s → %s", StateToString(m_state), StateToString(new_state));
        m_state = new_state;
        m_state_entered_time = std::chrono::steady_clock::now();
    }

    void Tick() {
        switch (m_state) {
            case IBDState::IDLE:
                if (HasPeerWithHigherHeight()) {
                    TransitionTo(IBDState::CONNECTING);
                }
                break;

            case IBDState::CONNECTING:
                if (GetConnectedPeerCount() >= 1) {
                    TransitionTo(IBDState::HEADERS_SYNC);
                }
                break;

            case IBDState::HEADERS_SYNC:
                RequestMoreHeadersIfNeeded();
                // Start block download when headers are ahead
                if (m_headers_manager.GetBestHeight() > m_chain.GetHeight() + 100) {
                    TransitionTo(IBDState::BLOCKS_DOWNLOAD);
                }
                break;

            case IBDState::BLOCKS_DOWNLOAD:
                m_block_window.RequestBlocks(GetValidPeers(), SendGetData);
                m_block_window.TimeoutCheck();
                CheckForFork();  // Proactive fork detection

                if (m_chain.GetHeight() >= m_headers_manager.GetBestHeight()) {
                    TransitionTo(IBDState::COMPLETE);
                }
                break;

            case IBDState::COMPLETE:
                if (HasPeerWithHigherHeight()) {
                    TransitionTo(IBDState::HEADERS_SYNC);
                }
                break;
        }
    }
};
```

**Fork Detection** (proactive, every tick):
```cpp
void CheckForFork() {
    uint256 our_tip = m_chain.GetTip()->GetBlockHash();
    uint256 expected = m_headers_manager.GetHashAtHeight(m_chain.GetHeight());

    if (our_tip != expected) {
        LogPrintf("[IBD] FORK DETECTED at height %d", m_chain.GetHeight());
        int fork_height = FindForkPoint();
        while (m_chain.GetHeight() > fork_height) {
            DisconnectTip();
        }
        m_block_window.Reset(fork_height + 1);
    }
}
```

**Test Checkpoint**: Full IBD completes reliably with clear state transitions logged.

---

## Files to Modify Summary

| Phase | Files | Changes |
|-------|-------|---------|
| 1 | `src/net/connman.cpp`, `src/net/connman.h` | Async message dispatch, worker threads |
| 2 | `src/net/headers_manager.cpp`, `src/net/headers_manager.h` | Async hash computation thread pool |
| 3 | `src/net/block_fetcher.cpp`, `src/net/block_fetcher.h` | Replace with CSimpleBlockWindow |
| 4 | `src/node/block_validation_queue.cpp` | Checkpoint-aware fast path |
| 5 | `src/node/ibd_coordinator.cpp`, `src/node/ibd_coordinator.h` | Simple state machine |
| Wire-up | `src/node/dilithion-node.cpp` | Connect new components |

---

## Current File States

### src/net/connman.cpp (1300 lines)

Key sections:
- Line 48-192: `Start()` - Initializes threads
- Line 194-229: `Stop()` - Shuts down threads
- Line 499-508: `ThreadSocketHandler()` - Socket I/O loop
- Line 510-682: `ThreadMessageHandler()` - **MODIFY THIS** - Currently processes messages synchronously
- Line 684-773: `ThreadOpenConnections()` - Outbound connection management
- Line 1141-1248: `ExtractMessages()` - Parses messages from socket buffer

**BUG #167 Temporary Fixes** (lines 532-600):
- `MAX_MSGS_PER_NODE_PER_BATCH = 20`
- `MAX_HEADERS_PER_BATCH = 1`
- `MAX_MSGS_TOTAL_PER_BATCH = 200`

### src/net/connman.h (308 lines)

Key sections:
- Line 50-305: `CConnman` class definition
- Line 264-266: Node management members
- Line 275-286: Thread control members
- **ADD**: New queue members, worker thread members

---

## Known Issues Handled by This Design

### Issue 1: Fork Detection (BUG #158)
- **Current**: Detect after 5 ticks of no progress
- **New**: Check EVERY tick in `BLOCKS_DOWNLOAD` state

### Issue 2: Orphan Block Handling
- **Current**: Reactive scan every 10 seconds
- **New**: Process orphans IMMEDIATELY when parent connects

### Issue 3: Message Queue Starvation (BUG #167)
- **Current**: One peer's headers block everything
- **New**: Separate async queues, headers don't block blocks

### Issue 4: In-Flight Tracking Desync (BUG #165, #166)
- **Current**: Multiple sources of truth desync
- **New**: `CSimpleBlockWindow` is THE ONLY tracker

### Issue 5: Peer Disconnection
- **Current**: In-flight blocks become orphaned
- **New**: Immediate cleanup, blocks return to pending

### Issue 6: Headers Processing Blocking
- **Current**: 150 seconds blocking
- **New**: ~1ms routing, parallel hash computation in background

---

## Expected Performance

| Metric | Current | Expected |
|--------|---------|----------|
| Headers sync (2000 headers) | 100-200 seconds blocking | <1ms routing, ~37s background hash |
| Block download | Stalls frequently | Continuous flow |
| Message handler responsiveness | Blocked for 100+s | Always responsive (<100ms) |
| Sync reliability | Frequent stalls | Reliable completion |

---

## Testing Strategy

### Phase 1 Test
1. Start node, connect to testnet
2. Verify control messages (version, verack) processed immediately
3. Check logs: headers/blocks should be routed to queues, not processed inline

### Phase 2 Test
1. Request headers from peer
2. Verify structure validation completes in ~10ms
3. Verify hash computation happens in background threads
4. Verify download queue populates progressively as hashes complete

### Phase 3 Test
1. Download blocks from multiple peers
2. Verify round-robin distribution
3. Disconnect a peer mid-download
4. Verify their blocks return to pending and get reassigned

### Phase 4 Test
1. Sync from genesis
2. Verify blocks 1-3000 connect fast (no PoW check)
3. Verify blocks 3001+ have full validation
4. Compare sync time before/after

### Phase 5 Test
1. Full IBD from genesis
2. Monitor state transitions in logs
3. Verify fork detection works (can test by creating temporary fork)
4. Verify sync completes reliably

---

## Important Constraints

1. **Do NOT use FastHash** - We tried this and it caused hash conflicts with RandomX. Always compute full RandomX hash.

2. **Checkpoint is at height 3000** (testnet) - Blocks at or below this height can use fast path validation.

3. **RandomX hash takes ~75ms** - This is the fundamental constraint. Cannot make it faster, must make it async.

4. **Maintain backward compatibility** - Same P2P messages, just different internal handling.

---

## How to Continue

1. Read this document and the plan file at `C:\Users\will\.claude\plans\compressed-coalescing-lemon.md`
2. Start with Phase 1 (Async Message Dispatch)
3. Test each phase before moving to next
4. Remove the temporary BUG #167 fixes from `connman.cpp` once Phase 1 is working

Good luck with the implementation!
