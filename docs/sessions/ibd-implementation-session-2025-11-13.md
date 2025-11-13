# IBD and Orphan Block Handling - Implementation Session

**Date**: 2025-11-13
**Bug**: #12 - Chain Synchronization Failure
**Branch**: fix/genesis-transaction-serialization
**Status**: Phase 1 In Progress

---

## Session Summary

### Objectives
1. Design comprehensive IBD fix following Bitcoin Core approach
2. Begin Phase 1: Headers Manager implementation
3. No shortcuts - permanent production-quality solution

### Completed
- ✓ Comprehensive implementation plan created (`docs/bugs/ibd-orphan-block-fix-implementation-plan.md`)
- ✓ Analyzed existing codebase structure
- ✓ Verified protocol messages (GETHEADERS/HEADERS already defined)
- ✓ Reviewed CBlockHeader structure
- ✓ Identified integration points

### Key Discoveries
1. **Protocol Messages Already Exist**: GETHEADERS and HEADERS are already defined in `src/net/protocol.h:53-54`
2. **MAX_HEADERS_SIZE**: Already set to 2000 (Bitcoin Core standard)
3. **Clean Architecture**: Modern C++17 codebase with proper separation
4. **No P2P Directory**: All networking in `src/net/`, not `src/p2p/`

---

## Phase 1 Analysis: Headers Manager

### Existing Infrastructure

**File**: `src/net/protocol.h`
```cpp
enum MessageType {
    // ... existing ...
    MSG_GETHEADERS,  // Line 53 - Already defined!
    MSG_HEADERS,     // Line 54 - Already defined!
    MSG_GETBLOCKS,
    // ...
};

static const unsigned int MAX_HEADERS_SIZE = 2000;  // Line 29
```

**File**: `src/primitives/block.h`
```cpp
class CBlockHeader {
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    uint256 GetHash() const;
};
```

###Files to Create

1. **`src/net/headers_manager.h`** (~300 lines)
   - CHeadersManager class
   - HeadersSyncState struct
   - Thread-safe header chain storage
   - Peer synchronization tracking

2. **`src/net/headers_manager.cpp`** (~800 lines)
   - Header validation logic
   - Block locator generation (Bitcoin Core algorithm)
   - Fork detection and resolution
   - Peer state management

3. **`src/test/headers_manager_tests.cpp`** (~400 lines)
   - Unit tests for header validation
   - Fork detection tests
   - Memory usage tests
   - Peer synchronization tests

### Implementation Steps

#### Step 1: Create CHeadersManager Class (2 hours)

**Data Structures**:
```cpp
class CHeadersManager {
private:
    // Header storage (in-memory, lightweight)
    std::map<uint256, CBlockHeader> mapHeaders;
    std::map<int, std::vector<uint256>> mapHeightIndex;

    // Best header tracking
    uint256 hashBestHeader;
    int nBestHeight;

    // Peer state
    struct HeadersSyncState {
        uint256 hashLastHeader;
        int nSyncHeight;
        std::chrono::time_point<std::chrono::steady_clock> lastUpdate;
        bool syncing;
    };
    std::map<int, HeadersSyncState> mapPeerStates;  // NodeId -> State

    // Synchronization
    mutable std::mutex cs_headers;
};
```

**Core Methods**:
- `ProcessHeaders()`: Validate and store header chain
- `ValidateHeader()`: Check PoW, timestamps, difficulty
- `RequestHeaders()`: Send GETHEADERS to peer
- `GetLocator()`: Build block locator for sync
- `IsSyncing()`: Check if in initial header download
- `GetBestHeader()`: Get tip of header chain

#### Step 2: Implement Header Validation (1.5 hours)

**Validation Rules** (Bitcoin Core standard):
1. Check PoW meets target
2. Timestamp not too far in future (< 2 hours)
3. Timestamp not before median of last 11 blocks
4. Difficulty transitions valid
5. Version number valid
6. Parent exists (or is genesis)

**Fork Handling**:
- Track multiple header chains at same height
- Select chain with most accumulated work
- Prune stale fork branches after 288 blocks

#### Step 3: Block Locator Algorithm (1 hour)

**Bitcoin Core Exponential Backoff**:
```
Start from tip, go back with exponential steps:
- 0 blocks back (tip)
- 1 block back
- 2 blocks back
- 4 blocks back
- 8 blocks back
- ...
- 2^n blocks back
- Then genesis
```

This allows efficient sync from any fork point.

#### Step 4: Message Handlers Integration (1.5 hours)

**Modify**: `src/node/dilithion-node.cpp`

Add handlers for:
```cpp
void HandleGETHEADERS(int peer_id, const CGetHeadersMessage& msg) {
    // Build header list from locator
    // Send up to 2000 headers in HEADERS message
}

void HandleHEADERS(int peer_id, const std::vector<CBlockHeader>& headers) {
    // Pass to HeadersManager for processing
    // Request more headers if needed
    // Trigger block downloads when headers complete
}
```

#### Step 5: Unit Testing (1 hour)

**Test Cases**:
- Header chain validation
- Fork detection and resolution
- Memory limits (1M headers = ~80MB)
- Invalid header rejection
- Block locator generation
- Concurrent access (thread safety)

---

## Implementation Status

### Current Branch State
```
Branch: fix/genesis-transaction-serialization
Files Modified: None yet
Files Created:
  - docs/bugs/ibd-orphan-block-fix-implementation-plan.md
  - docs/sessions/ibd-implementation-session-2025-11-13.md
```

### Next Session Tasks

1. **Create `src/net/headers_manager.h`**
   - Start with class skeleton
   - Add all data structures
   - Document with Doxygen comments

2. **Implement `src/net/headers_manager.cpp`**
   - ProcessHeaders() with validation
   - GetLocator() algorithm
   - RequestHeaders() message building

3. **Add Message Handlers**
   - GETHEADERS handler in dilithion-node.cpp
   - HEADERS handler in dilithion-node.cpp
   - Integration with existing P2P flow

4. **Write Unit Tests**
   - Test all validation rules
   - Test fork scenarios
   - Benchmark performance

5. **Integration Testing**
   - Test with 2-node setup
   - Verify header sync works
   - Check memory usage

### Estimated Time Remaining
- Phase 1: 6-7 hours (none completed yet, analysis only)
- Phase 2: 5-6 hours
- Phase 3: 5-6 hours
- Phase 4: 4-5 hours
- Phase 5: 4-5 hours
- **Total**: 24-28 hours

---

## Code Quality Checklist

### Before Committing Each Component
- [ ] Compiles without warnings
- [ ] Unit tests pass
- [ ] Valgrind clean (no leaks)
- [ ] Thread sanitizer clean
- [ ] Doxygen comments complete
- [ ] Follows existing code style
- [ ] Integration tests pass

### Before Phase Completion
- [ ] All unit tests >80% coverage
- [ ] Performance benchmarks met
- [ ] Documentation complete
- [ ] Peer review requested
- [ ] No shortcuts taken

---

## References

- **Implementation Plan**: `docs/bugs/ibd-orphan-block-fix-implementation-plan.md`
- **Bootstrap Research**: `docs/research/p2p-bootstrap-research.md`
- **Bitcoin Core**: Headers-first sync in `net_processing.cpp`
- **Existing Code**: `src/net/protocol.h`, `src/primitives/block.h`

---

## Notes

### Why This Approach?
- Bitcoin Core proven over 10+ years
- Headers-first prevents DoS attacks
- Memory efficient (80 bytes per header)
- Enables parallel block downloads
- Scales to mainnet

### Risks Mitigated
- Memory exhaustion: 2000 header limit per message
- DoS via invalid headers: Full validation before storage
- Fork attacks: Most-work chain selection
- Deadlocks: Fine-grained locking, RAII patterns

### Success Criteria
- New nodes sync from genesis
- Nodes converge to same chain tip
- < 5 minutes for full testnet sync
- Memory usage < 500MB during IBD
- Zero crashes in 48-hour soak test

---

**End of Session**

Next session should continue with creating `src/net/headers_manager.h` and beginning the implementation of Phase 1.
