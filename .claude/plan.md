# Dilithion Mainnet Readiness Implementation Plan

**Created:** December 6, 2025
**Based on:** Security Audit Report 2025-12-06
**Total Issues:** 13 CRITICAL, 23 HIGH, 33 MEDIUM, 21 LOW

---

## Executive Summary

| Phase | Priority | Duration | Effort | Issues |
|-------|----------|----------|--------|--------|
| P0 | BLOCKING | 3-5 days | 10-15 hrs | 5 CRITICAL |
| P1 | CRITICAL | 5-7 days | 20-30 hrs | 5 CRITICAL |
| P2 | CRITICAL | 4-6 days | 15-20 hrs | 3 CRITICAL |
| P3 | HIGH | 7-10 days | 40-50 hrs | 23 HIGH |
| P4 | MEDIUM | 10-15 days | 30-40 hrs | 33 MEDIUM |
| P5 | LOW | 30-60 days | 20-30 hrs | 21 LOW |

**Total Pre-Mainnet:** ~85-115 hours over 19-28 days (P0-P3)

---

## Phase 0: BLOCKING ISSUES (Must Fix First)

### P0-1: Command Injection via system()
- **File:** `src/consensus/chain_verifier.cpp` lines 357-380
- **Severity:** CRITICAL (RCE vulnerability)
- **Effort:** 1 hour

**Current Code (VULNERABLE):**
```cpp
std::string cmd = "rm -rf \"" + blocksDir + "\"";
system(cmd.c_str());
```

**Fixed Code:**
```cpp
#include <filesystem>
std::filesystem::remove_all(blocksDir);
```

**Testing:** Unit test with path containing `"; rm -rf /`

---

### P0-2: Missing fsync in Close() Stats Write
- **File:** `src/node/utxo_set.cpp` line 88
- **Severity:** CRITICAL (Data loss on crash)
- **Effort:** 30 minutes

**Current Code:**
```cpp
db->Put(leveldb::WriteOptions(), stats_key, stats_value);
```

**Fixed Code:**
```cpp
leveldb::WriteOptions write_options;
write_options.sync = true;
db->Put(write_options, stats_key, stats_value);
```

**Testing:** Kill process during shutdown, verify stats survive

---

### P0-3: Cache Not Flushed Before Close()
- **File:** `src/node/utxo_set.cpp` lines 76-96
- **Severity:** CRITICAL (Data loss)
- **Effort:** 1 hour

**Fix:** Add Flush() call at start of Close():
```cpp
void CUTXOSet::Close() {
    std::lock_guard<std::recursive_mutex> lock(cs_utxo);

    if (db != nullptr) {
        // CRITICAL: Flush pending changes FIRST
        if (!Flush()) {
            std::cerr << "[ERROR] CUTXOSet::Close: Failed to flush" << std::endl;
        }

        // Then write final stats with sync...
    }
}
```

**Testing:** Add UTXOs, close without explicit flush, reopen and verify

---

### P0-4: Unsync'd ApplyBlock/UndoBlock Writes
- **File:** `src/node/utxo_set.cpp` lines 552, 767, 1012
- **Severity:** CRITICAL (Chain corruption on crash)
- **Effort:** 1 hour

**Fix:** Add `sync=true` to all three locations:
```cpp
leveldb::WriteOptions write_options;
write_options.sync = true;
leveldb::Status status = db->Write(write_options, &batch);
```

**Locations:**
- [ ] Line 552 in `ApplyBlock()`
- [ ] Line 767 in `UndoBlock()`
- [ ] Line 1012 in `Clear()`

**Testing:** Crash during block processing, verify chain state

---

### P0-5: Global Pointer Initialization Race
- **File:** `src/net/net.cpp` lines 62-76
- **Severity:** CRITICAL (Crashes, use-after-free)
- **Effort:** 2-3 hours

**Current Code:**
```cpp
CTxRelayManager* g_tx_relay_manager = nullptr;
CTxMemPool* g_mempool = nullptr;
CTransactionValidator* g_tx_validator = nullptr;
CUTXOSet* g_utxo_set = nullptr;
```

**Fix Option A (Quick):** Use atomic pointers:
```cpp
std::atomic<CTxRelayManager*> g_tx_relay_manager{nullptr};
std::atomic<CTxMemPool*> g_mempool{nullptr};
// ...
```

**Fix Option B (Better):** Move to NodeContext struct with explicit initialization order

**Testing:** Stress test startup/shutdown with multiple threads

---

## Phase 1: CRITICAL CONSENSUS ISSUES

### P1-1: Missing Block Version Upper Bound
- **File:** `src/consensus/validation.cpp` lines 196-200
- **Severity:** CRITICAL (Consensus fork risk)
- **Effort:** 1 hour

**Current Code:**
```cpp
if (block.nVersion < 1) {
    error = "Invalid block version";
    return false;
}
```

**Fixed Code:**
```cpp
static const int32_t MAX_BLOCK_VERSION = 4;  // Or appropriate value
if (block.nVersion < 1 || block.nVersion > MAX_BLOCK_VERSION) {
    error = "Invalid block version";
    return false;
}
```

---

### P1-2: Dust Threshold Not Consensus-Enforced
- **File:** `src/consensus/tx_validation.cpp`
- **Severity:** CRITICAL (UTXO bloat attack)
- **Effort:** 2 hours

**Fix:** Move dust check from `IsStandardTransaction()` to `CheckTransactionBasic()`:
```cpp
// Add after line 103 (nValue <= 0 check):
if (txout.nValue > 0 && txout.nValue < DUST_THRESHOLD) {
    error = "Output value below dust threshold (50000 ions minimum)";
    return false;
}
```

---

### P1-3: UndoBlock Data Has No Integrity Check
- **File:** `src/node/utxo_set.cpp` lines 571-783
- **Severity:** CRITICAL (Silent corruption)
- **Effort:** 4 hours

**Fix:** Add SHA256 checksum to undo data:

In ApplyBlock (when storing):
```cpp
// Calculate checksum
uint256 checksum;
SHA256(undoData.data(), undoData.size(), checksum.begin());
// Append checksum to undo data
undoData.insert(undoData.end(), checksum.begin(), checksum.end());
```

In UndoBlock (when reading):
```cpp
// Extract and verify checksum
uint256 stored_checksum, computed_checksum;
memcpy(stored_checksum.begin(), undoValue.data() + undoValue.size() - 32, 32);
SHA256(undoValue.data(), undoValue.size() - 32, computed_checksum.begin());
if (stored_checksum != computed_checksum) {
    error = "Undo data checksum mismatch - corruption detected";
    return false;
}
```

---

### P1-4: Reorg Has No Transaction Atomicity
- **File:** `src/consensus/chain.cpp` lines 275-490
- **Severity:** CRITICAL (Unrecoverable state)
- **Effort:** 8-12 hours

**Fix:** Implement Write-Ahead Log (WAL) pattern:

1. Create WAL file before reorg: `wal/reorg_pending.dat`
2. Write intended operations (disconnect blocks, connect blocks)
3. Execute operations
4. On success, delete WAL
5. On startup, check for WAL and replay/rollback

**Structure:**
```cpp
struct ReorgWAL {
    std::vector<uint256> disconnect_hashes;  // Blocks to disconnect
    std::vector<uint256> connect_hashes;     // Blocks to connect
    uint32_t state;  // 0=pending, 1=disconnecting, 2=connecting, 3=complete
};
```

---

### P1-5: Block-Level Transaction Size Unchecked
- **File:** `src/consensus/validation.cpp` lines 124-130
- **Severity:** CRITICAL (1GB blocks possible)
- **Effort:** 1 hour

**Fix:** Add aggregate size check in CheckBlock():
```cpp
size_t total_tx_bytes = 0;
for (const auto& tx : block.vtx) {
    total_tx_bytes += tx->GetSerializedSize();
    if (total_tx_bytes > MAX_BLOCK_SIZE) {
        error = "Block transaction data exceeds maximum size";
        return false;
    }
}
```

---

## Phase 2: CRITICAL NETWORK ISSUES

### P2-1: Missing Rate Limiting on GETDATA
- **File:** `src/net/net.cpp` lines 561-636
- **Severity:** CRITICAL (DoS via CPU exhaustion)
- **Effort:** 2-3 hours

**Fix:** Add rate limiting at start of ProcessGetDataMessage():
```cpp
bool CNetMessageProcessor::ProcessGetDataMessage(int peer_id, CDataStream& stream) {
    // Rate limiting
    static std::map<int, std::vector<int64_t>> peer_getdata_timestamps;
    static std::mutex cs_getdata_rate;
    const int64_t MAX_GETDATA_PER_SECOND = 10;

    int64_t now = GetTime();
    {
        std::lock_guard<std::mutex> lock(cs_getdata_rate);
        auto& timestamps = peer_getdata_timestamps[peer_id];

        // Remove timestamps older than 1 second
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                [now](int64_t ts) { return now - ts > 1; }),
            timestamps.end());

        if (timestamps.size() >= MAX_GETDATA_PER_SECOND) {
            peer_manager.Misbehaving(peer_id, 10);
            return false;
        }
        timestamps.push_back(now);
    }

    // ... existing code
}
```

---

### P2-2: Connection Limit Bypass via Rapid Reconnection
- **File:** `src/net/net.cpp` lines 1195-1250
- **Severity:** CRITICAL (Resource exhaustion)
- **Effort:** 2 hours

**Fix:** Add per-IP connection cooldown:
```cpp
// At top of file or in header:
static std::map<std::string, int64_t> g_last_connection_attempt;
static std::mutex cs_connection_cooldown;
static const int64_t CONNECTION_COOLDOWN_SECONDS = 30;

// In ConnectToPeer():
{
    std::lock_guard<std::mutex> lock(cs_connection_cooldown);
    std::string ip_str = addr.ToStringIP();
    auto it = g_last_connection_attempt.find(ip_str);
    if (it != g_last_connection_attempt.end()) {
        if (GetTime() - it->second < CONNECTION_COOLDOWN_SECONDS) {
            return -1;  // Too soon to reconnect
        }
    }
    g_last_connection_attempt[ip_str] = GetTime();
}
```

---

### P2-3: No Validation of GETHEADERS Locator Hashes
- **File:** `src/net/net.cpp` lines 800-850
- **Severity:** CRITICAL (Eclipse attack vector)
- **Effort:** 3 hours

**Fix:** Validate locator hashes against our chain:
```cpp
// In ProcessGetHeadersMessage(), after reading locator:
for (const uint256& hash : msg.locator) {
    if (hash == Consensus::GenesisBlockHash()) continue;  // Genesis always valid

    if (!chainstate.HasBlockIndex(hash)) {
        std::cout << "[P2P] Unknown locator hash from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20);
        return false;
    }
}
```

---

## Phase 3: HIGH SEVERITY ISSUES

### Network (8 issues, ~20 hours)

| ID | Issue | File | Effort |
|----|-------|------|--------|
| H-N1 | Peer eviction logic incomplete | peers.h | 4 hrs |
| H-N2 | No rate limit on HEADERS messages | net.cpp:865 | 2 hrs |
| H-N3 | VERSION address validation weak | net.cpp:209 | 2 hrs |
| H-N4 | No timeout on partial messages | net.cpp:1617 | 3 hrs |
| H-N5 | Integer overflow in payload size | serialize.h | 2 hrs |
| H-N6 | No bandwidth tracking per peer | peers.h | 3 hrs |
| H-N7 | Misbehavior score never decays | peers.cpp | 2 hrs |
| H-N8 | No handshake timeout | net.cpp | 2 hrs |

### Consensus (6 issues, ~25 hours)

| ID | Issue | File | Effort |
|----|-------|------|--------|
| H-C1 | Missing locktime validation | tx_validation.cpp | 4 hrs |
| H-C2 | ApplyBlock atomicity issues | utxo_set.cpp:371 | 6 hrs |
| H-C3 | Difficulty overflow silent fail | pow.cpp | 3 hrs |
| H-C4 | Dilithium sig canonicalization | tx_validation.cpp:319 | 4 hrs |
| H-C5 | Sequence number not validated | tx_validation.cpp | 4 hrs |
| H-C6 | Time warp attack vectors | pow.cpp:407 | 4 hrs |

### RPC/Wallet (5 issues, ~16 hours)

| ID | Issue | File | Effort |
|----|-------|------|--------|
| H-R1 | Plaintext password in config | server.cpp:1177 | 4 hrs |
| H-R2 | Insecure JSON parsing | permissions.cpp:179 | 3 hrs |
| H-R3 | Address enumeration rate too high | ratelimiter.cpp:32 | 2 hrs |
| H-R4 | Wallet file permissions unchecked | wallet.cpp:1876 | 3 hrs |
| H-R5 | Mnemonic exposure in logs | server.cpp:2766 | 4 hrs |

### Code Quality (4 issues, ~18 hours)

| ID | Issue | File | Effort |
|----|-------|------|--------|
| H-X1 | Thread safety - lock ordering | Various | 6 hrs |
| H-X2 | Error handling gaps | Various | 4 hrs |
| H-X3 | Integer overflow in rate limiter | ratelimiter.cpp:192 | 4 hrs |
| H-X4 | EVP context cleanup not RAII | crypter.cpp | 4 hrs |

---

## Phase 4: MEDIUM SEVERITY (33 issues)

Post-mainnet priority. Categories:
- Database: 7 issues
- Network: 8 issues
- Consensus: 6 issues
- RPC: 7 issues
- Code: 5 issues

---

## Phase 5: LOW SEVERITY (21 issues)

Future improvements. Categories:
- Documentation
- Code style
- Additional tests
- Performance

---

## Testing Requirements

### Phase 0 Testing Checklist
- [ ] Kill process during Close() - verify stats persist
- [ ] Kill process during ApplyBlock() - verify chain recovers
- [ ] Command injection test with malicious paths
- [ ] Multi-threaded startup stress test

### Phase 1 Testing Checklist
- [ ] Invalid block version (negative, INT32_MAX)
- [ ] Dust output transactions
- [ ] Corrupted undo data detection
- [ ] Reorg with crash at each stage
- [ ] Oversized block rejection

### Phase 2 Testing Checklist
- [ ] GETDATA flood (1000+ messages/sec)
- [ ] Rapid reconnection (100 connects in 10 sec)
- [ ] Fabricated GETHEADERS locators
- [ ] Eclipse attack simulation

### Integration Testing
- [ ] 3-node testnet for 24 hours
- [ ] Reorg stress test (force 10+ block reorgs)
- [ ] Network partition simulation
- [ ] Full chain sync from genesis

---

## Dependencies

```
P0 (Blocking) ─────────┐
                       │
    ┌──────────────────┴──────────────────┐
    │                                      │
    ▼                                      ▼
P1 (Consensus)                      P2 (Network)
    │                                      │
    └──────────────────┬───────────────────┘
                       │
                       ▼
                 P3 (High Priority)
                       │
                       ▼
                 P4 (Medium)
                       │
                       ▼
                 P5 (Low)
```

---

## Implementation Order

### Week 1: P0 Complete
- [ ] P0-1: Command injection fix (1 hr)
- [ ] P0-2: fsync in Close() (0.5 hr)
- [ ] P0-3: Flush before Close() (1 hr)
- [ ] P0-4: Sync ApplyBlock/UndoBlock (1 hr)
- [ ] P0-5: Global pointer safety (3 hrs)
- [ ] P0 Testing complete

### Week 2: P1 Complete
- [ ] P1-1: Block version bounds (1 hr)
- [ ] P1-2: Dust consensus enforcement (2 hrs)
- [ ] P1-3: Undo data checksums (4 hrs)
- [ ] P1-4: Reorg WAL (12 hrs) - MAJOR
- [ ] P1-5: Block size aggregate check (1 hr)
- [ ] P1 Testing complete

### Week 3: P2 Complete
- [ ] P2-1: GETDATA rate limiting (3 hrs)
- [ ] P2-2: Connection cooldown (2 hrs)
- [ ] P2-3: GETHEADERS validation (3 hrs)
- [ ] P2 Testing complete

### Week 4: P3 (High Priority)
- [ ] Network issues (H-N1 through H-N8)
- [ ] Consensus issues (H-C1 through H-C6)
- [ ] RPC issues (H-R1 through H-R5)
- [ ] Code issues (H-X1 through H-X4)
- [ ] Integration testing

---

## Files to Modify

| File | Phase | Changes |
|------|-------|---------|
| `src/consensus/chain_verifier.cpp` | P0 | Remove system() |
| `src/node/utxo_set.cpp` | P0, P1 | fsync, flush, checksums |
| `src/net/net.cpp` | P0, P2 | Atomic pointers, rate limits |
| `src/consensus/validation.cpp` | P1 | Version bounds, size check |
| `src/consensus/tx_validation.cpp` | P1, P3 | Dust, locktime, sequence |
| `src/consensus/chain.cpp` | P1 | WAL for reorgs |
| `src/net/peers.cpp` | P3 | Eviction, scoring |
| `src/rpc/ratelimiter.cpp` | P3 | Address rate limit |
| `src/wallet/wallet.cpp` | P3 | File permissions |

---

## Success Criteria

**Mainnet Ready When:**
1. All 13 CRITICAL issues fixed and tested
2. All 23 HIGH issues fixed and tested
3. 3-node testnet stable for 72+ hours
4. No crashes or data loss during stress testing
5. Security re-audit passes

---

## Progress Tracking

### P0 Status: NOT STARTED
- [ ] P0-1 Command injection
- [ ] P0-2 fsync Close()
- [ ] P0-3 Flush before Close()
- [ ] P0-4 Sync ApplyBlock/UndoBlock
- [ ] P0-5 Global pointers

### P1 Status: NOT STARTED
- [ ] P1-1 Block version
- [ ] P1-2 Dust threshold
- [ ] P1-3 Undo checksums
- [ ] P1-4 Reorg WAL
- [ ] P1-5 Block size check

### P2 Status: NOT STARTED
- [ ] P2-1 GETDATA rate limit
- [ ] P2-2 Connection cooldown
- [ ] P2-3 GETHEADERS validation

### P3 Status: NOT STARTED
- [ ] 23 HIGH issues (see detailed list above)
