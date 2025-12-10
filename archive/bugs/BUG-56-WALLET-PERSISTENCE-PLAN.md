# BUG #56: Professional Wallet Persistence Implementation Plan

**Date:** 2025-11-27
**Status:** APPROVED - Ready for Implementation
**Estimated Time:** 10-15 hours
**Decision:** Option B (Professional) - Discard & Replace existing uncommitted code

---

## Step 0: Discard Existing Uncommitted Code

Before implementing the professional solution, discard the current uncommitted BUG #56 changes:

```bash
git checkout -- src/wallet/wallet.h src/wallet/wallet.cpp src/node/dilithion-node.cpp
```

This removes the basic startup-only implementation in favor of the full Bitcoin Core pattern.

---

## Research Summary

### Bitcoin Core Pattern (PR #30221 by achow101)
- [GitHub PR #30221](https://github.com/bitcoin/bitcoin/pull/30221)
- **Key insight**: Best block updated for EACH `blockConnected`/`blockDisconnected`, not just at startup
- **BestBlock struct**: Consolidates hash + height + locator with serialization
- **SetLastBlockProcessed()**: Updates memory AND writes to disk atomically
- **Race condition fix**: Removed `chainStateFlushed` which caused blocks to be skipped
- **Periodic writes**: Every 144 blocks even if no wallet transactions found

### Current Dilithion Implementation (Uncommitted BUG #56)
The existing uncommitted code has these **critical gaps**:

| Issue | Bitcoin Core | Dilithion Current |
|-------|-------------|-------------------|
| Best block updates | Per-block callbacks | Once at startup only |
| Incremental scan | Block-by-block rescan | Full UTXO set scan |
| Reorg handling | blockDisconnected callback | CleanupStaleUTXOs exists but never called |
| Crash recovery | Resume from last persisted block | May have inconsistent state |
| Callback integration | IWalletChainNotifications interface | None |

---

## Implementation Architecture (Bitcoin Core Pattern)

### Phase 1: Wallet Chain Interface (2-3 hours)

**File: `src/wallet/wallet.h`**
```cpp
// Add to CWallet class
public:
    // Chain notification handlers (Bitcoin Core pattern)
    void blockConnected(const CBlock& block, int height);
    void blockDisconnected(const CBlock& block, int height);

private:
    // Process block transactions without full UTXO scan
    void ProcessBlockTransactions(const CBlock& block, int height, bool connecting);

    // Atomic memory + disk update (Bitcoin Core: SetLastBlockProcessed)
    void SetLastBlockProcessed(const uint256& hash, int height);
```

### Phase 2: Implement Callbacks (2-3 hours)

**File: `src/wallet/wallet.cpp`**

**blockConnected():**
- Iterate block transactions
- Add outputs belonging to wallet addresses
- Mark spent inputs
- Call `SetLastBlockProcessed()` (persists to disk)

**blockDisconnected():**
- Reverse: unspend inputs, remove outputs
- Update best block to previous block
- Integrates with existing `CleanupStaleUTXOs()`

### Phase 3: Chain State Integration (1-2 hours)

**File: `src/consensus/chain.h` + `chain.cpp`**
- Add `RegisterBlockDisconnectCallback()`
- Call wallet from `DisconnectTip()`

**File: `src/node/dilithion-node.cpp`**
- Register wallet callbacks after initialization
- Remove current best block update at end of startup
- Callbacks handle all updates automatically

### Phase 4: True Incremental Scanning (2-3 hours)

**File: `src/wallet/wallet.cpp`**

New method `RescanFromHeight()`:
- Scan blocks in range [startHeight, endHeight]
- Load each block, process transactions
- Update best block after each block
- Replaces current `ScanUTXOs()` for incremental cases

**Startup logic:**
```cpp
if (wallet_height == 0) {
    // Full rescan from genesis
    wallet.RescanFromHeight(blockchain, 0, chain_height);
} else if (wallet_height < chain_height) {
    // Incremental: only new blocks since last sync
    wallet.RescanFromHeight(blockchain, wallet_height + 1, chain_height);
}
```

### Phase 5: Periodic Persistence (1 hour)

In `blockConnected()`:
```cpp
static const int WRITE_INTERVAL = 144;  // ~1 day of blocks
if (height % WRITE_INTERVAL == 0) {
    SaveUnlocked();  // Force save even if no wallet txs
}
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/wallet/wallet.h` | Add blockConnected/blockDisconnected, SetLastBlockProcessed, ProcessBlockTransactions |
| `src/wallet/wallet.cpp` | Implement callbacks, RescanFromHeight, periodic persistence |
| `src/consensus/chain.h` | Add BlockDisconnectCallback type |
| `src/consensus/chain.cpp` | Add RegisterBlockDisconnectCallback, notify in DisconnectTip |
| `src/node/dilithion-node.cpp` | Register wallet callbacks, update startup logic |

---

## Test Plan

### Unit Tests
1. blockConnected adds wallet outputs correctly
2. blockConnected marks wallet inputs as spent
3. blockDisconnected reverses both operations
4. Best block updated after each block
5. Crash recovery resumes from correct height

### Integration Tests
1. **Startup incremental scan**: Wallet at height 50, chain at 100 → scans 51-100
2. **Reorg handling**: 3-block reorg with wallet transactions
3. **Persistence**: Restart node, verify wallet state preserved

---

## Comparison: Dilithion vs Bitcoin Core

| Feature | Bitcoin Core | Dilithion (After Fix) |
|---------|-------------|----------------------|
| Best block tracking | BestBlock struct with locator | m_bestBlockHash + m_bestBlockHeight |
| Per-block updates | Yes (blockConnected/Disconnected) | Yes (same pattern) |
| Incremental scan | Block-by-block rescan | RescanFromHeight() |
| Reorg handling | blockDisconnected callback | blockDisconnected + CleanupStaleUTXOs |
| Persistence timing | Per-block + every 144 blocks | Same pattern |
| Database | LevelDB wallet.dat | Binary file with HMAC integrity |

---

## Sources

- [Bitcoin Core PR #30221](https://github.com/bitcoin/bitcoin/pull/30221) - Best block matching wallet scan state
- [Bitcoin Core wallet.h](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/wallet.h) - CWallet implementation
- [UTXO Model Guide](https://river.com/learn/bitcoins-utxo-model/) - UTXO tracking fundamentals
