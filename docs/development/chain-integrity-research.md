# Chain Integrity Validation - Industry Research

**Date**: November 15, 2025
**Purpose**: Research how major cryptocurrencies handle chain integrity validation and corruption recovery
**Goal**: Implement production-grade chain validation for Dilithion following industry best practices

---

## Research Methodology

Analyzed three major cryptocurrency implementations:
1. **Bitcoin Core** - The original blockchain implementation (14+ years in production)
2. **Ethereum Geth** - Large-scale PoS blockchain with complex state management
3. **Monero** - Privacy-focused cryptocurrency with LMDB database

Focus areas:
- When chain validation occurs
- What is validated (validation levels)
- How corruption is detected
- Corruption recovery mechanisms
- Testnet vs mainnet behavior
- Performance implications

---

## Bitcoin Core

### Chain Validation Approach

**When Validation Occurs**:
- During initial startup (LoadBlockIndex)
- During block acceptance (CheckBlock, CheckBlockHeader)
- On-demand via RPC (verifychain command)
- After unclean shutdown detection

**Validation Levels**:

Bitcoin Core uses a tiered validation approach:

1. **Block Header Validation**:
   - Check proof-of-work meets difficulty target
   - Verify timestamp is not too far in future
   - Check block version is acceptable
   - Verify previous block hash exists

2. **Block Structure Validation**:
   - Merkle root matches transactions
   - Block size within limits
   - First transaction is coinbase
   - No duplicate transactions

3. **Transaction Validation**:
   - Input scripts validate correctly
   - No double-spends
   - Fees are correct
   - Locktime rules followed

4. **Chain State Validation**:
   - UTXO set consistency
   - Total coin supply correct
   - No missing parent blocks

**Corruption Detection**:

Bitcoin Core detects corruption through:
- Missing block files
- Invalid block header linkage (cannot find parent)
- UTXO database consistency checks
- LevelDB internal error codes
- Abnormal shutdown detection (dirty flag)

### Recovery Mechanisms

**1. --reindex Flag**:
- **Purpose**: Rebuild block index from existing block files
- **Use case**: Block index corrupted but raw block data intact
- **Process**:
  1. Delete block index database
  2. Scan blk*.dat files
  3. Rebuild index with validation
  4. Faster than re-download (uses existing block files)
- **Data preserved**: Raw block files (blk*.dat)
- **Data rebuilt**: Block index, chainstate

**2. --reindex-chainstate Flag**:
- **Purpose**: Rebuild UTXO set from block index
- **Use case**: Chainstate database corrupted but block index intact
- **Process**:
  1. Delete chainstate database
  2. Replay blocks from genesis
  3. Rebuild UTXO set
- **Faster than --reindex**: Block index already validated

**3. Manual Recovery**:
- Delete specific database directories
- Preserve blocks/ directory when possible
- Full re-sync as last resort

**Testnet vs Mainnet Behavior**:
- **Same validation rules** - no auto-wipe in testnet
- Users must manually specify --reindex or delete data
- Rationale: Even testnet should behave predictably

**Key Implementation Patterns**:

```cpp
// LoadBlockIndex() pattern:
if (!fReindex && !LoadBlockIndex()) {
    return InitError("Failed to load block index");
}

// VerifyDB() pattern:
CVerifyDB verifier;
if (!verifier.VerifyDB(chainparams, &coinsTip, nCheckLevel, nCheckDepth)) {
    return InitError("Corrupted block database detected");
}

// Startup validation:
if (ShutdownRequested()) {
    return false;
}
```

---

## Ethereum Geth

### Chain Validation Approach

**When Validation Occurs**:
- During node startup (database integrity check)
- During block import (header → body → state validation)
- After unclean shutdown (check for dangling data)
- Continuous state root verification

**Validation Levels**:

1. **Ancient Database Validation**:
   - Check for dangling head/indexes
   - Truncate incomplete ancient data
   - Verify freezer table consistency

2. **State Database Validation**:
   - LevelDB internal consistency
   - State root verification
   - Account trie validation

3. **Block Validation**:
   - Header fields (difficulty, timestamp, gas limit)
   - Block hash matches header
   - State transitions valid

**Corruption Detection**:

Geth detects corruption through specific error patterns:

```
"leveldb/table: corruption on data-block"
"database contains incompatible formated data"
"missing trie node"
"state not available"
```

**Ancient Database Handling**:
- Geth stores old blocks in "ancient" database (immutable storage)
- On startup, checks for "dangling" data (incomplete writes)
- Automatically truncates dangling head/indexes
- Logs: "Truncating dangling head block" or "Truncating dangling head header"

### Recovery Mechanisms

**1. Automatic Truncation**:
- Detects incomplete writes on startup
- Automatically removes dangling data
- No user intervention required
- Safe for unclean shutdown recovery

**2. removedb Subcommand**:
```bash
geth removedb
```
- **Purpose**: Delete state database completely
- **Behavior**: Prompts user for confirmation
- **Use case**: Severe corruption requiring full resync
- **Preserved**: Ancient data (old blocks)
- **Deleted**: Chaindata (recent state)

**3. Graceful Shutdown**:
- **CRITICAL**: Geth requires 300+ seconds for clean shutdown
- Originally used SIGINT (not SIGTERM) to prevent immediate exit
- Modern versions handle SIGTERM correctly
- Flushes in-memory state to disk
- Prevents "dangling" data corruption

**Testnet vs Mainnet Behavior**:
- **Same validation** - no special testnet handling
- Corruption recovery manual in both cases
- Rationale: Predictable behavior across networks

**Key Implementation Patterns**:

```go
// Ancient database validation:
if err := db.truncateAncients(); err != nil {
    log.Error("Failed to truncate ancients", "err", err)
    return nil, err
}

// Corruption detection:
if corrupted(block) {
    log.Error("Found corrupted block", "hash", hash)
    return errors.New("database corrupted")
}

// Graceful shutdown requirement:
// systemd: TimeoutStopSec=300 (minimum)
```

---

## Monero

### Chain Validation Approach

**When Validation Occurs**:
- During daemon startup (blockchain database check)
- During block synchronization
- On-demand via --db-salvage flag

**Validation Levels**:

1. **Database Integrity**:
   - LMDB transaction consistency
   - Block height continuity
   - Transaction pool validity

2. **Block Validation**:
   - Proof-of-work verification
   - Transaction validity
   - Ring signature verification

**Corruption Detection**:

Monero uses LMDB (Lightning Memory-Mapped Database) which has specific corruption patterns:

```
"MDB_CORRUPTED: Located page was wrong type"
"MDB_BAD_TXN: Transaction must abort, has a child, or is invalid"
"Failed to query m_blocks: MDB_BAD_VALSIZE: Unsupported size of key/DB name/data"
```

### Recovery Mechanisms

**1. --db-salvage Flag**:
```bash
monerod --db-salvage
```
- **Purpose**: Use older LMDB snapshot to recover from corruption
- **How it works**:
  - LMDB keeps multiple snapshots (transaction snapshots)
  - --db-salvage uses previous valid snapshot
  - Discards corrupted recent data
  - May lose recent blocks
- **Use case**: Recent corruption with valid older state
- **Limitation**: Sometimes requires full blockchain re-download

**2. Manual Database Deletion**:
```bash
rm -rf ~/.bitmonero/lmdb/*
monerod
```
- Forces full blockchain re-sync
- Nuclear option for severe corruption

**3. Pop-Blocks Method**:
- Monero can "pop" (remove) recent blocks
- Useful for recovering from fork issues
- Not automated - requires manual intervention

**Testnet vs Mainnet Behavior**:
- **Same validation** - no auto-wipe
- Manual intervention required for both
- Rationale: Consistent behavior

**Key Implementation Patterns**:

```cpp
// Database initialization with corruption check:
if (db->is_open()) {
    if (!db->verify_db()) {
        LOG_ERROR("Database verification failed");
        return false;
    }
}

// Salvage mode detection:
if (command_line::get_arg(vm, arg_db_salvage)) {
    LOG_PRINT_L0("Attempting to salvage database...");
}
```

---

## Comparison Matrix

| Feature | Bitcoin Core | Ethereum Geth | Monero |
|---------|-------------|---------------|--------|
| **Validation timing** | Startup + on-demand | Startup + continuous | Startup + sync |
| **Corruption detection** | Missing parents, LevelDB errors | Dangling data, missing trie nodes | LMDB corruption codes |
| **Auto-recovery** | No | Yes (truncate dangling) | No |
| **Recovery flags** | --reindex, --reindex-chainstate | removedb subcommand | --db-salvage |
| **Testnet behavior** | Same as mainnet | Same as mainnet | Same as mainnet |
| **Graceful shutdown** | SIGTERM | SIGTERM (300s timeout) | SIGTERM |
| **Database** | LevelDB | LevelDB + Ancient | LMDB |

---

## Recommendations for Dilithion

Based on industry research, Dilithion should implement:

### 1. Validation Approach (Hybrid Model)

**Follow Bitcoin Core tiered validation**:
- **Level 0 (MINIMAL)**: Genesis exists, best block pointer valid
- **Level 1 (QUICK)**: Chain continuity (no missing parents) ← **DEFAULT FOR STARTUP**
- **Level 2 (STANDARD)**: + Block header validation
- **Level 3 (FULL)**: + Full block validation + UTXO consistency

**Why**: Bitcoin Core's approach is battle-tested and well-understood. Start with quick validation (Level 1) during normal startup, reserve full validation for --reindex.

### 2. Corruption Detection

**Implement Bitcoin Core-style detection**:
- Missing parent blocks (current issue)
- Invalid best block pointer
- LevelDB internal errors
- Orphaned chain segments

**Add Geth-style automatic handling for testnet only**:
- Detect corruption patterns
- Auto-wipe and restart from genesis (testnet only)
- Require --reindex flag for mainnet

### 3. Recovery Mechanisms

**Three-tier approach**:

**Tier 1: Automatic (Testnet Only)**
```cpp
if (fTestnet && DetectCorruption()) {
    LogPrintf("TESTNET: Auto-wiping corrupted blockchain data\n");
    WipeBlockchainData();
    return true;  // Continue with genesis
}
```

**Tier 2: Manual Flag (Mainnet)**
```cpp
if (!fTestnet && DetectCorruption() && !fReindex) {
    return InitError(
        "Corrupted blockchain database detected.\n"
        "Restart with --reindex to rebuild from existing blocks."
    );
}
```

**Tier 3: Full Re-sync**
- Delete .dilithion/ directory manually
- Force complete blockchain download
- Last resort option

### 4. Validation Timing

**On every startup**:
1. Check genesis block exists
2. Verify best block pointer is valid
3. Check best block's parent exists (prevent "Cannot find parent block" error)
4. If any check fails:
   - Testnet: Auto-wipe and log warning
   - Mainnet: Exit with error, suggest --reindex

**During sync**:
- Standard Bitcoin Core block validation
- Check parent exists before accepting block
- Validate PoW, merkle root, etc.

### 5. Implementation Architecture

**New class: CChainVerifier**
```cpp
class CChainVerifier {
public:
    enum ValidationLevel {
        LEVEL_MINIMAL,   // Genesis + best block exists
        LEVEL_QUICK,     // Chain continuity check
        LEVEL_STANDARD,  // + Block header validation
        LEVEL_FULL       // + Full block + UTXO consistency
    };

    // Main validation entry point
    bool VerifyChainIntegrity(ValidationLevel level, std::string& error);

    // Corruption detection
    bool DetectCorruption(std::string& error);

    // Recovery (testnet auto-wipe, mainnet require flag)
    bool RepairChain(bool testnet);

private:
    bool CheckGenesisExists();
    bool CheckBestBlockValid();
    bool CheckParentExists(const uint256& hash);
    bool CheckChainContinuity();
};
```

**Integration point (src/node/dilithion-node.cpp)**:
```cpp
// After blockchain initialized (line ~736):
CChainVerifier verifier;
std::string error;

// Quick validation on startup
if (!verifier.VerifyChainIntegrity(CChainVerifier::LEVEL_QUICK, error)) {
    if (fTestnet) {
        LogPrintf("TESTNET: Chain corruption detected: %s\n", error);
        if (!verifier.RepairChain(true)) {
            return InitError("Failed to repair testnet chain");
        }
        LogPrintf("TESTNET: Auto-wiped corrupted data, restarting from genesis\n");
    } else {
        return InitError(strprintf(
            "Chain corruption detected: %s\n"
            "Restart with --reindex to rebuild blockchain index.",
            error
        ));
    }
}
```

### 6. Testnet vs Mainnet Behavior

**Testnet (Aggressive Auto-Recovery)**:
- Detect corruption on startup
- Automatically wipe .dilithion-testnet/*
- Log warning but continue
- Rationale: Testing convenience, data not valuable

**Mainnet (Conservative Manual Recovery)**:
- Detect corruption on startup
- Exit with clear error message
- Require --reindex flag explicitly
- Rationale: User funds at risk, require explicit consent

### 7. Performance Implications

**Startup validation cost**:
- **Level 0 (MINIMAL)**: <100ms (check 2 blocks exist)
- **Level 1 (QUICK)**: ~1-10 seconds (verify chain continuity)
- **Level 2 (STANDARD)**: ~30-60 seconds (validate all headers)
- **Level 3 (FULL)**: Minutes to hours (full validation)

**Recommendation**: Use Level 1 (QUICK) by default - acceptable startup delay for corruption protection.

### 8. Error Messages

**Clear, actionable error messages following industry standards**:

```
TESTNET: Chain corruption detected - missing parent block
TESTNET: Auto-wiping blockchain data and restarting from genesis
TESTNET: This is normal behavior for testnet after code updates
```

```
ERROR: Corrupted blockchain database detected
ERROR: Cannot find parent block for best chain tip
ERROR: This usually indicates database corruption or incomplete shutdown
ERROR:
ERROR: To recover:
ERROR:   1. Restart with --reindex to rebuild from existing blocks
ERROR:   2. Or delete .dilithion/ directory for full re-sync
ERROR:
ERROR: For more information, see docs/troubleshooting.md
```

---

## Key Principles from Industry Research

1. **Fail Fast**: Detect corruption early (startup validation)
2. **Fail Safe**: Never auto-wipe mainnet data without explicit flag
3. **Fail Obvious**: Clear error messages with recovery instructions
4. **Tiered Validation**: Quick checks for common issues, full validation on-demand
5. **Graceful Shutdown**: Critical for preventing corruption (300s timeout)
6. **Testnet Convenience**: Auto-recovery acceptable for test networks
7. **Mainnet Conservation**: Require explicit user consent for destructive operations

---

## References

### Bitcoin Core
- Core validation logic: src/validation.cpp
- Reindex implementation: src/init.cpp
- Database recovery: src/txdb.cpp
- Documentation: doc/release-notes (various versions)

### Ethereum Geth
- Ancient database handling: core/rawdb/freezer.go
- Corruption detection: ethdb/leveldb/leveldb.go
- Graceful shutdown: node/node.go
- Community reports: GitHub issues #15218, #21848, #27694

### Monero
- Database salvage: src/daemon/command_line_args.h
- LMDB integration: src/blockchain_db/lmdb/db_lmdb.cpp
- Recovery procedures: docs/ANONYMITY_NETWORKS.md
- Community guides: monero.stackexchange.com

---

**Generated with [Claude Code](https://claude.com/claude-code)**
