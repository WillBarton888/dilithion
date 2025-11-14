# Chain Integrity Validation - System Design

**Date**: November 15, 2025
**Status**: Design Phase
**Purpose**: Detailed architecture for chain integrity validation and auto-recovery

---

## Design Goals

1. **Prevent "Cannot find parent block" errors** during systemd auto-restart
2. **Auto-wipe corrupted data in testnet mode** without intervention
3. **Require manual --reindex in mainnet mode** for safety
4. **Follow cryptocurrency industry best practices** (Bitcoin Core, Ethereum Geth, Monero)
5. **Keep it simple, robust, 10/10 quality**

---

## Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    dilithion-node startup                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Initialize Blockchain Database                  │
│           (LoadBlockIndex, LoadChainState)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   CChainVerifier                            │
│          VerifyChainIntegrity(LEVEL_QUICK)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
           ┌──────────┴──────────┐
           │   Validation OK?    │
           └──────────┬──────────┘
                      │
         ┌────────────┼────────────┐
         │ YES        │ NO         │
         ▼            ▼            │
    ┌────────┐  ┌─────────────┐   │
    │Continue│  │ Testnet?    │   │
    │ Startup│  └──────┬──────┘   │
    └────────┘         │          │
                  ┌────┼────┐     │
                  │YES │NO  │     │
                  ▼    ▼    ▼     │
         ┌────────────┐  ┌──────────────┐
         │  Auto-Wipe │  │Exit with     │
         │  & Restart │  │--reindex msg │
         └────────────┘  └──────────────┘
```

### File Structure

```
src/consensus/
├── chain_verifier.h       [NEW] - CChainVerifier class declaration
└── chain_verifier.cpp     [NEW] - Implementation

src/node/
└── dilithion-node.cpp     [MODIFY] - Add validation after blockchain init

Makefile                   [MODIFY] - Add new source files
```

---

## CChainVerifier Class Design

### Header (src/consensus/chain_verifier.h)

```cpp
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CHAIN_VERIFIER_H
#define DILITHION_CONSENSUS_CHAIN_VERIFIER_H

#include <primitives/block.h>
#include <string>
#include <vector>

/**
 * Chain integrity validation and corruption recovery
 *
 * Validates blockchain database integrity following industry best practices
 * from Bitcoin Core, Ethereum Geth, and Monero.
 *
 * Testnet behavior: Auto-wipe corrupted data and restart from genesis
 * Mainnet behavior: Exit with error, require --reindex flag
 */
class CChainVerifier {
public:
    /**
     * Validation levels (inspired by Bitcoin Core's VerifyDB)
     */
    enum ValidationLevel {
        LEVEL_MINIMAL,   // Genesis exists, best block pointer valid
        LEVEL_QUICK,     // Chain continuity (no missing parents) - DEFAULT
        LEVEL_STANDARD,  // + Block header validation (PoW, merkle root)
        LEVEL_FULL       // + Full block validation + UTXO consistency
    };

    CChainVerifier();

    /**
     * Verify chain integrity
     *
     * @param level Validation depth (LEVEL_QUICK recommended for startup)
     * @param error Output parameter for error description
     * @return true if validation passed, false if corruption detected
     */
    bool VerifyChainIntegrity(ValidationLevel level, std::string& error);

    /**
     * Detect common corruption patterns
     *
     * Checks for:
     * - Missing genesis block
     * - Invalid best block pointer
     * - Missing parent blocks
     * - Orphaned chain segments
     * - LevelDB internal errors
     *
     * @param error Output parameter for error description
     * @return true if corruption detected, false if database is healthy
     */
    bool DetectCorruption(std::string& error);

    /**
     * Attempt to repair corrupted chain
     *
     * Testnet behavior: Wipe .dilithion-testnet/* and return true
     * Mainnet behavior: Return false (require manual --reindex)
     *
     * @param testnet True if running in testnet mode
     * @return true if repair successful/attempted, false if manual intervention required
     */
    bool RepairChain(bool testnet);

private:
    // Validation helper methods
    bool CheckGenesisExists(std::string& error);
    bool CheckBestBlockValid(std::string& error);
    bool CheckParentExists(const uint256& hash, std::string& error);
    bool CheckChainContinuity(std::string& error);
    bool ValidateBlockHeaders(std::string& error);
    bool ValidateFullChain(std::string& error);

    // Corruption detection helpers
    bool IsOrphanedChainTip(std::string& error);
    bool HasMissingParents(std::string& error);

    // Recovery helpers
    bool WipeBlockchainData(bool testnet);
    std::string GetDataDirectory(bool testnet);
};

#endif // DILITHION_CONSENSUS_CHAIN_VERIFIER_H
```

### Implementation Design (chain_verifier.cpp)

#### Level 0 (MINIMAL) Validation
```cpp
bool CChainVerifier::CheckGenesisExists(std::string& error)
{
    // 1. Try to load block at height 0
    // 2. Verify it matches expected genesis hash
    // 3. If missing or wrong hash, set error and return false

    // Performance: <50ms (single database query)
}

bool CChainVerifier::CheckBestBlockValid(std::string& error)
{
    // 1. Get best block hash from database
    // 2. Verify block exists in database
    // 3. Verify block height makes sense (>= 0)
    // 4. If invalid, set error and return false

    // Performance: <100ms (2-3 database queries)
}
```

#### Level 1 (QUICK) Validation - DEFAULT
```cpp
bool CChainVerifier::CheckChainContinuity(std::string& error)
{
    // 1. Start at best block
    // 2. Walk backwards checking each parent exists
    // 3. Stop at genesis (height 0)
    // 4. If any parent missing, set error and return false
    // 5. OPTIMIZATION: Only check last 1000 blocks for startup speed
    //    (configurable via --check-blocks=N)

    // Performance: ~1-10 seconds for 1000 blocks
    // This is the PRIMARY check to prevent "Cannot find parent block"
}
```

#### Level 2 (STANDARD) Validation
```cpp
bool CChainVerifier::ValidateBlockHeaders(std::string& error)
{
    // 1. Walk chain from best block backwards
    // 2. For each block:
    //    - Verify PoW meets difficulty target
    //    - Verify merkle root matches transactions
    //    - Verify timestamp progression
    //    - Verify block version
    // 3. If any validation fails, set error and return false

    // Performance: ~30-60 seconds for 1000 blocks
}
```

#### Level 3 (FULL) Validation
```cpp
bool CChainVerifier::ValidateFullChain(std::string& error)
{
    // 1. Full block validation (Level 2 + transaction validation)
    // 2. UTXO set consistency
    // 3. Total coin supply verification
    // 4. Script validation

    // Performance: Minutes to hours (depending on chain length)
    // Only used for --reindex operations
}
```

#### Corruption Detection
```cpp
bool CChainVerifier::DetectCorruption(std::string& error)
{
    // Aggregate check combining:
    // 1. CheckGenesisExists()
    // 2. CheckBestBlockValid()
    // 3. CheckChainContinuity()  <- CRITICAL for current issue

    // Return true if ANY check fails
}
```

#### Recovery Implementation
```cpp
bool CChainVerifier::RepairChain(bool testnet)
{
    if (testnet) {
        // Testnet: Auto-wipe approach (following Ethereum Geth pattern)
        LogPrintf("TESTNET: Auto-wiping corrupted blockchain data\n");

        if (!WipeBlockchainData(testnet)) {
            LogPrintf("ERROR: Failed to wipe blockchain data\n");
            return false;
        }

        LogPrintf("TESTNET: Blockchain data wiped successfully\n");
        LogPrintf("TESTNET: Node will restart from genesis block\n");
        LogPrintf("TESTNET: This is normal after code updates\n");
        return true;
    } else {
        // Mainnet: Conservative approach (following Bitcoin Core pattern)
        LogPrintf("MAINNET: Corruption detected - manual intervention required\n");
        return false;  // Caller will exit with --reindex message
    }
}

bool CChainVerifier::WipeBlockchainData(bool testnet)
{
    // 1. Determine data directory (.dilithion-testnet/ or .dilithion/)
    // 2. Delete blocks/* subdirectory
    // 3. Delete chainstate/* subdirectory
    // 4. Preserve peers.dat, wallet.dat (if they exist)
    // 5. Return true on success, false on error

    // Safety: Only works if testnet=true, double-check before deletion
}
```

---

## Integration Point: dilithion-node.cpp

### Current Code (Approximate Line 736)

```cpp
// After blockchain initialized
LogPrintf("Blockchain initialized successfully\n");

// START P2P server
if (!StartP2PServer()) {
    return InitError("Failed to start P2P server");
}
```

### Modified Code with Validation

```cpp
// After blockchain initialized
LogPrintf("Blockchain initialized successfully\n");

// ============================================================================
// CHAIN INTEGRITY VALIDATION (following Bitcoin Core, Ethereum Geth best practices)
// ============================================================================
{
    CChainVerifier verifier;
    std::string error;

    // Quick validation on every startup (1-10 seconds)
    // This prevents "Cannot find parent block" errors during systemd auto-restart
    if (!verifier.VerifyChainIntegrity(CChainVerifier::LEVEL_QUICK, error)) {

        if (fTestnet) {
            // TESTNET: Auto-wipe corrupted data (following Ethereum Geth pattern)
            LogPrintf("=========================================================\n");
            LogPrintf("TESTNET: Chain corruption detected: %s\n", error);
            LogPrintf("TESTNET: Attempting automatic recovery...\n");
            LogPrintf("=========================================================\n");

            if (!verifier.RepairChain(true)) {
                return InitError("Failed to repair testnet blockchain data");
            }

            LogPrintf("=========================================================\n");
            LogPrintf("TESTNET: Auto-wiped corrupted data\n");
            LogPrintf("TESTNET: Node will restart from genesis block\n");
            LogPrintf("TESTNET: This is normal behavior after code updates\n");
            LogPrintf("=========================================================\n");

            // Re-initialize blockchain after wipe
            if (!InitBlockchain()) {
                return InitError("Failed to re-initialize blockchain after wipe");
            }

        } else {
            // MAINNET: Conservative approach (following Bitcoin Core pattern)
            return InitError(strprintf(
                "\n"
                "=========================================================\n"
                "ERROR: Corrupted blockchain database detected\n"
                "ERROR: %s\n"
                "=========================================================\n"
                "\n"
                "This usually indicates:\n"
                "  1. Database corruption from unclean shutdown\n"
                "  2. Incomplete blockchain download\n"
                "  3. Disk corruption\n"
                "\n"
                "To recover:\n"
                "  Option 1: Restart with --reindex flag\n"
                "    ./dilithion-node --reindex\n"
                "\n"
                "  Option 2: Delete blockchain data for full re-sync\n"
                "    rm -rf ~/.dilithion/blocks ~/.dilithion/chainstate\n"
                "    ./dilithion-node\n"
                "\n"
                "For more information, see docs/troubleshooting.md\n"
                "\n",
                error
            ));
        }
    }

    LogPrintf("Chain integrity validation passed\n");
}

// START P2P server
if (!StartP2PServer()) {
    return InitError("Failed to start P2P server");
}
```

---

## Command-Line Flag: --reindex

### Design

```cpp
// In command-line argument parsing (dilithion-node.cpp)

bool fReindex = false;  // Global variable

// Parse arguments
if (gArgs.IsArgSet("-reindex")) {
    fReindex = true;
    LogPrintf("Reindex mode enabled - will rebuild blockchain index\n");
}

// In blockchain initialization
if (fReindex) {
    // Skip chain integrity validation (we're rebuilding anyway)
    LogPrintf("Reindex mode: Skipping chain integrity validation\n");

    // Delete block index
    LogPrintf("Reindex mode: Deleting block index...\n");
    // ... delete blocks/index/* ...

    // Delete chainstate
    LogPrintf("Reindex mode: Deleting chainstate...\n");
    // ... delete chainstate/* ...

    // Rebuild from block files
    LogPrintf("Reindex mode: Rebuilding blockchain from block files...\n");
    // ... rebuild logic ...
}
```

---

## Error Messages Design

### Testnet Auto-Wipe Output

```
=========================================================
TESTNET: Chain corruption detected: Cannot find parent block 000000abcd1234...
TESTNET: Attempting automatic recovery...
=========================================================
TESTNET: Wiping /root/dilithion/.dilithion-testnet/blocks/*
TESTNET: Wiping /root/dilithion/.dilithion-testnet/chainstate/*
=========================================================
TESTNET: Auto-wiped corrupted data
TESTNET: Node will restart from genesis block
TESTNET: This is normal behavior after code updates
=========================================================
Blockchain initialized successfully
Genesis block: 00000008e647c53e77d11a61c618c4df0ee20e32e137ed3d56906d03bbf47f29
Chain integrity validation passed
Starting P2P server on port 18333...
```

### Mainnet Error Output

```
=========================================================
ERROR: Corrupted blockchain database detected
ERROR: Cannot find parent block for best chain tip
=========================================================

This usually indicates:
  1. Database corruption from unclean shutdown
  2. Incomplete blockchain download
  3. Disk corruption

To recover:
  Option 1: Restart with --reindex flag
    ./dilithion-node --reindex

  Option 2: Delete blockchain data for full re-sync
    rm -rf ~/.dilithion/blocks ~/.dilithion/chainstate
    ./dilithion-node

For more information, see docs/troubleshooting.md
```

---

## Performance Specifications

### Startup Validation Cost (Level 1 - QUICK)

| Chain Length | Blocks Checked | Validation Time | Acceptable? |
|-------------|----------------|-----------------|-------------|
| 0-1000      | All            | <5 seconds      | ✅ YES      |
| 1000-10000  | Last 1000      | ~5 seconds      | ✅ YES      |
| 10000+      | Last 1000      | ~5-10 seconds   | ✅ YES      |

**Rationale**: 5-10 second startup delay is acceptable to prevent hours of debugging corrupted chains.

### Full Validation Cost (Level 3 - FULL)

Only used during `--reindex` operations:
- 10,000 blocks: ~10-20 minutes
- 100,000 blocks: ~2-4 hours
- Acceptable because it's manual operation only

---

## Safety Mechanisms

### 1. Testnet Double-Check
```cpp
bool CChainVerifier::WipeBlockchainData(bool testnet)
{
    // SAFETY: Triple-check we're actually in testnet
    if (!testnet) {
        LogPrintf("ERROR: WipeBlockchainData called for mainnet - REFUSING\n");
        return false;
    }

    // SAFETY: Verify we're not wiping wrong directory
    std::string dataDir = GetDataDirectory(testnet);
    if (dataDir.find("testnet") == std::string::npos) {
        LogPrintf("ERROR: Data directory doesn't contain 'testnet' - REFUSING\n");
        return false;
    }

    // ... proceed with wipe ...
}
```

### 2. Preserve Important Files
```cpp
// When wiping blockchain data, preserve:
// - peers.dat (known peer addresses)
// - wallet.dat (if wallet exists)
// - dilithion.conf (configuration)
// - debug.log (historical logs)

// Only delete:
// - blocks/* (block data)
// - chainstate/* (UTXO set)
```

### 3. Atomic Operations
```cpp
// Use temporary directories for rebuilding
// Only move into place after validation succeeds
// This prevents corruption during rebuilding
```

---

## Testing Plan

### Test Case 1: Clean Startup (Testnet)
```bash
# Expected: Validation passes, node starts normally
rm -rf .dilithion-testnet/*
./dilithion-node --testnet
# Should see: "Chain integrity validation passed"
```

### Test Case 2: Corrupted Chain (Testnet)
```bash
# Simulate corruption: Delete parent of best block
# Expected: Auto-wipe and restart from genesis
rm .dilithion-testnet/blocks/blk00001.dat
./dilithion-node --testnet
# Should see: "TESTNET: Auto-wiped corrupted data"
```

### Test Case 3: Corrupted Chain (Mainnet)
```bash
# Expected: Exit with --reindex message
rm .dilithion/blocks/blk00001.dat
./dilithion-node
# Should see: "ERROR: Corrupted blockchain database detected"
# Should see: "Restart with --reindex flag"
```

### Test Case 4: Systemd Auto-Restart (Testnet)
```bash
# Expected: Auto-wipe after kill, restart from genesis
systemctl start dilithion-testnet.service
# Manually corrupt database
kill -9 $(pidof dilithion-node)
rm .dilithion-testnet/chainstate/*
# Wait 10 seconds for systemd restart
# Should see in logs: "TESTNET: Auto-wiped corrupted data"
```

### Test Case 5: Manual Reindex (Mainnet)
```bash
# Expected: Rebuild blockchain index
./dilithion-node --reindex
# Should see: "Reindex mode: Rebuilding blockchain from block files..."
```

---

## Dependencies

### External Libraries
- None (uses existing Dilithion infrastructure)

### Internal Dependencies
```cpp
#include <primitives/block.h>        // uint256, CBlock, CBlockHeader
#include <chain.h>                   // CBlockIndex (if exists)
#include <fs.h>                      // Filesystem operations
#include <util/system.h>             // GetDataDir(), logging
#include <iostream>                  // Error output
#include <algorithm>                 // std::find
```

### Build System Changes
```makefile
# Makefile additions
SOURCES += src/consensus/chain_verifier.cpp

HEADERS += src/consensus/chain_verifier.h
```

---

## Rollout Strategy

### Phase 1: Local Development Testing
1. Implement CChainVerifier class
2. Test all validation levels locally
3. Test corruption detection locally
4. Test auto-wipe in testnet mode
5. Test --reindex flag

### Phase 2: Single Node Testing (NYC)
1. Deploy to NYC node only
2. Test systemd auto-restart with corrupted data
3. Monitor for 24 hours
4. Verify auto-wipe works without intervention

### Phase 3: Multi-Node Deployment
1. Deploy to Singapore node
2. Monitor for 12 hours
3. Deploy to London node
4. Monitor for 12 hours
5. All 3 nodes running stably

### Phase 4: Long-Term Monitoring
1. Monitor all nodes for 1 week
2. Verify auto-restart works reliably
3. Document any edge cases
4. Update documentation

---

## Monitoring and Observability

### Log Patterns to Monitor

**Success Pattern**:
```
Blockchain initialized successfully
Chain integrity validation passed
Starting P2P server on port 18333...
```

**Auto-Wipe Pattern**:
```
TESTNET: Chain corruption detected: [reason]
TESTNET: Auto-wiped corrupted data
TESTNET: Node will restart from genesis block
```

**Mainnet Corruption Pattern**:
```
ERROR: Corrupted blockchain database detected
ERROR: [reason]
```

### Systemd Journal Integration
```bash
# Filter chain integrity logs
journalctl -u dilithion-testnet.service | grep "Chain integrity"

# Filter auto-wipe events
journalctl -u dilithion-testnet.service | grep "Auto-wiped"

# Filter corruption errors
journalctl -u dilithion-testnet.service | grep "Corrupted"
```

---

## Future Enhancements (Out of Scope)

1. **Configurable Validation Depth**: `--check-blocks=N` flag
2. **Periodic Validation**: Run validation every N blocks
3. **Corruption Metrics**: Track corruption frequency
4. **Smart Recovery**: Attempt to salvage partial chains
5. **Background Validation**: Validate while syncing

---

**Generated with [Claude Code](https://claude.com/claude-code)**
