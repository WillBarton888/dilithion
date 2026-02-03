// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/reorg_wal.h>  // P1-4: WAL for atomic reorgs
#include <consensus/validation.h> // BUG #109 FIX: DeserializeBlockTransactions
#include <core/chainparams.h>     // MAINNET: Checkpoint validation
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <node/mempool.h>         // BUG #109 FIX: RemoveConfirmedTxs
#include <dfmp/identity_db.h>     // Identity undo during reorg
#include <dfmp/mik.h>             // MIK parsing for identity undo
#include <util/assert.h>
#include <iostream>
#include <algorithm>
#include <set>

CChainState::CChainState() : pindexTip(nullptr), pdb(nullptr), pUTXOSet(nullptr) {
}

CChainState::~CChainState() {
    Cleanup();
}

// P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
bool CChainState::InitializeWAL(const std::string& dataDir) {
    m_reorgWAL = std::make_unique<CReorgWAL>(dataDir);

    if (m_reorgWAL->HasIncompleteReorg()) {
        std::cerr << "[Chain] CRITICAL: Incomplete reorganization detected!" << std::endl;
        std::cerr << "[Chain] " << m_reorgWAL->GetIncompleteReorgInfo() << std::endl;
        std::cerr << "[Chain] The database may be in an inconsistent state." << std::endl;
        std::cerr << "[Chain] Please restart with -reindex to rebuild the blockchain." << std::endl;
        m_requiresReindex = true;
        return false;
    }

    return true;
}

bool CChainState::RequiresReindex() const {
    return m_requiresReindex;
}

void CChainState::Cleanup() {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // HIGH-C001 FIX: Smart pointers automatically destruct when map is cleared
    // No need for manual delete - RAII handles cleanup
    mapBlockIndex.clear();
    pindexTip = nullptr;
    // BUG #74 FIX: Reset atomic cached height
    m_cachedHeight.store(-1, std::memory_order_release);
}

bool CChainState::AddBlockIndex(const uint256& hash, std::unique_ptr<CBlockIndex> pindex) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // HIGH-C001 FIX: Accept unique_ptr for automatic ownership transfer
    if (pindex == nullptr) {
        return false;
    }

    // Invariant: Hash must match block index hash
    Invariant(pindex->GetBlockHash() == hash);

    // Check if already exists (normal during concurrent block processing)
    if (mapBlockIndex.count(hash) > 0) {
        return false;
    }

    // Consensus invariant: If block has parent, parent must exist in map
    if (pindex->pprev != nullptr) {
        uint256 parentHash = pindex->pprev->GetBlockHash();
        ConsensusInvariant(mapBlockIndex.count(parentHash) > 0);
        
        // Consensus invariant: Height must be parent height + 1
        ConsensusInvariant(pindex->nHeight == pindex->pprev->nHeight + 1);
    } else {
        // Genesis block must be at height 0
        ConsensusInvariant(pindex->nHeight == 0);
    }

    // Transfer ownership to map using move semantics
    mapBlockIndex[hash] = std::move(pindex);
    return true;
}

CBlockIndex* CChainState::GetBlockIndex(const uint256& hash) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // HIGH-C001 FIX: Return raw pointer (non-owning) via .get()
    auto it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end()) {
        return it->second.get();  // Extract raw pointer from unique_ptr
    }
    return nullptr;
}

bool CChainState::HasBlockIndex(const uint256& hash) const {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    return mapBlockIndex.count(hash) > 0;
}

CBlockIndex* CChainState::FindFork(CBlockIndex* pindex1, CBlockIndex* pindex2) {
    // Find the last common ancestor between two chains
    // This is used to determine where chains diverge

    if (pindex1 == nullptr || pindex2 == nullptr) {
        return nullptr;
    }

    // Walk both chains back to same height
    while (pindex1->nHeight > pindex2->nHeight) {
        pindex1 = pindex1->pprev;
        if (pindex1 == nullptr) return nullptr;
    }

    while (pindex2->nHeight > pindex1->nHeight) {
        pindex2 = pindex2->pprev;
        if (pindex2 == nullptr) return nullptr;
    }

    // Now both at same height, walk back until we find common block
    while (pindex1 != pindex2) {
        pindex1 = pindex1->pprev;
        pindex2 = pindex2->pprev;

        if (pindex1 == nullptr || pindex2 == nullptr) {
            return nullptr;
        }
    }

    return pindex1;  // Common ancestor
}

bool CChainState::ActivateBestChain(CBlockIndex* pindexNew, const CBlock& block, bool& reorgOccurred) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    // This protects pindexTip, mapBlockIndex, and all chain operations
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    reorgOccurred = false;

    if (pindexNew == nullptr) {
        std::cerr << "[Chain] ERROR: ActivateBestChain called with nullptr" << std::endl;
        return false;
    }

    // MAINNET SECURITY: Validate block against checkpoint if one exists at this height
    // This ensures we never accept a block with a hash that doesn't match a checkpoint.
    // Testnet has no checkpoints, so this check will always pass on testnet.
    if (Dilithion::g_chainParams) {
        if (!Dilithion::g_chainParams->CheckpointCheck(pindexNew->nHeight, pindexNew->GetBlockHash())) {
            std::cerr << "[Chain] ERROR: Block hash does not match checkpoint!" << std::endl;
            std::cerr << "  Height: " << pindexNew->nHeight << std::endl;
            std::cerr << "  Block hash: " << pindexNew->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  This may indicate an attack or corrupted block data." << std::endl;
            return false;
        }
    }

    // Case 1: Genesis block (first block in chain)
    if (pindexTip == nullptr) {

        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] ERROR: Failed to connect genesis block" << std::endl;
            return false;
        }

        pindexTip = pindexNew;
        // BUG #74 FIX: Update atomic cached height
        m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

        // Persist to database
        if (pdb != nullptr) {
            pdb->WriteBestBlock(pindexNew->GetBlockHash());
        }

        return true;
    }

    // Case 2: Extends current tip (simple case - no reorg needed)
    if (pindexNew->pprev == pindexTip) {

        // Compare chain work to be safe (should always be greater if extending tip)
        if (!ChainWorkGreaterThan(pindexNew->nChainWork, pindexTip->nChainWork)) {
            std::cerr << "[Chain] WARNING: Block extends tip but doesn't increase chain work" << std::endl;
            std::cerr << "  Current work: " << pindexTip->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
            std::cerr << "  New work:     " << pindexNew->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }

        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] ERROR: Failed to connect block extending tip" << std::endl;
            return false;
        }

        pindexTip = pindexNew;
        // BUG #74 FIX: Update atomic cached height
        m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

        // Persist to database
        if (pdb != nullptr) {
            bool success = pdb->WriteBestBlock(pindexNew->GetBlockHash());
        } else {
            std::cerr << "[Chain] ERROR: pdb is nullptr! Cannot write best block!" << std::endl;
        }

        // Bug #40 fix: Notify registered callbacks of tip update
        NotifyTipUpdate(pindexTip);

        return true;
    }

    // Case 3: Competing chain - need to compare chain work
    std::cout << "  Current tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexTip->nHeight << ")" << std::endl;
    std::cout << "  New block:   " << pindexNew->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexNew->nHeight << ")" << std::endl;

    // Compare chain work
    if (!ChainWorkGreaterThan(pindexNew->nChainWork, pindexTip->nChainWork)) {
        std::cout << "  Current work: " << pindexTip->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "  New work:     " << pindexNew->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;

        // Block is valid but not on best chain - it's an orphan
        // Still save it to database, but don't activate it
        return true;  // Not an error - block is valid, just not best chain
    }

    // New chain has more work - REORGANIZATION REQUIRED
    std::cout << "[Chain] ⚠️  NEW CHAIN HAS MORE WORK - REORGANIZING" << std::endl;
    std::cout << "  Current work: " << pindexTip->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
    std::cout << "  New work:     " << pindexNew->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;

    // Find fork point
    CBlockIndex* pindexFork = FindFork(pindexTip, pindexNew);
    if (pindexFork == nullptr) {
        std::cerr << "[Chain] ERROR: Cannot find fork point between chains" << std::endl;
        return false;
    }


    // VULN-008 FIX: Protect against excessively deep reorganizations
    // CID 1675248 FIX: Use int64_t to prevent overflow when computing reorg depth
    // and add validation to ensure reorg_depth is non-negative
    static const int64_t MAX_REORG_DEPTH = 100;  // Similar to Bitcoin's practical limit
    int64_t reorg_depth = static_cast<int64_t>(pindexTip->nHeight) - static_cast<int64_t>(pindexFork->nHeight);
    if (reorg_depth < 0) {
        std::cerr << "[Chain] ERROR: Invalid reorg depth (negative): " << reorg_depth << std::endl;
        std::cerr << "  Tip height: " << pindexTip->nHeight << ", Fork height: " << pindexFork->nHeight << std::endl;
        return false;
    }
    if (reorg_depth > MAX_REORG_DEPTH) {
        std::cerr << "[Chain] ERROR: Reorganization too deep: " << reorg_depth << " blocks" << std::endl;
        std::cerr << "  Maximum allowed: " << MAX_REORG_DEPTH << " blocks" << std::endl;
        std::cerr << "  This may indicate a long-range attack or network partition" << std::endl;
        return false;
    }

    // MAINNET SECURITY: Checkpoint validation - prevent reorgs past checkpoints
    // Checkpoints are hardcoded trusted block hashes that protect old transaction history.
    // If a reorg would disconnect blocks before the last checkpoint, reject it.
    // Testnet has no checkpoints to allow testing deep reorgs.
    if (Dilithion::g_chainParams) {
        const Dilithion::CCheckpoint* checkpoint = Dilithion::g_chainParams->GetLastCheckpoint(pindexTip->nHeight);
        if (checkpoint && pindexFork->nHeight < checkpoint->nHeight) {
            std::cerr << "[Chain] ERROR: Cannot reorganize past checkpoint" << std::endl;
            std::cerr << "  Checkpoint height: " << checkpoint->nHeight << std::endl;
            std::cerr << "  Fork point height: " << pindexFork->nHeight << std::endl;
            std::cerr << "  This reorganization would undo blocks protected by a checkpoint." << std::endl;
            std::cerr << "  Checkpoints protect user funds from deep chain attacks." << std::endl;
            return false;
        }
    }

    if (reorg_depth > 10) {
        std::cout << "[Chain] ⚠️  WARNING: Deep reorganization (" << reorg_depth << " blocks)" << std::endl;
    }

    // Build list of blocks to disconnect (from current tip back to fork point)
    std::vector<CBlockIndex*> disconnectBlocks;
    CBlockIndex* pindex = pindexTip;
    while (pindex != pindexFork) {
        disconnectBlocks.push_back(pindex);
        pindex = pindex->pprev;

        if (pindex == nullptr) {
            std::cerr << "[Chain] ERROR: Hit nullptr while building disconnect list" << std::endl;
            return false;
        }
    }

    // Build list of blocks to connect (from fork point to new tip)
    std::vector<CBlockIndex*> connectBlocks;
    pindex = pindexNew;
    while (pindex != pindexFork) {
        connectBlocks.push_back(pindex);
        pindex = pindex->pprev;

        if (pindex == nullptr) {
            std::cerr << "[Chain] ERROR: Hit nullptr while building connect list" << std::endl;
            return false;
        }
    }

    // Reverse connect list so we connect from fork point -> new tip
    std::reverse(connectBlocks.begin(), connectBlocks.end());

    std::cout << "  Disconnect " << disconnectBlocks.size() << " block(s)" << std::endl;
    std::cout << "  Connect " << connectBlocks.size() << " block(s)" << std::endl;

    // ============================================================================
    // CRITICAL-C002 FIX: Pre-validate ALL blocks exist before starting reorg
    // ============================================================================
    // This prevents the most common cause of rollback failure: missing block data.
    // By validating ALL blocks can be loaded BEFORE making any changes, we ensure
    // that if the reorg fails, it fails cleanly without corrupting the database.
    //
    // This is a defense-in-depth measure. The ultimate fix requires database-level
    // atomic transactions or write-ahead logging, but this significantly reduces
    // the risk of corruption.


    // Validate all disconnect blocks exist in database
    for (size_t i = 0; i < disconnectBlocks.size(); ++i) {
        CBlockIndex* pindexCheck = disconnectBlocks[i];
        CBlock blockCheck;

        if (pdb == nullptr) {
            std::cerr << "[Chain] ERROR: No database connection - cannot perform reorg" << std::endl;
            return false;
        }

        if (!pdb->ReadBlock(pindexCheck->GetBlockHash(), blockCheck)) {
            std::cerr << "[Chain] ERROR: Cannot load block for disconnect (PRE-VALIDATION FAILED)" << std::endl;
            std::cerr << "  Block: " << pindexCheck->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  Height: " << pindexCheck->nHeight << std::endl;
            std::cerr << "  Aborting reorg - database may be corrupted" << std::endl;
            return false;
        }
    }

    // Validate all connect blocks exist in database (except the new tip which we already have)
    for (size_t i = 0; i < connectBlocks.size(); ++i) {
        CBlockIndex* pindexCheck = connectBlocks[i];

        // Skip the new tip - we already have its block data in 'block' parameter
        if (pindexCheck == pindexNew) {
            continue;
        }

        CBlock blockCheck;
        if (!pdb->ReadBlock(pindexCheck->GetBlockHash(), blockCheck)) {
            std::cerr << "[Chain] ERROR: Cannot load block for connect (PRE-VALIDATION FAILED)" << std::endl;
            std::cerr << "  Block: " << pindexCheck->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  Height: " << pindexCheck->nHeight << std::endl;
            std::cerr << "  Aborting reorg - missing block data" << std::endl;
            return false;
        }
    }

    std::cout << "[Chain] ✅ PRE-VALIDATION PASSED: All " << (disconnectBlocks.size() + connectBlocks.size())
              << " blocks can be loaded" << std::endl;

    // ============================================================================
    // P1-4 FIX: Write-Ahead Logging for Crash-Safe Reorganization
    // ============================================================================
    // Write intent to WAL BEFORE making any changes. If we crash during reorg,
    // the WAL will be detected on startup and -reindex will be required.

    // Build hash lists for WAL
    std::vector<uint256> disconnectHashes;
    for (const auto* pblockindex : disconnectBlocks) {
        disconnectHashes.push_back(pblockindex->GetBlockHash());
    }
    std::vector<uint256> connectHashes;
    for (const auto* pblockindex : connectBlocks) {
        connectHashes.push_back(pblockindex->GetBlockHash());
    }

    if (m_reorgWAL) {
        if (!m_reorgWAL->BeginReorg(pindexFork->GetBlockHash(),
                                     pindexTip->GetBlockHash(),
                                     pindexNew->GetBlockHash(),
                                     disconnectHashes,
                                     connectHashes)) {
            std::cerr << "[Chain] ERROR: Failed to write reorg WAL - aborting" << std::endl;
            return false;
        }
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - Atomic Reorg with Rollback
    // ============================================================================

    // Disconnect old chain

    // P1-4: Enter disconnect phase in WAL
    if (m_reorgWAL) {
        m_reorgWAL->EnterDisconnectPhase();
    }
    size_t disconnectedCount = 0;
    for (size_t i = 0; i < disconnectBlocks.size(); ++i) {
        CBlockIndex* pindexDisconnect = disconnectBlocks[i];
        std::cout << "  Disconnecting: " << pindexDisconnect->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexDisconnect->nHeight << ")" << std::endl;

        if (!DisconnectTip(pindexDisconnect)) {
            std::cerr << "[Chain] ERROR: Failed to disconnect block during reorg at height "
                      << pindexDisconnect->nHeight << std::endl;

            // ROLLBACK: Reconnect all blocks we already disconnected
            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlockIndex* pindexReconnect = disconnectBlocks[j];
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling for block read failures
                // Since we pre-validated all blocks exist, if ReadBlock fails here,
                // it indicates database corruption or disk failure.
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Failed at block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(pindexReconnect->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(pindexReconnect, reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        disconnectedCount++;

        // P1-4: Update disconnect progress in WAL
        if (m_reorgWAL) {
            m_reorgWAL->UpdateDisconnectProgress(static_cast<uint32_t>(disconnectedCount));
        }
    }

    // Connect new chain

    // P1-4: Enter connect phase in WAL
    if (m_reorgWAL) {
        m_reorgWAL->EnterConnectPhase();
    }
    size_t connectedCount = 0;
    for (size_t i = 0; i < connectBlocks.size(); ++i) {
        CBlockIndex* pindexConnect = connectBlocks[i];
        std::cout << "  Connecting: " << pindexConnect->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexConnect->nHeight << ")" << std::endl;

        // Load block data from database
        CBlock connectBlock;
        bool haveBlockData = false;

        if (pindexConnect == pindexNew) {
            // We have the full block data for the new tip
            connectBlock = block;
            haveBlockData = true;
        } else if (pdb != nullptr && pdb->ReadBlock(pindexConnect->GetBlockHash(), connectBlock)) {
            haveBlockData = true;
        }

        if (!haveBlockData) {
            std::cerr << "[Chain] ERROR: Cannot load block data for connect at height "
                      << pindexConnect->nHeight << std::endl;

            // ROLLBACK: Disconnect what we connected, reconnect what we disconnected
            std::cerr << "[Chain] ROLLBACK: Disconnecting " << connectedCount << " newly connected blocks..." << std::endl;
            for (int j = static_cast<int>(connectedCount) - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        if (!ConnectTip(pindexConnect, connectBlock)) {
            std::cerr << "[Chain] ERROR: Failed to connect block during reorg at height "
                      << pindexConnect->nHeight << std::endl;

            // ROLLBACK: Same as above
            std::cerr << "[Chain] ROLLBACK: Disconnecting " << connectedCount << " newly connected blocks..." << std::endl;
            for (int j = static_cast<int>(connectedCount) - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        connectedCount++;

        // P1-4: Update connect progress in WAL
        if (m_reorgWAL) {
            m_reorgWAL->UpdateConnectProgress(static_cast<uint32_t>(connectedCount));
        }
    }

    // Update tip
    pindexTip = pindexNew;
    // BUG #74 FIX: Update atomic cached height
    m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

    // Persist to database
    if (pdb != nullptr) {
        pdb->WriteBestBlock(pindexNew->GetBlockHash());
    }

    std::cout << "[Chain] ✅ REORGANIZATION COMPLETE" << std::endl;
    std::cout << "  New tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexTip->nHeight << ")" << std::endl;

    // P1-4: Reorg completed successfully - delete WAL
    if (m_reorgWAL) {
        m_reorgWAL->CompleteReorg();
    }

    // Bug #40 fix: Notify registered callbacks of tip update after reorg
    NotifyTipUpdate(pindexTip);

    reorgOccurred = true;
    return true;
}

bool CChainState::ConnectTip(CBlockIndex* pindex, const CBlock& block) {
    if (pindex == nullptr) {
        return false;
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - ConnectTip Implementation
    // ============================================================================

    // IBD OPTIMIZATION: Get cached hash once and reuse throughout
    const uint256& blockHash = pindex->GetBlockHash();

    // ============================================================================
    // FORK FIX: Validate MIK at connection time (not arrival time)
    // ============================================================================
    // MIK validation depends on the identity DB state. During fork recovery,
    // blocks may arrive before we have the correct identity DB state (our chain
    // is different from the fork chain). By validating at connection time:
    // 1. Identity DB reflects all blocks up to the parent (correct state)
    // 2. MIK can be validated against the correct identity registrations
    // 3. Fork blocks that passed PoW-only pre-validation get full MIK check here
    //
    // This allows fork recovery while maintaining MIK security:
    // - Fork pre-validation only checks PoW + hash match
    // - ConnectTip validates MIK when we have correct chain state
    {
        int dfmpActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpActivationHeight : 0;

        // Only validate MIK for post-DFMP blocks (skip genesis - it predates any mining identity)
        if (pindex->nHeight > 0 && pindex->nHeight >= dfmpActivationHeight) {
            if (!CheckProofOfWorkDFMP(block, blockHash, block.nBits, pindex->nHeight, dfmpActivationHeight)) {
                std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                          << " failed MIK validation at connection time" << std::endl;
                std::cerr << "[Chain] Hash: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

                // BUG #255: Mark block as permanently failed (authoritative validation)
                // This is ConnectTip with parent on active chain - failure is definitive.
                // Prevents infinite retry loops for invalid blocks.
                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                std::cerr << "[Chain] Block marked BLOCK_FAILED_VALID - will not retry" << std::endl;

                // Persist the failed status to disk so it survives restart
                if (pdb != nullptr) {
                    pdb->WriteBlockIndex(blockHash, *pindex);
                }

                return false;
            }
        }
    }

    // Step 1: Update UTXO set (CS-004)
    if (pUTXOSet != nullptr) {
        if (!pUTXOSet->ApplyBlock(block, pindex->nHeight, blockHash)) {
            std::cerr << "[Chain] ERROR: Failed to apply block to UTXO set at height "
                      << pindex->nHeight << std::endl;

            // BUG #255: Mark block as permanently failed (authoritative validation)
            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            std::cerr << "[Chain] Block marked BLOCK_FAILED_VALID - will not retry" << std::endl;

            // Persist the failed status to disk so it survives restart
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }

            return false;
        }
    }

    // Step 2: Update pnext pointer on parent
    if (pindex->pprev != nullptr) {
        pindex->pprev->pnext = pindex;
    }

    // Step 3: Mark block as connected
    pindex->nStatus |= CBlockIndex::BLOCK_VALID_CHAIN;

    // BUG #56 FIX: Notify block connect callbacks (wallet update)
    // NOTE: We don't hold cs_main during callbacks to prevent deadlock
    // The wallet has its own lock (cs_wallet)
    // IBD OPTIMIZATION: Pass cached hash to avoid RandomX recomputation
    for (size_t i = 0; i < m_blockConnectCallbacks.size(); ++i) {
        try {
            m_blockConnectCallbacks[i](block, pindex->nHeight, blockHash);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw unknown exception" << std::endl;
        }
    }

    // ========================================================================
    // BUG #109 FIX: Remove confirmed transactions from mempool
    // ========================================================================
    // CRITICAL: After UTXO set is updated, we must remove confirmed transactions
    // from mempool to prevent:
    // 1. UTXO/mempool inconsistency (inputs appearing unavailable)
    // 2. Transactions remaining in mempool after being confirmed
    // 3. Template building seeing stale transactions with unavailable inputs
    if (pMemPool != nullptr) {
        // Deserialize block transactions (block.vtx is raw bytes)
        CBlockValidator validator;
        std::vector<CTransactionRef> block_txs;
        std::string error;

        if (validator.DeserializeBlockTransactions(block, block_txs, error)) {
            size_t mempoolSizeBefore = pMemPool->Size();
            pMemPool->RemoveConfirmedTxs(block_txs);
            size_t mempoolSizeAfter = pMemPool->Size();

            if (mempoolSizeBefore != mempoolSizeAfter) {
                std::cout << "[Chain] BUG #109: Removed " << (mempoolSizeBefore - mempoolSizeAfter)
                          << " confirmed tx from mempool (height " << pindex->nHeight << ")" << std::endl;
            }
        } else {
            std::cerr << "[Chain] WARNING: Failed to deserialize block txs for mempool cleanup: " << error << std::endl;
        }
    }

    return true;
}

bool CChainState::DisconnectTip(CBlockIndex* pindex, bool force_skip_utxo) {
    if (pindex == nullptr) {
        return false;
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - DisconnectTip Implementation
    // RACE CONDITION FIX: Steps 1-5 must be done under cs_main lock
    // ============================================================================

    CBlock block;
    bool block_loaded = false;
    int disconnectHeight = 0;
    uint256 disconnectHash;

    // CRITICAL: Hold cs_main during chain state modifications
    {
        std::lock_guard<std::recursive_mutex> lock(cs_main);

        // Step 1: Load block data from database (needed for UTXO undo)
        if (pdb != nullptr) {
            if (pdb->ReadBlock(pindex->GetBlockHash(), block)) {
                block_loaded = true;
            } else if (!force_skip_utxo) {
                std::cerr << "[Chain] ERROR: Failed to load block from database for disconnect at height "
                          << pindex->nHeight << std::endl;
                return false;
            } else {
                std::cout << "[Chain] WARNING: Block data missing for disconnect at height "
                          << pindex->nHeight << " (force_skip_utxo=true)" << std::endl;
            }
        } else if (!force_skip_utxo) {
            std::cerr << "[Chain] ERROR: Cannot disconnect block without database access" << std::endl;
            return false;
        }

        // Step 2: Undo UTXO set changes (CS-004)
        // BUG #159 FIX: Allow skipping UTXO undo during IBD fork recovery when undo data is missing
        if (pUTXOSet != nullptr && block_loaded) {
            if (!pUTXOSet->UndoBlock(block)) {
                if (!force_skip_utxo) {
                    std::cerr << "[Chain] ERROR: Failed to undo block from UTXO set at height "
                              << pindex->nHeight << std::endl;
                    return false;
                } else {
                    std::cout << "[Chain] WARNING: Failed to undo UTXO at height "
                              << pindex->nHeight << " (force_skip_utxo=true, continuing anyway)" << std::endl;
                }
            }
        } else if (force_skip_utxo) {
            std::cout << "[Chain] Skipping UTXO undo for height " << pindex->nHeight
                      << " (force_skip_utxo=true)" << std::endl;
        }

        // Step 2.5: Undo identity DB changes (MIK registrations)
        // Only remove identities that were FIRST SEEN at this block height.
        // Identities introduced earlier remain valid on the remaining chain.
        if (block_loaded && DFMP::g_identityDb) {
            CBlockValidator validator;
            std::vector<CTransactionRef> txs;
            std::string err;
            if (validator.DeserializeBlockTransactions(block, txs, err) && !txs.empty()) {
                if (!txs[0]->vin.empty()) {
                    DFMP::CMIKScriptData mikData;
                    if (DFMP::ParseMIKFromScriptSig(txs[0]->vin[0].scriptSig, mikData)) {
                        DFMP::Identity identity = mikData.identity;
                        if (!identity.IsNull()) {
                            int firstSeen = DFMP::g_identityDb->GetFirstSeen(identity);
                            if (firstSeen == pindex->nHeight) {
                                // Identity was introduced at this height - safe to remove
                                if (DFMP::g_identityDb->RemoveMIKPubKey(identity)) {
                                    std::cout << "[Chain] Removed MIK identity (undo): "
                                              << identity.GetHex() << " (first-seen=" << firstSeen << ")" << std::endl;
                                }
                                DFMP::g_identityDb->RemoveFirstSeen(identity);
                            }
                            // If firstSeen != height, identity was introduced earlier - keep it
                        }
                    }
                }
            }
        }

        // Step 3: Clear pnext pointer on parent
        if (pindex->pprev != nullptr) {
            pindex->pprev->pnext = nullptr;
        }

        // Step 4: Clear own pnext pointer
        pindex->pnext = nullptr;

        // Step 5: Unmark block as on main chain
        pindex->nStatus &= ~CBlockIndex::BLOCK_VALID_CHAIN;

        // Cache values for callbacks (called outside lock)
        disconnectHeight = pindex->nHeight;
        disconnectHash = pindex->GetBlockHash();
    }
    // cs_main released here

    // BUG #56 FIX: Notify block disconnect callbacks (wallet update)
    // NOTE: We don't hold cs_main during callbacks to prevent deadlock
    // The wallet has its own lock (cs_wallet)
    for (size_t i = 0; i < m_blockDisconnectCallbacks.size(); ++i) {
        try {
            m_blockDisconnectCallbacks[i](block, disconnectHeight, disconnectHash);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Block disconnect callback " << i << " threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Chain] ERROR: Block disconnect callback " << i << " threw unknown exception" << std::endl;
        }
    }

    return true;
}

std::vector<uint256> CChainState::GetBlocksAtHeight(int height) const {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<uint256> result;

    for (const auto& pair : mapBlockIndex) {
        if (pair.second->nHeight == height) {
            result.push_back(pair.first);
        }
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

// Block explorer: Find all chain tips (blocks with no children)
std::vector<CChainState::ChainTip> CChainState::GetChainTips() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<ChainTip> tips;
    if (!pindexTip) return tips;

    // Build set of blocks that have children (i.e., are referenced as pprev)
    std::set<const CBlockIndex*> hasChildren;
    for (const auto& pair : mapBlockIndex) {
        if (pair.second->pprev) {
            hasChildren.insert(pair.second->pprev);
        }
    }

    // Any block NOT in hasChildren set is a tip
    for (const auto& pair : mapBlockIndex) {
        const CBlockIndex* pindex = pair.second.get();
        if (hasChildren.count(pindex) == 0) {
            ChainTip tip;
            tip.height = pindex->nHeight;
            tip.hash = pair.first;

            // Determine status and branch length
            if (pindex == pindexTip) {
                tip.status = "active";
                tip.branchlen = 0;
            } else {
                // Find fork point with main chain
                const CBlockIndex* pWalk = pindex;
                int branchlen = 0;
                // Walk back to find where this tip diverges from main chain
                // A block is on the main chain if walking from tip backwards reaches it
                while (pWalk && pWalk->nHeight > 0) {
                    // Check if this block is on the main chain by comparing with main chain at same height
                    bool onMainChain = false;
                    if (pWalk->nHeight <= pindexTip->nHeight) {
                        // Walk main chain to this height
                        const CBlockIndex* pMain = pindexTip;
                        while (pMain && pMain->nHeight > pWalk->nHeight) {
                            pMain = pMain->pprev;
                        }
                        if (pMain && pMain->GetBlockHash() == pWalk->GetBlockHash()) {
                            onMainChain = true;
                        }
                    }
                    if (onMainChain) break;
                    branchlen++;
                    pWalk = pWalk->pprev;
                }
                tip.branchlen = branchlen;
                tip.status = "valid-fork";
            }

            tips.push_back(tip);
        }
    }

    // Sort by height descending (active tip first)
    std::sort(tips.begin(), tips.end(), [](const ChainTip& a, const ChainTip& b) {
        if (a.status == "active") return true;
        if (b.status == "active") return false;
        return a.height > b.height;
    });

    return tips;
}

// RACE CONDITION FIX: Thread-safe chain snapshot for fork detection
std::vector<std::pair<int, uint256>> CChainState::GetChainSnapshot(int maxBlocks, int minHeight) const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<std::pair<int, uint256>> result;
    result.reserve(std::min(maxBlocks, pindexTip ? pindexTip->nHeight + 1 : 0));

    CBlockIndex* pindex = pindexTip;
    int count = 0;

    while (pindex && pindex->nHeight >= minHeight && count < maxBlocks) {
        result.push_back({pindex->nHeight, pindex->GetBlockHash()});
        pindex = pindex->pprev;
        count++;
    }

    return result;
}

// CRITICAL-1 FIX: Thread-safe accessor methods moved from inline to .cpp

CBlockIndex* CChainState::GetTip() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return pindexTip;
}

void CChainState::SetTip(CBlockIndex* pindex) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    
    // Consensus invariant: If tip is set, it must exist in mapBlockIndex
    if (pindex != nullptr) {
        uint256 tipHash = pindex->GetBlockHash();
        ConsensusInvariant(mapBlockIndex.count(tipHash) > 0);
        
        // Consensus invariant: Tip height must be >= 0
        ConsensusInvariant(pindex->nHeight >= 0);
    }
    
    pindexTip = pindex;
    // BUG #74 FIX: Update atomic cached height for lock-free reads
    m_cachedHeight.store(pindex ? pindex->nHeight : -1, std::memory_order_release);
    
    // Invariant: Cached height must match tip height
    if (pindex != nullptr) {
        Invariant(m_cachedHeight.load(std::memory_order_acquire) == pindex->nHeight);
    }
}

int CChainState::GetHeight() const {
    // BUG #74 FIX: Lock-free read of cached height
    // This prevents RPC calls from blocking on cs_main during block processing
    // The atomic is updated atomically whenever pindexTip changes
    return m_cachedHeight.load(std::memory_order_acquire);
}

uint256 CChainState::GetChainWork() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return pindexTip ? pindexTip->nChainWork : uint256();
}

// Bug #40 fix: Callback registration and notification

void CChainState::RegisterTipUpdateCallback(TipUpdateCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_tipCallbacks.push_back(callback);
}

void CChainState::NotifyTipUpdate(const CBlockIndex* pindex) {
    // NOTE: Caller must already hold cs_main lock
    // This is always called from within ActivateBestChain which holds the lock

    if (pindex == nullptr) {
        return;
    }

    // Execute all registered callbacks with exception handling
    for (size_t i = 0; i < m_tipCallbacks.size(); ++i) {
        try {
            m_tipCallbacks[i](pindex);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Tip callback " << i << " threw exception: " << e.what() << std::endl;
            // Continue executing other callbacks even if one fails
        } catch (...) {
            std::cerr << "[Chain] ERROR: Tip callback " << i << " threw unknown exception" << std::endl;
            // Continue executing other callbacks even if one fails
        }
    }
}

// BUG #56 FIX: Block connect/disconnect callback registration

void CChainState::RegisterBlockConnectCallback(BlockConnectCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_blockConnectCallbacks.push_back(callback);
}

void CChainState::RegisterBlockDisconnectCallback(BlockDisconnectCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_blockDisconnectCallbacks.push_back(callback);
}
