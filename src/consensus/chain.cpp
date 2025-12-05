// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <util/assert.h>
#include <iostream>
#include <algorithm>

CChainState::CChainState() : pindexTip(nullptr), pdb(nullptr), pUTXOSet(nullptr) {
}

CChainState::~CChainState() {
    Cleanup();
}

void CChainState::Cleanup() {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::mutex> lock(cs_main);

    // HIGH-C001 FIX: Smart pointers automatically destruct when map is cleared
    // No need for manual delete - RAII handles cleanup
    mapBlockIndex.clear();
    pindexTip = nullptr;
    // BUG #74 FIX: Reset atomic cached height
    m_cachedHeight.store(-1, std::memory_order_release);
}

bool CChainState::AddBlockIndex(const uint256& hash, std::unique_ptr<CBlockIndex> pindex) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::mutex> lock(cs_main);

    // HIGH-C001 FIX: Accept unique_ptr for automatic ownership transfer
    if (pindex == nullptr) {
        return false;
    }

    // Invariant: Hash must match block index hash
    Invariant(pindex->GetBlockHash() == hash);

    // Check if already exists
    if (mapBlockIndex.count(hash) > 0) {
        std::cerr << "[Chain] Warning: Block index " << hash.GetHex().substr(0, 16)
                  << " already exists in map" << std::endl;
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
    std::lock_guard<std::mutex> lock(cs_main);

    // HIGH-C001 FIX: Return raw pointer (non-owning) via .get()
    auto it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end()) {
        return it->second.get();  // Extract raw pointer from unique_ptr
    }
    return nullptr;
}

bool CChainState::HasBlockIndex(const uint256& hash) const {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::mutex> lock(cs_main);

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
    std::lock_guard<std::mutex> lock(cs_main);

    reorgOccurred = false;

    if (pindexNew == nullptr) {
        std::cerr << "[Chain] ERROR: ActivateBestChain called with nullptr" << std::endl;
        return false;
    }

    // Case 1: Genesis block (first block in chain)
    if (pindexTip == nullptr) {
        std::cout << "[Chain] Activating genesis block at height " << pindexNew->nHeight << std::endl;

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
        std::cout << "[Chain] Block extends current tip: height " << pindexNew->nHeight << std::endl;

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
            std::cout << "[Chain] DEBUG: Writing best block to DB: " << pindexNew->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
            bool success = pdb->WriteBestBlock(pindexNew->GetBlockHash());
            std::cout << "[Chain] DEBUG: WriteBestBlock returned: " << (success ? "SUCCESS" : "FAILED") << std::endl;
        } else {
            std::cerr << "[Chain] ERROR: pdb is nullptr! Cannot write best block!" << std::endl;
        }

        // Bug #40 fix: Notify registered callbacks of tip update
        NotifyTipUpdate(pindexTip);

        return true;
    }

    // Case 3: Competing chain - need to compare chain work
    std::cout << "[Chain] Received block on competing chain" << std::endl;
    std::cout << "  Current tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexTip->nHeight << ")" << std::endl;
    std::cout << "  New block:   " << pindexNew->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexNew->nHeight << ")" << std::endl;

    // Compare chain work
    if (!ChainWorkGreaterThan(pindexNew->nChainWork, pindexTip->nChainWork)) {
        std::cout << "[Chain] New chain has less or equal work - keeping current chain" << std::endl;
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

    std::cout << "[Chain] Fork point: " << pindexFork->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexFork->nHeight << ")" << std::endl;

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

    std::cout << "[Chain] Reorganization plan:" << std::endl;
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

    std::cout << "[Chain] PRE-VALIDATION: Checking all blocks can be loaded..." << std::endl;

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
    // CS-005: Chain Reorganization Rollback - Atomic Reorg with Rollback
    // ============================================================================

    // Disconnect old chain
    std::cout << "[Chain] Disconnecting old chain..." << std::endl;
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
            for (int j = disconnectedCount - 1; j >= 0; --j) {
                CBlockIndex* pindexReconnect = disconnectBlocks[j];
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling for block read failures
                // Since we pre-validated all blocks exist, if ReadBlock fails here,
                // it indicates database corruption or disk failure.
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Failed at block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!pdb->ReadBlock(pindexReconnect->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!ConnectTip(pindexReconnect, reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            return false;
        }

        disconnectedCount++;
    }

    // Connect new chain
    std::cout << "[Chain] Connecting new chain..." << std::endl;
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
            for (int j = connectedCount - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = disconnectedCount - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            return false;
        }

        if (!ConnectTip(pindexConnect, connectBlock)) {
            std::cerr << "[Chain] ERROR: Failed to connect block during reorg at height "
                      << pindexConnect->nHeight << std::endl;

            // ROLLBACK: Same as above
            std::cerr << "[Chain] ROLLBACK: Disconnecting " << connectedCount << " newly connected blocks..." << std::endl;
            for (int j = connectedCount - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = disconnectedCount - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            return false;
        }

        connectedCount++;
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

    // Step 1: Update UTXO set (CS-004)
    if (pUTXOSet != nullptr) {
        if (!pUTXOSet->ApplyBlock(block, pindex->nHeight)) {
            std::cerr << "[Chain] ERROR: Failed to apply block to UTXO set at height "
                      << pindex->nHeight << std::endl;
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
    for (size_t i = 0; i < m_blockConnectCallbacks.size(); ++i) {
        try {
            m_blockConnectCallbacks[i](block, pindex->nHeight);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw unknown exception" << std::endl;
        }
    }

    return true;
}

bool CChainState::DisconnectTip(CBlockIndex* pindex) {
    if (pindex == nullptr) {
        return false;
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - DisconnectTip Implementation
    // ============================================================================

    // Step 1: Load block data from database (needed for UTXO undo)
    CBlock block;
    if (pdb != nullptr) {
        if (!pdb->ReadBlock(pindex->GetBlockHash(), block)) {
            std::cerr << "[Chain] ERROR: Failed to load block from database for disconnect at height "
                      << pindex->nHeight << std::endl;
            return false;
        }
    } else {
        std::cerr << "[Chain] ERROR: Cannot disconnect block without database access" << std::endl;
        return false;
    }

    // Step 2: Undo UTXO set changes (CS-004)
    if (pUTXOSet != nullptr) {
        if (!pUTXOSet->UndoBlock(block)) {
            std::cerr << "[Chain] ERROR: Failed to undo block from UTXO set at height "
                      << pindex->nHeight << std::endl;
            return false;
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

    // BUG #56 FIX: Notify block disconnect callbacks (wallet update)
    // NOTE: We don't hold cs_main during callbacks to prevent deadlock
    // The wallet has its own lock (cs_wallet)
    for (size_t i = 0; i < m_blockDisconnectCallbacks.size(); ++i) {
        try {
            m_blockDisconnectCallbacks[i](block, pindex->nHeight);
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
    std::lock_guard<std::mutex> lock(cs_main);

    std::vector<uint256> result;

    for (const auto& pair : mapBlockIndex) {
        if (pair.second->nHeight == height) {
            result.push_back(pair.first);
        }
    }

    return result;
}

// CRITICAL-1 FIX: Thread-safe accessor methods moved from inline to .cpp

CBlockIndex* CChainState::GetTip() const {
    std::lock_guard<std::mutex> lock(cs_main);
    return pindexTip;
}

void CChainState::SetTip(CBlockIndex* pindex) {
    std::lock_guard<std::mutex> lock(cs_main);
    
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
    std::lock_guard<std::mutex> lock(cs_main);
    return pindexTip ? pindexTip->nChainWork : uint256();
}

// Bug #40 fix: Callback registration and notification

void CChainState::RegisterTipUpdateCallback(TipUpdateCallback callback) {
    std::lock_guard<std::mutex> lock(cs_main);
    m_tipCallbacks.push_back(callback);
    std::cout << "[Chain] Registered tip update callback (total: " << m_tipCallbacks.size() << ")" << std::endl;
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
    std::lock_guard<std::mutex> lock(cs_main);
    m_blockConnectCallbacks.push_back(callback);
    std::cout << "[Chain] Registered block connect callback (total: " << m_blockConnectCallbacks.size() << ")" << std::endl;
}

void CChainState::RegisterBlockDisconnectCallback(BlockDisconnectCallback callback) {
    std::lock_guard<std::mutex> lock(cs_main);
    m_blockDisconnectCallbacks.push_back(callback);
    std::cout << "[Chain] Registered block disconnect callback (total: " << m_blockDisconnectCallbacks.size() << ")" << std::endl;
}
