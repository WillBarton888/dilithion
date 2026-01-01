// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_processing.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <node/block_validation_queue.h>
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/validation.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/orphan_manager.h>
#include <net/headers_manager.h>
#include <net/async_broadcaster.h>
#include <net/net.h>
#include <net/protocol.h>
#include <net/connman.h>
#include <api/metrics.h>
#include <miner/controller.h>
#include <wallet/wallet.h>

#include <chrono>
#include <iostream>
#include <mutex>
#include <unordered_map>

// NodeState struct (defined in globals.cpp, duplicated here for extern declaration)
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};
    std::atomic<bool> mining_enabled{false};
    CMiningController* miner{nullptr};
    CWallet* wallet{nullptr};
};

// External globals (used throughout codebase, thread-safe via internal mutexes)
extern CChainState g_chainstate;
extern NodeState g_node_state;

// Chain tip update callback (set by main node at startup)
static ChainTipUpdateCallback g_chain_tip_callback = nullptr;

void SetChainTipUpdateCallback(ChainTipUpdateCallback callback) {
    g_chain_tip_callback = callback;
}


const char* BlockProcessResultToString(BlockProcessResult result) {
    switch (result) {
        case BlockProcessResult::ACCEPTED: return "ACCEPTED";
        case BlockProcessResult::ACCEPTED_ASYNC: return "ACCEPTED_ASYNC";
        case BlockProcessResult::ALREADY_HAVE: return "ALREADY_HAVE";
        case BlockProcessResult::INVALID_POW: return "INVALID_POW";
        case BlockProcessResult::ORPHAN: return "ORPHAN";
        case BlockProcessResult::DB_ERROR: return "DB_ERROR";
        case BlockProcessResult::CHAINSTATE_ERROR: return "CHAINSTATE_ERROR";
        case BlockProcessResult::VALIDATION_ERROR: return "VALIDATION_ERROR";
        default: return "UNKNOWN";
    }
}

BlockProcessResult ProcessNewBlock(
    NodeContext& ctx,
    CBlockchainDB& db,
    int peer_id,
    const CBlock& block,
    const uint256* precomputed_hash)
{
    std::cout << "[ProcessNewBlock] ENTRY peer=" << peer_id << std::endl;
    std::cout.flush();
    auto handler_start = std::chrono::steady_clock::now();

    // =========================================================================
    // PHASE 1: HASH COMPUTATION/LOOKUP
    // BUG #152 FIX: ALWAYS use canonical (RandomX) hash for block identity
    // =========================================================================
    int currentChainHeight = g_chainstate.GetHeight();
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    // Skip PoW validation (target check) for blocks below checkpoint
    bool skipPoWCheck = (checkpointHeight > 0 && currentChainHeight < checkpointHeight);

    uint256 blockHash;

    // Use precomputed hash if provided (e.g., from compact block reconstruction)
    if (precomputed_hash && !precomputed_hash->IsNull()) {
        blockHash = *precomputed_hash;
        std::cout << "[ProcessNewBlock] Using precomputed hash: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
    } else if (ctx.headers_manager) {
        // ALWAYS look up hash from headers first (both above and below checkpoint)
        int expectedHeight = -1;

        // 1a. Try chainstate for parent
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            expectedHeight = pParent->nHeight + 1;
        } else {
            // 1b. Try headers manager for parent height
            expectedHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
            if (expectedHeight >= 0) {
                expectedHeight += 1;  // Our height is parent + 1
            }
        }

        // 2. Look up our hash from headers manager
        if (expectedHeight > 0) {
            blockHash = ctx.headers_manager->GetRandomXHashAtHeight(expectedHeight);
            if (!blockHash.IsNull()) {
                std::cout << "[ProcessNewBlock] Hash from headers (height " << expectedHeight << "): "
                          << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
            }
        }
    }

    // Fallback: compute hash if not found in headers
    if (blockHash.IsNull()) {
        std::cout << "[ProcessNewBlock] Computing block hash (RandomX)..." << std::endl;
        std::cout.flush();
        auto hash_start = std::chrono::steady_clock::now();
        blockHash = block.GetHash();
        auto hash_end = std::chrono::steady_clock::now();
        auto hash_ms = std::chrono::duration_cast<std::chrono::milliseconds>(hash_end - hash_start).count();
        std::cout << "[ProcessNewBlock] Hash computed in " << hash_ms << "ms: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout.flush();
    }

    std::cout << "[ProcessNewBlock] Processing block: " << blockHash.GetHex().substr(0, 16) << "..."
              << " (chainHeight=" << currentChainHeight << ", checkpoint=" << checkpointHeight
              << ", skipPoWCheck=" << (skipPoWCheck ? "yes" : "no") << ")" << std::endl;

    // =========================================================================
    // PHASE 2: PROOF-OF-WORK VALIDATION
    // =========================================================================
    if (!skipPoWCheck && !CheckProofOfWork(blockHash, block.nBits)) {
        std::cerr << "[ProcessNewBlock] ERROR: Block has invalid PoW" << std::endl;
        std::cerr << "  Hash must be less than target" << std::endl;
        g_metrics.RecordInvalidBlock();
        return BlockProcessResult::INVALID_POW;
    }

    // =========================================================================
    // PHASE 3: DUPLICATE/EXISTING BLOCK CHECKS
    // BUG #114, #150 fixes
    // =========================================================================
    CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
    if (pindex && pindex->HaveData()) {
        // Check if block is actually on main chain (BLOCK_VALID_CHAIN flag)
        if (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) {
            std::cout << "[ProcessNewBlock] Block already in chain and connected, skipping"
                      << " height=" << pindex->nHeight << " hash=" << blockHash.GetHex().substr(0, 16)
                      << std::endl;
            // BUG #167 FIX: Use per-block tracking
            if (ctx.block_fetcher) {
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight);
            }
            return BlockProcessResult::ALREADY_HAVE;
        }

        // BUG #150 FIX: Block has data but is NOT connected - try to activate it
        std::cout << "[ProcessNewBlock] Block in chainstate but not connected, trying to activate"
                  << " height=" << pindex->nHeight << " hash=" << blockHash.GetHex().substr(0, 16)
                  << std::endl;

        bool reorgOccurred = false;
        if (g_chainstate.ActivateBestChain(pindex, block, reorgOccurred)) {
            std::cout << "[ProcessNewBlock] Successfully activated previously stuck block at height "
                      << pindex->nHeight << std::endl;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight);
            }
            return BlockProcessResult::ACCEPTED;
        } else {
            std::cerr << "[ProcessNewBlock] Failed to activate stuck block at height " << pindex->nHeight << std::endl;
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, pindex->nHeight);
            }
            return BlockProcessResult::VALIDATION_ERROR;
        }
    }

    // Check if we already have this block in database
    bool blockInDb = db.BlockExists(blockHash);
    if (blockInDb) {
        // BUG #86 FIX: Mark block as received even when skipping
        if (ctx.block_fetcher) {
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
        }

        // BUG #88 FIX: If block is in DB but NOT in chainstate, try to connect it
        if (!g_chainstate.HasBlockIndex(blockHash)) {
            CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pParent != nullptr) {
                std::cout << "[BUG88-FIX] Block in DB but not chainstate, parent now available - connecting" << std::endl;
                // Don't return - fall through to create block index and connect
            } else {
                // BUG #149 FIX: Check if parent is on a competing fork
                int parent_height = -1;
                if (ctx.headers_manager) {
                    parent_height = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                }

                if (parent_height <= 0 && ctx.connman && ctx.message_processor) {
                    // Parent is on a competing fork - request it directly
                    struct Uint256Hasher {
                        size_t operator()(const uint256& h) const {
                            return *reinterpret_cast<const size_t*>(h.data);
                        }
                    };
                    static std::unordered_map<uint256, std::chrono::steady_clock::time_point, Uint256Hasher> s_requested_parents;
                    static std::mutex s_requested_mutex;

                    std::lock_guard<std::mutex> lock(s_requested_mutex);
                    auto now = std::chrono::steady_clock::now();
                    auto it = s_requested_parents.find(block.hashPrevBlock);

                    // Only request if we haven't requested this parent in the last 30 seconds
                    if (it == s_requested_parents.end() ||
                        std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() > 30) {
                        s_requested_parents[block.hashPrevBlock] = now;

                        std::cout << "[ProcessNewBlock] Block in DB, parent on competing fork - requesting: "
                                  << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;

                        std::vector<NetProtocol::CInv> getdata_inv;
                        getdata_inv.emplace_back(NetProtocol::MSG_BLOCK_INV, block.hashPrevBlock);
                        CNetMessage getdata_msg = ctx.message_processor->CreateGetDataMessage(getdata_inv);
                        ctx.connman->PushMessage(peer_id, getdata_msg);
                    }
                }

                std::cout << "[ProcessNewBlock] Block in DB but parent still missing, skipping" << std::endl;
                return BlockProcessResult::ORPHAN;
            }
        } else {
            std::cout << "[ProcessNewBlock] Block already in chainstate, skipping" << std::endl;
            return BlockProcessResult::ALREADY_HAVE;
        }
    }

    // =========================================================================
    // PHASE 4: DATABASE PERSISTENCE
    // =========================================================================
    if (!blockInDb && !db.WriteBlock(blockHash, block)) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to save block to database" << std::endl;
        return BlockProcessResult::DB_ERROR;
    }
    if (!blockInDb) {
        std::cout << "[ProcessNewBlock] Block saved to database" << std::endl;
    }

    // =========================================================================
    // PHASE 5: BLOCK INDEX CREATION / ORPHAN HANDLING
    // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
    // =========================================================================
    auto pblockIndex = std::make_unique<CBlockIndex>(block);
    pblockIndex->phashBlock = blockHash;
    pblockIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;

    // Link to parent block
    pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
    if (pblockIndex->pprev == nullptr) {
        // BUG #12 FIX (Phase 4.3): Orphan block handling
        std::cout << "[ProcessNewBlock] Parent block not found: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "[ProcessNewBlock] Storing block as orphan and requesting parent" << std::endl;

        // CRITICAL-3 FIX: Validate orphan block before storing
        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string validationError;

        // Deserialize and verify merkle root
        if (!validator.DeserializeBlockTransactions(block, transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Failed to deserialize orphan block transactions" << std::endl;
            std::cerr << "  Error: " << validationError << std::endl;
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        if (!validator.VerifyMerkleRoot(block, transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block has invalid merkle root" << std::endl;
            std::cerr << "  Error: " << validationError << std::endl;
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Check for duplicate transactions
        if (!validator.CheckNoDuplicateTransactions(transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block contains duplicate transactions" << std::endl;
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Check for double-spends within block
        if (!validator.CheckNoDoubleSpends(transactions, validationError)) {
            std::cerr << "[Orphan] ERROR: Orphan block contains double-spend" << std::endl;
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100);
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // Add block to orphan manager (now validated)
        if (ctx.orphan_manager->AddOrphanBlock(peer_id, block)) {
            // SSOT FIX: Free CBlockTracker entry by HEIGHT
            if (ctx.block_fetcher && ctx.headers_manager) {
                int orphan_height = ctx.headers_manager->GetHeightForHash(blockHash);
                if (orphan_height > 0) {
                    ctx.block_fetcher->OnBlockReceived(peer_id, orphan_height);
                }
            }

            // IBD OPTIMIZATION: Check if parent is already in-flight
            bool parent_in_flight = false;
            int parent_height = -1;
            if (ctx.headers_manager && ctx.block_tracker) {
                parent_height = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                if (parent_height > 0) {
                    parent_in_flight = ctx.block_tracker->IsTracked(parent_height);
                }
            }

            if (parent_in_flight) {
                std::cout << "[ProcessNewBlock] Orphan block stored - parent height " << parent_height
                          << " already in-flight" << std::endl;
            } else if (parent_height <= 0) {
                // BUG #149 FIX: Parent is not in our header chain (competing fork)
                uint256 orphan_root = ctx.orphan_manager->GetOrphanRoot(blockHash);
                CBlock orphan_block;
                if (ctx.orphan_manager->GetOrphanBlock(orphan_root, orphan_block)) {
                    uint256 missing_parent = orphan_block.hashPrevBlock;
                    std::cout << "[ProcessNewBlock] Orphan on competing fork - requesting parent block: "
                              << missing_parent.GetHex().substr(0, 16) << "..." << std::endl;

                    std::vector<NetProtocol::CInv> getdata_inv;
                    getdata_inv.emplace_back(NetProtocol::MSG_BLOCK_INV, missing_parent);
                    CNetMessage getdata_msg = ctx.message_processor->CreateGetDataMessage(getdata_inv);
                    ctx.connman->PushMessage(peer_id, getdata_msg);
                }
            } else {
                std::cout << "[ProcessNewBlock] Orphan block stored - IBD coordinator will handle block request" << std::endl;
            }
        } else {
            std::cerr << "[Orphan] ERROR: Failed to add block to orphan pool" << std::endl;
        }

        // BUG #148 FIX: Mark block as received even when storing as orphan
        if (ctx.block_fetcher) {
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
        }

        return BlockProcessResult::ORPHAN;
    }

    // Calculate height and chain work
    pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
    pblockIndex->BuildChainWork();

    std::cout << "[ProcessNewBlock] Block index created (height " << pblockIndex->nHeight << ")" << std::endl;

    // Save block index to database
    if (!db.WriteBlockIndex(blockHash, *pblockIndex)) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to save block index" << std::endl;
        return BlockProcessResult::DB_ERROR;
    }

    // Add to chain state memory map (transfer ownership with std::move)
    if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to add block to chain state" << std::endl;
        return BlockProcessResult::CHAINSTATE_ERROR;
    }

    // HIGH-C001 FIX: After move, retrieve pointer from chain state
    CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
    if (pblockIndexPtr == nullptr) {
        std::cerr << "[ProcessNewBlock] CRITICAL ERROR: Block index not found after adding!" << std::endl;
        return BlockProcessResult::CHAINSTATE_ERROR;
    }

    // =========================================================================
    // PHASE 6: VALIDATION ROUTING (ASYNC VS SYNC)
    // =========================================================================
    bool useAsyncValidation = false;
    if (ctx.validation_queue && ctx.validation_queue->IsRunning()) {
        int header_height = ctx.headers_manager ?
            ctx.headers_manager->GetBestHeight() : currentChainHeight;
        int blocks_behind = header_height - currentChainHeight;

        // Use async validation if we're more than 10 blocks behind (active IBD)
        useAsyncValidation = (blocks_behind > 10);
    }

    if (useAsyncValidation) {
        // Queue for async validation - returns immediately
        int expected_height = pblockIndexPtr->nHeight;
        if (ctx.validation_queue->QueueBlock(peer_id, block, expected_height, blockHash, pblockIndexPtr)) {
            std::cout << "[ProcessNewBlock] Block queued for async validation (height " << expected_height
                      << ", queue depth: " << ctx.validation_queue->GetQueueDepth() << ")" << std::endl;
            // IBD HANG FIX: Mark block as received IMMEDIATELY
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
            ctx.block_fetcher->OnBlockReceived(peer_id, expected_height);
            auto handler_end = std::chrono::steady_clock::now();
            auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
            std::cout << "[ProcessNewBlock] EXIT (async) total=" << handler_ms << "ms" << std::endl;
            return BlockProcessResult::ACCEPTED_ASYNC;
        } else {
            std::cerr << "[ProcessNewBlock] WARNING: Failed to queue block for async validation, falling back to sync" << std::endl;
            // Fall through to synchronous validation
        }
    }

    // =========================================================================
    // PHASE 7: SYNCHRONOUS BLOCK ACTIVATION + MINING UPDATE + RELAY
    // =========================================================================
    std::cout << "[ProcessNewBlock] Calling ActivateBestChain synchronously..." << std::endl;
    std::cout.flush();
    auto activate_start = std::chrono::steady_clock::now();
    bool reorgOccurred = false;
    if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
        auto activate_end = std::chrono::steady_clock::now();
        auto activate_ms = std::chrono::duration_cast<std::chrono::milliseconds>(activate_end - activate_start).count();
        std::cout << "[ProcessNewBlock] ActivateBestChain succeeded in " << activate_ms << "ms" << std::endl;

        if (reorgOccurred) {
            std::cout << "[ProcessNewBlock] CHAIN REORGANIZATION occurred!" << std::endl;
            std::cout << "  New tip: " << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                      << " (height " << g_chainstate.GetHeight() << ")" << std::endl;
            g_metrics.RecordReorg();

            g_node_state.new_block_found = true;

            // BUG #32 FIX: Notify callback to update mining template when reorg occurs
            if (g_chain_tip_callback) {
                g_chain_tip_callback(db, g_chainstate.GetHeight(), true /* is_reorg */);
            }
        } else {
            std::cout << "[ProcessNewBlock] Block activated successfully" << std::endl;
            g_metrics.blocks_accepted_total++;

            // Check if this became the new tip
            if (g_chainstate.GetTip() == pblockIndexPtr) {
                std::cout << "[ProcessNewBlock] Updated best block to height " << pblockIndexPtr->nHeight << std::endl;
                g_node_state.new_block_found = true;

                // BUG #32 FIX: Notify callback to update mining template
                if (g_chain_tip_callback) {
                    g_chain_tip_callback(db, pblockIndexPtr->nHeight, false /* is_reorg */);
                }

                // BUG #43 FIX: Relay received blocks to other peers (Bitcoin Core standard)
                if (ctx.peer_manager && ctx.async_broadcaster) {
                    auto connected_peers = ctx.peer_manager->GetConnectedPeers();
                    std::vector<int> relay_peer_ids;

                    for (const auto& peer : connected_peers) {
                        if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
                            relay_peer_ids.push_back(peer->id);
                        }
                    }

                    if (!relay_peer_ids.empty()) {
                        if (ctx.async_broadcaster->BroadcastBlock(blockHash, block, relay_peer_ids)) {
                            std::cout << "[ProcessNewBlock] Relaying block to " << relay_peer_ids.size()
                                      << " peer(s) (excluding sender peer " << peer_id << ")" << std::endl;
                        } else {
                            std::cerr << "[ProcessNewBlock] ERROR: Failed to queue block relay" << std::endl;
                        }
                    }
                }
            } else {
                std::cout << "[ProcessNewBlock] Block is valid but not on best chain" << std::endl;
            }
        }

        // FORK REORG FIX: Process orphan children after successful block activation
        // When a block validates successfully, check if any orphans were waiting for it as their parent
        // This mirrors the logic in block_validation_queue.cpp for the async path
        // Without this, nodes fail to reorganize to longer chains (blocks marked ORPHAN instead of connecting)
        if (ctx.orphan_manager) {
            std::vector<uint256> orphanChildren = ctx.orphan_manager->GetOrphanChildren(blockHash);
            if (!orphanChildren.empty()) {
                std::cout << "[ProcessNewBlock] Found " << orphanChildren.size()
                          << " orphan children waiting for block " << blockHash.GetHex().substr(0, 16)
                          << "... at height " << pblockIndexPtr->nHeight << std::endl;

                // Process orphan children by recursively calling ProcessNewBlock
                for (const uint256& orphanHash : orphanChildren) {
                    CBlock orphanBlock;
                    if (ctx.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                        // Erase from orphan pool BEFORE processing to avoid re-entry
                        ctx.orphan_manager->EraseOrphanBlock(orphanHash);

                        // Recursively process the orphan block
                        uint256 orphanBlockHash = orphanBlock.GetHash();
                        std::cout << "[ProcessNewBlock] Processing orphan child "
                                  << orphanBlockHash.GetHex().substr(0, 16) << "..." << std::endl;

                        BlockProcessResult orphan_result = ProcessNewBlock(ctx, db, -1, orphanBlock, &orphanBlockHash);
                        std::cout << "[ProcessNewBlock] Orphan child result: "
                                  << BlockProcessResultToString(orphan_result) << std::endl;
                    }
                }
            }
        }

        // Notify BlockFetcher
        if (ctx.block_fetcher) {
            ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
            ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight);
        }

        return BlockProcessResult::ACCEPTED;
    } else {
        std::cerr << "[ProcessNewBlock] ERROR: Failed to activate block in chain" << std::endl;
        return BlockProcessResult::VALIDATION_ERROR;
    }
}
