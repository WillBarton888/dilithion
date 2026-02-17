// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_processing.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <node/block_validation_queue.h>
#include <node/fork_manager.h>
#include <node/ibd_coordinator.h>
#include <node/utxo_set.h>
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/validation.h>
#include <consensus/tx_validation.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/banman.h>
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
    // PHASE 1.5: FORK BLOCK PRE-VALIDATION (Validate-Before-Disconnect)
    // If a fork is being validated, pre-validate blocks before normal processing.
    // Blocks still go through normal processing to create CBlockIndex entries,
    // but we skip ActivateBestChain until all fork blocks are ready.
    // =========================================================================
    bool isForkBlock = false;
    bool forkPreValidated = false;  // Track if fork block actually passed pre-validation
    int blockHeight = -1;  // Will be calculated if needed
    {
        ForkManager& forkMgr = ForkManager::GetInstance();

        if (forkMgr.HasActiveFork()) {
            // Calculate block height
            blockHeight = currentChainHeight + 1;
            CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pParent) {
                blockHeight = pParent->nHeight + 1;
            } else if (ctx.headers_manager) {
                int parentHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
                if (parentHeight >= 0) {
                    blockHeight = parentHeight + 1;
                }
            }

            auto fork = forkMgr.GetActiveFork();
            if (fork) {
                int32_t forkPoint = fork->GetForkPointHeight();
                int32_t forkTip = fork->GetExpectedTipHeight();

                // BUG #256 DEBUG: Log height calculation for fork block matching
                std::cout << "[ProcessNewBlock] Fork check: blockHeight=" << blockHeight
                          << " forkRange=[" << (forkPoint + 1) << "," << forkTip << "]"
                          << " hash=" << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

                // Check if this block belongs to the fork using hash verification
                // IsExpectedBlock checks both height range AND hash match (if expected hashes available)
                bool inForkRange = (blockHeight > forkPoint && blockHeight <= forkTip);
                if (fork->IsExpectedBlock(blockHash, blockHeight)) {
                    isForkBlock = true;

                    if (fork->HasExpectedHashes()) {
                        std::cout << "[ProcessNewBlock] Block VERIFIED as fork member (height "
                                  << blockHeight << ", hash matches expected)" << std::endl;
                    } else {
                        std::cout << "[ProcessNewBlock] Block in fork range (height "
                                  << blockHeight << " in " << (forkPoint + 1) << "-" << forkTip
                                  << ", no hash verification available)" << std::endl;
                    }

                    // Add block to fork tracking
                    forkMgr.AddBlockToFork(block, blockHash, blockHeight);

                    // Pre-validate this fork block (PoW + MIK) BEFORE normal processing
                    // MIK validation uses fork identity cache + main DB
                    ForkBlock* forkBlock = fork->GetBlockAtHeight(blockHeight);
                    if (forkBlock && forkBlock->status == ForkBlockStatus::PENDING) {
                        if (!forkMgr.PreValidateBlock(*forkBlock, db)) {
                            std::cerr << "[ProcessNewBlock] Fork block FAILED pre-validation: "
                                      << forkBlock->invalidReason << std::endl;

                            // Cancel the fork - invalid block detected!
                            int cancelForkPoint = fork->GetForkPointHeight();
                            forkMgr.CancelFork("Block failed pre-validation: " + forkBlock->invalidReason);
                            forkMgr.ClearInFlightState(ctx, cancelForkPoint);
                            g_node_context.fork_detected.store(false);
                            g_metrics.ClearForkDetected();

                            // Invalidate the header
                            if (ctx.headers_manager) {
                                ctx.headers_manager->InvalidateHeader(blockHash);
                            }

                            // FORK FIX: Do NOT ban peer on fork pre-validation failure
                            // Fork blocks may appear invalid due to our incorrect chain state.
                            // Banning prevents the peer from helping us recover.
                            // Just cancel the fork and let the node try again.
                            std::cout << "[ProcessNewBlock] Fork cancelled, NOT banning peer (fork recovery mode)" << std::endl;

                            return BlockProcessResult::INVALID_POW;
                        }
                        forkPreValidated = true;  // Track successful pre-validation
                        std::cout << "[ProcessNewBlock] Fork block pre-validated successfully (PoW + MIK)" << std::endl;
                    }
                } else if (inForkRange) {
                    // BUG #256 FIX: Block is in fork height range but hash doesn't match expected
                    // This could be:
                    // 1. A block from a DIFFERENT chain (e.g., valid chain from NYC)
                    // 2. Peer sent wrong block
                    // Log for debugging and try to validate it through normal path
                    uint256 expectedHash = fork->GetExpectedHashAtHeight(blockHeight);
                    std::cout << "[ProcessNewBlock] Block in fork range but HASH MISMATCH at height " << blockHeight
                              << "\n  Expected: " << expectedHash.GetHex().substr(0, 16) << "..."
                              << "\n  Got:      " << blockHash.GetHex().substr(0, 16) << "..."
                              << "\n  prevBlock: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;

                    // This block might be from the CORRECT chain (not the fork we're tracking)
                    // Don't invalidate - let it go through normal orphan handling
                    // If the fork we're tracking is wrong, we'll eventually time out and try the other chain
                }
            }
        }
    }
    // Note: Fork blocks continue through normal processing below to create CBlockIndex.
    // We will skip ActivateBestChain in Phase 7 if isForkBlock is true.

    // =========================================================================
    // PHASE 2: PROOF-OF-WORK VALIDATION (with DFMP enforcement)
    // =========================================================================
    // FORK FIX: Skip DFMP check for fork blocks that passed pre-validation
    // Fork blocks are MIK-validated during PreValidateBlock using the fork
    // identity cache. Only skip DFMP if pre-validation actually succeeded.
    // If pre-validation wasn't run (race condition), fall through to DFMP check.
    if (!skipPoWCheck && !forkPreValidated) {
        // Get block height for DFMP calculation
        // BUG FIX: Use headers_manager for correct height when blocks arrive out of order
        int blockHeight = currentChainHeight + 1;  // Default: next block
        std::string heightSource = "default";
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            blockHeight = pParent->nHeight + 1;
            heightSource = "pParent";
        } else if (ctx.headers_manager) {
            // Parent not in chain yet - get height from headers manager
            int parentHeight = ctx.headers_manager->GetHeightForHash(block.hashPrevBlock);
            if (parentHeight >= 0) {
                blockHeight = parentHeight + 1;
                heightSource = "headers_manager";
            }
        }

        // Debug: Show height derivation
        std::cout << "[ProcessNewBlock] DFMP height=" << blockHeight
                  << " (source=" << heightSource << ", chainHeight=" << currentChainHeight << ")" << std::endl;

        // BUG #246c/248 FIX: Skip DFMP validation when parent not connected
        // MIK validation requires registration blocks to be processed first.
        // If parent isn't in chainstate, we can't trust that the identity database
        // has all necessary MIK registrations. Defer MIK validation until the
        // parent connects and this block is reprocessed.
        // Basic PoW check still runs; full MIK validation happens on reconnect.
        //
        // CRITICAL: The old condition was:
        //   isOrphanBlock = (!pParent && blockHeight > currentChainHeight + 1)
        // This failed for blocks exactly 1 ahead (e.g., block 1001 when chain at 1000).
        // Those blocks would run MIK validation before their parent connected,
        // causing signature failure if the height was derived wrong or identity
        // wasn't registered yet.
        //
        // BUG #250 FIX: Only run DFMP when parent is on ACTIVE chain.
        // The identity DB only contains identities from the active chain (connect-only writes).
        // If parent exists but is on a competing chain, identity lookups will fail incorrectly.
        // Treat such blocks like orphans: basic PoW only, defer MIK until parent is on active chain.
        //
        // BLOCK_VALID_CHAIN is set in ConnectTip and cleared in DisconnectTip,
        // so it reliably indicates "block is part of current active chain."
        bool parentOnActiveChain = (pParent != nullptr) && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);
        bool shouldSkipDFMP = !parentOnActiveChain;

        // =========================================================================
        // CRITICAL FIX: Validate nBits matches expected difficulty
        // =========================================================================
        // Without this check, miners can use ANY difficulty (including genesis difficulty)
        // forever, bypassing the difficulty adjustment algorithm entirely.
        // This was causing blocks to be accepted with easy difficulty after block 2016.
        //
        // Only validate when parent is on active chain (we need full chain history
        // to calculate expected difficulty). For orphan blocks, nBits validation
        // is deferred until the parent connects (same as DFMP validation).
        if (parentOnActiveChain) {
            uint32_t expectedNBits = GetNextWorkRequired(pParent, static_cast<int64_t>(block.nTime));
            if (block.nBits != expectedNBits) {
                std::cerr << "[ProcessNewBlock] ERROR: Block has wrong difficulty" << std::endl;
                std::cerr << "  Block nBits:    0x" << std::hex << block.nBits << std::endl;
                std::cerr << "  Expected nBits: 0x" << expectedNBits << std::dec << std::endl;
                std::cerr << "  Parent height:  " << pParent->nHeight << std::endl;
                g_metrics.RecordInvalidBlock();
                return BlockProcessResult::INVALID_POW;
            }
        }

        if (shouldSkipDFMP) {
            // Parent missing OR parent on competing chain - do basic PoW check only (no MIK/DFMP)
            // VDF blocks skip hash-under-target check (proof validated in CheckVDFProof)
            if (!block.IsVDFBlock() && !CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[ProcessNewBlock] ERROR: Block has invalid basic PoW (parent not on active chain)" << std::endl;
                return BlockProcessResult::INVALID_POW;
            }
            if (pParent == nullptr) {
                std::cout << "[ProcessNewBlock] Orphan block at height " << blockHeight
                          << " (chainHeight=" << currentChainHeight << ") - deferring MIK validation until parent connects" << std::endl;
            } else {
                std::cout << "[ProcessNewBlock] Block at height " << blockHeight
                          << " has parent on competing chain - deferring MIK validation" << std::endl;
            }
            // Skip DFMP check - will run when block is reprocessed after parent is on active chain
        }

        // Get DFMP activation height
        int dfmpActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpActivationHeight : 0;

        // Use DFMP-aware PoW check (applies identity-based difficulty multipliers)
        // Skip when parent is not on active chain - MIK validation deferred
        if (!shouldSkipDFMP && !CheckProofOfWorkDFMP(block, blockHash, block.nBits, blockHeight, dfmpActivationHeight)) {
            std::cerr << "[ProcessNewBlock] ERROR: Block has invalid PoW (DFMP check failed)" << std::endl;
            std::cerr << "  Hash must be less than DFMP-adjusted target" << std::endl;
            g_metrics.RecordInvalidBlock();

            // Invalidate header to prevent re-requesting this block
            if (ctx.headers_manager) {
                ctx.headers_manager->InvalidateHeader(blockHash);
            }

            // BUG #250 FIX: Only reset headers if parent IS on active chain.
            // If parent is on active chain and MIK fails, block is truly invalid.
            // If parent is NOT on active chain, identity DB may not have the identity
            // (since we only write on connect) - don't invalidate headers for chain mismatch.
            if (parentOnActiveChain) {
                g_node_context.headers_chain_invalid.store(true);
                std::cout << "[ProcessNewBlock] Headers chain invalid (parent on active chain, MIK failed) - will resync from different peer" << std::endl;

                // BUG #255 FIX: Mark block as permanently failed (authoritative validation)
                // Parent is on active chain, so chain state is correct. DFMP failure is definitive.
                CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
                if (pindex) {
                    pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                    std::cerr << "[ProcessNewBlock] Block marked BLOCK_FAILED_VALID - will not retry" << std::endl;
                    // Persist to disk
                    if (ctx.blockchain_db) {
                        ctx.blockchain_db->WriteBlockIndex(blockHash, *pindex);
                    }
                }
            } else {
                std::cout << "[ProcessNewBlock] MIK validation failed but parent not on active chain at height " << blockHeight
                          << " (chainHeight=" << currentChainHeight << ") - NOT resetting headers (chain mismatch expected)" << std::endl;
            }

            // BUG #246 FIX: NO misbehavior for MIK failures.
            // MIK failures are almost always chain mismatch (peer on different fork),
            // not malicious behavior. Banning peers for being on a different chain
            // causes network partitioning and prevents fork resolution.
            // The block is already rejected - that's sufficient protection.
            // if (ctx.peer_manager && peer_id >= 0) {
            //     ctx.peer_manager->Misbehaving(peer_id, 20, MisbehaviorType::INVALID_BLOCK_POW);
            // }

            // BUG #246b FIX: Mark block as received even when validation fails.
            // Without this, failed blocks stay in-flight forever, causing
            // "all peers at capacity" stalls. We still reject the block, but
            // we clear it from tracking so new blocks can be requested.
            if (ctx.block_fetcher) {
                ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                ctx.block_fetcher->OnBlockReceived(peer_id, blockHeight);
            }

            return BlockProcessResult::INVALID_POW;
        }
    } else if (forkPreValidated) {
        std::cout << "[ProcessNewBlock] Fork block - skipping DFMP check (MIK validated in PreValidateBlock)" << std::endl;
    }

    // =========================================================================
    // PHASE 2.5: COINBASE TAX VALIDATION (MAINNET ONLY)
    // Validates that coinbase includes required Dev Fund & Dev Reward outputs
    // =========================================================================
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();
    if (!isTestnet && !skipPoWCheck) {
        // Get block height
        int blockHeight = currentChainHeight + 1;
        CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (pParent) {
            blockHeight = pParent->nHeight + 1;
        }

        // Deserialize transactions to get coinbase
        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string validationError;

        if (!validator.DeserializeBlockTransactions(block, transactions, validationError)) {
            std::cerr << "[ProcessNewBlock] ERROR: Failed to deserialize transactions for coinbase check: "
                      << validationError << std::endl;
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        if (transactions.empty()) {
            std::cerr << "[ProcessNewBlock] ERROR: Block has no transactions" << std::endl;
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }

        // BUG #260 FIX: Calculate transaction fees before validating coinbase
        // Previously passed fees=0, which rejected blocks with any transaction fees
        uint64_t totalFees = 0;
        CUTXOSet* utxoSet = g_utxo_set.load();

        if (utxoSet && transactions.size() > 1) {
            // Calculate fees from non-coinbase transactions
            CTransactionValidator txValidator;
            for (size_t i = 1; i < transactions.size(); i++) {
                CAmount txFee = 0;
                std::string txError;
                if (txValidator.CheckTransactionInputs(*transactions[i], *utxoSet, blockHeight, txFee, txError)) {
                    if (txFee > 0) {
                        totalFees += static_cast<uint64_t>(txFee);
                    }
                }
                // Note: Don't fail on individual tx validation here - CheckCoinbase just needs fee estimate
                // Full tx validation happens during block connect
            }
        }

        // CheckCoinbase validates:
        // - Coinbase value doesn't exceed subsidy + fees
        // - Required Dev Fund and Dev Reward outputs are present with correct amounts
        if (!validator.CheckCoinbase(*transactions[0], static_cast<uint32_t>(blockHeight), totalFees, validationError)) {
            std::cerr << "[ProcessNewBlock] ERROR: Coinbase validation failed: " << validationError << std::endl;
            if (ctx.peer_manager) {
                ctx.peer_manager->Misbehaving(peer_id, 100);  // Ban peer for invalid coinbase
            }
            g_metrics.RecordInvalidBlock();
            return BlockProcessResult::VALIDATION_ERROR;
        }
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

        // BUG #243 FIX: Ensure block data is saved to database before activation
        // HaveData() flag may be stale if block was deleted during fork recovery
        if (!db.BlockExists(blockHash)) {
            std::cout << "[ProcessNewBlock] Block not in database - saving before activation" << std::endl;
            if (!db.WriteBlock(blockHash, block)) {
                std::cerr << "[ProcessNewBlock] ERROR: Failed to save block to database" << std::endl;
                return BlockProcessResult::DB_ERROR;
            }
            std::cout << "[ProcessNewBlock] Block saved to database" << std::endl;
        }

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

                // Diagnostic: why can't we find the parent?
                std::cout << "[ProcessNewBlock] Block in DB but parent still missing"
                          << " prevBlock=" << block.hashPrevBlock.GetHex().substr(0, 16) << "..."
                          << " parentHeight=" << parent_height
                          << " chainTip=" << currentChainHeight << std::endl;
                // Check what hash we actually have at the expected parent height
                if (ctx.headers_manager && parent_height > 0) {
                    uint256 expected_parent = ctx.headers_manager->GetRandomXHashAtHeight(parent_height);
                    if (!expected_parent.IsNull() && expected_parent != block.hashPrevBlock) {
                        std::cout << "[ProcessNewBlock] FORK: prevBlock doesn't match header chain at height " << parent_height
                                  << " header=" << expected_parent.GetHex().substr(0, 16) << "..."
                                  << " block.prev=" << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
                // Notify IBD coordinator of orphan block for Layer 2 fork detection
                if (g_node_context.ibd_coordinator) {
                    g_node_context.ibd_coordinator->OnOrphanBlockReceived();
                }
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
                // Instead of requesting one block at a time (inefficient for deep forks),
                // request HEADERS to find common ancestor efficiently
                //
                // BUG #186 FIX: Only request headers if we're not already syncing.
                // During fork sync, every compact block triggers this code, but FAST PATH
                // is already requesting headers efficiently. Avoid redundant requests.
                //
                // BUG FIX: During IBD below checkpoints, orphan blocks with unknown
                // parents are EXPECTED (tip blocks arriving via compact relay while
                // we're catching up). Don't trigger fork detection below checkpoints.
                bool below_checkpoint = (currentChainHeight < checkpointHeight && blockHeight > checkpointHeight);
                if (below_checkpoint) {
                    // Normal IBD - parent unknown because we haven't synced past checkpoints yet
                } else if (ctx.headers_manager && !ctx.headers_manager->IsHeaderSyncInProgress()) {
                    std::cout << "[ProcessNewBlock] Competing fork detected (parent "
                              << block.hashPrevBlock.GetHex().substr(0, 16) << " unknown) - requesting headers" << std::endl;

                    // Use pure locator from our tip to find common ancestor
                    ctx.headers_manager->RequestHeaders(peer_id, uint256());  // null = use our tip's locator

                    // BUG #261 FIX: Only signal fork if node is synced
                    // During startup, blocks can arrive with "unknown" parents due to timing.
                    // This is normal startup behavior, not a real fork.
                    bool is_synced = g_node_context.ibd_coordinator &&
                                     g_node_context.ibd_coordinator->IsSynced();
                    if (is_synced) {
                        g_node_context.fork_detected.store(true);
                        g_metrics.SetForkDetected(true, 0, 0);
                    }
                } else {
                    // Header sync already in progress - skip redundant request
                    std::cout << "[ProcessNewBlock] Fork header sync already in progress - skipping redundant request" << std::endl;
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

        // Notify IBD coordinator of orphan block for Layer 2 fork detection
        if (g_node_context.ibd_coordinator) {
            g_node_context.ibd_coordinator->OnOrphanBlockReceived();
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
        // FORK BLOCK FIX: Never use async validation for fork blocks
        // Fork blocks must go through Phase 7 for proper staging/activation
        useAsyncValidation = (blocks_behind > 10) && !isForkBlock;
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

    // FORK BLOCK HANDLING: Skip normal ActivateBestChain for fork blocks
    // Fork blocks are staged and only activated via TriggerChainSwitch when all are ready
    if (isForkBlock) {
        ForkManager& forkMgr = ForkManager::GetInstance();
        auto fork = forkMgr.GetActiveFork();

        if (fork) {
            std::cout << "[ProcessNewBlock] Fork block stored with index, checking if ready to switch..." << std::endl;

            // ROBUST FIX: Switch when fork has more work, not when ALL blocks received
            // This prevents the race condition where fast blocks cause the fork to never complete
            bool allReceivedPrevalidated = fork->AllReceivedBlocksPrevalidated();
            int32_t highestPrevalidated = fork->GetHighestPrevalidatedHeight();

            // Get chainwork comparison - switch if fork has more work than current chain
            bool forkHasMoreWork = false;
            if (highestPrevalidated > 0) {
                // Get the block index for our highest prevalidated fork block
                ForkBlock* highestBlock = fork->GetBlockAtHeight(highestPrevalidated);
                if (highestBlock) {
                    CBlockIndex* forkIndex = g_chainstate.GetBlockIndex(highestBlock->hash);
                    CBlockIndex* currentTip = g_chainstate.GetTip();

                    if (forkIndex && currentTip) {
                        forkHasMoreWork = (currentTip->nChainWork < forkIndex->nChainWork);
                        std::cout << "[ProcessNewBlock] Chainwork comparison: fork="
                                  << forkIndex->nChainWork.GetHex().substr(0, 16) << " current="
                                  << currentTip->nChainWork.GetHex().substr(0, 16)
                                  << " forkHasMore=" << (forkHasMoreWork ? "yes" : "no") << std::endl;
                    }
                }
            }

            // Switch if: all received blocks are prevalidated AND fork has more chainwork
            if (allReceivedPrevalidated && forkHasMoreWork) {
                std::cout << "[ProcessNewBlock] Fork has more work and all received blocks prevalidated!" << std::endl;
                std::cout << "[ProcessNewBlock] Triggering early chain switch (height " << highestPrevalidated << ")..." << std::endl;

                // Trigger chain switch - this uses ActivateBestChain with the fork tip
                if (forkMgr.TriggerChainSwitch(ctx, db)) {
                    std::cout << "[ProcessNewBlock] Fork chain switch SUCCESSFUL!" << std::endl;
                    g_node_context.fork_detected.store(false);
                    g_metrics.ClearForkDetected();

                    // Mark block as received
                    if (ctx.block_fetcher) {
                        ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                        ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight);
                    }

                    auto handler_end = std::chrono::steady_clock::now();
                    auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
                    std::cout << "[ProcessNewBlock] EXIT (fork switch) total=" << handler_ms << "ms" << std::endl;
                    return BlockProcessResult::ACCEPTED;
                } else {
                    std::cerr << "[ProcessNewBlock] Fork chain switch FAILED!" << std::endl;
                    // Fork manager already cleared state
                    return BlockProcessResult::VALIDATION_ERROR;
                }
            } else {
                // Not ready to switch yet
                std::cout << "[ProcessNewBlock] Fork block staged, waiting for more work..."
                          << " (stats: " << fork->GetStats() << ")"
                          << " allPrevalidated=" << (allReceivedPrevalidated ? "yes" : "no")
                          << " forkHasMoreWork=" << (forkHasMoreWork ? "yes" : "no") << std::endl;

                // Mark block as received
                if (ctx.block_fetcher) {
                    ctx.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                    ctx.block_fetcher->OnBlockReceived(peer_id, pblockIndexPtr->nHeight);
                }

                auto handler_end = std::chrono::steady_clock::now();
                auto handler_ms = std::chrono::duration_cast<std::chrono::milliseconds>(handler_end - handler_start).count();
                std::cout << "[ProcessNewBlock] EXIT (fork staging) total=" << handler_ms << "ms" << std::endl;
                return BlockProcessResult::ACCEPTED_ASYNC;
            }
        }
    }

    // Normal block processing (non-fork blocks)
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

            // Clear stale fork detection when active chain advances normally
            if (g_node_context.fork_detected.load()) {
                g_node_context.fork_detected.store(false);
                g_metrics.ClearForkDetected();
            }

            // Phase 2.2: Mark this block as received if it was a pending parent request
            if (ctx.orphan_manager) {
                ctx.orphan_manager->MarkParentReceived(blockHash);
            }

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
