// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/headers_manager.h>
#include <net/net.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <net/peers.h>
#include <consensus/params.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <util/time.h>
#include <util/logging.h>  // For g_verbose flag
#include <node/genesis.h>
#include <node/ibd_coordinator.h>  // Phase 1: IsSynced() check
#include <core/node_context.h>
#include <core/chainparams.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>

// BUG #150 FIX: Access to validated chainstate for fork-safe locator building
extern CChainState g_chainstate;

CHeadersManager::CHeadersManager()
    : nBestHeight(-1)
{
    hashBestHeader = uint256();

    // Bug #46 Fix: Initialize minimum chain work to zero (accept all chains initially)
    // Production networks should set this to a reasonable threshold to prevent DoS
    nMinimumChainWork = uint256();
}

// ============================================================================
// Public API: Header Processing
// ============================================================================

bool CHeadersManager::ProcessHeaders(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    std::cout << "[HeadersManager] ProcessHeaders called: peer=" << peer
              << ", count=" << headers.size() << std::endl;

    // DEADLOCK FIX: Get chainstate tip BEFORE acquiring cs_headers
    // This is needed because GetLocatorImpl may be called while holding cs_headers,
    // and we must avoid calling GetTip() (which needs cs_main) while holding cs_headers.
    CBlockIndex* pTipPreFetched = g_chainstate.GetTip();
    int chainstateHeightPreFetched = (pTipPreFetched && pTipPreFetched->nHeight > 0) ? pTipPreFetched->nHeight : 0;

    std::lock_guard<std::mutex> lock(cs_headers);
    std::cout << "[HeadersManager] Lock acquired" << std::endl;

    if (headers.empty()) {
        std::cout << "[HeadersManager] Empty headers, returning true" << std::endl;
        return true;  // Empty is valid (no new headers)
    }

    if (headers.size() > MAX_HEADERS_BUFFER) {
        std::cout << "[HeadersManager] Too many headers (" << headers.size()
                  << " > " << MAX_HEADERS_BUFFER << "), returning false" << std::endl;
        return false;
    }

    std::cout << "[HeadersManager] Processing " << headers.size() << " headers" << std::endl;

    // COMMON ANCESTOR OPTIMIZATION: Find where incoming chain diverges from ours.
    // Headers below the common ancestor are identical on both chains - skip hash computation.
    // Only compute expensive RandomX hashes for headers ABOVE the divergence point.
    int commonAncestorHeight = -1;
    const HeaderWithChainWork* commonAncestor = nullptr;

    // Check first header's parent to find common ancestor
    if (!headers.empty()) {
        const uint256& firstParent = headers[0].hashPrevBlock;
        auto parentIt = mapHeaders.find(firstParent);
        if (parentIt != mapHeaders.end()) {
            commonAncestorHeight = parentIt->second.height;
            commonAncestor = &parentIt->second;
            std::cout << "[HeadersManager] Common ancestor found at height " << commonAncestorHeight
                      << " - will skip hash computation for heights <= " << commonAncestorHeight << std::endl;
        }
    }

    // Process each header sequentially
    const HeaderWithChainWork* pprev = commonAncestor;  // Start from common ancestor if found
    uint256 prevHash;  // Track previous header's hash for sequential iteration
    int heightStart = commonAncestorHeight;

    // Get checkpoint height once
    int highestCheckpoint = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    for (size_t i = 0; i < headers.size(); i++) {
        const CBlockHeader& header = headers[i];

        // Calculate expected height
        int expectedHeight = pprev ? (pprev->height + 1) : 1;

        auto heightIt = mapHeightIndex.find(expectedHeight);
        bool heightHasHeaders = (heightIt != mapHeightIndex.end() && !heightIt->second.empty());

        // FAST PATH 1: Below checkpoint, if height exists, skip entirely (no hash computation)
        // Checkpoints are hardcoded guarantees of the canonical chain
        if (expectedHeight <= highestCheckpoint && heightHasHeaders) {
            uint256 existingHash = *heightIt->second.begin();
            auto existingIt = mapHeaders.find(existingHash);
            if (existingIt != mapHeaders.end()) {
                pprev = &existingIt->second;
                prevHash = existingHash;
                heightStart = existingIt->second.height;
                UpdateBestHeader(existingHash);
                continue;  // Skip without computing hash
            }
        }

        // FAST PATH 2: Below common ancestor height, headers are identical on both chains
        // Skip hash computation - use our existing headers instead
        if (commonAncestorHeight > 0 && expectedHeight <= commonAncestorHeight && heightHasHeaders) {
            uint256 existingHash = *heightIt->second.begin();
            auto existingIt = mapHeaders.find(existingHash);
            if (existingIt != mapHeaders.end()) {
                pprev = &existingIt->second;
                prevHash = existingHash;
                heightStart = existingIt->second.height;
                // Don't update best header - just traversing common history
                continue;  // Skip without computing hash
            }
        }

        // SLOW PATH: Above common ancestor - compute hash for fork detection and work comparison
        uint256 storageHash = header.GetHash();

        // Skip TRUE duplicates (same hash already exists)
        if (mapHeaders.find(storageHash) != mapHeaders.end()) {
            auto it = mapHeaders.find(storageHash);
            pprev = &it->second;
            prevHash = storageHash;
            heightStart = it->second.height;
            UpdateBestHeader(storageHash);
            continue;
        }

        // FORK DETECTION: Only relevant above checkpoint
        if (heightHasHeaders && expectedHeight > highestCheckpoint) {
            std::cout << "[HeadersManager] Fork header received at height " << expectedHeight
                      << " - processing competing chain" << std::endl;
        }

        // SIMPLIFIED PARENT LOOKUP: With RandomX-only storage, hashPrevBlock directly
        // references the parent's storage hash (no mapping needed)

        // Check if parent is genesis block
        uint256 genesisHash = Genesis::GetGenesisHash();
        if (header.hashPrevBlock == genesisHash || header.hashPrevBlock.IsNull()) {
            if (i == 0) {
                std::cout << "[HeadersManager] Parent is genesis block" << std::endl;
            }
            pprev = nullptr;
        }
        // Direct parent lookup (hashPrevBlock = parent's RandomX hash = parent's storage hash)
        else {
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            if (parentIt != mapHeaders.end()) {
                pprev = &parentIt->second;
            } else {
                // FORK DETECTED: Parent not found - this is a competing chain
                // Check if we already requested this parent (avoid duplicate requests)
                if (m_pendingParentRequests.find(header.hashPrevBlock) == m_pendingParentRequests.end()) {
                    std::cout << "[HeadersManager] FORK: Parent " << header.hashPrevBlock.GetHex().substr(0, 16)
                              << " unknown - requesting headers from common ancestor (peer=" << peer << ")" << std::endl;

                    // Track missing parent and request ancestors immediately
                    m_pendingParentRequests.insert(header.hashPrevBlock);

                    // DEADLOCK FIX: Use GetLocatorImpl directly since we already hold cs_headers.
                    // Calling RequestHeaders() would call GetLocator() which tries to relock cs_headers,
                    // causing a deadlock (std::mutex is not recursive).
                    // Pass pre-fetched tip to avoid cs_main/cs_headers lock inversion.
                    std::vector<uint256> locator = GetLocatorImpl(uint256(), pTipPreFetched, chainstateHeightPreFetched);

                    // Send GETHEADERS message directly
                    auto* connman = g_node_context.connman.get();
                    auto* msg_proc = g_message_processor.load();
                    if (connman && msg_proc) {
                        NetProtocol::CGetHeadersMessage msg(locator, uint256());
                        CNetMessage getheaders = msg_proc->CreateGetHeadersMessage(msg);
                        connman->PushMessage(peer, getheaders);
                        std::cout << "[HeadersManager] FORK: Sent GETHEADERS to peer " << peer << std::endl;
                    }

                    // Signal fork detected for mining pause
                    g_node_context.fork_detected.store(true);
                }

                // Continue - remaining headers will also fail to connect, that's expected
                continue;
            }
        }

        // Validate header
        if (!ValidateHeader(header, pprev ? &pprev->header : nullptr)) {
            return false;
        }

        // Calculate height and chain work
        int height = pprev ? (pprev->height + 1) : 1;
        uint256 chainWork = CalculateChainWork(header, pprev);

        // Store header
        HeaderWithChainWork headerData(header, height);
        headerData.chainWork = chainWork;
        mapHeaders[storageHash] = headerData;
        AddToHeightIndex(storageHash, height);

        // DEBUG: Log storage details near height 5547
        if (height >= 5545 && height <= 5550) {
            std::cerr << "[DEBUG-STORE] height=" << height
                      << " storageHash=" << storageHash.GetHex().substr(0, 16) << "..."
                      << " hashPrevBlock=" << header.hashPrevBlock.GetHex().substr(0, 16) << "..."
                      << std::endl;
        }
        UpdateChainTips(storageHash);
        UpdateBestHeader(storageHash);

        // FORK RESOLUTION: Check if this header was a pending parent
        // If so, the fork is resolving - clear from pending and check if fully resolved
        if (m_pendingParentRequests.erase(storageHash) > 0) {
            std::cout << "[HeadersManager] Pending parent " << storageHash.GetHex().substr(0, 16)
                      << " arrived at height " << height << " - fork resolving" << std::endl;

            // If no more pending parents, fork is fully resolved
            if (m_pendingParentRequests.empty()) {
                std::cout << "[HeadersManager] Fork resolved - all ancestors received, mining can resume" << std::endl;
                g_node_context.fork_detected.store(false);
            }
        }

        // Update for next iteration
        pprev = &mapHeaders[storageHash];
        prevHash = storageHash;

        if (heightStart < 0) {
            heightStart = height;
        }
    }

    // Update peer state
    if (!headers.empty() && !prevHash.IsNull()) {
        auto it = mapHeaders.find(prevHash);
        if (it != mapHeaders.end()) {
            UpdatePeerState(peer, prevHash, it->second.height);
        }
    }

    // IBD DEBUG: Log summary after processing headers
    std::cout << "[HeadersManager] ProcessHeaders complete: peer=" << peer
              << " processed=" << headers.size()
              << " nBestHeight=" << nBestHeight
              << " mapHeaders.size=" << mapHeaders.size()
              << " mapHeightIndex.size=" << mapHeightIndex.size() << std::endl;

    // Bug #150: Trigger periodic orphan pruning
    m_headers_since_last_prune += headers.size();
    if (m_headers_since_last_prune >= PRUNE_BATCH_SIZE) {
        // Note: PruneOrphanedHeaders acquires its own lock, so we must release first
        // We can't call it here while holding cs_headers. Instead, we set a flag
        // and the caller can check if pruning is needed.
        // For now, just reset the counter - pruning will be triggered by external call
        m_headers_since_last_prune = 0;
    }

    return true;
}

// ============================================================================
// DoS-Protected Header Sync (Bitcoin Core two-phase)
// ============================================================================

bool CHeadersManager::ProcessHeadersWithDoSProtection(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    // Check if peer has active HeadersSyncState
    auto it = mapHeadersSyncStates.find(peer);
    if (it == mapHeadersSyncStates.end()) {
        return ProcessHeaders(peer, headers);
    }

    HeadersSyncState* sync_state = it->second.get();
    if (!sync_state || sync_state->GetState() == HeadersSyncState::State::FINAL) {
        mapHeadersSyncStates.erase(peer);
        return ProcessHeaders(peer, headers);
    }


    // Process through HeadersSyncState
    auto result = sync_state->ProcessNextHeaders(headers, true);

    if (!result.success) {
        mapHeadersSyncStates.erase(peer);
        return false;
    }

    // If we got validated headers back, store them
    if (!result.pow_validated_headers.empty()) {

        // Store validated headers using existing logic (but without re-validation)
        std::lock_guard<std::mutex> lock(cs_headers);
        for (const auto& header : result.pow_validated_headers) {
            uint256 hash = header.GetHash();

            // Skip if already stored
            if (mapHeaders.find(hash) != mapHeaders.end()) {
                continue;
            }

            // Find parent
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            const HeaderWithChainWork* pprev = nullptr;
            int height = 1;

            if (parentIt != mapHeaders.end()) {
                pprev = &parentIt->second;
                height = pprev->height + 1;
            }

            // Calculate chain work and store
            uint256 chainWork = CalculateChainWork(header, pprev);
            HeaderWithChainWork headerData(header, height);
            headerData.chainWork = chainWork;

            mapHeaders[hash] = headerData;
            AddToHeightIndex(hash, height);
            UpdateChainTips(hash);
            UpdateBestHeader(hash);
        }

    }

    // Check if sync is complete
    if (sync_state->GetState() == HeadersSyncState::State::FINAL) {
        mapHeadersSyncStates.erase(peer);
    }

    return true;
}

bool CHeadersManager::ShouldUseDoSProtection(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Check if peer already has active HeadersSyncState
    if (mapHeadersSyncStates.find(peer) != mapHeadersSyncStates.end()) {
        return true;
    }

    // Bug #150: Lower threshold for DoS protection activation
    // If peer claims significantly more headers, use protected sync
    auto heightIt = mapPeerStartHeight.find(peer);
    if (heightIt != mapPeerStartHeight.end()) {
        int peerHeight = heightIt->second;
        // Bug #150: Reduced from 2000 to 500 blocks for earlier protection
        if (peerHeight > nBestHeight + 500) {
            std::cout << "[HeadersManager] DoS protection activated for peer " << peer
                      << " (claims height " << peerHeight << " vs our " << nBestHeight << ")" << std::endl;
            return true;
        }
    }

    // Bug #150: Also activate if we have competing forks
    // This helps protect against fork flooding attacks
    if (m_chainTipsTracker.HasCompetingForks()) {
        std::cout << "[HeadersManager] DoS protection activated due to competing forks ("
                  << m_chainTipsTracker.TipCount() << " tips)" << std::endl;
        return true;
    }

    return false;
}

bool CHeadersManager::InitializeDoSProtectedSync(NodeId peer, const uint256& minimum_work)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Don't reinitialize if already exists
    if (mapHeadersSyncStates.find(peer) != mapHeadersSyncStates.end()) {
        return true;
    }

    // Create HeadersSyncState parameters
    HeadersSyncParams params;
    // Use defaults from HeadersSyncParams

    // Get chain start (our current best header or genesis)
    uint256 chainStartHash = hashBestHeader;
    int64_t chainStartHeight = nBestHeight;

    if (chainStartHash.IsNull()) {
        // Start from genesis
        chainStartHash = Genesis::GetGenesisHash();
        chainStartHeight = 0;
    }

    // Create the state
    auto state = std::make_unique<HeadersSyncState>(
        peer,
        params,
        chainStartHash,
        chainStartHeight,
        minimum_work
    );

    mapHeadersSyncStates[peer] = std::move(state);


    return true;
}

bool CHeadersManager::ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev)
{
    uint256 hash = header.GetHash();

    // 1. Check Proof of Work
    if (!CheckProofOfWork(hash, header.nBits)) {
        // Compute target for debug
        uint256 target = CompactToBig(header.nBits);
        std::cerr << "  hash=   " << hash.GetHex() << std::endl;
        std::cerr << "  target= " << target.GetHex() << std::endl;
        std::cerr << "  Hash must be < target to be valid" << std::endl;
        return false;
    }

    // If this is genesis block (no parent), that's all we need to check
    if (pprev == nullptr) {
        return true;
    }

    // Get parent header data for additional checks
    uint256 parentHash = pprev->GetHash();
    auto parentIt = mapHeaders.find(parentHash);
    if (parentIt == mapHeaders.end()) {
        // Parent not in our map yet - this shouldn't happen if ProcessHeaders calls us correctly
        return true;  // Allow it for now, parent checks will catch issues
    }

    const HeaderWithChainWork* pprevData = &parentIt->second;

    // 2. Check timestamp is valid
    if (!CheckTimestamp(header, pprevData)) {
        return false;
    }

    // 3. Check difficulty transition (simplified - full implementation would check retarget logic)
    // For now, just check bits are within reasonable range
    if (header.nBits == 0) {
        return false;
    }

    // 4. Check version (should be > 0)
    if (header.nVersion <= 0) {
        return false;
    }

    return true;
}

void CHeadersManager::RequestHeaders(NodeId peer, const uint256& hashStart)
{
    // No throttle needed - SyncHeadersFromPeer handles dedup via m_headers_requested_height
    // Build locator and send request

    // BUG #178 FIX (Part 2): Always use full exponential locator
    //
    // Old bug: Used single-hash locator when hashStart was provided.
    // Problem: If peer doesn't have that hash (we're on a fork), peer falls
    // back to genesis instead of finding the common ancestor.
    //
    // Fix: Always build exponential locator. If hashStart is provided,
    // prepend it so peer tries that first, but has fallback hashes.
    // This allows peers to find the fork point instead of starting from genesis.
    std::vector<uint256> locator = GetLocator(hashStart);

    // Prepend hashStart if it's not already first in locator
    if (!hashStart.IsNull() && (locator.empty() || locator[0] != hashStart)) {
        locator.insert(locator.begin(), hashStart);
        std::cout << "[IBD] RequestHeaders: Prepended hashStart to exponential locator" << std::endl;
    } else {
        std::cout << "[IBD] RequestHeaders: Using exponential locator (size=" << locator.size() << ")" << std::endl;
    }

    auto* connman = g_node_context.connman.get();
    auto* msg_proc = g_message_processor.load();
    if (connman && msg_proc) {
        NetProtocol::CGetHeadersMessage msg(locator, uint256());
        CNetMessage getheaders = msg_proc->CreateGetHeadersMessage(msg);
        connman->PushMessage(peer, getheaders);
        std::cout << "[IBD] RequestHeaders: Sent GETHEADERS to peer " << peer << std::endl;
    }
}

bool CHeadersManager::SyncHeadersFromPeer(NodeId peer, int peer_height, bool force)
{
    // SSOT: Single entry point for all header requests
    // Handles dedup, correct locator hash, and tracking

    // =========================================================================
    // PHASE 1: SYNCED STATE - SIMPLE HEADER REQUEST
    // =========================================================================
    // When node is synced (not in IBD), bypass dedup logic entirely.
    // In steady-state, we want to immediately request headers when:
    // - We receive an INV for an unknown block
    // - A peer announces a higher height
    // The dedup logic is only needed during IBD to prevent request spam.
    // =========================================================================

    if (g_node_context.ibd_coordinator && g_node_context.ibd_coordinator->IsSynced()) {
        // Synced state: Simple request, no dedup
        // Bug #179 Fix: Use m_last_request_hash to continue fork chain sync
        // If we received headers from a fork, hashBestHeader won't update (fork has less work),
        // but m_last_request_hash will have the last received fork header so we can continue.
        uint256 request_from;
        {
            std::lock_guard<std::mutex> lock(cs_headers);
            request_from = m_last_request_hash.IsNull() ? hashBestHeader : m_last_request_hash;
        }

        std::cout << "[SYNCED] Requesting headers from peer " << peer
                  << " (peer_height=" << peer_height
                  << ", our_best=" << request_from.GetHex().substr(0, 16) << "...)" << std::endl;

        RequestHeaders(peer, request_from);
        return true;
    }

    // =========================================================================
    // IBD MODE: DEDUP LOGIC TO PREVENT REQUEST SPAM
    // =========================================================================

    int requested = m_headers_requested_height.load();

    // Already requested up to peer's height? Skip (unless forced).
    // Force is used when receiving INV for unknown blocks - we MUST request
    // headers even if our tracking says we already requested "enough".
    if (!force && peer_height <= requested) {
        return false;
    }

    // Calculate target (cap at requested + 2000 to limit pipeline depth)
    int expected_new_height = std::min(peer_height, requested + 2000);

    // Update tracking BEFORE sending request (prevents duplicate requests)
    m_headers_requested_height.store(expected_new_height);

    // Use last request hash if we have one, otherwise validated tip
    // m_last_request_hash is updated by QueueRawHeadersForProcessing when headers arrive
    uint256 request_from;
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        request_from = m_last_request_hash.IsNull() ? hashBestHeader : m_last_request_hash;
    }

    std::cout << "[IBD-SYNC] Requesting headers (requested=" << requested
              << " -> " << expected_new_height << ", peer_height=" << peer_height
              << ", locator=" << request_from.GetHex().substr(0, 16) << "...)" << std::endl;

    RequestHeaders(peer, request_from);
    return true;
}

void CHeadersManager::OnBlockActivated(const CBlockHeader& header, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_headers);


    // Check if we already have this header
    auto it = mapHeaders.find(hash);
    if (it != mapHeaders.end()) {
        // Already have header - just update best header tracking
        UpdateBestHeader(hash);
        return;
    }

    // Find parent to determine height
    auto parentIt = mapHeaders.find(header.hashPrevBlock);
    int height = 1;  // Default for block 1 (parent is genesis at height 0)
    const HeaderWithChainWork* pprev = nullptr;

    if (parentIt != mapHeaders.end()) {
        pprev = &parentIt->second;
        height = pprev->height + 1;
    } else {
        // Parent not in map - this could be genesis (height 0) or block 1 (height 1)
        // If this is genesis block, height should be 0
        if (header.hashPrevBlock.IsNull()) {
            height = 0;  // Genesis block
        } else {
        }
    }

    // Calculate chain work
    uint256 chainWork = CalculateChainWork(header, pprev);

    // Store header
    HeaderWithChainWork headerData(header, height);
    headerData.chainWork = chainWork;
    mapHeaders[hash] = headerData;

    // Add to height index
    AddToHeightIndex(hash, height);

    // Update best header
    UpdateBestHeader(hash);

}

std::vector<uint256> CHeadersManager::GetLocator(const uint256& hashTip)
{
    // DEADLOCK FIX: Get chainstate tip BEFORE acquiring cs_headers
    // to avoid cs_headers/cs_main lock order inversion.
    // (OnBlockActivated holds cs_main and wants cs_headers;
    //  GetLocatorImpl would hold cs_headers and want cs_main via GetTip)
    CBlockIndex* pTip = g_chainstate.GetTip();
    int chainstateHeight = (pTip && pTip->nHeight > 0) ? pTip->nHeight : 0;

    std::lock_guard<std::mutex> lock(cs_headers);
    return GetLocatorImpl(hashTip, pTip, chainstateHeight);
}

std::vector<uint256> CHeadersManager::GetLocatorImpl(const uint256& hashTip, CBlockIndex* pTip, int chainstateHeight) const
{
    // NOTE: Caller MUST hold cs_headers lock
    // This is the implementation of GetLocator without lock acquisition.
    // Used by internal functions that already hold the lock to avoid deadlock.
    //
    // DEADLOCK FIX: pTip and chainstateHeight must be obtained BEFORE
    // acquiring cs_headers to avoid lock order inversion with cs_main.

    std::vector<uint256> locator;
    locator.reserve(32);  // Pre-allocate for efficiency

    // BUG #150 FIX (Part 3): Build locator from MAX(chainstate, headers_manager)
    //
    // Problem: If we build locator ONLY from chainstate and headers_manager has
    // more headers, we'll keep re-requesting the same headers we already have.
    //
    // Solution:
    // 1. Start from MAX(chainstate height, headers_manager best header height)
    // 2. For heights <= chainstate: use chainstate hashes (verified fork-safe)
    // 3. For heights > chainstate: use headers_manager best chain hashes
    //
    // This ensures we don't re-request headers while maintaining fork safety.
    // Note: pTip and chainstateHeight are pre-fetched before cs_headers lock.

    // Get headers_manager's best header height
    int headersHeight = 0;
    if (!hashBestHeader.IsNull()) {
        auto it = mapHeaders.find(hashBestHeader);
        if (it != mapHeaders.end()) {
            headersHeight = it->second.height;
        }
    }

    // Start from the HIGHER of the two to avoid re-requesting headers
    int startHeight = std::max(chainstateHeight, headersHeight);

    // DEBUG: Locator state
    std::cout << "[GetLocator] chainstateHeight=" << chainstateHeight
              << " headersHeight=" << headersHeight << " nBestHeight=" << nBestHeight
              << " startHeight=" << startHeight << " pTip=" << (pTip ? "valid" : "null") << std::endl;

    if (startHeight > 0) {
        int height = startHeight;
        int step = 1;
        int nStep = 0;

        while (height >= 0) {
            uint256 hashAtHeight;

            // Use chainstate for heights it covers (verified fork-safe)
            if (pTip && height <= chainstateHeight) {
                CBlockIndex* pBlock = pTip->GetAncestor(height);
                if (pBlock) {
                    hashAtHeight = pBlock->GetBlockHash();
                }
            } else {
                // Above chainstate: use headers_manager's best chain RandomX hashes
                // BUG FIX: GetBestChainHashAtHeight now returns RandomX hash, not SHA256
                hashAtHeight = GetBestChainHashAtHeight(height);
            }

            if (!hashAtHeight.IsNull()) {
                locator.push_back(hashAtHeight);
            }

            // Stop at genesis
            if (height == 0)
                break;

            // Exponential backoff after 10 entries
            if (nStep >= 10) {
                step *= 2;
            }

            height -= step;
            nStep++;

            // Limit total locator size (safety check)
            if (locator.size() >= 32) {
                break;
            }
        }

        if (!locator.empty()) {
            return locator;
        }
    }

    // Fallback: fresh node with no chainstate and no headers
    // Return empty locator - peer will send headers from genesis
    return locator;
}

// ============================================================================
// Public API: State Queries
// ============================================================================

bool CHeadersManager::IsSyncing() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Check if any peer is actively syncing
    for (const auto& pair : mapPeerStates) {
        if (pair.second.syncing) {
            return true;
        }
    }

    return false;
}

double CHeadersManager::GetSyncProgress() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (mapPeerStates.empty()) {
        return 0.0;
    }

    // Find highest claimed height from peers
    int maxPeerHeight = nBestHeight;
    for (const auto& pair : mapPeerStates) {
        if (pair.second.nSyncHeight > maxPeerHeight) {
            maxPeerHeight = pair.second.nSyncHeight;
        }
    }

    if (maxPeerHeight <= 0) {
        return 0.0;
    }

    return static_cast<double>(nBestHeight) / static_cast<double>(maxPeerHeight);
}

const CBlockHeader* CHeadersManager::GetBestHeader() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (hashBestHeader.IsNull()) {
        return nullptr;
    }

    auto it = mapHeaders.find(hashBestHeader);
    if (it == mapHeaders.end()) {
        return nullptr;
    }

    return &it->second.header;
}

uint256 CHeadersManager::GetBestHeaderHash() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return hashBestHeader;
}

int CHeadersManager::GetBestHeight() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return nBestHeight;
}

bool CHeadersManager::GetHeader(const uint256& hash, CBlockHeader& header) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        return false;
    }

    header = it->second.header;
    return true;
}

bool CHeadersManager::HaveHeader(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return mapHeaders.find(hash) != mapHeaders.end();
}

int CHeadersManager::GetHeightForHash(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    auto it = mapHeaders.find(hash);
    if (it != mapHeaders.end()) {
        return it->second.height;
    }
    return -1;  // Not found
}

std::vector<uint256> CHeadersManager::GetHeadersAtHeight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    std::vector<uint256> result;

    auto it = mapHeightIndex.find(height);
    if (it != mapHeightIndex.end()) {
        result.insert(result.end(), it->second.begin(), it->second.end());
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

uint256 CHeadersManager::GetRandomXHashAtHeight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Bug #150 Fix: Use fork-safe lookup that follows best-work chain
    // Previously used *heightIt->second.begin() which selected by hash order,
    // NOT by chain work. This caused wrong block downloads during forks.
    return GetBestChainHashAtHeight(height);
}

// ============================================================================
// Public API: Peer Management
// ============================================================================

void CHeadersManager::OnPeerConnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates[peer] = PeerSyncState();

}

void CHeadersManager::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates.erase(peer);
    mapPeerStartHeight.erase(peer);  // BUG #62: Clean up peer height tracking
    mapHeadersSyncStates.erase(peer);  // Clean up DoS protection state

}

void CHeadersManager::SetPeerStartHeight(NodeId peer, int height)
{
    std::lock_guard<std::mutex> lock(cs_headers);
    mapPeerStartHeight[peer] = height;
}

int CHeadersManager::GetPeerStartHeight(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    auto it = mapPeerStartHeight.find(peer);
    return (it != mapPeerStartHeight.end()) ? it->second : 0;
}

bool CHeadersManager::ShouldFetchHeaders(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        return false;
    }

    // Rate limiting: Don't request more than once per 30 seconds
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastUpdate);

    return elapsed.count() >= 30;
}

void CHeadersManager::UpdatePeerState(NodeId peer, const uint256& hash, int height)
{
    // BUG #35 FIX: Do NOT lock here - ProcessHeaders already holds cs_headers
    // Locking again causes deadlock since std::mutex is not recursive
    // NOTE: This function is ONLY called from ProcessHeaders which holds the lock

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        mapPeerStates[peer] = PeerSyncState();
        it = mapPeerStates.find(peer);
    }

    it->second.hashLastHeader = hash;
    it->second.nSyncHeight = height;
    it->second.lastUpdate = std::chrono::steady_clock::now();
    it->second.syncing = true;
}

// ============================================================================
// Public API: Diagnostics
// ============================================================================

size_t CHeadersManager::GetHeaderCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return mapHeaders.size();
}

size_t CHeadersManager::GetMemoryUsage() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Rough estimate: 80 bytes per header + overhead
    return mapHeaders.size() * 128;  // Conservative estimate
}

void CHeadersManager::Clear()
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapHeaders.clear();
    mapHeightIndex.clear();
    mapPeerStates.clear();
    hashBestHeader = uint256();
    nBestHeight = -1;
    setChainTips.clear();
    m_chainTipsTracker.Clear();
    InvalidateBestChainCache();

    // Reset request tracking state (critical for resync after fork)
    m_headers_requested_height.store(0);
    m_last_request_hash = uint256();
}

// ============================================================================
// Bug #150 Fix: Fork Management API
// ============================================================================

bool CHeadersManager::HasCompetingForks() const
{
    return m_chainTipsTracker.HasCompetingForks();
}

size_t CHeadersManager::GetForkCount() const
{
    return m_chainTipsTracker.TipCount();
}

std::string CHeadersManager::GetForkDebugInfo() const
{
    return m_chainTipsTracker.GetDebugInfo();
}

size_t CHeadersManager::PruneOrphanedHeaders()
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (nBestHeight < ORPHAN_HEADER_EXPIRY_BLOCKS) {
        return 0;  // Chain too short for pruning
    }

    // Get the minimum height to keep (best - expiry blocks)
    int minHeightToKeep = nBestHeight - ORPHAN_HEADER_EXPIRY_BLOCKS;

    // Get current best chain work for comparison
    uint256 bestWork;
    if (!hashBestHeader.IsNull()) {
        auto it = mapHeaders.find(hashBestHeader);
        if (it != mapHeaders.end()) {
            bestWork = it->second.chainWork;
        }
    }

    // Build set of hashes on best chain (these are NOT orphans)
    std::set<uint256> onBestChain;
    uint256 current = hashBestHeader;
    while (!current.IsNull()) {
        onBestChain.insert(current);
        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) break;
        current = it->second.hashPrevBlock;
    }

    // Find headers to prune
    std::vector<uint256> toPrune;
    for (const auto& pair : mapHeaders) {
        const uint256& hash = pair.first;
        const HeaderWithChainWork& header = pair.second;

        // Skip if on best chain
        if (onBestChain.count(hash)) {
            continue;
        }

        // Keep chain tips that still have significant work
        // (Simplified: keep tips that are close to best work)
        if (m_chainTipsTracker.IsTip(hash)) {
            // Keep this tip if it has at least some work (non-null)
            // More sophisticated pruning can compare work percentages later
            if (!header.chainWork.IsNull()) {
                continue;
            }
        }

        // Prune if height is below threshold
        if (header.height < minHeightToKeep) {
            toPrune.push_back(hash);
        }
    }

    // Actually remove the orphaned headers
    size_t pruned = 0;
    for (const uint256& hash : toPrune) {
        auto it = mapHeaders.find(hash);
        if (it != mapHeaders.end()) {
            int height = it->second.height;

            // Remove from height index
            RemoveFromHeightIndex(hash, height);

            // Remove from chain tips (if present)
            setChainTips.erase(hash);
            m_chainTipsTracker.RemoveTip(hash);

            // Remove the header itself
            mapHeaders.erase(it);
            pruned++;
        }
    }

    if (pruned > 0) {
        std::cout << "[HeadersManager] Pruned " << pruned << " orphaned headers"
                  << " (below height " << minHeightToKeep << " or <"
                  << ORPHAN_HEADER_MIN_WORK_PERCENT << "% best work)" << std::endl;
        InvalidateBestChainCache();  // Cache may be affected
    }

    // Reset prune counter
    m_headers_since_last_prune = 0;

    return pruned;
}

size_t CHeadersManager::GetOrphanedHeaderCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Build set of hashes on best chain
    std::set<uint256> onBestChain;
    uint256 current = hashBestHeader;
    while (!current.IsNull()) {
        onBestChain.insert(current);
        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) break;
        current = it->second.hashPrevBlock;
    }

    // Count headers not on best chain
    size_t orphaned = 0;
    for (const auto& pair : mapHeaders) {
        if (!onBestChain.count(pair.first)) {
            orphaned++;
        }
    }

    return orphaned;
}

// ============================================================================
// Note: Orphan header storage was removed (KISS approach)
// Fork handling now uses direct ancestor requests instead of storing orphans.
// See ProcessHeaders() - when parent not found, we request ancestors immediately.
// ============================================================================

// ============================================================================
// Private: Chain Work Calculations
// ============================================================================

uint256 CHeadersManager::CalculateChainWork(const CBlockHeader& header, const HeaderWithChainWork* pprev) const
{
    uint256 blockWork = GetBlockWork(header.nBits);

    if (pprev == nullptr) {
        return blockWork;  // Genesis/first block: chain work = block work
    }

    // Bug #46 Fix: Add parent's accumulated work + this block's work
    return AddChainWork(blockWork, pprev->chainWork);
}

uint256 CHeadersManager::GetBlockWork(uint32_t nBits) const
{
    // Bug #46 Fix: Implement proper work calculation
    // Uses same logic as CBlockIndex::GetBlockProof()
    // Bug #47 Fix: Use consensus CompactToBig instead of custom GetTarget

    uint256 target = CompactToBig(nBits);
    uint256 proof;
    memset(proof.data, 0, 32);

    // If target is zero, return max work (should never happen)
    bool isZero = true;
    for (int i = 0; i < 32; i++) {
        if (target.data[i] != 0) {
            isZero = false;
            break;
        }
    }

    if (isZero) {
        memset(proof.data, 0xFF, 32);
        return proof;
    }

    // Extract size and mantissa from nBits compact form
    int size = nBits >> 24;
    uint64_t mantissa = nBits & 0x00FFFFFF;

    if (mantissa == 0) {
        memset(proof.data, 0xFF, 32);
        return proof;
    }

    // Calculate work = 2^(256 - 8*size) / mantissa
    int work_exponent = 256 - 8 * size;
    int work_byte_pos = work_exponent / 8;

    // Clamp to valid range
    if (work_byte_pos < 0) work_byte_pos = 0;
    if (work_byte_pos > 31) work_byte_pos = 31;

    // CID 1675253 FIX: Calculate reciprocal of mantissa scaled to 64 bits
    // Note: mantissa > 0 is guaranteed here because we check mantissa == 0 and return early at line 766
    // The ternary operator's else branch is dead code, so we simplify to just the division
    uint64_t work_mantissa = 0xFFFFFFFFFFFFFFFFULL / mantissa;

    // Store the work value at the appropriate byte position
    for (int i = 0; i < 8 && (work_byte_pos + i) < 32; i++) {
        proof.data[work_byte_pos + i] = (work_mantissa >> (i * 8)) & 0xFF;
    }

    return proof;
}

// Bug #47 Fix: Use consensus PoW functions instead of custom implementation
// The custom GetTarget() had incorrect byte ordering due to memcpy usage
bool CHeadersManager::CheckProofOfWork(const uint256& hash, uint32_t nBits) const
{
    // Use the consensus CheckProofOfWork which:
    // 1. Validates nBits range (MIN_DIFFICULTY_BITS to MAX_DIFFICULTY_BITS)
    // 2. Uses CompactToBig() for correct target expansion
    // 3. Performs proper big-endian comparison
    return ::CheckProofOfWork(hash, nBits);
}

bool CHeadersManager::CheckTimestamp(const CBlockHeader& header, const HeaderWithChainWork* pprev) const
{
    // 1. Check not too far in future (2 hours)
    // CID 1675246 FIX: Safe 64-to-32 bit time conversion (valid until 2106)
    uint32_t now = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);
    if (header.nTime > now + MAX_HEADERS_AGE_SECONDS) {
        return false;
    }

    // 2. Check greater than median of last 11 blocks
    if (pprev != nullptr) {
        uint32_t medianPast = GetMedianTimePast(pprev, MEDIAN_TIME_SPAN);
        if (header.nTime <= medianPast) {
            return false;
        }
    }

    return true;
}

uint32_t CHeadersManager::GetMedianTimePast(const HeaderWithChainWork* pprev, int span) const
{
    std::vector<uint32_t> times;

    const HeaderWithChainWork* pindex = pprev;
    for (int i = 0; i < span && pindex != nullptr; i++) {
        times.push_back(pindex->header.nTime);

        // Get parent
        uint256 parentHash = pindex->header.hashPrevBlock;
        auto it = mapHeaders.find(parentHash);
        if (it == mapHeaders.end()) {
            break;
        }
        pindex = &it->second;
    }

    if (times.empty()) {
        return 0;
    }

    // Sort and return median
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

bool CHeadersManager::UpdateBestHeader(const uint256& hash)
{
    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        static int notfound_count = 0;
        if (notfound_count++ < 5) {
            std::cout << "[UpdateBestHeader] Header not found: " << hash.GetHex().substr(0, 16) << "..." << std::endl;
        }
        return false;
    }

    int newHeight = it->second.height;

    // Bug #46 Fix: Compare cumulative work, not height!
    // This is critical for chain reorganization

    // Check if this header has more work than current best
    if (hashBestHeader.IsNull()) {
        std::cout << "[UpdateBestHeader] First header: height=" << newHeight << std::endl;
        hashBestHeader = hash;
        nBestHeight = newHeight;
        return true;
    }

    auto bestIt = mapHeaders.find(hashBestHeader);
    if (bestIt == mapHeaders.end()) {
        std::cout << "[UpdateBestHeader] Best header missing, updating: height=" << newHeight << std::endl;
        hashBestHeader = hash;
        nBestHeight = newHeight;
        return true;
    }

    // Bug #46 Fix: Use ChainWorkGreaterThan() for proper cumulative work comparison
    // This enables reorganization to chains with more work but fewer blocks
    bool hasMoreWork = ChainWorkGreaterThan(it->second.chainWork, bestIt->second.chainWork);

    // FALLBACK: If both chainWork values are zero (IBD below checkpoint), use height comparison
    // This ensures proper header chain progression during initial sync
    if (!hasMoreWork && it->second.chainWork.IsNull() && bestIt->second.chainWork.IsNull()) {
        hasMoreWork = (newHeight > nBestHeight);
    }

    // Log updates and periodic comparisons
    static int compare_count = 0;
    if (hasMoreWork) {
        std::cout << "[UpdateBestHeader] UPDATING: " << nBestHeight << " -> " << newHeight << std::endl;
    } else if (compare_count++ % 1000 == 0) {
        std::cout << "[UpdateBestHeader] Comparing: height=" << nBestHeight << " vs fork=" << newHeight << std::endl;
    }

    if (hasMoreWork) {
        hashBestHeader = hash;
        nBestHeight = newHeight;
        InvalidateBestChainCache();  // Bug #150: Cache is stale after chain tip change
        return true;
    }

    return false;
}

// ============================================================================
// Bug #150 Fix: Fork-Safe Height Lookup
// ============================================================================

void CHeadersManager::InvalidateBestChainCache()
{
    // Already holding cs_headers (called from UpdateBestHeader)
    m_bestChainCacheDirty = true;
    m_bestChainCache.clear();
}

uint256 CHeadersManager::GetBestChainHashAtHeight(int height) const
{
    // Already holding cs_headers (called from GetRandomXHashAtHeight/GetLocator)

    if (hashBestHeader.IsNull() || height < 0 || height > nBestHeight) {
        return uint256();
    }

    // Check cache first
    if (!m_bestChainCacheDirty) {
        auto cacheIt = m_bestChainCache.find(height);
        if (cacheIt != m_bestChainCache.end()) {
            return cacheIt->second;
        }
    }

    // Walk backward from best header to find block at target height
    // This ensures we follow the BEST-WORK chain, not arbitrary fork members
    uint256 current = hashBestHeader;
    int currentHeight = nBestHeight;

    // DEBUG: Detect infinite loops
    int loopCount = 0;
    const int MAX_LOOP = nBestHeight + 10;  // Should never exceed this

    // Build cache as we walk (we'll likely need nearby heights too)
    while (!current.IsNull() && currentHeight >= 0) {
        loopCount++;
        if (loopCount > MAX_LOOP) {
            std::cerr << "[GetBestChainHashAtHeight] INFINITE LOOP DETECTED at height " << currentHeight
                      << " after " << loopCount << " iterations!" << std::endl;
            break;
        }

        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) {
            // BUG #178 DEBUG: Log exactly where chain walk breaks
            std::cerr << "[GetBestChainHashAtHeight] CHAIN BREAK at height " << currentHeight
                      << " - cannot find hash " << current.GetHex().substr(0, 16) << "..."
                      << " (started from " << nBestHeight << ", target=" << height << ")" << std::endl;

            // DEBUG: What hashes DO we have at this height?
            if (g_verbose.load(std::memory_order_relaxed)) {
                auto heightIt = mapHeightIndex.find(currentHeight);
                if (heightIt != mapHeightIndex.end() && !heightIt->second.empty()) {
                    std::cerr << "[DEBUG] mapHeightIndex HAS " << heightIt->second.size()
                              << " hash(es) at height " << currentHeight << ":" << std::endl;
                    for (const auto& h : heightIt->second) {
                        std::cerr << "  - " << h.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                } else {
                    std::cerr << "[DEBUG] mapHeightIndex has NO hashes at height " << currentHeight << std::endl;
                }

                // DEBUG: Check if the hash exists anywhere with different key (only once)
                static int debugLogCount = 0;
                if (debugLogCount < 3) {  // Only log first 3 breaks
                    debugLogCount++;
                    int foundCount = 0;
                    for (const auto& entry : mapHeaders) {
                        if (entry.second.height == currentHeight) {
                            std::cerr << "[DEBUG] Found header at height " << currentHeight
                                      << " stored under key " << entry.first.GetHex().substr(0, 16) << "..."
                                      << " hashPrevBlock=" << entry.second.hashPrevBlock.GetHex().substr(0, 16) << "..."
                                      << std::endl;
                            foundCount++;
                        }
                    }
                    if (foundCount == 0) {
                        std::cerr << "[DEBUG] NO header found at height " << currentHeight << " in mapHeaders!" << std::endl;
                    }
                }
            }
            break;
        }

        // BUG FIX: Return RandomX hash, not SHA256 hash
        // The mapHeaders key is SHA256, but peers use RandomX hashes for locators
        uint256 randomXHash = it->second.randomXHash;
        if (randomXHash.IsNull()) {
            // Fallback: If no RandomX hash, use the storage hash
            // This happens for headers below checkpoint where RandomX wasn't computed
            randomXHash = current;
        }

        // Cache this height (with RandomX hash for peer communication)
        m_bestChainCache[currentHeight] = randomXHash;

        if (currentHeight == height) {
            m_bestChainCacheDirty = false;  // Cache is now valid
            return randomXHash;
        }

        if (currentHeight < height) {
            // Overshot - should not happen if height <= nBestHeight
            break;
        }

        // Move to parent
        current = it->second.hashPrevBlock;
        currentHeight--;
    }

    // Fully populated cache from best header to genesis
    m_bestChainCacheDirty = false;

    // Height not found on best chain
    return uint256();
}

void CHeadersManager::AddToHeightIndex(const uint256& hash, int height)
{
    mapHeightIndex[height].insert(hash);

    // FORK DETECTION: Log when multiple headers exist at same height
    if (mapHeightIndex[height].size() > 1) {
        std::cout << "[HeadersManager] FORK DETECTED at height " << height
                  << " - " << mapHeightIndex[height].size() << " competing headers" << std::endl;
    }
}

void CHeadersManager::RemoveFromHeightIndex(const uint256& hash, int height)
{
    auto it = mapHeightIndex.find(height);
    if (it != mapHeightIndex.end()) {
        it->second.erase(hash);
        if (it->second.empty()) {
            mapHeightIndex.erase(it);
        }
    }
}

// ============================================================================
// Bug #46 Fix: Chain Reorganization Support
// ============================================================================

void CHeadersManager::UpdateChainTips(const uint256& hashNew)
{
    // Add the new header as a chain tip (legacy set)
    setChainTips.insert(hashNew);

    // Remove its parent from chain tips (no longer a leaf)
    auto it = mapHeaders.find(hashNew);
    if (it != mapHeaders.end()) {
        const HeaderWithChainWork& header = it->second;
        if (!header.hashPrevBlock.IsNull()) {
            setChainTips.erase(header.hashPrevBlock);
            // Bug #150: Also update the new tracker
            m_chainTipsTracker.RemoveTip(header.hashPrevBlock);
        }

        // Bug #150: Add to the new chain tips tracker with chain work
        m_chainTipsTracker.AddOrUpdateTip(hashNew, header.height, header.chainWork);
    }
}

uint256 CHeadersManager::AddChainWork(const uint256& blockProof, const uint256& parentChainWork) const
{
    // Implement same logic as CBlockIndex::BuildChainWork()
    // Simple byte-by-byte addition with carry
    uint256 result;
    uint32_t carry = 0;

    for (int i = 0; i < 32; i++) {
        uint32_t sum = (uint32_t)parentChainWork.data[i] +
                      (uint32_t)blockProof.data[i] +
                      carry;
        result.data[i] = sum & 0xFF;
        carry = sum >> 8;
    }

    // Handle overflow - saturate at maximum value
    if (carry != 0) {
        memset(result.data, 0xFF, 32);
    }

    return result;
}

// ============================================================================
// BUG #125: Async Header Validation
// ============================================================================

bool CHeadersManager::QuickValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev) const
{
    // Quick structural validation - NO RandomX PoW check
    // This runs in <1ms per header

    // 1. Check version (should be > 0)
    if (header.nVersion <= 0) {
        std::cerr << "[HeadersManager] Quick validate FAILED: version <= 0" << std::endl;
        return false;
    }

    // 2. Check bits are set (non-zero difficulty)
    if (header.nBits == 0) {
        std::cerr << "[HeadersManager] Quick validate FAILED: nBits == 0" << std::endl;
        return false;
    }

    // 3. If we have a parent, check timestamp validity
    if (pprev != nullptr) {
        // Check not too far in future (2 hours)
        uint32_t now = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);
        if (header.nTime > now + MAX_HEADERS_AGE_SECONDS) {
            std::cerr << "[HeadersManager] Quick validate FAILED: timestamp too far in future" << std::endl;
            return false;
        }
    }

    // Structure is valid - PoW will be validated async
    return true;
}

bool CHeadersManager::FullValidateHeader(const CBlockHeader& header, int height)
{
    // CHECKPOINT OPTIMIZATION: Skip expensive PoW validation for headers at/before
    // the highest checkpoint. These headers are trusted by the hardcoded checkpoint.
    // This dramatically speeds up IBD (~100ms -> <1ms per header for checkpointed blocks).

    // DEBUG: Log checkpoint check (first 10 headers only)
    static int debug_count = 0;
    if (g_verbose.load(std::memory_order_relaxed) && debug_count < 10) {
        debug_count++;
        std::cout << "[DEBUG] FullValidateHeader height=" << height
                  << " g_chainParams=" << (Dilithion::g_chainParams ? "SET" : "NULL");
        if (Dilithion::g_chainParams) {
            std::cout << " highestCheckpoint=" << Dilithion::g_chainParams->GetHighestCheckpointHeight();
        }
        std::cout << std::endl;
    }

    if (Dilithion::g_chainParams) {
        int highestCheckpoint = Dilithion::g_chainParams->GetHighestCheckpointHeight();
        if (highestCheckpoint >= 0 && height <= highestCheckpoint) {
            // PoW validation skipped - block is at/before checkpoint
            return true;
        }
    }

    // Full PoW validation - this is the expensive operation (50-250ms)
    uint256 hash = header.GetHash();
    return CheckProofOfWork(hash, header.nBits);
}

bool CHeadersManager::QueueHeadersForValidation(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    if (!m_validation_running.load()) {
        std::cerr << "[HeadersManager] Validation thread not running, falling back to sync" << std::endl;
        return ProcessHeaders(peer, headers);
    }

    std::cout << "[HeadersManager] Queueing " << headers.size()
              << " headers for async validation from peer " << peer << std::endl;

    if (headers.empty()) {
        return true;
    }

    if (headers.size() > MAX_HEADERS_BUFFER) {
        std::cerr << "[HeadersManager] Too many headers (" << headers.size() << ")" << std::endl;
        return false;
    }

    // =========================================================================
    // PROGRESSIVE HEADER PROCESSING (Compute & Store Immediately)
    // =========================================================================
    // Problem: Batch processing waits for ALL hashes before storing ANY headers.
    // This means blocks can't download new headers until entire batch is done.
    //
    // Solution: Process headers progressively in small batches.
    // - Compute hash for batch of N headers (lock-free)
    // - Store batch immediately (brief lock)
    // - Repeat until all headers processed
    //
    // This allows block downloading to start as soon as first headers are stored,
    // rather than waiting for all 2000 hashes to complete.
    // =========================================================================

    const size_t BATCH_SIZE = 100;  // Process 100 headers at a time
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    // Get initial parent info (brief lock)
    uint256 prevHash;
    int startHeight = 1;
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        uint256 genesisHash = Genesis::GetGenesisHash();

        if (headers[0].hashPrevBlock == genesisHash || headers[0].hashPrevBlock.IsNull()) {
            startHeight = 1;

            // BUG #178 FIX: REMOVED early "duplicate batch" optimization
            //
            // Old buggy code assumed any headers starting from genesis are duplicates
            // if we already have headers at height 1. This is WRONG because:
            //
            // 1. A competing fork ALSO starts from genesis
            // 2. Both forks may share headers 1-N, then diverge at height N+1
            // 3. Comparing only height 1 cannot detect forks at higher heights
            //
            // Example: London stuck at 5569, NYC at 5660 on different fork
            // - Both share headers 1-5568 (same hashes)
            // - Diverged at height 5569 (different hashes)
            // - NYC sends headers from genesis (London's locator unknown)
            // - Old code: "We have height 1, skip!" → London stays stuck
            // - Fixed code: Process all headers, per-header logic detects fork at 5569
            //
            // The per-header logic at lines ~1609-1623 correctly handles:
            // - True duplicates (same hash): continue, update pprev
            // - Fork headers (different hash at same height): detect and track
            //
            // Cost: ~50ms to compute 2000 hashes in parallel (acceptable)
            // Benefit: Fork safety - nodes can always sync to best chain
            if (nBestHeight > 0) {
                std::cout << "[HeadersManager] Headers start from genesis, nBestHeight="
                          << nBestHeight << " - processing to check for forks" << std::endl;
            }

            std::cout << "[HeadersManager] Parent is genesis, startHeight=1" << std::endl;
        } else {
            // DEBUG: Log the parent lookup attempt
            std::cout << "[HeadersManager] Looking up parent: " << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                      << "... mapHeaders.size=" << mapHeaders.size() << std::endl;

            auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
            if (parentIt != mapHeaders.end()) {
                startHeight = parentIt->second.height + 1;
                prevHash = headers[0].hashPrevBlock;
                std::cout << "[HeadersManager] Parent found at height " << parentIt->second.height
                          << ", startHeight=" << startHeight << std::endl;
            } else {
                // DEBUG: Check what heights we have and their hashes
                std::cerr << "[HeadersManager] ORPHAN: Parent " << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                          << " not found" << std::endl;

                // Log some of the existing hashes near expected height for debugging
                int expectedParentHeight = nBestHeight;  // Best guess
                std::cerr << "[HeadersManager] DEBUG: nBestHeight=" << nBestHeight
                          << " mapHeaders.size=" << mapHeaders.size() << std::endl;

                auto heightIt = mapHeightIndex.find(expectedParentHeight);
                if (heightIt != mapHeightIndex.end() && !heightIt->second.empty()) {
                    uint256 storedHash = *heightIt->second.begin();
                    std::cerr << "[HeadersManager] DEBUG: At height " << expectedParentHeight
                              << " stored hash=" << storedHash.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cerr << "[HeadersManager] DEBUG: hashPrevBlock=" << headers[0].hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cerr << "[HeadersManager] DEBUG: Match=" << (storedHash == headers[0].hashPrevBlock ? "YES" : "NO") << std::endl;
                } else {
                    std::cerr << "[HeadersManager] DEBUG: No headers at height " << expectedParentHeight << std::endl;
                }

                return false;
            }
        }
    }

    auto total_start = std::chrono::steady_clock::now();
    size_t totalProcessed = 0;

    // =========================================================================
    // COMMON ANCESTOR OPTIMIZATION (Bug #180)
    // =========================================================================
    // If all headers in this batch are below our current best height AND we can
    // verify a sample matches, skip the expensive hash computation entirely.
    // This dramatically speeds up fork chain sync through shared history.
    int endHeight = startHeight + static_cast<int>(headers.size()) - 1;
    bool skipHashComputation = false;

    if (endHeight <= nBestHeight && startHeight > 0) {
        // Check ALL headers' hashPrevBlock against our stored hashes
        // This is O(n) map lookups (microseconds) vs O(n) hash computations (100+ seconds)
        // Must check every header to catch fork at ANY position in the batch
        std::lock_guard<std::mutex> lock(cs_headers);
        bool allMatch = true;

        for (size_t i = 0; i < headers.size(); ++i) {
            int height = startHeight + static_cast<int>(i);
            int prevHeight = height - 1;

            // Every header's hashPrevBlock must match our stored hash at prevHeight
            auto heightIt = mapHeightIndex.find(prevHeight);
            if (heightIt == mapHeightIndex.end() || heightIt->second.empty()) {
                allMatch = false;
                break;
            }

            uint256 storedPrevHash = *heightIt->second.begin();
            if (headers[i].hashPrevBlock != storedPrevHash) {
                // Fork detected at this position - cannot skip
                allMatch = false;
                break;
            }
        }

        if (allMatch) {
            skipHashComputation = true;
            std::cout << "[HeadersManager] OPTIMIZATION: Skipping hash computation for heights "
                      << startHeight << "-" << endHeight << " (shared history)" << std::endl;
        }
    }

    // =========================================================================
    // STEP 1: Compute ALL hashes in PARALLEL using N worker threads
    // =========================================================================
    // Use fixed number of threads (= CPU cores) to avoid thread creation overhead.
    // Each thread processes a chunk of headers, reusing its thread-local RandomX VM.
    // This is MUCH faster than spawning 100 threads per batch.

    const size_t numWorkers = std::min(size_t(8), headers.size());  // Cap at 8 workers
    const size_t chunkSize = (headers.size() + numWorkers - 1) / numWorkers;

    std::vector<uint256> allHashes(headers.size());
    std::vector<std::future<void>> workers;
    workers.reserve(numWorkers);

    auto hash_start = std::chrono::steady_clock::now();

    if (!skipHashComputation) {
        for (size_t w = 0; w < numWorkers; ++w) {
            size_t start = w * chunkSize;
            size_t end = std::min(start + chunkSize, headers.size());
            if (start >= end) break;

            workers.push_back(std::async(std::launch::async, [&headers, &allHashes, start, end]() {
                // Each worker processes its chunk sequentially, reusing thread-local RandomX VM
                for (size_t i = start; i < end; ++i) {
                    allHashes[i] = headers[i].GetHash();
                }
            }));
        }
    }

    // Wait for all workers to complete
    for (auto& worker : workers) {
        worker.get();
    }

    auto hash_end = std::chrono::steady_clock::now();
    auto hash_ms = std::chrono::duration_cast<std::chrono::milliseconds>(hash_end - hash_start).count();

    if (skipHashComputation) {
        // FAST PATH: All headers in this batch are shared history (already stored)
        // Skip hash computation entirely - QueueRawHeadersForProcessing already
        // updated m_last_request_hash and requested more headers.
        //
        // IMPORTANT: Do NOT update m_last_request_hash here! The P2P thread has
        // already set it to the newest batch's last hash. Updating it here would
        // overwrite with an OLDER value, causing request loops.
        std::cout << "[HeadersManager] FAST PATH: Skipped " << headers.size()
                  << " shared history headers (already stored)" << std::endl;
        return true;
    }

    std::cout << "[HeadersManager] Parallel hash computation: " << headers.size()
              << " headers, " << numWorkers << " workers, " << hash_ms << "ms" << std::endl;

    // =========================================================================
    // STEP 2: Store ALL headers progressively in batches (for block download)
    // =========================================================================
    // Even though hashes are already computed, we store in batches to release
    // cs_headers lock periodically, allowing block processing to proceed.

    for (size_t batchStart = 0; batchStart < headers.size(); batchStart += BATCH_SIZE) {
        size_t batchEnd = std::min(batchStart + BATCH_SIZE, headers.size());
        size_t batchSize = batchEnd - batchStart;

        // STEP 2: Store this batch (brief lock)
        {
            std::lock_guard<std::mutex> lock(cs_headers);

            const HeaderWithChainWork* pprev = nullptr;

            // Find parent for first header in batch
            if (batchStart == 0) {
                uint256 genesisHash = Genesis::GetGenesisHash();
                if (headers[0].hashPrevBlock != genesisHash && !headers[0].hashPrevBlock.IsNull()) {
                    auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
                    if (parentIt != mapHeaders.end()) {
                        pprev = &parentIt->second;
                        std::cout << "[HeadersManager] Batch 0: Parent found at height " << pprev->height << std::endl;
                    } else {
                        // BUG: This should have been caught by the initial lookup!
                        std::cerr << "[HeadersManager] BUG: Batch 0 parent lookup failed but initial lookup succeeded!" << std::endl;
                        std::cerr << "[HeadersManager] BUG: hashPrevBlock=" << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                                  << " mapHeaders.size=" << mapHeaders.size() << std::endl;
                        // Don't return false here - we already validated in initial lookup
                        // This might indicate a race condition
                    }
                }
            } else if (!prevHash.IsNull()) {
                auto parentIt = mapHeaders.find(prevHash);
                if (parentIt != mapHeaders.end()) {
                    pprev = &parentIt->second;
                } else {
                    std::cerr << "[HeadersManager] BUG: Subsequent batch parent lookup failed!" << std::endl;
                    std::cerr << "[HeadersManager] BUG: prevHash=" << prevHash.GetHex().substr(0, 16)
                              << " mapHeaders.size=" << mapHeaders.size() << std::endl;
                }
            }

            for (size_t i = 0; i < batchSize; ++i) {
                const CBlockHeader& header = headers[batchStart + i];
                int expectedHeight = startHeight + batchStart + i;

                // Check if height exists
                auto heightIt = mapHeightIndex.find(expectedHeight);
                bool heightHasHeaders = (heightIt != mapHeightIndex.end() && !heightIt->second.empty());

                // CHECKPOINT OPTIMIZATION: Skip existing headers below checkpoint
                if (expectedHeight <= checkpointHeight && heightHasHeaders) {
                    uint256 existingHash = *heightIt->second.begin();
                    auto existingIt = mapHeaders.find(existingHash);
                    if (existingIt != mapHeaders.end()) {
                        // BUG FIX: Update best header for existing checkpoint headers too
                        UpdateBestHeader(existingHash);
                        pprev = &existingIt->second;
                        prevHash = existingHash;
                        continue;
                    }
                }

                // Get pre-computed hash (computed in parallel in STEP 1)
                uint256 storageHash = allHashes[batchStart + i];

                // Skip TRUE duplicates (same hash already exists)
                if (mapHeaders.find(storageHash) != mapHeaders.end()) {
                    // BUG FIX: Still update best header for existing headers!
                    // After restart, nBestHeight may be stale while headers exist.
                    // This ensures best header tracking catches up to stored headers.
                    UpdateBestHeader(storageHash);
                    pprev = &mapHeaders[storageHash];
                    prevHash = storageHash;
                    continue;
                }

                // FORK DETECTION: Only relevant above checkpoint
                if (heightHasHeaders && expectedHeight > checkpointHeight) {
                    std::cout << "[HeadersManager] Fork header queued at height " << expectedHeight << std::endl;
                }

                // Quick validate (structure only - fast)
                if (!QuickValidateHeader(header, pprev ? &pprev->header : nullptr)) {
                    return false;
                }

                // Calculate height and chain work
                int height = pprev ? (pprev->height + 1) : 1;
                uint256 chainWork = CalculateChainWork(header, pprev);

                // Store header
                HeaderWithChainWork headerData(header, height);
                headerData.chainWork = chainWork;
                mapHeaders[storageHash] = headerData;
                AddToHeightIndex(storageHash, height);
                UpdateChainTips(storageHash);
                UpdateBestHeader(storageHash);

                // Queue for background PoW validation (only for blocks above checkpoint)
                if (expectedHeight > checkpointHeight) {
                    std::lock_guard<std::mutex> vlock(m_validation_mutex);
                    m_validation_queue.emplace(peer, header, height, chainWork);
                }

                // Update for next iteration
                pprev = &mapHeaders[storageHash];
                prevHash = storageHash;
                totalProcessed++;
            }
        }  // Release cs_headers lock after each batch - allows block downloading to progress

        // Log batch progress
        if (batchStart > 0 && batchStart % 500 == 0) {
            std::cout << "[HeadersManager] Batch progress: " << totalProcessed
                      << "/" << headers.size() << " headers stored" << std::endl;
        }
    }  // End batch loop

    // Update peer state (final update after all batches)
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        if (!headers.empty() && !prevHash.IsNull()) {
            auto it = mapHeaders.find(prevHash);
            if (it != mapHeaders.end()) {
                UpdatePeerState(peer, prevHash, it->second.height);
            }
        }
    }

    // Wake up validation thread (only if we queued any for validation)
    m_validation_cv.notify_one();

    auto total_end = std::chrono::steady_clock::now();
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start).count();
    std::cout << "[HeadersManager] Progressive processing complete: " << totalProcessed
              << " headers stored in " << total_ms << "ms (hashes: " << hash_ms << "ms)" << std::endl;

    return true;
}

bool CHeadersManager::StartValidationThread()
{
    if (m_validation_running.load()) {
        std::cerr << "[HeadersManager] Validation thread pool already running" << std::endl;
        return false;
    }

    // IBD Redesign Phase 2: Spawn N worker threads where N = CPU cores
    // This parallelizes RandomX hash computation for massive speedup
    m_hash_worker_count = std::thread::hardware_concurrency();
    if (m_hash_worker_count == 0) {
        m_hash_worker_count = 4;  // Fallback if detection fails
    }
    // Cap at 8 threads to avoid memory contention with RandomX VMs
    if (m_hash_worker_count > 8) {
        m_hash_worker_count = 8;
    }

    std::cout << "[HeadersManager] Starting " << m_hash_worker_count
              << " hash worker threads (Phase 2 parallel validation)..." << std::endl;

    m_validation_running.store(true);
    m_processor_running.store(true);

    try {
        // Start hash worker threads
        m_hash_workers.reserve(m_hash_worker_count);
        for (size_t i = 0; i < m_hash_worker_count; ++i) {
            m_hash_workers.emplace_back(&CHeadersManager::ValidationWorkerThread, this);
        }
        std::cout << "[HeadersManager] " << m_hash_worker_count << " hash workers started" << std::endl;

        // Start header processor thread (offloads P2P thread)
        m_header_processor_thread = std::thread(&CHeadersManager::HeaderProcessorThread, this);
        std::cout << "[HeadersManager] Header processor thread started" << std::endl;

        return true;
    } catch (const std::exception& e) {
        m_validation_running.store(false);
        m_processor_running.store(false);
        // Join any threads that were started
        for (auto& thread : m_hash_workers) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_hash_workers.clear();
        if (m_header_processor_thread.joinable()) {
            m_raw_queue_cv.notify_all();
            m_header_processor_thread.join();
        }
        std::cerr << "[HeadersManager] Failed to start threads: " << e.what() << std::endl;
        return false;
    }
}

void CHeadersManager::StopValidationThread()
{
    if (!m_validation_running.load() && !m_processor_running.load()) {
        return;
    }

    std::cout << "[HeadersManager] Stopping " << m_hash_workers.size()
              << " hash worker threads and header processor..." << std::endl;

    // Stop all threads
    m_validation_running.store(false);
    m_processor_running.store(false);
    m_validation_cv.notify_all();  // Wake all validation workers
    m_raw_queue_cv.notify_all();   // Wake header processor

    // Join hash worker threads
    for (auto& thread : m_hash_workers) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_hash_workers.clear();

    // Join header processor thread
    if (m_header_processor_thread.joinable()) {
        m_header_processor_thread.join();
    }

    // Clear remaining queues
    {
        std::lock_guard<std::mutex> lock(m_validation_mutex);
        while (!m_validation_queue.empty()) {
            m_validation_queue.pop();
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_raw_queue_mutex);
        while (!m_raw_header_queue.empty()) {
            m_raw_header_queue.pop();
        }
    }

    std::cout << "[HeadersManager] All threads stopped. Validated: "
              << m_validated_count.load() << ", Failures: "
              << m_validation_failures.load() << std::endl;
}

void CHeadersManager::PauseHeaderProcessing()
{
    if (m_processing_paused.load()) {
        return;  // Already paused
    }

    std::cout << "[HeadersManager] Pausing header processing for fork recovery..." << std::endl;
    std::cout.flush();

    // Set paused flag - workers will check this before starting new work
    m_processing_paused.store(true);

    // Wait for any active workers to finish (with timeout to prevent deadlock)
    {
        std::unique_lock<std::mutex> lock(m_pause_mutex);
        auto timeout = std::chrono::seconds(10);
        bool finished = m_pause_cv.wait_for(lock, timeout, [this] {
            return m_active_workers.load() == 0;
        });

        if (!finished) {
            std::cerr << "[HeadersManager] WARNING: Timeout waiting for workers, continuing anyway ("
                      << m_active_workers.load() << " workers still active)" << std::endl;
        }
    }

    std::cout << "[HeadersManager] Header processing paused" << std::endl;
}

void CHeadersManager::ResumeHeaderProcessing()
{
    if (!m_processing_paused.load()) {
        return;  // Not paused
    }

    std::cout << "[HeadersManager] Resuming header processing..." << std::endl;
    m_processing_paused.store(false);

    // Wake up any waiting workers
    m_validation_cv.notify_all();
    m_raw_queue_cv.notify_all();
}

size_t CHeadersManager::GetValidationQueueDepth() const
{
    std::lock_guard<std::mutex> lock(m_validation_mutex);
    return m_validation_queue.size();
}

void CHeadersManager::ValidationWorkerThread()
{
    // IBD Redesign Phase 2: This runs in N parallel threads
    // Each thread has its own RandomX VM via thread-local storage in randomx_hash_thread()

    while (m_validation_running.load()) {
        // Check if paused for fork recovery - wait until unpaused
        if (m_processing_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        PendingValidation pending;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_validation_mutex);

            m_validation_cv.wait(lock, [this] {
                return !m_validation_running.load() || !m_validation_queue.empty() || m_processing_paused.load();
            });

            if (!m_validation_running.load()) {
                break;
            }

            // Recheck pause state after waking
            if (m_processing_paused.load() || m_validation_queue.empty()) {
                continue;
            }

            pending = m_validation_queue.front();
            m_validation_queue.pop();

            // RACE FIX: Increment INSIDE lock scope so pause can't miss us
            m_active_workers++;
        }

        // Validate PoW (expensive - runs outside lock, unless checkpointed)
        bool valid = FullValidateHeader(pending.header, pending.height);

        // Decrement active workers and notify pause waiter if needed
        if (--m_active_workers == 0 && m_processing_paused.load()) {
            std::lock_guard<std::mutex> lock(m_pause_mutex);
            m_pause_cv.notify_all();
        }

        if (valid) {
            m_validated_count++;

            // Log progress periodically
            size_t count = m_validated_count.load();
            if (count % 100 == 0) {
                std::cout << "[HeadersManager] Validated " << count << " headers (height "
                          << pending.height << ")" << std::endl;
            }
        } else {
            m_validation_failures++;
            std::cerr << "[HeadersManager] PoW FAILED for header at height "
                      << pending.height << " from peer " << pending.peer << std::endl;

            // TODO: Could disconnect peer or mark header as invalid
            // For now, just log the failure
        }
    }

    std::cout << "[HeadersManager] Validation worker thread stopped" << std::endl;
}

// ============================================================================
// Async Raw Header Processing (P2P Thread Offload)
// ============================================================================

bool CHeadersManager::QueueRawHeadersForProcessing(NodeId peer, std::vector<CBlockHeader> headers)
{
    // Instant return - just queue the headers for background processing
    // P2P thread only computes ONE hash (for prefetch locator)

    if (headers.empty()) {
        return true;
    }

    size_t header_count = headers.size();
    std::cout << "[HeadersManager] Queueing " << header_count
              << " raw headers from peer " << peer << " for async processing" << std::endl;

    // PIPELINE: Get last header's hash BEFORE moving for prefetch locator
    // This is the only hash computed in P2P thread (1 hash vs 2000)
    uint256 last_header_hash = headers.back().GetHash();

    {
        std::lock_guard<std::mutex> lock(m_raw_queue_mutex);
        m_raw_header_queue.push({peer, std::move(headers)});
    }

    m_raw_queue_cv.notify_one();

    // PIPELINE OPTIMIZATION: Immediately request NEXT batch of headers
    // Don't wait for validation - keep the pipeline full
    //
    // SSOT: Update m_last_request_hash so SyncHeadersFromPeer uses correct locator
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        m_last_request_hash = last_header_hash;
    }

    // Request more headers if peer has more (single entry point)
    int peer_height = GetPeerStartHeight(peer);
    if (peer_height > 0) {
        SyncHeadersFromPeer(peer, peer_height);
    }

    return true;
}

void CHeadersManager::HeaderProcessorThread()
{
    std::cout << "[HeadersManager] Header processor thread started" << std::endl;

    while (m_processor_running.load()) {
        // Check if paused for fork recovery - wait until unpaused
        if (m_processing_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        PendingHeaders pending;

        // Wait for raw headers
        {
            std::unique_lock<std::mutex> lock(m_raw_queue_mutex);

            m_raw_queue_cv.wait(lock, [this] {
                return !m_processor_running.load() || !m_raw_header_queue.empty() || m_processing_paused.load();
            });

            if (!m_processor_running.load()) {
                break;
            }

            // Recheck pause state after waking
            if (m_processing_paused.load() || m_raw_header_queue.empty()) {
                continue;
            }

            pending = std::move(m_raw_header_queue.front());
            m_raw_header_queue.pop();

            // RACE FIX: Increment INSIDE lock scope so pause can't miss us
            m_active_workers++;
        }

        // Process headers - hash computation happens HERE, not in P2P thread
        // This calls QueueHeadersForValidation which does hash computation + stores headers
        std::cout << "[HeadersManager] Processing " << pending.headers.size()
                  << " headers from peer " << pending.peer_id << std::endl;

        bool success = QueueHeadersForValidation(pending.peer_id, pending.headers);

        // Decrement active workers and notify pause waiter if needed
        if (--m_active_workers == 0 && m_processing_paused.load()) {
            std::lock_guard<std::mutex> lock(m_pause_mutex);
            m_pause_cv.notify_all();
        }

        if (success) {
            // Update peer's best known height (was previously in P2P handler)
            int bestHeight = GetBestHeight();
            std::cout << "[HeadersManager] Headers processed. Best height: " << bestHeight << std::endl;

            // Update peer height tracking for FetchBlocks
            if (g_node_context.peer_manager) {
                g_node_context.peer_manager->UpdatePeerBestKnownHeight(pending.peer_id, bestHeight);
            }
        } else {
            std::cerr << "[HeadersManager] Failed to process headers from peer "
                      << pending.peer_id << std::endl;
        }
    }

    std::cout << "[HeadersManager] Header processor thread stopped" << std::endl;
}
