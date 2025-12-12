// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/headers_manager.h>
#include <net/net.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <consensus/params.h>
#include <consensus/pow.h>
#include <util/time.h>
#include <node/genesis.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <algorithm>
#include <cstring>
#include <iostream>

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

    std::cout << "[HeadersManager] Processing " << headers.size() << " headers, first hash: "
              << headers[0].GetHash().GetHex().substr(0, 16) << "..." << std::endl;


    // Process each header sequentially
    const HeaderWithChainWork* pprev = nullptr;
    int heightStart = -1;

    for (size_t i = 0; i < headers.size(); i++) {
        const CBlockHeader& header = headers[i];
        uint256 hash = header.GetHash();

        // Skip if we already have this header
        // NOTE: We already hold cs_headers, so check mapHeaders directly instead of calling HaveHeader()
        // to avoid deadlock (ProcessHeaders already holds cs_headers)
        if (mapHeaders.find(hash) != mapHeaders.end()) {
            auto it = mapHeaders.find(hash);
            if (it != mapHeaders.end()) {
                pprev = &it->second;
                heightStart = it->second.height;
                // BUG #33 FIX: Update best header even for existing headers
                // so that nBestHeight is set correctly after restart
                UpdateBestHeader(hash);
            }
            continue;
        }

        // Bug #46 Fix: Find parent - allow headers from competing chains
        if (pprev == nullptr || pprev->header.GetHash() != header.hashPrevBlock) {
            if (i == 0) {
                std::cout << "[HeadersManager] First header parent: "
                          << header.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                std::cout << "[HeadersManager] mapHeaders.size() = " << mapHeaders.size() << std::endl;
            }
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            if (parentIt == mapHeaders.end()) {
                // Bug #46 Fix: Check if parent is genesis block
                // This allows the first block on ANY valid chain to be accepted
                uint256 genesisHash = Genesis::GetGenesisHash();
                std::cout << "[HeadersManager] Parent not in mapHeaders, checking genesis. Genesis="
                          << genesisHash.GetHex().substr(0, 16) << "..." << std::endl;
                if (header.hashPrevBlock == genesisHash || header.hashPrevBlock.IsNull()) {
                    std::cout << "[HeadersManager] Parent is genesis block" << std::endl;
                    pprev = nullptr;  // Parent is genesis - this is block 1
                } else {
                    // True orphan - reject per Bitcoin Core design
                    // This prevents DoS attacks with disconnected headers
                    std::cerr << "[HeadersManager] ORPHAN: Parent " << header.hashPrevBlock.GetHex().substr(0, 16)
                              << "... not found in header tree" << std::endl;
                    std::cerr << "  Peer should send headers in order from common ancestor" << std::endl;
                    return false;  // Orphan header - reject
                }
            } else {
                if (i == 0) {
                    std::cout << "[HeadersManager] Found parent at height " << parentIt->second.height << std::endl;
                }
                pprev = &parentIt->second;
            }
        }

        // Validate header
        if (!ValidateHeader(header, pprev ? &pprev->header : nullptr)) {
            return false;
        }

        // Calculate height and chain work
        // Bug #38 fix: When pprev is nullptr during first IBD, this is block 1 (height 1, not 0)
        // nullptr means parent is genesis (height 0), so this header is height 1
        int height = pprev ? (pprev->height + 1) : 1;
        uint256 chainWork = CalculateChainWork(header, pprev);

        // Store header
        HeaderWithChainWork headerData(header, height);
        headerData.chainWork = chainWork;

        mapHeaders[hash] = headerData;
        AddToHeightIndex(hash, height);

        // Bug #46 Fix: Update chain tips tracking
        UpdateChainTips(hash);

        // Update best header if this has more work
        UpdateBestHeader(hash);

        // Update for next iteration
        pprev = &mapHeaders[hash];

        if (heightStart < 0) {
            heightStart = height;
        }
    }


    // Update peer state
    if (!headers.empty()) {
        uint256 lastHash = headers.back().GetHash();
        auto it = mapHeaders.find(lastHash);
        if (it != mapHeaders.end()) {
            UpdatePeerState(peer, lastHash, it->second.height);
        }
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

    // Check if we're in IBD (peer claims significantly more headers than we have)
    auto heightIt = mapPeerStartHeight.find(peer);
    if (heightIt != mapPeerStartHeight.end()) {
        int peerHeight = heightIt->second;
        // If peer is 2000+ blocks ahead, use DoS protection
        if (peerHeight > nBestHeight + 2000) {
            return true;
        }
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

    // Build locator (holds cs_headers briefly, DOES NOT access blockchain)
    std::vector<uint256> locator = GetLocator(hashStart);
    // cs_headers is now released

    if (locator.empty()) {
    } else {
    }

    // Send message (no locks held - safe for network I/O)
    // BUG #143 FIX: Use g_node_context.connman instead of deprecated g_connection_manager
    auto* connman = g_node_context.connman.get();
    auto* msg_proc = g_message_processor.load();
    if (connman && msg_proc) {
        NetProtocol::CGetHeadersMessage msg(locator, uint256());
        CNetMessage getheaders = msg_proc->CreateGetHeadersMessage(msg);
        connman->PushMessage(peer, getheaders);
        std::cout << "[IBD] RequestHeaders: PushMessage(" << peer << ") GETHEADERS (locator size=" << locator.size() << ")" << std::endl;
    } else {
        std::cout << "[IBD] RequestHeaders: FAILED - connman=" << (connman ? "valid" : "null")
                  << " msg_proc=" << (msg_proc ? "valid" : "null") << std::endl;
    }
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
    std::lock_guard<std::mutex> lock(cs_headers);

    std::vector<uint256> locator;
    locator.reserve(32);  // Pre-allocate for efficiency

    // Find the starting header in our headers map
    auto it = mapHeaders.find(hashTip);
    if (it == mapHeaders.end()) {
        // If we don't have this hash, start from our best header
        if (!hashBestHeader.IsNull()) {
            it = mapHeaders.find(hashBestHeader);
        }
    }

    if (it == mapHeaders.end()) {
        // No headers yet - return empty locator (peer will send from genesis)
        return locator;
    }

    // Save starting height for logging
    int startHeight = it->second.height;

    // Bitcoin Core exponential backoff algorithm
    // Adds headers at: current, -1, -2, -4, -8, -16, -32, -64, -128, -256, -512, -1024...
    int height = startHeight;
    int step = 1;
    int nStep = 0;

    while (height >= 0) {
        // Get hash at this height from our height index
        auto heightIt = mapHeightIndex.find(height);
        if (heightIt != mapHeightIndex.end() && !heightIt->second.empty()) {
            // Use the first hash at this height (our best chain)
            locator.push_back(*heightIt->second.begin());
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

    // Ensure genesis is always included
    if (!locator.empty() && locator.back() != uint256()) {
        auto genesisIt = mapHeightIndex.find(0);
        if (genesisIt != mapHeightIndex.end() && !genesisIt->second.empty()) {
            uint256 genesisHash = *genesisIt->second.begin();
            if (locator.back() != genesisHash) {
                locator.push_back(genesisHash);
            }
        }
    }


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

}

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
        return false;
    }

    // Bug #46 Fix: Compare cumulative work, not height!
    // This is critical for chain reorganization

    // Check if this header has more work than current best
    if (hashBestHeader.IsNull()) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        return true;
    }

    auto bestIt = mapHeaders.find(hashBestHeader);
    if (bestIt == mapHeaders.end()) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        return true;
    }

    // Bug #46 Fix: Use ChainWorkGreaterThan() for proper cumulative work comparison
    // This enables reorganization to chains with more work but fewer blocks
    if (ChainWorkGreaterThan(it->second.chainWork, bestIt->second.chainWork)) {

        hashBestHeader = hash;
        nBestHeight = it->second.height;

        return true;
    }

    return false;
}

void CHeadersManager::AddToHeightIndex(const uint256& hash, int height)
{
    mapHeightIndex[height].insert(hash);
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
    // Add the new header as a chain tip
    setChainTips.insert(hashNew);

    // Remove its parent from chain tips (no longer a leaf)
    auto it = mapHeaders.find(hashNew);
    if (it != mapHeaders.end()) {
        const HeaderWithChainWork& header = it->second;
        if (!header.hashPrevBlock.IsNull()) {
            setChainTips.erase(header.hashPrevBlock);
        }
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
    if (debug_count < 10) {
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

    // Quick-validate and store headers immediately (non-blocking)
    {
        std::lock_guard<std::mutex> lock(cs_headers);

        if (headers.empty()) {
            return true;
        }

        if (headers.size() > MAX_HEADERS_BUFFER) {
            std::cerr << "[HeadersManager] Too many headers (" << headers.size() << ")" << std::endl;
            return false;
        }

        const HeaderWithChainWork* pprev = nullptr;

        for (const CBlockHeader& header : headers) {
            uint256 hash = header.GetHash();

            // Skip duplicates
            if (mapHeaders.find(hash) != mapHeaders.end()) {
                pprev = &mapHeaders[hash];
                continue;
            }

            // Find parent
            if (pprev == nullptr || pprev->header.GetHash() != header.hashPrevBlock) {
                auto parentIt = mapHeaders.find(header.hashPrevBlock);
                if (parentIt == mapHeaders.end()) {
                    uint256 genesisHash = Genesis::GetGenesisHash();
                    if (header.hashPrevBlock == genesisHash || header.hashPrevBlock.IsNull()) {
                        pprev = nullptr;
                    } else {
                        std::cerr << "[HeadersManager] Orphan header - parent not found" << std::endl;
                        return false;
                    }
                } else {
                    pprev = &parentIt->second;
                }
            }

            // Quick validate (structure only - fast)
            if (!QuickValidateHeader(header, pprev ? &pprev->header : nullptr)) {
                return false;
            }

            // Calculate height and chain work
            int height = pprev ? (pprev->height + 1) : 1;
            uint256 chainWork = CalculateChainWork(header, pprev);

            // Store header (marked as pending PoW validation)
            HeaderWithChainWork headerData(header, height);
            headerData.chainWork = chainWork;
            mapHeaders[hash] = headerData;
            AddToHeightIndex(hash, height);
            UpdateChainTips(hash);
            UpdateBestHeader(hash);

            // Queue for background PoW validation
            {
                std::lock_guard<std::mutex> vlock(m_validation_mutex);
                m_validation_queue.emplace(peer, header, height, chainWork);
            }

            // Update for next iteration
            pprev = &mapHeaders[hash];
        }

        // Update peer state
        if (!headers.empty()) {
            uint256 lastHash = headers.back().GetHash();
            auto it = mapHeaders.find(lastHash);
            if (it != mapHeaders.end()) {
                UpdatePeerState(peer, lastHash, it->second.height);
            }
        }
    }

    // Wake up validation thread
    m_validation_cv.notify_one();

    std::cout << "[HeadersManager] Headers queued successfully, returning immediately" << std::endl;
    return true;
}

bool CHeadersManager::StartValidationThread()
{
    if (m_validation_running.load()) {
        std::cerr << "[HeadersManager] Validation thread already running" << std::endl;
        return false;
    }

    std::cout << "[HeadersManager] Starting validation worker thread..." << std::endl;

    m_validation_running.store(true);

    try {
        m_validation_thread = std::thread(&CHeadersManager::ValidationWorkerThread, this);
        std::cout << "[HeadersManager] Validation thread started" << std::endl;
        return true;
    } catch (const std::exception& e) {
        m_validation_running.store(false);
        std::cerr << "[HeadersManager] Failed to start validation thread: " << e.what() << std::endl;
        return false;
    }
}

void CHeadersManager::StopValidationThread()
{
    if (!m_validation_running.load()) {
        return;
    }

    std::cout << "[HeadersManager] Stopping validation thread..." << std::endl;

    m_validation_running.store(false);
    m_validation_cv.notify_all();

    if (m_validation_thread.joinable()) {
        m_validation_thread.join();
    }

    // Clear remaining queue
    {
        std::lock_guard<std::mutex> lock(m_validation_mutex);
        while (!m_validation_queue.empty()) {
            m_validation_queue.pop();
        }
    }

    std::cout << "[HeadersManager] Validation thread stopped. Validated: "
              << m_validated_count.load() << ", Failures: "
              << m_validation_failures.load() << std::endl;
}

size_t CHeadersManager::GetValidationQueueDepth() const
{
    std::lock_guard<std::mutex> lock(m_validation_mutex);
    return m_validation_queue.size();
}

void CHeadersManager::ValidationWorkerThread()
{
    std::cout << "[HeadersManager] Validation worker thread started" << std::endl;

    while (m_validation_running.load()) {
        PendingValidation pending;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_validation_mutex);

            m_validation_cv.wait(lock, [this] {
                return !m_validation_running.load() || !m_validation_queue.empty();
            });

            if (!m_validation_running.load()) {
                break;
            }

            if (m_validation_queue.empty()) {
                continue;
            }

            pending = m_validation_queue.front();
            m_validation_queue.pop();
        }

        // Validate PoW (expensive - runs outside lock, unless checkpointed)
        bool valid = FullValidateHeader(pending.header, pending.height);

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
