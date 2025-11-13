// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/headers_manager.h>
#include <consensus/params.h>
#include <util/time.h>
#include <algorithm>
#include <cstring>
#include <iostream>

CHeadersManager::CHeadersManager()
    : nBestHeight(-1)
{
    hashBestHeader = uint256();
}

// ============================================================================
// Public API: Header Processing
// ============================================================================

bool CHeadersManager::ProcessHeaders(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (headers.empty()) {
        return true;  // Empty is valid (no new headers)
    }

    if (headers.size() > MAX_HEADERS_BUFFER) {
        std::cerr << "[HeadersManager] ERROR: Received " << headers.size()
                  << " headers from peer " << peer << " (max " << MAX_HEADERS_BUFFER << ")" << std::endl;
        return false;
    }

    std::cout << "[HeadersManager] Processing " << headers.size()
              << " headers from peer " << peer << std::endl;

    // Process each header sequentially
    const HeaderWithChainWork* pprev = nullptr;
    int heightStart = -1;

    for (size_t i = 0; i < headers.size(); i++) {
        const CBlockHeader& header = headers[i];
        uint256 hash = header.GetHash();

        // Skip if we already have this header
        if (HaveHeader(hash)) {
            auto it = mapHeaders.find(hash);
            if (it != mapHeaders.end()) {
                pprev = &it->second;
                heightStart = it->second.height;
            }
            continue;
        }

        // Find parent
        if (pprev == nullptr || pprev->header.GetHash() != header.hashPrevBlock) {
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            if (parentIt == mapHeaders.end()) {
                std::cerr << "[HeadersManager] ERROR: Cannot find parent "
                          << header.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                std::cerr << "  for header " << hash.GetHex().substr(0, 16) << "..." << std::endl;
                std::cerr << "  This header chain is disconnected from our chain" << std::endl;
                return false;  // Parent not found - disconnected chain
            }
            pprev = &parentIt->second;
        }

        // Validate header
        if (!ValidateHeader(header, pprev ? &pprev->header : nullptr)) {
            std::cerr << "[HeadersManager] ERROR: Invalid header "
                      << hash.GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }

        // Calculate height and chain work
        int height = pprev ? (pprev->height + 1) : 0;
        uint256 chainWork = CalculateChainWork(header, pprev);

        // Store header
        HeaderWithChainWork headerData(header, height);
        headerData.chainWork = chainWork;

        mapHeaders[hash] = headerData;
        AddToHeightIndex(hash, height);

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

    std::cout << "[HeadersManager] Successfully processed " << headers.size()
              << " headers. Best height: " << nBestHeight << std::endl;

    return true;
}

bool CHeadersManager::ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev)
{
    uint256 hash = header.GetHash();

    // 1. Check Proof of Work
    if (!CheckProofOfWork(hash, header.nBits)) {
        std::cerr << "[HeadersManager] Invalid PoW for header "
                  << hash.GetHex().substr(0, 16) << "..." << std::endl;
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
        std::cerr << "[HeadersManager] Invalid timestamp for header "
                  << hash.GetHex().substr(0, 16) << "..." << std::endl;
        return false;
    }

    // 3. Check difficulty transition (simplified - full implementation would check retarget logic)
    // For now, just check bits are within reasonable range
    if (header.nBits == 0) {
        std::cerr << "[HeadersManager] Zero difficulty bits" << std::endl;
        return false;
    }

    // 4. Check version (should be > 0)
    if (header.nVersion <= 0) {
        std::cerr << "[HeadersManager] Invalid version: " << header.nVersion << std::endl;
        return false;
    }

    return true;
}

void CHeadersManager::RequestHeaders(NodeId peer, const uint256& hashStart)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Generate locator from starting hash
    std::vector<uint256> locator = GetLocator(hashStart);

    std::cout << "[HeadersManager] Requesting headers from peer " << peer
              << " with locator of " << locator.size() << " hashes" << std::endl;

    // In a real implementation, this would send a GETHEADERS message via P2P
    // For now, this is a stub that the message handler will call
    // The actual message sending will be implemented in Phase 1.4
}

std::vector<uint256> CHeadersManager::GetLocator(const uint256& hashTip)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    std::vector<uint256> locator;

    // Find the starting header
    auto it = mapHeaders.find(hashTip);
    if (it == mapHeaders.end()) {
        // If we don't have this hash, start from our best
        if (!hashBestHeader.IsNull()) {
            it = mapHeaders.find(hashBestHeader);
        }
    }

    if (it == mapHeaders.end()) {
        return locator;  // Empty locator if we have no headers
    }

    // Bitcoin Core exponential backoff algorithm
    // Add: 0, -1, -2, -4, -8, -16, -32, -64, -128, -256, -512, -1024...
    int height = it->second.height;
    int step = 1;
    int nStep = 0;

    while (height >= 0) {
        // Get hash at this height
        auto heightIt = mapHeightIndex.find(height);
        if (heightIt != mapHeightIndex.end() && !heightIt->second.empty()) {
            // Use the first hash at this height (our main chain)
            // In case of forks, we use whichever we saw first
            locator.push_back(*heightIt->second.begin());
        }

        // Exponential backoff
        if (nStep >= 10) {
            step *= 2;
        }

        height -= step;
        nStep++;

        // Limit total locator size (shouldn't hit this normally)
        if (locator.size() >= 32) {
            break;
        }
    }

    // Always add genesis (height 0) if we didn't already
    if (locator.empty() || (height > 0 && locator.back() != uint256())) {
        auto genesisIt = mapHeightIndex.find(0);
        if (genesisIt != mapHeightIndex.end() && !genesisIt->second.empty()) {
            locator.push_back(*genesisIt->second.begin());
        }
    }

    std::cout << "[HeadersManager] Generated locator with " << locator.size()
              << " hashes for height " << it->second.height << std::endl;

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

    return result;
}

// ============================================================================
// Public API: Peer Management
// ============================================================================

void CHeadersManager::OnPeerConnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates[peer] = HeadersSyncState();

    std::cout << "[HeadersManager] Peer " << peer << " connected" << std::endl;
}

void CHeadersManager::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates.erase(peer);

    std::cout << "[HeadersManager] Peer " << peer << " disconnected" << std::endl;
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
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        mapPeerStates[peer] = HeadersSyncState();
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

    std::cout << "[HeadersManager] Cleared all headers" << std::endl;
}

// ============================================================================
// Private: Chain Work Calculations
// ============================================================================

uint256 CHeadersManager::CalculateChainWork(const CBlockHeader& header, const HeaderWithChainWork* pprev) const
{
    uint256 blockWork = GetBlockWork(header.nBits);

    if (pprev == nullptr) {
        return blockWork;  // Genesis block
    }

    // Add parent's accumulated work
    uint256 chainWork = pprev->chainWork;

    // Add current block's work (simplified - real implementation would use proper uint256 addition)
    // For now, we'll just return the parent work as a placeholder
    // TODO: Implement proper uint256 addition
    return chainWork;
}

uint256 CHeadersManager::GetBlockWork(uint32_t nBits) const
{
    uint256 target = GetTarget(nBits);

    // Work = 2^256 / (target + 1)
    // Simplified for now - just return a placeholder
    // TODO: Implement proper work calculation
    uint256 work;
    return work;
}

uint256 CHeadersManager::GetTarget(uint32_t nBits) const
{
    // Extract target from compact representation
    // Format: 0xNNTTTTTT where NN is size, TTTTTT is mantissa

    uint256 target;

    int nSize = nBits >> 24;
    uint32_t nWord = nBits & 0x007fffff;

    if (nSize <= 3) {
        nWord >>= 8 * (3 - nSize);
        memcpy(target.data, &nWord, sizeof(uint32_t));
    } else {
        memcpy(target.data + (nSize - 3), &nWord, sizeof(uint32_t));
    }

    return target;
}

bool CHeadersManager::CheckProofOfWork(const uint256& hash, uint32_t nBits) const
{
    uint256 target = GetTarget(nBits);

    // Check: hash < target
    return hash < target;
}

bool CHeadersManager::CheckTimestamp(const CBlockHeader& header, const HeaderWithChainWork* pprev) const
{
    // 1. Check not too far in future (2 hours)
    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    if (header.nTime > now + MAX_HEADERS_AGE_SECONDS) {
        std::cerr << "[HeadersManager] Timestamp too far in future: "
                  << header.nTime << " vs now " << now << std::endl;
        return false;
    }

    // 2. Check greater than median of last 11 blocks
    if (pprev != nullptr) {
        uint32_t medianPast = GetMedianTimePast(pprev, MEDIAN_TIME_SPAN);
        if (header.nTime <= medianPast) {
            std::cerr << "[HeadersManager] Timestamp not greater than median past: "
                      << header.nTime << " vs " << medianPast << std::endl;
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

    // Compare chain work (simplified - just compare heights for now)
    // TODO: Implement proper chain work comparison
    if (it->second.height > bestIt->second.height) {
        hashBestHeader = hash;
        nBestHeight = it->second.height;
        std::cout << "[HeadersManager] New best header at height " << nBestHeight << std::endl;
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
