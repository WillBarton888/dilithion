// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/orphan_manager.h>
#include <algorithm>
#include <iostream>

COrphanManager::COrphanManager()
    : nOrphanBytes(0)
{
}

bool COrphanManager::AddOrphanBlock(NodeId peer, const CBlock& block)
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    uint256 hash = block.GetHash();

    // Check if we already have this orphan
    if (mapOrphanBlocks.find(hash) != mapOrphanBlocks.end()) {
        return true;  // Already have it
    }

    // DoS protection: Check if this peer has exceeded orphan limit
    if (PeerExceedsOrphanLimit(peer)) {
        std::cerr << "[OrphanManager] Peer " << peer
                  << " exceeded orphan limit (" << MAX_ORPHANS_PER_PEER << ")" << std::endl;
        return false;
    }

    // Calculate block size for memory tracking
    size_t blockSize = GetBlockSize(block);

    // Check global memory limit before adding
    if (nOrphanBytes + blockSize > MAX_ORPHAN_BYTES) {
        LimitOrphans();

        // After eviction, check again
        if (nOrphanBytes + blockSize > MAX_ORPHAN_BYTES) {
            std::cerr << "[OrphanManager] Cannot add orphan: would exceed memory limit" << std::endl;
            return false;
        }
    }

    // Add to primary storage
    mapOrphanBlocks.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(hash),
        std::forward_as_tuple(block, peer, blockSize)
    );

    // Add to parent index for quick lookup when parent arrives
    mapOrphanBlocksByPrev.emplace(block.hashPrevBlock, hash);

    // Add to peer index for DoS protection
    mapOrphanBlocksByPeer[peer].insert(hash);

    // Update memory tracking
    nOrphanBytes += blockSize;

    // Enforce limits after adding
    LimitOrphans();

    return true;
}

bool COrphanManager::HaveOrphanBlock(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_orphans);
    return mapOrphanBlocks.find(hash) != mapOrphanBlocks.end();
}

bool COrphanManager::GetOrphanBlock(const uint256& hash, CBlock& block) const
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    auto it = mapOrphanBlocks.find(hash);
    if (it == mapOrphanBlocks.end()) {
        return false;
    }

    block = it->second.block;
    return true;
}

bool COrphanManager::EraseOrphanBlock(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    auto it = mapOrphanBlocks.find(hash);
    if (it == mapOrphanBlocks.end()) {
        return false;
    }

    // Update memory tracking before erasing
    nOrphanBytes -= it->second.nBlockSize;

    // Remove from all indices
    EraseOrphanInternal(it);

    return true;
}

std::vector<uint256> COrphanManager::GetOrphanChildren(const uint256& parentHash) const
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    std::vector<uint256> children;

    // Find all orphans that have this parent
    auto range = mapOrphanBlocksByPrev.equal_range(parentHash);
    for (auto it = range.first; it != range.second; ++it) {
        children.push_back(it->second);
    }

    return children;
}

uint256 COrphanManager::GetOrphanRoot(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    uint256 current = hash;
    uint256 root = hash;

    // Follow the chain of orphans backwards until we find one whose parent
    // is not in the orphan pool (that's the root we need to request)
    std::set<uint256> visited;  // Prevent infinite loops

    while (true) {
        auto it = mapOrphanBlocks.find(current);
        if (it == mapOrphanBlocks.end()) {
            // Current block is not an orphan, so previous was the root
            break;
        }

        // Check for cycles (CRITICAL-7 FIX)
        if (visited.count(current) > 0) {
            std::cerr << "[OrphanManager] ERROR: Cycle detected in orphan chain, returning original hash" << std::endl;
            // Return the original hash, not a corrupted root from the cycle
            // This prevents IBD from stalling while waiting for a non-existent parent
            return hash;
        }
        visited.insert(current);

        root = current;
        current = it->second.block.hashPrevBlock;

        // Check if parent is also an orphan
        if (mapOrphanBlocks.find(current) == mapOrphanBlocks.end()) {
            // Parent is not an orphan, so current block is the root
            break;
        }
    }

    return root;
}

size_t COrphanManager::EraseOrphansForPeer(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    auto it = mapOrphanBlocksByPeer.find(peer);
    if (it == mapOrphanBlocksByPeer.end()) {
        return 0;
    }

    // Copy hashes to avoid iterator invalidation
    std::set<uint256> orphansToErase = it->second;
    size_t count = 0;

    for (const uint256& hash : orphansToErase) {
        auto orphanIt = mapOrphanBlocks.find(hash);
        if (orphanIt != mapOrphanBlocks.end()) {
            // Update memory tracking
            nOrphanBytes -= orphanIt->second.nBlockSize;

            // Remove from all indices
            EraseOrphanInternal(orphanIt);
            count++;
        }
    }

    // Remove peer entry
    mapOrphanBlocksByPeer.erase(peer);

    return count;
}

size_t COrphanManager::GetOrphanCountForPeer(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    auto it = mapOrphanBlocksByPeer.find(peer);
    if (it == mapOrphanBlocksByPeer.end()) {
        return 0;
    }

    return it->second.size();
}

size_t COrphanManager::EraseExpiredOrphans(std::chrono::seconds maxAge)
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    auto now = std::chrono::steady_clock::now();
    std::vector<uint256> toErase;

    // Find expired orphans
    for (const auto& entry : mapOrphanBlocks) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.second.timeReceived
        );

        if (age > maxAge) {
            toErase.push_back(entry.first);
        }
    }

    // Erase them
    size_t count = 0;
    for (const uint256& hash : toErase) {
        auto it = mapOrphanBlocks.find(hash);
        if (it != mapOrphanBlocks.end()) {
            nOrphanBytes -= it->second.nBlockSize;
            EraseOrphanInternal(it);
            count++;
        }
    }

    return count;
}

size_t COrphanManager::GetOrphanCount() const
{
    std::lock_guard<std::mutex> lock(cs_orphans);
    return mapOrphanBlocks.size();
}

size_t COrphanManager::GetOrphanBytes() const
{
    std::lock_guard<std::mutex> lock(cs_orphans);
    return nOrphanBytes;
}

std::vector<uint256> COrphanManager::GetAllOrphans() const
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    std::vector<uint256> orphans;
    orphans.reserve(mapOrphanBlocks.size());

    for (const auto& entry : mapOrphanBlocks) {
        orphans.push_back(entry.first);
    }

    return orphans;
}

void COrphanManager::Clear()
{
    std::lock_guard<std::mutex> lock(cs_orphans);

    mapOrphanBlocks.clear();
    mapOrphanBlocksByPrev.clear();
    mapOrphanBlocksByPeer.clear();
    nOrphanBytes = 0;
}

// ============================================================================
// Private helper methods
// ============================================================================

void COrphanManager::LimitOrphans()
{
    // Must be called with cs_orphans lock held

    // Enforce count limit
    while (mapOrphanBlocks.size() > MAX_ORPHAN_BLOCKS) {
        uint256 toEvict = SelectOrphanForEviction();
        if (toEvict.IsNull()) {
            break;  // Shouldn't happen, but be safe
        }

        auto it = mapOrphanBlocks.find(toEvict);
        if (it != mapOrphanBlocks.end()) {
            nOrphanBytes -= it->second.nBlockSize;
            EraseOrphanInternal(it);
        }
    }

    // Enforce memory limit
    while (nOrphanBytes > MAX_ORPHAN_BYTES && !mapOrphanBlocks.empty()) {
        uint256 toEvict = SelectOrphanForEviction();
        if (toEvict.IsNull()) {
            break;  // Shouldn't happen, but be safe
        }

        auto it = mapOrphanBlocks.find(toEvict);
        if (it != mapOrphanBlocks.end()) {
            nOrphanBytes -= it->second.nBlockSize;
            EraseOrphanInternal(it);
        }
    }
}

uint256 COrphanManager::SelectOrphanForEviction()
{
    // Must be called with cs_orphans lock held

    if (mapOrphanBlocks.empty()) {
        return uint256();  // Null hash
    }

    // FIFO eviction: Find oldest orphan
    auto oldest = mapOrphanBlocks.begin();
    auto oldestTime = oldest->second.timeReceived;

    for (auto it = mapOrphanBlocks.begin(); it != mapOrphanBlocks.end(); ++it) {
        if (it->second.timeReceived < oldestTime) {
            oldest = it;
            oldestTime = it->second.timeReceived;
        }
    }

    return oldest->first;
}

void COrphanManager::EraseOrphanInternal(std::map<uint256, COrphanBlock>::iterator it)
{
    // Must be called with cs_orphans lock held
    // Does not update nOrphanBytes (caller's responsibility)

    const uint256& hash = it->first;
    const COrphanBlock& orphan = it->second;

    // Remove from parent index
    auto range = mapOrphanBlocksByPrev.equal_range(orphan.block.hashPrevBlock);
    for (auto prevIt = range.first; prevIt != range.second; ) {
        if (prevIt->second == hash) {
            prevIt = mapOrphanBlocksByPrev.erase(prevIt);
        } else {
            ++prevIt;
        }
    }

    // Remove from peer index
    auto peerIt = mapOrphanBlocksByPeer.find(orphan.fromPeer);
    if (peerIt != mapOrphanBlocksByPeer.end()) {
        peerIt->second.erase(hash);
        // If peer has no more orphans, remove peer entry
        if (peerIt->second.empty()) {
            mapOrphanBlocksByPeer.erase(peerIt);
        }
    }

    // Remove from primary storage
    mapOrphanBlocks.erase(it);
}

size_t COrphanManager::GetBlockSize(const CBlock& block) const
{
    // Estimate serialized block size
    // Header: 80 bytes (version:4, prevHash:32, merkleRoot:32, time:4, bits:4, nonce:4)
    // vtx: variable
    size_t size = 80;  // Header size
    size += block.vtx.size();  // Transaction data

    // Add overhead for data structures (conservative estimate)
    size += 100;  // Overhead for maps, pointers, etc.

    return size;
}

bool COrphanManager::PeerExceedsOrphanLimit(NodeId peer) const
{
    // Must be called with cs_orphans lock held

    auto it = mapOrphanBlocksByPeer.find(peer);
    if (it == mapOrphanBlocksByPeer.end()) {
        return false;  // No orphans from this peer yet
    }

    return it->second.size() >= MAX_ORPHANS_PER_PEER;
}
