// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <node/blockchain_storage.h>
#include <iostream>
#include <algorithm>

CChainState::CChainState() : pindexTip(nullptr), pdb(nullptr) {
}

CChainState::~CChainState() {
    Cleanup();
}

void CChainState::Cleanup() {
    // Delete all block index pointers
    for (auto& pair : mapBlockIndex) {
        delete pair.second;
    }
    mapBlockIndex.clear();
    pindexTip = nullptr;
}

bool CChainState::AddBlockIndex(const uint256& hash, CBlockIndex* pindex) {
    if (pindex == nullptr) {
        return false;
    }

    // Check if already exists
    if (mapBlockIndex.count(hash) > 0) {
        std::cerr << "[Chain] Warning: Block index " << hash.GetHex().substr(0, 16)
                  << " already exists in map" << std::endl;
        return false;
    }

    mapBlockIndex[hash] = pindex;
    return true;
}

CBlockIndex* CChainState::GetBlockIndex(const uint256& hash) {
    auto it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end()) {
        return it->second;
    }
    return nullptr;
}

bool CChainState::HasBlockIndex(const uint256& hash) const {
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
            return false;
        }

        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] ERROR: Failed to connect block extending tip" << std::endl;
            return false;
        }

        pindexTip = pindexNew;

        // Persist to database
        if (pdb != nullptr) {
            pdb->WriteBestBlock(pindexNew->GetBlockHash());
        }

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

    // Disconnect old chain
    std::cout << "[Chain] Disconnecting old chain..." << std::endl;
    for (CBlockIndex* pindexDisconnect : disconnectBlocks) {
        std::cout << "  Disconnecting: " << pindexDisconnect->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexDisconnect->nHeight << ")" << std::endl;

        if (!DisconnectTip(pindexDisconnect)) {
            std::cerr << "[Chain] ERROR: Failed to disconnect block during reorg" << std::endl;
            // This is a critical error - chain state is now inconsistent
            // In production, would need rollback mechanism
            return false;
        }
    }

    // Connect new chain
    std::cout << "[Chain] Connecting new chain..." << std::endl;
    for (CBlockIndex* pindexConnect : connectBlocks) {
        std::cout << "  Connecting: " << pindexConnect->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexConnect->nHeight << ")" << std::endl;

        // Need to load block data from database
        // For now, we only have the last block's full data
        // In production, would load from database
        if (pindexConnect == pindexNew) {
            // We have the full block data for the new tip
            if (!ConnectTip(pindexConnect, block)) {
                std::cerr << "[Chain] ERROR: Failed to connect block during reorg" << std::endl;
                return false;
            }
        } else {
            // For other blocks in the new chain, we already connected them
            // when they were first received. Just update pnext pointers.
            if (pindexConnect->pprev != nullptr) {
                pindexConnect->pprev->pnext = pindexConnect;
            }
        }
    }

    // Update tip
    pindexTip = pindexNew;

    // Persist to database
    if (pdb != nullptr) {
        pdb->WriteBestBlock(pindexNew->GetBlockHash());
    }

    std::cout << "[Chain] ✅ REORGANIZATION COMPLETE" << std::endl;
    std::cout << "  New tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
              << " (height " << pindexTip->nHeight << ")" << std::endl;

    reorgOccurred = true;
    return true;
}

bool CChainState::ConnectTip(CBlockIndex* pindex, const CBlock& block) {
    if (pindex == nullptr) {
        return false;
    }

    // Update pnext pointer on parent
    if (pindex->pprev != nullptr) {
        pindex->pprev->pnext = pindex;
    }

    // Mark block as connected
    pindex->nStatus |= CBlockIndex::BLOCK_VALID_CHAIN;

    // In production, would also:
    // - Update UTXO set
    // - Validate all transactions
    // - Update wallet balances

    return true;
}

bool CChainState::DisconnectTip(CBlockIndex* pindex) {
    if (pindex == nullptr) {
        return false;
    }

    // Clear pnext pointer on parent
    if (pindex->pprev != nullptr) {
        pindex->pprev->pnext = nullptr;
    }

    // Clear own pnext pointer
    pindex->pnext = nullptr;

    // Unmark block as on main chain
    pindex->nStatus &= ~CBlockIndex::BLOCK_VALID_CHAIN;

    // In production, would also:
    // - Revert UTXO set changes
    // - Return transactions to mempool
    // - Update wallet balances

    return true;
}

std::vector<uint256> CChainState::GetBlocksAtHeight(int height) const {
    std::vector<uint256> result;

    for (const auto& pair : mapBlockIndex) {
        if (pair.second->nHeight == height) {
            result.push_back(pair.first);
        }
    }

    return result;
}
