// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/chain_verifier.h>
#include <consensus/chain.h>
#include <node/genesis.h>
#include <util/system.h>
#include <iostream>

// Cross-platform filesystem support
#ifdef __APPLE__
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <cstring>

// POSIX-based directory removal for macOS (recursive)
static bool RemoveDirectoryRecursive(const std::string& path) {
    DIR* dir = opendir(path.c_str());
    if (!dir) return true;  // Directory doesn't exist, success

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string fullPath = path + "/" + entry->d_name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                RemoveDirectoryRecursive(fullPath);
            } else {
                unlink(fullPath.c_str());
            }
        }
    }
    closedir(dir);
    return rmdir(path.c_str()) == 0;
}

static bool DirectoryExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}
#else
#include <filesystem>
#endif

// External global chain state (defined in dilithion-node.cpp)
extern CChainState g_chainstate;

// ============================================================================
// Constructor
// ============================================================================

CChainVerifier::CChainVerifier()
{
    // Constructor intentionally empty - stateless validator
}

// ============================================================================
// Public Interface
// ============================================================================

bool CChainVerifier::VerifyChainIntegrity(ValidationLevel level, std::string& error)
{
    switch (level) {
        case LEVEL_MINIMAL:
            // Check genesis + best block pointer
            if (!CheckGenesisExists(error)) {
                return false;
            }
            if (!CheckBestBlockValid(error)) {
                return false;
            }
            break;

        case LEVEL_QUICK:
            // Most important check for preventing "Cannot find parent block"
            if (!CheckGenesisExists(error)) {
                return false;
            }
            if (!CheckBestBlockValid(error)) {
                return false;
            }
            if (!CheckChainContinuity(error)) {
                return false;
            }
            break;

        case LEVEL_STANDARD:
            // Full header validation
            if (!CheckGenesisExists(error)) {
                return false;
            }
            if (!CheckBestBlockValid(error)) {
                return false;
            }
            if (!CheckChainContinuity(error)) {
                return false;
            }
            if (!ValidateBlockHeaders(error)) {
                return false;
            }
            break;

        case LEVEL_FULL:
            // Complete validation including UTXO
            if (!ValidateFullChain(error)) {
                return false;
            }
            break;
    }

    return true;  // All checks passed
}

bool CChainVerifier::DetectCorruption(std::string& error)
{
    // Run LEVEL_QUICK validation to detect corruption
    return !VerifyChainIntegrity(LEVEL_QUICK, error);
}

bool CChainVerifier::RepairChain(bool testnet)
{
    if (testnet) {
        // Testnet: Auto-wipe approach (following Ethereum Geth pattern)
        std::cout << "[ChainVerifier] TESTNET: Attempting automatic blockchain wipe" << std::endl;

        if (!WipeBlockchainData(testnet)) {
            std::cerr << "[ChainVerifier] ERROR: Failed to wipe blockchain data" << std::endl;
            return false;
        }

        std::cout << "[ChainVerifier] TESTNET: Blockchain data wiped successfully" << std::endl;
        std::cout << "[ChainVerifier] TESTNET: Node will restart from genesis block" << std::endl;
        return true;
    } else {
        // Mainnet: Conservative approach (following Bitcoin Core pattern)
        std::cerr << "[ChainVerifier] MAINNET: Corruption detected - manual intervention required" << std::endl;
        return false;  // Caller will exit with --reindex message
    }
}

// ============================================================================
// Validation Helper Methods
// ============================================================================

bool CChainVerifier::CheckGenesisExists(std::string& error)
{
    // Get expected genesis hash
    uint256 genesisHash = Genesis::GetGenesisHash();

    // Check if genesis block exists in chain state
    if (!g_chainstate.HasBlockIndex(genesisHash)) {
        error = "Genesis block not found in blockchain database";
        return false;
    }

    // Verify it's at height 0
    CBlockIndex* pGenesisIndex = g_chainstate.GetBlockIndex(genesisHash);
    if (pGenesisIndex == nullptr) {
        error = "Genesis block index is null (internal error)";
        return false;
    }

    if (pGenesisIndex->nHeight != 0) {
        error = "Genesis block has invalid height (expected 0, got " +
                std::to_string(pGenesisIndex->nHeight) + ")";
        return false;
    }

    return true;  // Genesis exists and is correct
}

bool CChainVerifier::CheckBestBlockValid(std::string& error)
{
    // Get current chain tip
    CBlockIndex* pTip = g_chainstate.GetTip();

    // Check if tip exists
    if (pTip == nullptr) {
        error = "Best block pointer is null (chain state not initialized)";
        return false;
    }

    // Check if tip height is valid
    if (pTip->nHeight < 0) {
        error = "Best block has invalid height: " + std::to_string(pTip->nHeight);
        return false;
    }

    // Verify block hash is in block index
    uint256 tipHash = pTip->GetBlockHash();
    if (!g_chainstate.HasBlockIndex(tipHash)) {
        error = "Best block hash not found in block index: " + tipHash.GetHex();
        return false;
    }

    return true;  // Best block is valid
}

bool CChainVerifier::CheckParentExists(const uint256& hash, std::string& error)
{
    // Get block index for this hash
    CBlockIndex* pIndex = g_chainstate.GetBlockIndex(hash);
    if (pIndex == nullptr) {
        error = "Block not found: " + hash.GetHex();
        return false;
    }

    // Genesis block has no parent (check by height for safety)
    if (pIndex->nHeight == 0) {
        return true;  // Genesis has no parent - OK
    }

    // Non-genesis blocks must have parent
    if (pIndex->pprev == nullptr) {
        error = "Block " + hash.GetHex().substr(0, 16) + "... (height " +
                std::to_string(pIndex->nHeight) + ") has null parent pointer";
        return false;
    }

    // Verify parent exists in block index
    uint256 parentHash = pIndex->pprev->GetBlockHash();
    if (!g_chainstate.HasBlockIndex(parentHash)) {
        error = "Cannot find parent block " + parentHash.GetHex().substr(0, 16) +
                "... for block at height " + std::to_string(pIndex->nHeight);
        return false;
    }

    return true;  // Parent exists
}

bool CChainVerifier::CheckChainContinuity(std::string& error)
{
    // Get chain tip
    CBlockIndex* pTip = g_chainstate.GetTip();
    if (pTip == nullptr) {
        error = "Chain tip is null";
        return false;
    }

    // Walk backwards from tip to genesis
    CBlockIndex* pCurrent = pTip;
    int blocksChecked = 0;
    const int MAX_BLOCKS_TO_CHECK = 1000;  // Check last 1000 blocks for performance

    std::cout << "[ChainVerifier] Checking chain continuity from height "
              << pTip->nHeight << "..." << std::endl;

    while (pCurrent != nullptr) {
        // Check if parent exists (unless genesis)
        if (pCurrent->nHeight > 0) {
            if (pCurrent->pprev == nullptr) {
                error = "Block at height " + std::to_string(pCurrent->nHeight) +
                        " has null parent pointer";
                return false;
            }

            // Verify parent is in block index
            uint256 parentHash = pCurrent->pprev->GetBlockHash();
            if (!g_chainstate.HasBlockIndex(parentHash)) {
                error = "Cannot find parent block " + parentHash.GetHex().substr(0, 16) +
                        "... for block at height " + std::to_string(pCurrent->nHeight);
                return false;
            }

            // Verify parent height is correct
            if (pCurrent->pprev->nHeight != pCurrent->nHeight - 1) {
                error = "Invalid parent height: block at height " +
                        std::to_string(pCurrent->nHeight) + " has parent at height " +
                        std::to_string(pCurrent->pprev->nHeight);
                return false;
            }
        }

        blocksChecked++;

        // Performance optimization: only check last N blocks
        if (blocksChecked >= MAX_BLOCKS_TO_CHECK) {
            std::cout << "[ChainVerifier] Checked last " << MAX_BLOCKS_TO_CHECK
                      << " blocks - continuity verified" << std::endl;
            break;
        }

        // Move to parent
        pCurrent = pCurrent->pprev;
    }

    std::cout << "[ChainVerifier] Chain continuity check passed ("
              << blocksChecked << " blocks verified)" << std::endl;
    return true;
}

bool CChainVerifier::ValidateBlockHeaders(std::string& error)
{
    // This is a placeholder for LEVEL_STANDARD validation
    // Full implementation would include:
    // - PoW verification
    // - Merkle root validation
    // - Timestamp progression checks
    // - Block version validation

    std::cout << "[ChainVerifier] WARNING: LEVEL_STANDARD validation not fully implemented" << std::endl;
    std::cout << "[ChainVerifier] Running LEVEL_QUICK instead" << std::endl;

    return CheckChainContinuity(error);
}

bool CChainVerifier::ValidateFullChain(std::string& error)
{
    // This is a placeholder for LEVEL_FULL validation
    // Full implementation would include:
    // - All LEVEL_STANDARD checks
    // - Transaction validation
    // - UTXO set consistency
    // - Total coin supply verification

    std::cout << "[ChainVerifier] WARNING: LEVEL_FULL validation not fully implemented" << std::endl;
    std::cout << "[ChainVerifier] Running LEVEL_QUICK instead" << std::endl;

    return CheckChainContinuity(error);
}

// ============================================================================
// Corruption Detection Helpers
// ============================================================================

bool CChainVerifier::IsOrphanedChainTip(std::string& error)
{
    // Get chain tip
    CBlockIndex* pTip = g_chainstate.GetTip();
    if (pTip == nullptr) {
        error = "Chain tip is null";
        return true;  // Tip is "orphaned" (doesn't exist)
    }

    // Check if tip's parent exists
    return !CheckParentExists(pTip->GetBlockHash(), error);
}

bool CChainVerifier::HasMissingParents(std::string& error)
{
    // This is equivalent to CheckChainContinuity
    return !CheckChainContinuity(error);
}

// ============================================================================
// Recovery Helpers
// ============================================================================

bool CChainVerifier::WipeBlockchainData(bool testnet)
{
    // SAFETY CHECK 1: Refuse if not testnet
    if (!testnet) {
        std::cerr << "[ChainVerifier] ERROR: WipeBlockchainData called for MAINNET - REFUSING" << std::endl;
        return false;
    }

    // Get data directory
    std::string dataDir = GetDataDirectory(testnet);

    // SAFETY CHECK 2: Verify directory contains "testnet"
    if (dataDir.find("testnet") == std::string::npos) {
        std::cerr << "[ChainVerifier] ERROR: Data directory doesn't contain 'testnet' - REFUSING" << std::endl;
        std::cerr << "[ChainVerifier] Directory: " << dataDir << std::endl;
        return false;
    }

    // SAFETY CHECK 3: Triple-check testnet parameter
    if (!testnet) {
        std::cerr << "[ChainVerifier] ERROR: Triple-check failed - testnet parameter is false" << std::endl;
        return false;
    }

    std::cout << "[ChainVerifier] Wiping blockchain data from: " << dataDir << std::endl;

    // Define paths to wipe
    std::string blocksDir = dataDir + "/blocks";
    std::string chainstateDir = dataDir + "/chainstate";

    // Wipe blocks directory (using platform-specific APIs for security - no shell command injection)
    try {
#ifdef __APPLE__
        if (DirectoryExists(blocksDir)) {
            std::cout << "[ChainVerifier] Removing: " << blocksDir << std::endl;
            RemoveDirectoryRecursive(blocksDir);
            std::cout << "[ChainVerifier] Removed blocks directory" << std::endl;
        }
#else
        if (std::filesystem::exists(blocksDir)) {
            std::cout << "[ChainVerifier] Removing: " << blocksDir << std::endl;
            std::filesystem::remove_all(blocksDir);
            std::cout << "[ChainVerifier] Removed blocks directory" << std::endl;
        }
#endif
    } catch (const std::exception& e) {
        std::cerr << "[ChainVerifier] ERROR: Failed to remove blocks directory: " << e.what() << std::endl;
        return false;
    }

    // Wipe chainstate directory (using platform-specific APIs for security - no shell command injection)
    try {
#ifdef __APPLE__
        if (DirectoryExists(chainstateDir)) {
            std::cout << "[ChainVerifier] Removing: " << chainstateDir << std::endl;
            RemoveDirectoryRecursive(chainstateDir);
            std::cout << "[ChainVerifier] Removed chainstate directory" << std::endl;
        }
#else
        if (std::filesystem::exists(chainstateDir)) {
            std::cout << "[ChainVerifier] Removing: " << chainstateDir << std::endl;
            std::filesystem::remove_all(chainstateDir);
            std::cout << "[ChainVerifier] Removed chainstate directory" << std::endl;
        }
#endif
    } catch (const std::exception& e) {
        std::cerr << "[ChainVerifier] ERROR: Failed to remove chainstate directory: " << e.what() << std::endl;
        return false;
    }

    std::cout << "[ChainVerifier] Successfully wiped blockchain data" << std::endl;
    std::cout << "[ChainVerifier] Preserved: peers.dat, wallet.dat, dilithion.conf" << std::endl;

    return true;
}

std::string CChainVerifier::GetDataDirectory(bool testnet)
{
    // Use utility function to get data directory for the specified network
    // GetDataDir(testnet) returns:
    //   - testnet=true:  ~/.dilithion-testnet
    //   - testnet=false: ~/.dilithion
    std::string dataDir = GetDataDir(testnet);

    return dataDir;
}
