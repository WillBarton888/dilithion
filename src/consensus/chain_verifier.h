// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CHAIN_VERIFIER_H
#define DILITHION_CONSENSUS_CHAIN_VERIFIER_H

#include <primitives/block.h>
#include <string>

/**
 * Chain Integrity Validation and Corruption Recovery
 *
 * Validates blockchain database integrity following industry best practices
 * from Bitcoin Core, Ethereum Geth, and Monero.
 *
 * Testnet behavior: Auto-wipe corrupted data and restart from genesis
 * Mainnet behavior: Exit with error, require manual intervention
 *
 * Design Principles:
 * - Fail Fast: Detect corruption early (startup validation)
 * - Fail Safe: Never auto-wipe mainnet data
 * - Fail Obvious: Clear error messages with recovery instructions
 */
class CChainVerifier {
public:
    /**
     * Validation levels (inspired by Bitcoin Core's VerifyDB)
     *
     * Performance characteristics:
     * - LEVEL_MINIMAL:  <100ms   (check 2 blocks exist)
     * - LEVEL_QUICK:    1-10s    (verify chain continuity) - DEFAULT
     * - LEVEL_STANDARD: 30-60s   (validate all headers)
     * - LEVEL_FULL:     minutes+ (full validation + UTXO)
     */
    enum ValidationLevel {
        LEVEL_MINIMAL,   // Genesis exists, best block pointer valid
        LEVEL_QUICK,     // Chain continuity (no missing parents) - DEFAULT FOR STARTUP
        LEVEL_STANDARD,  // + Block header validation (PoW, merkle root)
        LEVEL_FULL       // + Full block validation + UTXO consistency
    };

    CChainVerifier();

    /**
     * Verify chain integrity
     *
     * Runs validation checks to detect database corruption.
     * LEVEL_QUICK (default) prevents "Cannot find parent block" errors.
     *
     * @param level Validation depth (LEVEL_QUICK recommended for startup)
     * @param error Output parameter for error description
     * @return true if validation passed, false if corruption detected
     */
    bool VerifyChainIntegrity(ValidationLevel level, std::string& error);

    /**
     * Detect common corruption patterns
     *
     * Checks for:
     * - Missing genesis block
     * - Invalid best block pointer
     * - Missing parent blocks (current issue)
     * - Orphaned chain segments
     *
     * @param error Output parameter for error description
     * @return true if corruption detected, false if database is healthy
     */
    bool DetectCorruption(std::string& error);

    /**
     * Attempt to repair corrupted chain
     *
     * Testnet behavior: Wipe blockchain data and return true
     * Mainnet behavior: Return false (require manual --reindex)
     *
     * Safety: Triple-checked to prevent accidental mainnet wipe
     *
     * @param testnet True if running in testnet mode
     * @return true if repair successful/attempted, false if manual intervention required
     */
    bool RepairChain(bool testnet);

private:
    // ========================================================================
    // Validation Helper Methods
    // ========================================================================

    /**
     * Check if genesis block exists in chain state
     *
     * @param error Output parameter for error description
     * @return true if genesis exists and is correct, false otherwise
     */
    bool CheckGenesisExists(std::string& error);

    /**
     * Check if best block pointer is valid
     *
     * Verifies:
     * - Best block hash is not null
     * - Best block exists in block index
     * - Best block height is >= 0
     *
     * @param error Output parameter for error description
     * @return true if best block is valid, false otherwise
     */
    bool CheckBestBlockValid(std::string& error);

    /**
     * Check if parent of given block exists
     *
     * CRITICAL: This check prevents "Cannot find parent block" errors
     *
     * @param hash Block hash to check
     * @param error Output parameter for error description
     * @return true if parent exists (or block is genesis), false if missing
     */
    bool CheckParentExists(const uint256& hash, std::string& error);

    /**
     * Check chain continuity (no missing parents)
     *
     * Walks backwards from best block to genesis, verifying each
     * parent exists. This is the PRIMARY check for preventing
     * "Cannot find parent block" errors.
     *
     * Performance: Checks last 1000 blocks for speed (configurable)
     *
     * @param error Output parameter for error description
     * @return true if chain is continuous, false if missing parents found
     */
    bool CheckChainContinuity(std::string& error);

    /**
     * Validate block headers (LEVEL_STANDARD)
     *
     * For each block in chain:
     * - Verify PoW meets difficulty target
     * - Verify merkle root matches transactions
     * - Verify timestamp progression
     *
     * @param error Output parameter for error description
     * @return true if all headers valid, false otherwise
     */
    bool ValidateBlockHeaders(std::string& error);

    /**
     * Full chain validation (LEVEL_FULL)
     *
     * Includes:
     * - All LEVEL_STANDARD checks
     * - Transaction validation
     * - UTXO set consistency
     * - Total coin supply verification
     *
     * @param error Output parameter for error description
     * @return true if full validation passed, false otherwise
     */
    bool ValidateFullChain(std::string& error);

    // ========================================================================
    // Corruption Detection Helpers
    // ========================================================================

    /**
     * Check if chain tip is orphaned
     *
     * An orphaned chain tip has a parent that doesn't exist.
     * This is the specific issue we encountered with systemd restart.
     *
     * @param error Output parameter for error description
     * @return true if chain tip is orphaned, false otherwise
     */
    bool IsOrphanedChainTip(std::string& error);

    /**
     * Check for missing parents anywhere in chain
     *
     * Scans chain for any blocks with missing parents.
     *
     * @param error Output parameter for error description
     * @return true if missing parents found, false otherwise
     */
    bool HasMissingParents(std::string& error);

    // ========================================================================
    // Recovery Helpers
    // ========================================================================

    /**
     * Wipe blockchain data directories
     *
     * Deletes:
     * - blocks/* (block data)
     * - chainstate/* (UTXO set)
     *
     * Preserves:
     * - peers.dat (known peer addresses)
     * - wallet.dat (if exists)
     * - dilithion.conf (configuration)
     *
     * SAFETY: Only works if testnet=true, triple-checked
     *
     * @param testnet Must be true, or function refuses to wipe
     * @return true on success, false on error
     */
    bool WipeBlockchainData(bool testnet);

    /**
     * Get data directory path for current network
     *
     * @param testnet True for testnet directory, false for mainnet
     * @return Full path to data directory
     */
    std::string GetDataDirectory(bool testnet);
};

#endif // DILITHION_CONSENSUS_CHAIN_VERIFIER_H
