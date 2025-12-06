// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// P1-4 FIX: Write-Ahead Logging for Atomic Chain Reorganizations
// This prevents database corruption if the node crashes during a reorg.

#ifndef DILITHION_CONSENSUS_REORG_WAL_H
#define DILITHION_CONSENSUS_REORG_WAL_H

#include <uint256.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>

/**
 * Reorg phases for progress tracking
 */
enum class ReorgPhase : uint8_t {
    INITIALIZED = 0,    // WAL written, reorg not started
    DISCONNECTING = 1,  // Disconnecting old chain blocks
    CONNECTING = 2,     // Connecting new chain blocks
    COMPLETED = 3       // Reorg finished successfully
};

/**
 * Write-Ahead Log for Chain Reorganizations
 *
 * SECURITY RATIONALE (P1-4 / CONS-CRIT-004):
 * Without a WAL, a crash during reorganization leaves the database in an
 * inconsistent state:
 *   - Some blocks disconnected, some not
 *   - UTXO set partially updated
 *   - Best block pointer points to non-existent chain
 *
 * With WAL:
 *   1. Before reorg: Write intent to disk (fsync)
 *   2. During reorg: Update progress atomically
 *   3. After reorg: Delete WAL
 *   4. On startup: If WAL exists, detect incomplete reorg and recover
 *
 * Recovery strategy:
 *   - If phase == INITIALIZED: Safe to ignore (reorg never started)
 *   - If phase == DISCONNECTING/CONNECTING: Require -reindex (safest)
 *   - If phase == COMPLETED: Delete WAL and continue
 */
class CReorgWAL {
private:
    std::string m_walPath;
    bool m_active;

    // WAL file format constants
    static constexpr char MAGIC[16] = "DILITHION_WAL_1";
    static constexpr uint32_t VERSION = 1;

    // Current reorg state
    uint256 m_forkPointHash;
    uint256 m_currentTipHash;
    uint256 m_targetTipHash;
    std::vector<uint256> m_disconnectHashes;
    std::vector<uint256> m_connectHashes;
    ReorgPhase m_phase;
    uint32_t m_disconnectedCount;
    uint32_t m_connectedCount;

    // Write WAL to disk with fsync
    bool WriteWAL();

    // Read WAL from disk
    bool ReadWAL();

    // Compute SHA3-256 checksum of WAL data
    void ComputeChecksum(uint8_t* checksum) const;

public:
    /**
     * Construct a ReorgWAL instance
     * @param dataDir The data directory (e.g., ~/.dilithion-testnet)
     */
    explicit CReorgWAL(const std::string& dataDir);

    ~CReorgWAL();

    /**
     * Check if an incomplete reorg exists on startup
     * @return true if incomplete reorg detected
     */
    bool HasIncompleteReorg() const;

    /**
     * Get information about incomplete reorg for logging
     * @return Human-readable description of incomplete state
     */
    std::string GetIncompleteReorgInfo() const;

    /**
     * Begin a new reorg - write intent to WAL
     *
     * @param forkPoint Hash of fork point (last common block)
     * @param currentTip Current chain tip (will disconnect back to fork)
     * @param targetTip Target chain tip (will connect from fork to this)
     * @param disconnectBlocks Hashes of blocks to disconnect (tip -> fork order)
     * @param connectBlocks Hashes of blocks to connect (fork -> tip order)
     * @return true if WAL written successfully
     */
    bool BeginReorg(const uint256& forkPoint,
                    const uint256& currentTip,
                    const uint256& targetTip,
                    const std::vector<uint256>& disconnectBlocks,
                    const std::vector<uint256>& connectBlocks);

    /**
     * Update progress - entering disconnect phase
     * @return true if WAL updated successfully
     */
    bool EnterDisconnectPhase();

    /**
     * Update disconnect progress
     * @param count Number of blocks disconnected so far
     * @return true if WAL updated successfully
     */
    bool UpdateDisconnectProgress(uint32_t count);

    /**
     * Update progress - entering connect phase
     * @return true if WAL updated successfully
     */
    bool EnterConnectPhase();

    /**
     * Update connect progress
     * @param count Number of blocks connected so far
     * @return true if WAL updated successfully
     */
    bool UpdateConnectProgress(uint32_t count);

    /**
     * Complete the reorg - delete WAL
     * @return true if WAL deleted successfully
     */
    bool CompleteReorg();

    /**
     * Abort the reorg - delete WAL without completing
     * Use when reorg is rolled back in-memory before any changes persisted
     * @return true if WAL deleted successfully
     */
    bool AbortReorg();

    /**
     * Check if WAL is currently active (reorg in progress)
     */
    bool IsActive() const { return m_active; }

    /**
     * Get current phase
     */
    ReorgPhase GetPhase() const { return m_phase; }

    /**
     * Get fork point hash (for recovery logging)
     */
    const uint256& GetForkPointHash() const { return m_forkPointHash; }

    /**
     * Get target tip hash (for recovery logging)
     */
    const uint256& GetTargetTipHash() const { return m_targetTipHash; }
};

#endif // DILITHION_CONSENSUS_REORG_WAL_H
