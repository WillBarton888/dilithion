// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_MINER_CONTROLLER_H
#define DILITHION_MINER_CONTROLLER_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <thread>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <optional>

/**
 * Mining statistics tracking
 */
struct CMiningStats {
    std::atomic<uint64_t> nHashesComputed{0};
    std::atomic<uint64_t> nBlocksFound{0};
    std::atomic<uint64_t> nStartTime{0};
    std::atomic<uint64_t> nLastHashRate{0};

    CMiningStats() = default;

    // Copy constructor - loads atomic values
    CMiningStats(const CMiningStats& other) {
        nHashesComputed.store(other.nHashesComputed.load());
        nBlocksFound.store(other.nBlocksFound.load());
        nStartTime.store(other.nStartTime.load());
        nLastHashRate.store(other.nLastHashRate.load());
    }

    // Copy assignment - loads atomic values
    CMiningStats& operator=(const CMiningStats& other) {
        if (this != &other) {
            nHashesComputed.store(other.nHashesComputed.load());
            nBlocksFound.store(other.nBlocksFound.load());
            nStartTime.store(other.nStartTime.load());
            nLastHashRate.store(other.nLastHashRate.load());
        }
        return *this;
    }

    void Reset() {
        nHashesComputed = 0;
        nBlocksFound = 0;
        nStartTime = 0;
        nLastHashRate = 0;
    }

    uint64_t GetHashRate() const { return nLastHashRate; }
    uint64_t GetUptime() const;
};

/**
 * Block template for mining
 */
struct CBlockTemplate {
    CBlock block;
    uint256 hashTarget;
    uint32_t nHeight;

    CBlockTemplate() : nHeight(0) {}
    CBlockTemplate(const CBlock& blk, const uint256& target, uint32_t height)
        : block(blk), hashTarget(target), nHeight(height) {}
};

/**
 * Mining controller - manages CPU mining threads and hash rate monitoring
 *
 * Features:
 * - Multi-threaded CPU mining using thread pool
 * - RandomX proof-of-work algorithm
 * - Real-time hash rate monitoring
 * - Block template management
 * - Start/stop controls
 *
 * Usage:
 *   CMiningController miner(4); // 4 threads
 *   miner.SetBlockFoundCallback([](const CBlock& block) {
 *       // Handle found block
 *   });
 *   miner.StartMining(blockTemplate);
 *   // ... mining runs in background
 *   auto stats = miner.GetStats();
 *   miner.StopMining();
 */
class CMiningController {
private:
    // Mining state
    std::atomic<bool> m_mining{false};
    std::vector<std::thread> m_workers;
    std::atomic<uint32_t> m_nThreads{0};

    // Current block template
    std::unique_ptr<CBlockTemplate> m_pTemplate;
    std::mutex m_templateMutex;

    // Mining statistics
    CMiningStats m_stats;

    // Callbacks
    std::function<void(const CBlock&)> m_blockFoundCallback;
    std::mutex m_callbackMutex;

    // Hash rate monitoring thread
    std::thread m_monitorThread;
    std::atomic<bool> m_monitoring{false};

    /**
     * Mining worker function - runs in separate thread
     * @param threadId Thread identifier (0 to m_nThreads-1)
     */
    void MiningWorker(uint32_t threadId);

    /**
     * Hash rate monitoring function - tracks and updates hash rate
     */
    void HashRateMonitor();

    /**
     * Check if block hash meets target difficulty
     */
    bool CheckProofOfWork(const uint256& hash, const uint256& target) const;

public:
    /**
     * Constructor
     * @param nThreads Number of mining threads (0 = auto-detect CPU cores)
     */
    explicit CMiningController(uint32_t nThreads = 0);

    /**
     * Destructor - ensures clean shutdown
     */
    ~CMiningController();

    // Prevent copying
    CMiningController(const CMiningController&) = delete;
    CMiningController& operator=(const CMiningController&) = delete;

    /**
     * Start mining with given block template
     * @param blockTemplate Template containing block header and target
     * @return true if mining started successfully
     */
    bool StartMining(const CBlockTemplate& blockTemplate);

    /**
     * Stop mining and wait for threads to complete
     */
    void StopMining();

    /**
     * Update block template (e.g., new transactions)
     * @param blockTemplate New template to use
     */
    void UpdateTemplate(const CBlockTemplate& blockTemplate);

    /**
     * Check if currently mining
     */
    bool IsMining() const { return m_mining; }

    /**
     * Get current mining statistics
     */
    CMiningStats GetStats() const { return m_stats; }

    /**
     * Set callback for when a valid block is found
     * @param callback Function to call with found block
     */
    void SetBlockFoundCallback(std::function<void(const CBlock&)> callback);

    /**
     * Get number of mining threads
     */
    uint32_t GetThreadCount() const { return m_nThreads; }

    /**
     * Get current hash rate in hashes per second
     */
    uint64_t GetHashRate() const { return m_stats.GetHashRate(); }

    /**
     * CreateBlockTemplate - Generate mining template with mempool transactions
     *
     * Creates a block template by:
     * 1. Selecting transactions from mempool (ordered by fee rate)
     * 2. Validating transactions against UTXO set
     * 3. Calculating total fees
     * 4. Creating coinbase transaction with subsidy + fees
     * 5. Building complete block with merkle root
     *
     * This is the core of transaction integration with mining.
     *
     * @param mempool Transaction mempool to pull transactions from
     * @param utxoSet UTXO set for validating transaction inputs
     * @param hashPrevBlock Hash of previous block (chain tip)
     * @param nHeight Height of block being mined
     * @param nBits Difficulty target in compact format
     * @param minerAddress Address to receive coinbase reward
     * @param error String to store error message on failure
     * @return Optional block template if successful, nullopt on error
     *
     * Thread Safety: This method is thread-safe if mempool and utxoSet
     * are properly synchronized by caller
     */
    std::optional<CBlockTemplate> CreateBlockTemplate(
        class CTxMemPool& mempool,
        class CUTXOSet& utxoSet,
        const uint256& hashPrevBlock,
        uint32_t nHeight,
        uint32_t nBits,
        const std::vector<uint8_t>& minerAddress,
        std::string& error
    );

private:
    // Friend declarations for unit tests
    friend void test_block_subsidy_calculation();
    friend void test_coinbase_transaction_creation();
    friend void test_merkle_root_calculation();
    friend void test_block_validation_no_duplicates();
    friend void test_subsidy_consistency();

    /**
     * SelectTransactionsForBlock - Choose transactions from mempool
     *
     * Implements greedy algorithm to maximize fees while respecting size limit.
     * Skips transactions with missing inputs (dependencies).
     *
     * @param mempool Transaction mempool
     * @param utxoSet UTXO set for input validation
     * @param maxBlockSize Maximum block size in bytes (default: 1MB)
     * @param totalFees Output: total fees from selected transactions
     * @return Vector of selected transactions
     */
    std::vector<CTransactionRef> SelectTransactionsForBlock(
        CTxMemPool& mempool,
        CUTXOSet& utxoSet,
        size_t maxBlockSize,
        uint64_t& totalFees
    );

    /**
     * CreateCoinbaseTransaction - Build coinbase TX with subsidy + fees
     *
     * @param nHeight Block height (for subsidy calculation)
     * @param totalFees Total transaction fees collected
     * @param minerAddress Address to pay coinbase reward to
     * @return Coinbase transaction reference
     */
    CTransactionRef CreateCoinbaseTransaction(
        uint32_t nHeight,
        uint64_t totalFees,
        const std::vector<uint8_t>& minerAddress
    );

    /**
     * CalculateBlockSubsidy - Get block mining subsidy
     *
     * Implements halving schedule: 50 DIL initial, halving every 210,000 blocks
     *
     * @param nHeight Block height
     * @return Subsidy amount in ions
     */
    uint64_t CalculateBlockSubsidy(uint32_t nHeight) const;

    /**
     * BuildMerkleRoot - Calculate merkle root from transactions
     *
     * @param transactions Vector of all transactions (coinbase first)
     * @return Merkle root hash
     */
    uint256 BuildMerkleRoot(const std::vector<CTransactionRef>& transactions) const;
};

#endif // DILITHION_MINER_CONTROLLER_H
