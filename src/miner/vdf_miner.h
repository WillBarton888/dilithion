// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_MINER_VDF_MINER_H
#define DILITHION_MINER_VDF_MINER_H

#include <miner/controller.h>  // CBlockTemplate
#include <vdf/vdf.h>
#include <vdf/cooldown_tracker.h>
#include <consensus/vdf_validation.h>
#include <primitives/block.h>

#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <condition_variable>
#include <array>

/**
 * VDF Mining Controller
 *
 * Replaces RandomX nonce-grinding with single-threaded VDF computation.
 * Each round:
 *   1. Wait for new block (epoch change)
 *   2. Check cooldown — skip if miner recently won
 *   3. Compute VDF challenge from prevHash + height + minerAddress
 *   4. Run vdf::compute() (~200s on reference hardware)
 *   5. Build VDF block (version 4) with proof in coinbase
 *   6. Submit via callback
 *
 * Key differences from CMiningController:
 *   - Single thread (VDF is inherently sequential)
 *   - Deterministic duration (no nonce brute-force)
 *   - Epoch-aware: aborts computation if a new block arrives
 */
class CVDFMiner {
public:
    using Address = std::array<uint8_t, 20>;
    using BlockFoundCallback = std::function<void(const CBlock&)>;
    using TemplateProvider = std::function<std::optional<CBlockTemplate>()>;

    CVDFMiner();
    ~CVDFMiner();

    // Non-copyable
    CVDFMiner(const CVDFMiner&) = delete;
    CVDFMiner& operator=(const CVDFMiner&) = delete;

    /**
     * Start VDF mining.
     * Launches a single background thread that loops:
     *   get template → compute VDF → submit block.
     */
    void Start();

    /**
     * Stop VDF mining and wait for thread to join.
     */
    void Stop();

    /**
     * Signal that a new block has arrived.
     * Aborts any in-progress VDF computation and restarts on the new epoch.
     */
    void OnNewBlock();

    /**
     * Check if VDF miner is running.
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Set callback invoked when a valid VDF block is produced.
     * Same safety requirements as CMiningController::SetBlockFoundCallback.
     */
    void SetBlockFoundCallback(BlockFoundCallback cb);

    /**
     * Set the function that provides fresh block templates.
     * Called at the start of each VDF round to get the current chain tip data.
     * The template should include coinbase with miner's payout address.
     */
    void SetTemplateProvider(TemplateProvider provider);

    /**
     * Set the miner's payout address (20-byte pubkey hash).
     */
    void SetMinerAddress(const Address& addr);

    /**
     * Set the VDF iteration count (from chainparams).
     */
    void SetIterations(uint64_t iterations);

    /**
     * Set the cooldown tracker (optional).
     * If set, the miner will skip rounds when in cooldown.
     */
    void SetCooldownTracker(CCooldownTracker* tracker);

    /**
     * Get the number of VDF blocks found.
     */
    uint64_t GetBlocksFound() const { return m_blocksFound.load(); }

    /**
     * Get the height currently being computed for (0 if idle).
     */
    uint32_t GetCurrentHeight() const { return m_currentHeight.load(); }

    /**
     * Finalize a VDF block: embed proof in coinbase, set header fields,
     * recompute merkle root.
     *
     * Takes a block from BuildMiningTemplate (version 1, no VDF fields)
     * and transforms it into a valid VDF block (version 4).
     *
     * @param block       Block from template (version will be set to 4)
     * @param result      VDF computation result (output + proof)
     * @param minerAddr   Miner's 20-byte payout address
     * @param height      Block height (for coinbase scriptSig)
     * @return true if finalization succeeded
     */
    bool FinalizeVDFBlock(CBlock& block, const vdf::VDFResult& result,
                          const Address& minerAddr, uint32_t height);

private:
    /**
     * Main mining loop (runs in m_thread).
     */
    void MiningLoop();

    // Thread and state
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_abort{false};  // Abort current VDF computation

    // Epoch tracking
    std::atomic<uint32_t> m_currentHeight{0};
    std::mutex m_epochMutex;
    std::condition_variable m_epochCV;
    bool m_epochChanged{false};

    // Configuration
    Address m_minerAddress{};
    uint64_t m_iterations{200'000'000};
    CCooldownTracker* m_cooldownTracker{nullptr};

    // Callbacks
    BlockFoundCallback m_blockFoundCallback;
    TemplateProvider m_templateProvider;
    std::mutex m_callbackMutex;

    // Stats
    std::atomic<uint64_t> m_blocksFound{0};
};

#endif // DILITHION_MINER_VDF_MINER_H
