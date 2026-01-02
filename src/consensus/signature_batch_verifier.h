// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H
#define DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H

/**
 * CSignatureBatchVerifier - Parallel signature verification for Dilithium3
 *
 * PHASE 3.2 PERFORMANCE OPTIMIZATION: Batch signature verification
 *
 * Problem: Dilithium3 signature verification takes ~2-3ms per signature.
 * A block with 1000 transactions (each with 1 input) takes ~2-3 seconds
 * for signature verification alone, blocking the validation thread.
 *
 * Solution: Verify signatures in parallel using a thread pool.
 * With 4 workers, a block with 1000 signatures takes ~500-750ms instead.
 *
 * Architecture (based on Bitcoin Core's CCheckQueue):
 * - Main thread collects signature verification tasks
 * - Worker threads verify signatures in parallel
 * - Results aggregated - any failure fails the batch
 *
 * Usage:
 *   CSignatureBatchVerifier verifier(4);  // 4 worker threads
 *   verifier.Start();
 *
 *   for (const auto& input : tx.vin) {
 *       verifier.Add(signature, message, pubkey);
 *   }
 *
 *   bool allValid = verifier.Wait();  // Blocks until all verified
 */

#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <functional>
#include <cstdint>
#include <string>

/**
 * CSignatureTask - A single signature verification task
 */
struct CSignatureTask {
    std::vector<uint8_t> signature;      // Dilithium3 signature (3309 bytes)
    std::vector<uint8_t> message;        // Message that was signed (32 bytes hash)
    std::vector<uint8_t> pubkey;         // Dilithium3 public key (1952 bytes)
    std::string* error_out;              // Where to store error message if failed
    size_t input_index;                  // Input index for error reporting
};

/**
 * CSignatureBatchVerifier - Parallel Dilithium3 signature verifier
 */
class CSignatureBatchVerifier {
public:
    /**
     * Constructor
     * @param num_workers Number of worker threads (default: 4)
     */
    explicit CSignatureBatchVerifier(size_t num_workers = DEFAULT_WORKERS);

    /**
     * Destructor - ensures all workers are stopped
     */
    ~CSignatureBatchVerifier();

    // Disable copy/move
    CSignatureBatchVerifier(const CSignatureBatchVerifier&) = delete;
    CSignatureBatchVerifier& operator=(const CSignatureBatchVerifier&) = delete;

    /**
     * Start worker threads
     * Must be called before adding tasks
     */
    void Start();

    /**
     * Stop worker threads
     * Called automatically by destructor
     */
    void Stop();

    /**
     * Begin a new batch of verifications
     * Must be called before adding tasks for a new transaction/block
     */
    void BeginBatch();

    /**
     * Add a signature verification task to the batch
     * Thread-safe, can be called from any thread
     *
     * @param signature Dilithium3 signature bytes
     * @param message Message hash (32 bytes)
     * @param pubkey Dilithium3 public key bytes
     * @param input_index Input index for error reporting
     */
    void Add(const std::vector<uint8_t>& signature,
             const std::vector<uint8_t>& message,
             const std::vector<uint8_t>& pubkey,
             size_t input_index);

    /**
     * Wait for all tasks in current batch to complete
     * @param error Output parameter - set to first error if any verification fails
     * @return true if ALL signatures verified successfully
     */
    bool Wait(std::string& error);

    /**
     * Check if verifier is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get number of worker threads
     */
    size_t NumWorkers() const { return m_num_workers; }

    // Configuration constants
    static constexpr size_t DEFAULT_WORKERS = 4;
    static constexpr size_t MAX_WORKERS = 16;

private:
    /**
     * Worker thread main loop
     * Continuously processes tasks from the queue
     */
    void WorkerThread();

    /**
     * Verify a single signature
     * Called by worker threads
     * @param task The signature task to verify
     * @return true if signature is valid
     */
    bool VerifySingle(CSignatureTask& task);

    // Configuration
    size_t m_num_workers;

    // Worker threads
    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running{false};

    // Task queue
    std::queue<CSignatureTask> m_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Batch state
    std::atomic<size_t> m_pending_count{0};    // Tasks pending in current batch
    std::atomic<bool> m_batch_failed{false};   // Any task in batch failed?
    std::string m_first_error;                 // First error encountered
    std::mutex m_error_mutex;

    // Completion notification
    std::mutex m_complete_mutex;
    std::condition_variable m_complete_cv;
};

/**
 * Global batch signature verifier instance
 * Initialized once, reused for all block/transaction validation
 */
extern CSignatureBatchVerifier* g_signature_verifier;

/**
 * Initialize global signature verifier
 * Called during node startup
 */
void InitSignatureVerifier(size_t num_workers = CSignatureBatchVerifier::DEFAULT_WORKERS);

/**
 * Shutdown global signature verifier
 * Called during node shutdown
 */
void ShutdownSignatureVerifier();

#endif // DILITHION_CONSENSUS_SIGNATURE_BATCH_VERIFIER_H
