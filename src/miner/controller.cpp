// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <miner/controller.h>
#include <crypto/randomx_hash.h>
#include <util/time.h>

#include <thread>
#include <chrono>
#include <algorithm>
#include <cstring>

// Get current time in milliseconds
static uint64_t GetTimeMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

uint64_t CMiningStats::GetUptime() const {
    if (nStartTime == 0) return 0;
    return GetTime() - nStartTime; // Uses util/time.h GetTime()
}

CMiningController::CMiningController(uint32_t nThreads)
    : m_nThreads(nThreads)
{
    // Auto-detect CPU cores if not specified
    if (m_nThreads == 0) {
        m_nThreads = std::thread::hardware_concurrency();
        if (m_nThreads == 0) {
            m_nThreads = 1; // Fallback to single thread
        }
    }

    // Limit to reasonable number of threads (max 64)
    m_nThreads = std::min(m_nThreads.load(), 64u);
}

CMiningController::~CMiningController() {
    StopMining();
}

bool CMiningController::StartMining(const CBlockTemplate& blockTemplate) {
    // Check if already mining
    if (m_mining) {
        return false;
    }

    // Validate block template
    if (blockTemplate.hashTarget.IsNull()) {
        return false;
    }

    // Initialize RandomX cache with genesis block hash as key
    // In production, this would use the previous block hash
    uint256 key = blockTemplate.block.hashPrevBlock;
    randomx_init_cache(key.begin(), 32);

    // Store block template
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        m_pTemplate = std::make_unique<CBlockTemplate>(blockTemplate);
    }

    // Reset statistics
    m_stats.Reset();
    m_stats.nStartTime = GetTime();

    // Start mining flag
    m_mining = true;

    // Start mining worker threads
    m_workers.clear();
    m_workers.reserve(m_nThreads);
    for (uint32_t i = 0; i < m_nThreads; ++i) {
        m_workers.emplace_back(&CMiningController::MiningWorker, this, i);
    }

    // Start hash rate monitoring thread
    m_monitoring = true;
    m_monitorThread = std::thread(&CMiningController::HashRateMonitor, this);

    return true;
}

void CMiningController::StopMining() {
    // Check if mining
    if (!m_mining) {
        return;
    }

    // Stop mining flag
    m_mining = false;
    m_monitoring = false;

    // Wait for worker threads
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();

    // Wait for monitoring thread
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    // Cleanup RandomX
    randomx_cleanup();
}

void CMiningController::UpdateTemplate(const CBlockTemplate& blockTemplate) {
    std::lock_guard<std::mutex> lock(m_templateMutex);
    m_pTemplate = std::make_unique<CBlockTemplate>(blockTemplate);
}

void CMiningController::SetBlockFoundCallback(std::function<void(const CBlock&)> callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_blockFoundCallback = callback;
}

bool CMiningController::CheckProofOfWork(const uint256& hash, const uint256& target) const {
    // Hash must be less than target
    return hash < target;
}

void CMiningController::MiningWorker(uint32_t threadId) {
    // Thread-local nonce range
    // Each thread gets its own range to avoid collisions
    const uint32_t nonceStep = m_nThreads;
    uint32_t nonce = threadId;

    // Hash buffer
    uint8_t hashBuffer[RANDOMX_HASH_SIZE];

    while (m_mining) {
        // Get current template
        CBlock block;
        uint256 hashTarget;
        {
            std::lock_guard<std::mutex> lock(m_templateMutex);
            if (!m_pTemplate) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            block = m_pTemplate->block;
            hashTarget = m_pTemplate->hashTarget;
        }

        // Try nonce
        block.nNonce = nonce;

        // Serialize block header for hashing
        std::vector<uint8_t> header;
        header.reserve(80); // Standard block header size

        // Serialize: version (4) + prevBlock (32) + merkleRoot (32) + time (4) + bits (4) + nonce (4)
        // Simple serialization - in production would use CDataStream
        const uint8_t* versionBytes = reinterpret_cast<const uint8_t*>(&block.nVersion);
        header.insert(header.end(), versionBytes, versionBytes + 4);
        header.insert(header.end(), block.hashPrevBlock.begin(), block.hashPrevBlock.end());
        header.insert(header.end(), block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
        const uint8_t* timeBytes = reinterpret_cast<const uint8_t*>(&block.nTime);
        header.insert(header.end(), timeBytes, timeBytes + 4);
        const uint8_t* bitsBytes = reinterpret_cast<const uint8_t*>(&block.nBits);
        header.insert(header.end(), bitsBytes, bitsBytes + 4);
        const uint8_t* nonceBytes = reinterpret_cast<const uint8_t*>(&block.nNonce);
        header.insert(header.end(), nonceBytes, nonceBytes + 4);

        // Compute RandomX hash
        try {
            randomx_hash_fast(header.data(), header.size(), hashBuffer);

            // Convert to uint256
            uint256 hash;
            std::memcpy(hash.begin(), hashBuffer, RANDOMX_HASH_SIZE);

            // Update hash counter
            m_stats.nHashesComputed++;

            // Check if valid block
            if (CheckProofOfWork(hash, hashTarget)) {
                // Found valid block!
                m_stats.nBlocksFound++;

                // Call callback if set
                {
                    std::lock_guard<std::mutex> lock(m_callbackMutex);
                    if (m_blockFoundCallback) {
                        m_blockFoundCallback(block);
                    }
                }

                // Continue mining (in production, would update template)
            }
        } catch (...) {
            // RandomX error - continue mining
        }

        // Increment nonce for this thread
        nonce += nonceStep;
    }
}

void CMiningController::HashRateMonitor() {
    uint64_t lastHashes = 0;
    uint64_t lastTime = GetTimeMillis();

    while (m_monitoring) {
        // Sleep for 1 second
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Calculate hash rate
        uint64_t currentHashes = m_stats.nHashesComputed;
        uint64_t currentTime = GetTimeMillis();

        uint64_t hashDelta = currentHashes - lastHashes;
        uint64_t timeDelta = currentTime - lastTime;

        if (timeDelta > 0) {
            // Hashes per second
            uint64_t hashRate = (hashDelta * 1000) / timeDelta;
            m_stats.nLastHashRate = hashRate;
        }

        lastHashes = currentHashes;
        lastTime = currentTime;
    }
}
