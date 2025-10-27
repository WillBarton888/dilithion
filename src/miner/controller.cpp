// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <miner/controller.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <consensus/pow.h>
#include <consensus/tx_validation.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <util/time.h>
#include <amount.h>

#include <thread>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <set>

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

    // Initialize RandomX cache with constant key
    // Using same key as node startup for consistency
    const char* rx_key = "Dilithion";
    randomx_init_cache(rx_key, strlen(rx_key));

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
    // Hash must be less than target (using big-endian comparison for PoW)
    // CRITICAL: Must use HashLessThan(), NOT operator<
    // operator< uses memcmp (little-endian byte order)
    // PoW requires big-endian comparison (MSB first)
    return HashLessThan(hash, target);
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
                // Double-check mining flag to prevent race during shutdown
                // If StopMining() was called between finding block and this check,
                // discard the block to prevent database corruption
                if (!m_mining) {
                    break;  // Shutdown in progress, exit immediately
                }

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

// ============================================================================
// Phase 5.4: Mining Integration - Transaction Selection and Block Assembly
// ============================================================================

uint64_t CMiningController::CalculateBlockSubsidy(uint32_t nHeight) const {
    // Initial subsidy: 50 DIL = 50 * COIN = 50 * 100,000,000 ions
    uint64_t nSubsidy = 50 * COIN;

    // Halving interval: 210,000 blocks (same as Bitcoin)
    const uint32_t nHalvingInterval = 210000;

    // Number of halvings that have occurred
    uint32_t nHalvings = nHeight / nHalvingInterval;

    // Subsidy goes to zero after 64 halvings (very far in future)
    if (nHalvings >= 64) {
        return 0;
    }

    // Apply halving: subsidy >> halvings
    nSubsidy >>= nHalvings;

    return nSubsidy;
}

CTransactionRef CMiningController::CreateCoinbaseTransaction(
    uint32_t nHeight,
    uint64_t totalFees,
    const std::vector<uint8_t>& minerAddress
) {
    // Calculate total coinbase value: subsidy + fees
    uint64_t nSubsidy = CalculateBlockSubsidy(nHeight);

    // Check for overflow when adding fees
    uint64_t nCoinbaseValue = nSubsidy;
    if (totalFees > 0) {
        if (nCoinbaseValue + totalFees < nCoinbaseValue) {
            // Overflow detected - cap at max value
            nCoinbaseValue = UINT64_MAX;
        } else {
            nCoinbaseValue += totalFees;
        }
    }

    // Create coinbase transaction
    CTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nLockTime = 0;

    // Coinbase input: null prevout with height in scriptSig
    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();

    // Encode height in scriptSig (BIP34-style)
    // Format: <height> <arbitrary data>
    std::string coinbaseMsg = "Block " + std::to_string(nHeight) + " - Dilithion";
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>(nHeight & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 8) & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 16) & 0xFF));
    coinbaseIn.scriptSig.push_back(static_cast<uint8_t>((nHeight >> 24) & 0xFF));
    coinbaseIn.scriptSig.insert(coinbaseIn.scriptSig.end(),
                                 coinbaseMsg.begin(), coinbaseMsg.end());

    coinbaseIn.nSequence = CTxIn::SEQUENCE_FINAL;
    coinbase.vin.push_back(coinbaseIn);

    // Coinbase output: pay to miner address
    CTxOut coinbaseOut;
    coinbaseOut.nValue = nCoinbaseValue;
    coinbaseOut.scriptPubKey = minerAddress;

    coinbase.vout.push_back(coinbaseOut);

    return MakeTransactionRef(coinbase);
}

uint256 CMiningController::BuildMerkleRoot(const std::vector<CTransactionRef>& transactions) const {
    if (transactions.empty()) {
        return uint256();  // Null hash for empty block
    }

    // Build merkle tree from transaction hashes
    std::vector<uint256> merkleTree;
    merkleTree.reserve(transactions.size());

    // Level 0: transaction hashes
    for (const auto& tx : transactions) {
        merkleTree.push_back(tx->GetHash());
    }

    // Build tree levels until we reach root
    size_t levelOffset = 0;
    for (size_t levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
        for (size_t i = 0; i < levelSize; i += 2) {
            size_t i2 = std::min(i + 1, levelSize - 1);

            // Concatenate two hashes
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i].begin(),
                          merkleTree[levelOffset + i].end());
            combined.insert(combined.end(),
                          merkleTree[levelOffset + i2].begin(),
                          merkleTree[levelOffset + i2].end());

            // Hash the combination (SHA3-256)
            uint256 hash;
            SHA3_256(combined.data(), combined.size(), hash.data);
            merkleTree.push_back(hash);
        }
        levelOffset += levelSize;
    }

    // Return root (last element in tree)
    return merkleTree.empty() ? uint256() : merkleTree.back();
}

std::vector<CTransactionRef> CMiningController::SelectTransactionsForBlock(
    CTxMemPool& mempool,
    CUTXOSet& utxoSet,
    size_t maxBlockSize,
    uint64_t& totalFees
) {
    std::vector<CTransactionRef> selectedTxs;
    totalFees = 0;

    // Reserve space for coinbase (conservative estimate: 200 bytes)
    size_t currentBlockSize = 200;

    // Maximum block size (1 MB)
    const size_t MAX_BLOCK_SIZE = maxBlockSize > 0 ? maxBlockSize : 1000000;

    // Get transactions ordered by fee rate (highest first)
    std::vector<CTransactionRef> candidateTxs = mempool.GetOrderedTxs();

    // Track which outpoints are spent in this block (to handle dependencies)
    std::set<COutPoint> spentInBlock;

    // Validator for checking transactions
    CTransactionValidator validator;

    // Select transactions greedily by fee rate
    for (const auto& tx : candidateTxs) {
        // Skip coinbase transactions (shouldn't be in mempool, but be safe)
        if (tx->IsCoinBase()) {
            continue;
        }

        // Calculate transaction size
        size_t txSize = tx->GetSerializedSize();

        // Check if transaction fits in block
        if (currentBlockSize + txSize > MAX_BLOCK_SIZE) {
            continue;  // Skip this transaction, try next
        }

        // Verify all inputs are available (either in UTXO set or created in this block)
        bool allInputsAvailable = true;
        bool hasConflict = false;

        for (const auto& txin : tx->vin) {
            // Check if input was spent in this block already (conflict)
            if (spentInBlock.count(txin.prevout) > 0) {
                hasConflict = true;
                break;
            }

            // Check if input exists in UTXO set
            CUTXOEntry utxoEntry;
            bool foundInUTXO = utxoSet.GetUTXO(txin.prevout, utxoEntry);

            // Check if input was created in this block
            bool foundInBlock = false;
            for (const auto& selectedTx : selectedTxs) {
                uint256 selectedTxHash = selectedTx->GetHash();
                if (selectedTxHash == txin.prevout.hash &&
                    txin.prevout.n < selectedTx->vout.size()) {
                    foundInBlock = true;
                    break;
                }
            }

            if (!foundInUTXO && !foundInBlock) {
                allInputsAvailable = false;
                break;
            }
        }

        // Skip transactions with conflicts or missing inputs
        if (hasConflict || !allInputsAvailable) {
            continue;
        }

        // Calculate transaction fee: sum(inputs) - sum(outputs)
        uint64_t txFee = 0;
        uint64_t inputSum = 0;
        for (const auto& input : tx->vin) {
            CUTXOEntry utxo;
            if (utxoSet.GetUTXO(input.prevout, utxo)) {
                inputSum += utxo.out.nValue;
            }
        }
        uint64_t outputSum = 0;
        for (const auto& output : tx->vout) {
            outputSum += output.nValue;
        }
        if (inputSum > outputSum) {
            txFee = inputSum - outputSum;
        }

        // Sanity check: fee should be reasonable (not more than 10 DIL)
        const uint64_t MAX_REASONABLE_FEE = 10 * COIN;
        if (txFee > MAX_REASONABLE_FEE) {
            continue;  // Skip suspiciously high fee transactions
        }

        // Add transaction to block
        selectedTxs.push_back(tx);
        currentBlockSize += txSize;

        // Check for overflow when adding fees
        if (totalFees + txFee < totalFees) {
            // Overflow - cap at current value
            break;
        }
        totalFees += txFee;

        // Mark inputs as spent in this block
        for (const auto& txin : tx->vin) {
            spentInBlock.insert(txin.prevout);
        }
    }

    return selectedTxs;
}

std::optional<CBlockTemplate> CMiningController::CreateBlockTemplate(
    CTxMemPool& mempool,
    CUTXOSet& utxoSet,
    const uint256& hashPrevBlock,
    uint32_t nHeight,
    uint32_t nBits,
    const std::vector<uint8_t>& minerAddress,
    std::string& error
) {
    // Validate inputs
    if (minerAddress.empty()) {
        error = "Invalid miner address (empty)";
        return std::nullopt;
    }

    if (hashPrevBlock.IsNull() && nHeight != 0) {
        error = "Invalid previous block hash for non-genesis block";
        return std::nullopt;
    }

    // Step 1: Select transactions from mempool
    uint64_t totalFees = 0;
    std::vector<CTransactionRef> selectedTxs = SelectTransactionsForBlock(
        mempool,
        utxoSet,
        1000000,  // 1 MB max block size
        totalFees
    );

    // Step 2: Create coinbase transaction
    CTransactionRef coinbaseTx = CreateCoinbaseTransaction(nHeight, totalFees, minerAddress);

    // Step 3: Build complete transaction list (coinbase first)
    std::vector<CTransactionRef> allTxs;
    allTxs.reserve(1 + selectedTxs.size());
    allTxs.push_back(coinbaseTx);
    allTxs.insert(allTxs.end(), selectedTxs.begin(), selectedTxs.end());

    // Step 4: Calculate merkle root
    uint256 hashMerkleRoot = BuildMerkleRoot(allTxs);

    // Step 5: Serialize all transactions into block.vtx
    // For now, CBlock.vtx is std::vector<uint8_t> representing raw transaction data
    // We'll serialize all transactions concatenated
    std::vector<uint8_t> blockTxData;

    // Serialize transaction count (compact size)
    uint64_t txCount = allTxs.size();
    if (txCount < 253) {
        blockTxData.push_back(static_cast<uint8_t>(txCount));
    } else if (txCount <= 0xFFFF) {
        blockTxData.push_back(253);
        blockTxData.push_back(static_cast<uint8_t>(txCount));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 8));
    } else {
        blockTxData.push_back(254);
        blockTxData.push_back(static_cast<uint8_t>(txCount));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 8));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 16));
        blockTxData.push_back(static_cast<uint8_t>(txCount >> 24));
    }

    // Serialize each transaction
    for (const auto& tx : allTxs) {
        std::vector<uint8_t> txData = tx->Serialize();
        blockTxData.insert(blockTxData.end(), txData.begin(), txData.end());
    }

    // Step 6: Build block header
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime = static_cast<uint32_t>(GetTime());
    block.nBits = nBits;
    block.nNonce = 0;  // Miner will increment this
    block.vtx = blockTxData;

    // Step 7: Calculate target from nBits
    uint256 hashTarget = CompactToBig(nBits);

    // Step 8: Create and return block template
    CBlockTemplate blockTemplate(block, hashTarget, nHeight);

    return blockTemplate;
}
