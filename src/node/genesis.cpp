// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/genesis.h>
#include <primitives/transaction.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <consensus/pow.h>
#include <core/chainparams.h>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

namespace Genesis {

CBlock CreateGenesisBlock() {
    // Ensure chain parameters are initialized
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized. Call InitChainParams() first.");
    }

    CBlock genesis;

    // Set header fields from chain parameters
    genesis.nVersion = VERSION;
    genesis.hashPrevBlock = uint256();  // All zeros (no previous block)
    genesis.nTime = Dilithion::g_chainParams->genesisTime;
    genesis.nBits = Dilithion::g_chainParams->genesisNBits;
    genesis.nNonce = Dilithion::g_chainParams->genesisNonce;

    // =========================================================================
    // BUG #4 FIX: Create proper coinbase transaction
    // =========================================================================
    // Following Bitcoin Core's pattern, genesis coinbase is a real transaction
    // that can be deserialized and validated like any other coinbase.
    //
    // Structure:
    // - 1 input with null prevout (standard for coinbase)
    // - scriptSig contains block height (0) + genesis message
    // - 1 output with 5 billion satoshi subsidy to unspendable address
    // - Transaction is serialized and stored in block.vtx
    // - Merkle root = hash of this single transaction

    CTransaction coinbaseTx;
    coinbaseTx.nVersion = 1;

    // Input: Null prevout (standard for coinbase)
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();  // Marks this as coinbase
    coinbaseTx.vin[0].nSequence = 0xFFFFFFFF;

    // scriptSig: Height (0) + genesis message
    // Following BIP34 pattern for height encoding
    std::vector<uint8_t> scriptSigData;
    scriptSigData.push_back(0);  // Height 0 for genesis
    const std::string& genesisMsg = Dilithion::g_chainParams->genesisCoinbaseMsg;
    scriptSigData.insert(scriptSigData.end(), genesisMsg.begin(), genesisMsg.end());
    coinbaseTx.vin[0].scriptSig = scriptSigData;

    // Output: 5 billion ions (matching miner subsidy)
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].nValue = 5000000000ULL;  // 50 DLT (5 billion ions)

    // scriptPubKey: OP_RETURN (unspendable)
    // Genesis coins are traditionally unspendable
    coinbaseTx.vout[0].scriptPubKey.push_back(0x6a);  // OP_RETURN opcode

    coinbaseTx.nLockTime = 0;

    // Serialize the transaction
    std::vector<uint8_t> serializedTx = coinbaseTx.Serialize();

    // BUG #7 FIX: Store transaction with count prefix
    // DeserializeBlockTransactions expects: [count][tx1][tx2]...
    // Genesis has 1 transaction, so prefix with count=1
    genesis.vtx.clear();
    genesis.vtx.push_back(1);  // Transaction count = 1
    genesis.vtx.insert(genesis.vtx.end(), serializedTx.begin(), serializedTx.end());

    // Calculate merkle root from transaction hash
    // Genesis block has only 1 transaction, so merkle root = transaction hash
    genesis.hashMerkleRoot = coinbaseTx.GetHash();

    return genesis;
}

uint256 GetGenesisHash() {
    static uint256 hash;
    static bool initialized = false;

    if (!initialized) {
        CBlock genesis = CreateGenesisBlock();
        hash = genesis.GetHash();
        initialized = true;
    }

    return hash;
}

bool IsGenesisBlock(const CBlock& block) {
    // Ensure chain parameters are initialized
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    // Check all genesis block fields
    if (block.nVersion != VERSION) return false;
    if (!block.hashPrevBlock.IsNull()) return false;
    if (block.nTime != Dilithion::g_chainParams->genesisTime) return false;
    if (block.nBits != Dilithion::g_chainParams->genesisNBits) return false;

    // Check merkle root matches expected
    CBlock genesis = CreateGenesisBlock();
    if (!(block.hashMerkleRoot == genesis.hashMerkleRoot)) return false;

    return true;
}

// Global state for multi-threaded mining
static std::atomic<bool> g_found{false};
static std::atomic<uint64_t> g_totalHashes{0};
static std::mutex g_resultMutex;
static uint32_t g_winningNonce = 0;
static uint256 g_winningHash;

// Serialize block header to 80 bytes (for thread-safe hashing)
static void SerializeBlockHeader(const CBlock& block, uint32_t nonce, std::vector<uint8_t>& data) {
    data.clear();
    data.reserve(80);

    // version (4) + prevBlock (32) + merkleRoot (32) + time (4) + bits (4) + nonce (4) = 80
    const uint8_t* versionBytes = reinterpret_cast<const uint8_t*>(&block.nVersion);
    data.insert(data.end(), versionBytes, versionBytes + 4);
    data.insert(data.end(), block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    data.insert(data.end(), block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
    const uint8_t* timeBytes = reinterpret_cast<const uint8_t*>(&block.nTime);
    data.insert(data.end(), timeBytes, timeBytes + 4);
    const uint8_t* bitsBytes = reinterpret_cast<const uint8_t*>(&block.nBits);
    data.insert(data.end(), bitsBytes, bitsBytes + 4);
    const uint8_t* nonceBytes = reinterpret_cast<const uint8_t*>(&nonce);
    data.insert(data.end(), nonceBytes, nonceBytes + 4);
}

void MineWorker(int threadId, int numThreads, const CBlock& templateBlock, const uint256& target) {
    // Each thread searches a different part of the nonce space
    uint32_t start = (uint32_t)(((uint64_t)0xFFFFFFFF * threadId) / numThreads);
    uint32_t end = (uint32_t)(((uint64_t)0xFFFFFFFF * (threadId + 1)) / numThreads);

    // Create per-thread RandomX VM for true parallel mining
    void* vm = randomx_create_thread_vm();
    if (!vm) {
        std::cerr << "[Thread " << threadId << "] Failed to create VM" << std::endl;
        return;
    }

    std::vector<uint8_t> headerData;
    uint64_t localHashes = 0;

    for (uint32_t nonce = start; nonce < end && !g_found.load(); ++nonce) {
        // Serialize header with current nonce
        SerializeBlockHeader(templateBlock, nonce, headerData);

        // Hash with thread-local VM (no mutex, fully parallel)
        uint256 hash;
        randomx_hash_thread(vm, headerData.data(), headerData.size(), hash.data);
        localHashes++;

        if (HashLessThan(hash, target)) {
            // Found a valid nonce!
            std::lock_guard<std::mutex> lock(g_resultMutex);
            if (!g_found.load()) {  // Double-check under lock
                g_found.store(true);
                g_winningNonce = nonce;
                g_winningHash = hash;
            }
            break;
        }

        // Update global counter periodically
        if (localHashes % 1000 == 0) {
            g_totalHashes.fetch_add(1000);
        }
    }

    // Add remaining hashes to global counter
    g_totalHashes.fetch_add(localHashes % 1000);

    // Cleanup thread-local VM
    randomx_destroy_thread_vm(vm);
}

bool MineGenesisBlock(CBlock& block, const uint256& target, int numThreads) {
    std::cout << "Mining genesis block..." << std::endl;
    std::cout << "Target: " << target.GetHex() << std::endl;
    std::cout << "Using " << numThreads << " threads..." << std::endl;

    // Reset global state
    g_found.store(false);
    g_totalHashes.store(0);
    g_winningNonce = 0;
    g_winningHash = uint256();

    // Launch worker threads
    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(MineWorker, i, numThreads, std::cref(block), std::cref(target));
    }

    // Progress reporting in main thread
    while (!g_found.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\rHashes: " << g_totalHashes.load() << std::flush;
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();
    }

    if (g_found.load()) {
        block.nNonce = g_winningNonce;
        block.InvalidateCache();

        std::cout << "\n\nGenesis block found!" << std::endl;
        std::cout << "Nonce: " << g_winningNonce << std::endl;
        std::cout << "Hash: " << g_winningHash.GetHex() << std::endl;
        std::cout << "Hashes tried: " << g_totalHashes.load() << std::endl;

        // Verify the found nonce passes consensus validation
        std::cout << "Verifying with consensus rules..." << std::endl;
        if (!CheckProofOfWork(g_winningHash, block.nBits)) {
            std::cout << "ERROR: Found nonce does NOT pass CheckProofOfWork!" << std::endl;
            return false;
        }
        std::cout << "Verification passed! Genesis block is valid." << std::endl;

        return true;
    }

    std::cout << "\nFailed to find valid nonce" << std::endl;
    return false;
}

// Backward compatible overload
bool MineGenesisBlock(CBlock& block, const uint256& target) {
    return MineGenesisBlock(block, target, 1);
}

} // namespace Genesis
