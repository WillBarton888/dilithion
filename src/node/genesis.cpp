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

bool MineGenesisBlock(CBlock& block, const uint256& target) {
    std::cout << "Mining genesis block..." << std::endl;
    std::cout << "Target: " << target.GetHex() << std::endl;
    std::cout << "This may take a while..." << std::endl;

    uint64_t nHashesTried = 0;
    const uint64_t REPORT_INTERVAL = 10000;

    // Try different nonces until we find one that meets the target
    for (uint32_t nonce = 0; nonce < 0xFFFFFFFF; ++nonce) {
        block.nNonce = nonce;
        block.InvalidateCache();  // CRITICAL: Must invalidate cache after changing nonce

        // Calculate hash
        uint256 hash = block.GetHash();

        // Check if hash is less than target (BIG-ENDIAN comparison for PoW)
        if (HashLessThan(hash, target)) {
            std::cout << "\nGenesis block found!" << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Hash: " << hash.GetHex() << std::endl;
            std::cout << "Hashes tried: " << nHashesTried << std::endl;

            // Verify the found nonce passes consensus validation
            std::cout << "Verifying with consensus rules..." << std::endl;
            if (!CheckProofOfWork(hash, block.nBits)) {
                std::cout << "ERROR: Found nonce does NOT pass CheckProofOfWork!" << std::endl;
                std::cout << "This indicates a bug in the mining code." << std::endl;
                return false;
            }
            std::cout << "Verification passed! Genesis block is valid." << std::endl;

            return true;
        }

        nHashesTried++;

        // Report progress
        if (nHashesTried % REPORT_INTERVAL == 0) {
            std::cout << "\rHashes: " << nHashesTried << std::flush;
        }
    }

    std::cout << "\nFailed to find valid nonce" << std::endl;
    return false;
}

} // namespace Genesis
