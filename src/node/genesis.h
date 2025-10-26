// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_GENESIS_H
#define DILITHION_NODE_GENESIS_H

#include <primitives/block.h>
#include <uint256.h>
#include <core/chainparams.h>

/**
 * Genesis Block Parameters
 *
 * The genesis block is the first block in the Dilithion blockchain.
 * It is hardcoded and must be identical across all nodes.
 *
 * Parameters are network-specific (mainnet vs testnet) and defined in ChainParams.
 */
namespace Genesis {

// Genesis block version (constant across all networks)
const int32_t VERSION = 1;

/**
 * Create the genesis block
 *
 * This function creates the genesis block using parameters from g_chainParams.
 * The genesis block has:
 * - No previous block (hashPrevBlock = 0)
 * - Merkle root from coinbase transaction
 * - Timestamp from ChainParams
 * - Difficulty target from ChainParams
 * - Nonce from ChainParams (0 if not yet mined)
 *
 * @return The genesis block for the current network
 */
CBlock CreateGenesisBlock();

/**
 * Get the genesis block hash
 *
 * This is the hash of the genesis block after it has been mined.
 * It must match across all nodes.
 *
 * @return The genesis block hash
 */
uint256 GetGenesisHash();

/**
 * Verify a block is the genesis block
 *
 * @param block Block to verify
 * @return true if the block is the genesis block
 */
bool IsGenesisBlock(const CBlock& block);

/**
 * Mine the genesis block
 *
 * This function mines the genesis block by finding a valid nonce.
 * It should only be called once during initial setup.
 *
 * WARNING: This can take a long time depending on the difficulty target.
 *
 * @param block Genesis block to mine
 * @param target Target hash value (derived from nBits)
 * @return true if a valid nonce was found
 */
bool MineGenesisBlock(CBlock& block, const uint256& target);

} // namespace Genesis

#endif // DILITHION_NODE_GENESIS_H
