// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_GENESIS_H
#define DILITHION_NODE_GENESIS_H

#include <primitives/block.h>
#include <uint256.h>

/**
 * Genesis Block Parameters
 *
 * The genesis block is the first block in the Dilithion blockchain.
 * It is hardcoded and must be identical across all nodes.
 *
 * Launch: January 1, 2026 00:00:00 UTC
 */
namespace Genesis {

// Genesis block timestamp (Unix time)
// January 1, 2026 00:00:00 UTC
const uint32_t TIMESTAMP = 1767225600;

// Genesis block version
const int32_t VERSION = 1;

// Genesis block difficulty target (nBits)
// This represents the initial mining difficulty
// Format: compact representation of 256-bit target
// 0x1d00ffff = difficulty 1 (Bitcoin's genesis difficulty)
const uint32_t NBITS = 0x1d00ffff;

// Genesis block nonce
// This will be found by mining the genesis block
// Placeholder until we mine it
const uint32_t NONCE = 0;

// Genesis coinbase message
// Traditional: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
// Dilithion: Reference to quantum computing threat + People's Coin mission
extern const char* COINBASE_MESSAGE;

/**
 * Create the genesis block
 *
 * This function creates the genesis block with the hardcoded parameters.
 * The genesis block has:
 * - No previous block (hashPrevBlock = 0)
 * - Empty merkle root (or hash of coinbase message)
 * - Timestamp: January 1, 2026 00:00:00 UTC
 * - Initial difficulty target
 * - Specific nonce (found by mining)
 *
 * @return The genesis block
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
