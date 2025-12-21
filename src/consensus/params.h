// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_PARAMS_H
#define DILITHION_CONSENSUS_PARAMS_H

#include <amount.h>
#include <cstdint>

/**
 * Consensus Parameters
 *
 * This file contains all consensus-critical constants for the Dilithion blockchain.
 * These parameters define the economic model, security limits, and network behavior.
 *
 * CRITICAL: Changing these values creates incompatible consensus rules.
 * All nodes must use identical values for network consensus.
 */

namespace Consensus {

//==============================================================================
// Block Reward Parameters
//==============================================================================

/** Initial block subsidy in ions (50 DIL) */
static const CAmount INITIAL_BLOCK_SUBSIDY = 50 * COIN;

/** Number of blocks between subsidy halvings (~1.6 years at 4-min blocks) */
static const uint32_t SUBSIDY_HALVING_INTERVAL = 210000;

/** Stop halving after this many halvings (64 halvings = ~102 years) */
static const int SUBSIDY_HALVING_BITS = 64;

/** Minimum coinbase maturity (blocks before coinbase can be spent) */
static const unsigned int COINBASE_MATURITY = 100;

//==============================================================================
// Network Protocol Limits
//==============================================================================

/** Maximum inventory items per message (prevents DoS) */
static const unsigned int MAX_INV_SIZE = 50000;

/** Maximum Base58 string length (prevents memory exhaustion) */
static const size_t MAX_BASE58_LENGTH = 1024;

/** Maximum RPC request size in bytes (1 MB limit) */
static const size_t MAX_REQUEST_SIZE = 1024 * 1024;

/** Maximum block size in bytes (1 MB, same as early Bitcoin) */
static const size_t MAX_BLOCK_SIZE = 1000000;

//==============================================================================
// Port Range Validation
//==============================================================================

/** Minimum valid port number */
static const int MIN_PORT = 1;

/** Maximum valid port number */
static const int MAX_PORT = 65535;

/** Default P2P port for mainnet */
static const uint16_t DEFAULT_P2P_PORT = 8444;

/** Default RPC port for mainnet */
static const uint16_t DEFAULT_RPC_PORT = 8445;

/** Default P2P port for testnet */
static const uint16_t DEFAULT_TESTNET_P2P_PORT = 18444;

/** Default RPC port for testnet */
static const uint16_t DEFAULT_TESTNET_RPC_PORT = 18445;

//==============================================================================
// Mining Parameters
//==============================================================================

/** Minimum mining threads */
static const int MIN_MINING_THREADS = 1;

/** Maximum mining threads (reasonable upper bound) */
static const int MAX_MINING_THREADS = 256;

/** Target block time in seconds (4 minutes) */
static const int64_t TARGET_BLOCK_TIME = 240;

/** Difficulty adjustment interval in blocks */
static const int DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;

//==============================================================================
// Chain Security Parameters
//==============================================================================

/** Maximum allowed chain reorganization depth (similar to Bitcoin's practical limit) */
static const int MAX_REORG_DEPTH = 100;

/** Maximum number of block headers to process in one message */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

/** Maximum number of blocks to keep in flight per peer */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 128;

//==============================================================================
// P2P Network Parameters
//==============================================================================

/** Maximum number of outbound connections */
static const int MAX_OUTBOUND_CONNECTIONS = 8;

/** Maximum number of inbound connections */
static const int MAX_INBOUND_CONNECTIONS = 117;

/** Maximum total connections (8 outbound + 117 inbound = 125 total, similar to Bitcoin) */
static const int MAX_CONNECTIONS = MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS;

/** Peer connection timeout in seconds */
static const int PEER_CONNECT_TIMEOUT = 60;

/** Peer handshake timeout in seconds */
static const int PEER_HANDSHAKE_TIMEOUT = 60;

//==============================================================================
// Mempool Parameters
//==============================================================================

/** Maximum number of transactions in mempool */
static const size_t MAX_MEMPOOL_SIZE = 300000000;  // 300 MB

/** Minimum transaction fee per kilobyte (in ions) */
static const CAmount MIN_TX_FEE_PER_KB = 1000;  // 0.00001 DIL per KB

/** Maximum transaction size in bytes */
static const size_t MAX_TX_SIZE = 100000;  // 100 KB

//==============================================================================
// Script and Transaction Limits
//==============================================================================

/** Maximum number of signature operations per transaction */
static const unsigned int MAX_TX_SIGOPS = 20000;

/** Maximum script size in bytes */
static const size_t MAX_SCRIPT_SIZE = 10000;

/** Maximum number of transaction inputs */
static const size_t MAX_TX_INPUTS = 100000;

/** Maximum number of transaction outputs */
static const size_t MAX_TX_OUTPUTS = 100000;

//==============================================================================
// Cryptographic Constants
//==============================================================================

/** Dilithium3 public key size in bytes */
static const size_t DILITHIUM3_PUBKEY_SIZE = 1952;

/** Dilithium3 signature size in bytes */
static const size_t DILITHIUM3_SIGNATURE_SIZE = 3309;

/** Dilithium3 private key size in bytes */
static const size_t DILITHIUM3_PRIVKEY_SIZE = 4000;

/** SHA3-256 hash output size in bytes */
static const size_t SHA3_256_SIZE = 32;

//==============================================================================
// Time Constants
//==============================================================================

/** Maximum future block timestamp (2 hours) */
static const int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/** Maximum block timestamp drift (median time of past 11 blocks) */
static const int MEDIAN_TIME_SPAN = 11;

} // namespace Consensus

#endif // DILITHION_CONSENSUS_PARAMS_H
