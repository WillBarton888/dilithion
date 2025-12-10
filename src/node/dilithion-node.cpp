// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Dilithion Node - Main Application
 *
 * Integrates all components:
 * - Phase 1: Blockchain storage, mempool, fees
 * - Phase 2: P2P networking
 * - Phase 3: Mining
 * - Phase 4: Wallet, RPC server
 *
 * Usage:
 *   dilithion-node [options]
 *     --datadir=<path>      Data directory (default: ~/.dilithion)
 *     --rpcport=<port>      RPC server port (default: 8332)
 *     --mine                Start mining automatically
 *     --threads=<n>         Mining threads (default: auto-detect)
 */

#include <node/blockchain_storage.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <node/genesis.h>
#include <node/block_index.h>
#include <consensus/params.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/tx_relay.h>
#include <net/socket.h>
#include <net/async_broadcaster.h>
#include <net/message_queue.h>  // BUG #125: Async message processing
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <net/node_state.h>  // BUG #69: Bitcoin Core-style per-peer state and stalling detection
#include <net/feeler.h>  // Bitcoin Core-style feeler connections
#include <net/connman.h>  // Phase 5: Event-driven connection manager
#include <api/http_server.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <core/chainparams.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <consensus/validation.h>  // CRITICAL-3 FIX: For CBlockValidator
#include <consensus/tx_validation.h>  // BUG #108 FIX: For CTransactionValidator
#include <consensus/chain_verifier.h>  // Chain integrity validation (Bug #17)
#include <crypto/randomx_hash.h>
#include <util/logging.h>  // Bitcoin Core-style logging
#include <util/stacktrace.h>  // Phase 2.2: Crash diagnostics
#include <util/config.h>  // Phase 10: Configuration system
#include <util/config_validator.h>  // UX: Configuration validation
#include <util/error_format.h>  // User experience: Better error messages
#include <util/bench.h>  // Performance: Benchmarking

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <sstream>  // For mnemonic display parsing
#include <memory>
#include <csignal>
#include <cstring>
#include <cassert>
#include <thread>
#include <chrono>
#include <atomic>
#include <optional>
#include <queue>  // CRITICAL-2 FIX: For iterative orphan resolution
#include <set>  // BUG #109 FIX: For tracking spent outpoints in block template
#include <filesystem>  // BUG #56: For wallet file existence check

#ifdef _WIN32
    #include <winsock2.h>   // For socket functions
    #include <ws2tcpip.h>   // For inet_pton
    #include <windows.h>    // For GlobalMemoryStatusEx (Bug #23 fix)
#else
    #include <arpa/inet.h>  // For inet_pton on Unix
    #include <netdb.h>      // For gethostname, getaddrinfo
    #include <unistd.h>     // For gethostname
#endif

// Windows API macro conflicts - undef after including headers
#ifdef _WIN32
    #ifdef SendMessage
        #undef SendMessage  // Windows defines this as SendMessageA/SendMessageW
    #endif
#endif

// Global chain state (defined in src/core/globals.cpp)
extern CChainState g_chainstate;

// Phase 1.2: NodeContext for centralized global state management (Bitcoin Core pattern)
#include <core/node_context.h>
#include <node/ibd_coordinator.h>  // Phase 5.1: IBD Coordinator
extern NodeContext g_node_context;

// Phase 5: Helper function to connect to a peer (for outbound connections)
// BUG #139 FIX: Don't send VERSION here - SocketHandler will send it
// after connection completes (STATE_CONNECTING -> STATE_CONNECTED)
// Can be called from any thread since it uses g_node_context
static int ConnectAndHandshake(const NetProtocol::CAddress& addr) {
    if (!g_node_context.connman || !g_node_context.peer_manager) {
        return -1;
    }
    CNode* pnode = g_node_context.connman->ConnectNode(addr);
    if (!pnode) {
        return -1;
    }
    // BUG #139: Don't send VERSION here - connection is still in progress
    // SocketHandler will detect connection completion and send VERSION
    return pnode->id;
}

// Global node state for signal handling (defined in src/core/globals.cpp)
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    std::atomic<uint64_t> template_version{0}; // BUG #109 FIX: Template version counter for race detection
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
    CWallet* wallet = nullptr;
    CSocket* p2p_socket = nullptr;
    CHttpServer* http_server = nullptr;
};
extern NodeState g_node_state;

// Phase 1.2: NodeContext for centralized global state management (Bitcoin Core pattern)
#include <core/node_context.h>
#include <node/ibd_coordinator.h>  // Phase 5.1: IBD Coordinator
extern NodeContext g_node_context;

// Global async broadcaster pointer (initialized in main)
CAsyncBroadcaster* g_async_broadcaster = nullptr;

// Phase 1.2: Global state now managed via NodeContext
// Legacy globals kept for backward compatibility during migration
// TODO: Remove after full migration to NodeContext
CHeadersManager* g_headers_manager = nullptr;
COrphanManager* g_orphan_manager = nullptr;
CBlockFetcher* g_block_fetcher = nullptr;

/**
 * BUG #69 FIX: Bitcoin Core-style Initial Block Download detection
 *
 * Replaces custom peer-height-based detection with Bitcoin Core's proven approach:
 * 1. LATCH MECHANISM - Once IBD=false, it stays false permanently (like Bitcoin Core)
 * 2. TIP TIMESTAMP - Primary criterion: tip < 24 hours old = exit IBD
 * 3. HEADERS AHEAD - Secondary: if headers ahead of tip, still downloading
 *
 * This fixes BUG #69 where IsInitialBlockDownload() couldn't distinguish between:
 * - "Waiting for peer handshakes to complete" (version=0)
 * - "Peers have completed handshake but are at height 0" (true bootstrap)
 *
 * The old condition `bestPeerHeight == 0 && peerCount > 0` incorrectly returned
 * IBD=true when all peers were legitimately at height 0.
 *
 * Bitcoin Core reference: src/validation.cpp IsInitialBlockDownload()
 */
bool IsInitialBlockDownload() {
    // LATCH MECHANISM: Once we exit IBD, we never re-enter
    // This prevents mining from being disabled by transient network conditions
    // (e.g., a peer reconnecting, a temporary network split)
    static std::atomic<bool> s_initial_download_complete{false};
    if (s_initial_download_complete.load(std::memory_order_relaxed)) {
        return false;  // Already exited IBD - stay out forever
    }

    const CBlockIndex* tip = g_chainstate.GetTip();

    // No tip = no chain = definitely IBD
    if (!tip) {
        return true;
    }

    int ourHeight = tip->nHeight;

    // BUG #94 FIX: Check headers and peers BEFORE tip time!
    // The tip time check can exit IBD permanently (via the latch), so we MUST verify
    // we're actually synced before allowing that. During IBD, each newly downloaded
    // block has a recent timestamp (because blocks are actively being mined on the
    // network), which would cause premature IBD exit if checked first.

    // PRIMARY CRITERION: Check if headers are ahead of chain tip
    // This check MUST come first to prevent premature IBD exit during sync
    if (g_node_context.headers_manager) {
        int headerHeight = g_node_context.headers_manager->GetBestHeight();
        if (headerHeight > ourHeight) {
            return true;  // Headers ahead = actively downloading = IBD mode
        }
    }

    // SECONDARY CRITERION: Check peer heights (but only if peers have completed handshake)
    // Use the new HasCompletedHandshakes() to distinguish "waiting" from "at height 0"
    if (g_node_context.peer_manager) {
        int bestPeerHeight = g_node_context.peer_manager->GetBestPeerHeight();
        size_t peerCount = g_node_context.peer_manager->GetConnectionCount();

        // If we have peers that are ahead of us, stay in IBD
        if (bestPeerHeight > ourHeight + 6) {
            return true;  // Peers have 6+ more blocks - we're behind
        }

        // BUG #69 FIX: Only wait for handshakes if peers haven't completed any yet
        // If HasCompletedHandshakes() returns true, peers ARE at height 0 legitimately
        if (peerCount > 0 && bestPeerHeight == 0 && !g_node_context.peer_manager->HasCompletedHandshakes()) {
            // Connections exist but NO peer has completed handshake - wait
            return true;
        }
    }

    // TERTIARY CRITERION: Is tip timestamp recent?
    // Only check this AFTER verifying we're not actively syncing (headers/peers checks).
    // If our chain tip is less than 24 hours old AND we passed the checks above, we're caught up.
    int64_t tipTime = tip->nTime;
    int64_t now = GetTime();
    const int64_t MAX_TIP_AGE = 24 * 60 * 60;  // 24 hours (same as Bitcoin Core)

    if (now - tipTime < MAX_TIP_AGE) {
        // Tip is recent AND we're synced - exit IBD permanently
        s_initial_download_complete.store(true, std::memory_order_relaxed);
        return false;
    }

    // If we get here:
    // - Tip exists but is stale (> 24 hours old)
    // - No headers ahead (not actively downloading)
    // - Either no peers, or peers completed handshake and are at similar height
    // This is likely a bootstrap scenario or stale network - allow mining
    s_initial_download_complete.store(true, std::memory_order_relaxed);
    return false;
}

// Signal handler for graceful shutdown
void SignalHandler(int signal) {
    LogPrintf(ALL, INFO, "Received signal %d, shutting down gracefully...", signal);
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    g_node_state.running = false;

        if (g_node_state.rpc_server) {
            g_node_state.rpc_server->Stop();
            std::cout << " ✓" << std::endl;
        }
    if (g_node_state.miner) {
        g_node_state.miner->StopMining();
    }
    if (g_node_state.p2p_socket) {
        g_node_state.p2p_socket->Close();
    }
    if (g_node_state.http_server) {
        g_node_state.http_server->Stop();
    }
}

// Parse command line arguments
struct NodeConfig {
    bool testnet = false;
    std::string datadir = "";       // Will be set based on network
    uint16_t rpcport = 0;           // Will be set based on network
    uint16_t p2pport = 0;           // Will be set based on network
    bool start_mining = false;
    int mining_threads = 0;         // 0 = auto-detect
    std::vector<std::string> connect_nodes;  // --connect nodes (exclusive)
    std::vector<std::string> add_nodes;      // --addnode nodes (additional)
    bool reindex = false;           // Phase 4.2: Rebuild block index from blocks on disk
    bool rescan = false;            // Phase 4.2: Rescan wallet transactions

    bool ParseArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg == "--testnet") {
                testnet = true;
            }
            else if (arg.find("--datadir=") == 0) {
                datadir = arg.substr(10);
            }
            else if (arg.find("--rpcport=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid port numbers
                try {
                    int port = std::stoi(arg.substr(10));
                    if (port < Consensus::MIN_PORT || port > Consensus::MAX_PORT) {
                        ErrorMessage error = CErrorFormatter::ConfigError("rpcport", 
                            "Port must be between " + std::to_string(Consensus::MIN_PORT) + 
                            " and " + std::to_string(Consensus::MAX_PORT));
                        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
                        return false;
                    }
                    rpcport = static_cast<uint16_t>(port);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid RPC port format (not a number): " << arg << std::endl;
                    return false;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: RPC port number out of range: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--port=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid port numbers
                try {
                    int port = std::stoi(arg.substr(7));
                    if (port < Consensus::MIN_PORT || port > Consensus::MAX_PORT) {
                        std::cerr << "Error: Invalid P2P port (must be " << Consensus::MIN_PORT
                                  << "-" << Consensus::MAX_PORT << "): " << arg << std::endl;
                        return false;
                    }
                    p2pport = static_cast<uint16_t>(port);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid P2P port format (not a number): " << arg << std::endl;
                    return false;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: P2P port number out of range: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--connect=") == 0) {
                connect_nodes.push_back(arg.substr(10));
            }
            else if (arg.find("--addnode=") == 0) {
                add_nodes.push_back(arg.substr(10));
            }
            else if (arg == "--mine") {
                start_mining = true;
            }
            else if (arg.find("--threads=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid thread count
                std::string threads_str = arg.substr(10);

                // Support "auto" for automatic thread detection
                if (threads_str == "auto" || threads_str == "AUTO") {
                    mining_threads = 0;  // 0 means auto-detect
                } else {
                    try {
                        int threads = std::stoi(threads_str);
                        if (threads < Consensus::MIN_MINING_THREADS || threads > Consensus::MAX_MINING_THREADS) {
                            std::cerr << "Error: Invalid thread count (must be " << Consensus::MIN_MINING_THREADS
                                      << "-" << Consensus::MAX_MINING_THREADS << " or 'auto'): " << arg << std::endl;
                            return false;
                        }
                        mining_threads = threads;
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Error: Invalid thread count (must be a number or 'auto'): " << arg << std::endl;
                        return false;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Error: Thread count number out of range: " << arg << std::endl;
                        return false;
                    }
                }
            }
            else if (arg == "--reindex" || arg == "-reindex") {
                // Phase 4.2: Rebuild block index from blocks on disk
                reindex = true;
            }
            else if (arg == "--rescan" || arg == "-rescan") {
                // Phase 4.2: Rescan wallet transactions
                rescan = true;
            }
            else if (arg == "--help" || arg == "-h") {
                return false;
            }
            else {
                std::cerr << "Unknown option: " << arg << std::endl;
                return false;
            }
        }
        return true;
    }

    void PrintUsage(const char* program) {
        std::cout << "Dilithion Node - Post-Quantum Cryptocurrency" << std::endl;
        std::cout << std::endl;
        std::cout << "Usage: " << program << " [options]" << std::endl;
        std::cout << std::endl;
        std::cout << "\033[1;32mQUICK START (Beginners):\033[0m" << std::endl;
        std::cout << "  " << program << "              No arguments = Auto-start testnet mining!" << std::endl;
        std::cout << "                            • Testnet mode" << std::endl;
        std::cout << "                            • Auto-connect to seed node" << std::endl;
        std::cout << "                            • Auto-detect CPU threads" << std::endl;
        std::cout << "                            • Start mining immediately" << std::endl;
        std::cout << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --testnet             Use testnet (production difficulty, ~60s blocks)" << std::endl;
        std::cout << "  --datadir=<path>      Data directory (default: network-specific)" << std::endl;
        std::cout << "  --port=<port>         P2P network port (default: network-specific)" << std::endl;
        std::cout << "  --rpcport=<port>      RPC server port (default: network-specific)" << std::endl;
        std::cout << "  --connect=<ip:port>   Connect to node (disables DNS seeds)" << std::endl;
        std::cout << "  --addnode=<ip:port>   Add node to connect to (repeatable)" << std::endl;
        std::cout << "  --mine                Start mining automatically" << std::endl;
        std::cout << "  --threads=<n|auto>    Mining threads (number or 'auto' to detect)" << std::endl;
        std::cout << "  --help, -h            Show this help message" << std::endl;
        std::cout << std::endl;
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Configuration file: dilithion.conf (in data directory)" << std::endl;
        std::cout << "  Environment variables: DILITHION_* (e.g., DILITHION_RPCPORT=8332)" << std::endl;
        std::cout << "  Priority: Command-line > Environment > Config file > Default" << std::endl;
        std::cout << std::endl;
        std::cout << "Network Defaults:" << std::endl;
        std::cout << "  Mainnet:  datadir=.dilithion         port=8444  rpcport=8332" << std::endl;
        std::cout << "  Testnet:  datadir=.dilithion-testnet port=18444 rpcport=18332" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  " << program << "                                                    (Quick start testnet)" << std::endl;
        std::cout << "  " << program << " --testnet --mine --threads=auto                     (Same as above)" << std::endl;
        std::cout << "  " << program << " --testnet --addnode=134.122.4.164:18444 --mine     (Connect to seed)" << std::endl;
        std::cout << "  " << program << " --testnet --mine --threads=4                        (4 CPU cores)" << std::endl;
        std::cout << std::endl;
        std::cout << "Post-Quantum Security Stack:" << std::endl;
        std::cout << "  Mining:      RandomX (CPU-friendly, ASIC-resistant)" << std::endl;
        std::cout << "  Signatures:  CRYSTALS-Dilithium3 (NIST PQC standard)" << std::endl;
        std::cout << "  Hashing:     SHA-3/Keccak-256 (quantum-resistant)" << std::endl;
        std::cout << std::endl;
    }
};

// Global coinbase transaction reference for mining callback
static CTransactionRef g_currentCoinbase;
static std::mutex g_coinbaseMutex;

/**
 * Build mining template for next block
 * @param blockchain Reference to blockchain database
 * @param wallet Reference to wallet (for coinbase reward address)
 * @param verbose If true, print detailed template information
 * @return Optional containing template if successful, nullopt if error
 */
std::optional<CBlockTemplate> BuildMiningTemplate(CBlockchainDB& blockchain, CWallet& wallet, bool verbose = false) {
    // Get blockchain tip to build on
    uint256 hashBestBlock;
    uint32_t nHeight = 0;

    // BUG #65 FIX: Add logging to diagnose template build failures
    std::cout << "[Mining] Building template - reading best block from DB..." << std::endl;

    if (!blockchain.ReadBestBlock(hashBestBlock)) {
        std::cerr << "[Mining] ERROR: Cannot read best block from blockchain database" << std::endl;
        return std::nullopt;
    }

    // BUG #65: Always log the best block hash for debugging
    std::cout << "[Mining] Building template on best block: "
              << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;

    if (verbose) {
        std::cout << "  Best block hash: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // Read best block index to get height and calculate next difficulty
    CBlockIndex bestIndex;
    const CBlockIndex* pindexPrev = nullptr;
    if (blockchain.ReadBlockIndex(hashBestBlock, bestIndex)) {
        nHeight = bestIndex.nHeight + 1;  // New block height
        pindexPrev = &bestIndex;  // For difficulty calculation
        if (verbose) {
            std::cout << "  Building on block height " << bestIndex.nHeight << std::endl;
            std::cout << "  Mining block height " << nHeight << std::endl;
        }
    } else {
        if (verbose) {
            std::cout << "  WARNING: Cannot read block index for best block" << std::endl;
            std::cout << "  Assuming best block is genesis, mining block 1" << std::endl;
        }
        nHeight = 1;  // Mining block 1 (after genesis at 0)
        pindexPrev = nullptr;  // Will use genesis difficulty
    }

    // Create block header
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = hashBestBlock;
    // CID 1675302 FIX: Use safe 64-to-32 bit time conversion
    // Block timestamps are uint32_t per blockchain protocol (valid until year 2106)
    time_t currentTime = std::time(nullptr);
    block.nTime = static_cast<uint32_t>(currentTime & 0xFFFFFFFF);
    block.nBits = GetNextWorkRequired(pindexPrev);
    block.nNonce = 0;

    // Get wallet address for coinbase reward
    CDilithiumAddress minerAddress = wallet.GetNewAddress();
    std::vector<uint8_t> minerPubKeyHash = wallet.GetPubKeyHash();

    // Calculate block subsidy using consensus parameters
    int64_t nSubsidy = Consensus::INITIAL_BLOCK_SUBSIDY;
    int nHalvings = nHeight / Consensus::SUBSIDY_HALVING_INTERVAL;
    if (nHalvings >= Consensus::SUBSIDY_HALVING_BITS) {
        nSubsidy = 0;
    } else {
        nSubsidy >>= nHalvings;
    }

    // Create coinbase transaction
    CTransaction coinbaseTx;
    coinbaseTx.nVersion = 1;
    coinbaseTx.nLockTime = 0;

    // Coinbase input (null prevout)
    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();
    std::string coinbaseMsg = "Block " + std::to_string(nHeight) + " mined by Dilithion";
    coinbaseIn.scriptSig.resize(coinbaseMsg.size());
    memcpy(coinbaseIn.scriptSig.data(), coinbaseMsg.c_str(), coinbaseMsg.size());
    coinbaseIn.nSequence = 0xffffffff;
    coinbaseTx.vin.push_back(coinbaseIn);

    // BUG #109 FIX: Include mempool transactions in mined blocks
    // Previously, this function only included the coinbase transaction.
    // Now we select valid transactions from mempool just like CreateBlockTemplate does.

    // Load mempool and UTXO set from global atomic pointers
    CTxMemPool* mempool = g_mempool.load();
    CUTXOSet* utxoSet = g_utxo_set.load();

    // Select transactions from mempool if available
    std::vector<CTransactionRef> selectedTxs;
    uint64_t totalFees = 0;

    // DEBUG: Log mempool and UTXO set state
    std::cout << "[BuildMiningTemplate] DEBUG: mempool=" << (mempool ? "valid" : "NULL")
              << ", utxoSet=" << (utxoSet ? "valid" : "NULL") << std::endl;

    if (mempool && utxoSet) {
        // Get transactions ordered by fee rate (highest first)
        std::vector<CTransactionRef> candidateTxs = mempool->GetOrderedTxs();

        std::cout << "[BuildMiningTemplate] DEBUG: candidateTxs.size()=" << candidateTxs.size() << std::endl;

        // Limit candidates and set resource limits
        const size_t MAX_CANDIDATES = 50000;
        const size_t MAX_BLOCK_SIZE = 1000000;  // 1 MB
        size_t currentBlockSize = 200;  // Reserve for coinbase

        if (candidateTxs.size() > MAX_CANDIDATES) {
            candidateTxs.resize(MAX_CANDIDATES);
        }

        std::set<COutPoint> spentInBlock;
        CTransactionValidator validator;

        for (const auto& tx : candidateTxs) {
            if (tx->IsCoinBase()) continue;

            size_t txSize = tx->GetSerializedSize();
            if (currentBlockSize + txSize > MAX_BLOCK_SIZE) continue;

            // ========================================================================
            // BUG #109 FIX (Part 4): Enhanced input availability logging
            // ========================================================================
            // Check inputs are available and not double-spent in this block
            bool allInputsAvailable = true;
            bool hasConflict = false;
            std::string missingInputInfo;  // For detailed logging

            for (const auto& txin : tx->vin) {
                if (spentInBlock.count(txin.prevout) > 0) {
                    hasConflict = true;
                    missingInputInfo = "input " + txin.prevout.hash.GetHex().substr(0, 16) +
                                      ":" + std::to_string(txin.prevout.n) + " already spent in this block";
                    break;
                }

                CUTXOEntry utxoEntry;
                bool foundInUTXO = utxoSet->GetUTXO(txin.prevout, utxoEntry);

                bool foundInBlock = false;
                for (const auto& selectedTx : selectedTxs) {
                    if (selectedTx->GetHash() == txin.prevout.hash &&
                        txin.prevout.n < selectedTx->vout.size()) {
                        foundInBlock = true;
                        break;
                    }
                }

                if (!foundInUTXO && !foundInBlock) {
                    allInputsAvailable = false;
                    missingInputInfo = "input " + txin.prevout.hash.GetHex().substr(0, 16) +
                                      ":" + std::to_string(txin.prevout.n) +
                                      " NOT in UTXO set and NOT in selected block txs";
                    break;
                }
            }

            if (hasConflict || !allInputsAvailable) {
                std::cout << "[BuildMiningTemplate] DEBUG: TX " << tx->GetHash().GetHex().substr(0, 16)
                          << " rejected: " << missingInputInfo << std::endl;
                continue;
            }

            // Validate transaction (signature, coinbase maturity, etc.)
            std::string validationError;
            CAmount txFee = 0;
            if (!validator.CheckTransaction(*tx, *utxoSet, nHeight, txFee, validationError)) {
                std::cout << "[BuildMiningTemplate] DEBUG: TX " << tx->GetHash().GetHex().substr(0, 16)
                          << " FAILED CheckTransaction: " << validationError << std::endl;
                continue;
            }

            // Sanity check on fee
            const uint64_t MAX_REASONABLE_FEE = 10 * COIN;
            if (txFee > MAX_REASONABLE_FEE) continue;

            // Add transaction to block
            selectedTxs.push_back(tx);
            currentBlockSize += txSize;
            totalFees += static_cast<uint64_t>(txFee);

            std::cout << "[BuildMiningTemplate] DEBUG: TX " << tx->GetHash().GetHex().substr(0, 16)
                      << " SELECTED for block (fee=" << txFee << ")" << std::endl;

            // Mark inputs as spent
            for (const auto& txin : tx->vin) {
                spentInBlock.insert(txin.prevout);
            }
        }

        if (!selectedTxs.empty()) {
            std::cout << "[Mining] Including " << selectedTxs.size()
                      << " mempool transactions, fees: " << totalFees << " ions" << std::endl;
        }
    }

    // Coinbase output (reward to miner = subsidy + fees)
    CTxOut coinbaseOut;
    coinbaseOut.nValue = nSubsidy + static_cast<int64_t>(totalFees);
    coinbaseOut.scriptPubKey = WalletCrypto::CreateScriptPubKey(minerPubKeyHash);
    coinbaseTx.vout.push_back(coinbaseOut);

    // Store coinbase transaction globally for callback access
    {
        std::lock_guard<std::mutex> lock(g_coinbaseMutex);
        g_currentCoinbase = MakeTransactionRef(coinbaseTx);
    }

    // BUG #109 FIX: Serialize ALL transactions (coinbase + mempool) with proper count
    size_t txCount = 1 + selectedTxs.size();  // coinbase + selected transactions

    std::vector<uint8_t> coinbaseData = coinbaseTx.Serialize();
    block.vtx.clear();

    // Estimate total size and reserve
    size_t totalSize = 1 + coinbaseData.size();  // count + coinbase
    for (const auto& tx : selectedTxs) {
        totalSize += tx->GetSerializedSize();
    }
    block.vtx.reserve(totalSize + 10);

    // Write transaction count (compact size encoding)
    if (txCount < 253) {
        block.vtx.push_back(static_cast<uint8_t>(txCount));
    } else if (txCount <= 0xFFFF) {
        block.vtx.push_back(253);
        block.vtx.push_back(txCount & 0xFF);
        block.vtx.push_back((txCount >> 8) & 0xFF);
    } else {
        block.vtx.push_back(254);
        block.vtx.push_back(txCount & 0xFF);
        block.vtx.push_back((txCount >> 8) & 0xFF);
        block.vtx.push_back((txCount >> 16) & 0xFF);
        block.vtx.push_back((txCount >> 24) & 0xFF);
    }

    // Add coinbase transaction
    block.vtx.insert(block.vtx.end(), coinbaseData.begin(), coinbaseData.end());

    // Add all selected transactions
    for (const auto& tx : selectedTxs) {
        std::vector<uint8_t> txData = tx->Serialize();
        block.vtx.insert(block.vtx.end(), txData.begin(), txData.end());
    }

    // BUG #109 FIX: Calculate merkle root from ALL transaction hashes
    // Build vector of all transactions for merkle computation
    std::vector<CTransactionRef> allTransactions;
    allTransactions.reserve(1 + selectedTxs.size());
    allTransactions.push_back(MakeTransactionRef(coinbaseTx));
    for (const auto& tx : selectedTxs) {
        allTransactions.push_back(tx);
    }

    // Use CBlockValidator to compute merkle root properly
    CBlockValidator blockValidator;
    block.hashMerkleRoot = blockValidator.BuildMerkleRoot(allTransactions);

    // Calculate target from nBits (compact format)
    uint256 hashTarget = CompactToBig(block.nBits);

    if (verbose) {
        std::cout << "  Block height: " << nHeight << std::endl;
        std::cout << "  Previous block: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
        // CID 1675194/1675256 FIX: Save and restore ostream format state
        // This prevents format state leakage to subsequent output operations
        std::ios_base::fmtflags oldFlags = std::cout.flags();
        std::cout << "  Difficulty (nBits): 0x" << std::hex << block.nBits;
        std::cout.flags(oldFlags);  // Restore original format flags
        std::cout << std::endl;
        std::cout << "  Target: " << hashTarget.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "  Coinbase: " << coinbaseMsg << std::endl;
        std::cout << "  Merkle root: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // Create and return block template
    // BUG #109 FIX: Increment and set template version for race detection
    uint64_t version = ++g_node_state.template_version;
    return CBlockTemplate(block, hashTarget, nHeight, version);
}

int main(int argc, char* argv[]) {
    // Quick Start Mode: If no arguments provided, use beginner-friendly defaults
    bool quick_start_mode = (argc == 1);

    // Parse configuration
    NodeConfig config;

    if (quick_start_mode) {
        // Smart defaults for crypto novices
        std::cout << "\033[1;32m" << std::endl;  // Green bold
        std::cout << "======================================" << std::endl;
        std::cout << "  DILITHION QUICK START MODE" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "\033[0m" << std::endl;  // Reset color
        std::cout << "No arguments detected - using beginner-friendly defaults:" << std::endl;
        std::cout << "  • Testnet:    ENABLED (coins have no value)" << std::endl;
        std::cout << "  • Seed node:  134.122.4.164:18444 (NYC - official)" << std::endl;
        std::cout << "  • Mining:     ENABLED" << std::endl;
        std::cout << "  • Threads:    AUTO-DETECT (50-75% of your CPU)" << std::endl;
        std::cout << std::endl;
        std::cout << "To customize settings, run: " << argv[0] << " --help" << std::endl;
        std::cout << "To stop mining anytime: Press Ctrl+C" << std::endl;
        std::cout << std::endl;
        std::cout << "Starting in 3 seconds..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::cout << std::endl;

        // Apply smart defaults
        config.testnet = true;
        config.start_mining = true;
        config.mining_threads = 0;  // 0 = auto-detect
        config.add_nodes.push_back("134.122.4.164:18444");  // NYC seed node
    }
    else if (!config.ParseArgs(argc, argv)) {
        config.PrintUsage(argv[0]);
        return 1;
    }

    // Phase 10: Load configuration from dilithion.conf
    // Determine initial data directory based on command-line testnet flag
    // (Config file may override testnet, but we need initial location to load config)
    std::string initial_datadir = config.datadir;
    if (initial_datadir.empty()) {
        initial_datadir = GetDefaultDataDir(config.testnet);
    }
    
    // Load config file from initial datadir
    std::string config_file = GetConfigFilePath(initial_datadir);
    CConfigParser config_parser;
    if (!config_parser.LoadConfigFile(config_file)) {
        std::cerr << "ERROR: Failed to load configuration file: " << config_file << std::endl;
        return 1;
    }
    
    // Apply config file and environment variable settings (only if not set via command-line)
    // Priority: Command-line > Environment > Config file > Default
    
    // Testnet (only if not set via command-line)
    // Note: This may change the datadir location, but we've already loaded config from initial location
    if (!config.testnet) {
        config.testnet = config_parser.GetBool("testnet", false);
    }
    
    // Data directory (only if not set via command-line)
    // If testnet changed, update datadir accordingly
    if (config.datadir.empty()) {
        std::string conf_datadir = config_parser.GetString("datadir", "");
        if (!conf_datadir.empty()) {
            config.datadir = conf_datadir;
        } else {
            // Use default based on current testnet setting
            config.datadir = GetDefaultDataDir(config.testnet);
        }
    }
    
    // RPC port (only if not set via command-line)
    if (config.rpcport == 0) {
        int64_t conf_rpcport = config_parser.GetInt64("rpcport", 0);
        if (conf_rpcport > 0 && conf_rpcport <= 65535) {
            config.rpcport = static_cast<uint16_t>(conf_rpcport);
        }
    }
    
    // P2P port (only if not set via command-line)
    if (config.p2pport == 0) {
        int64_t conf_p2pport = config_parser.GetInt64("port", 0);
        if (conf_p2pport > 0 && conf_p2pport <= 65535) {
            config.p2pport = static_cast<uint16_t>(conf_p2pport);
        }
    }
    
    // Mining (only if not set via command-line)
    if (!config.start_mining) {
        config.start_mining = config_parser.GetBool("mine", false);
    }
    
    // Mining threads (only if not set via command-line)
    if (config.mining_threads == 0) {
        std::string conf_threads = config_parser.GetString("threads", "");
        if (!conf_threads.empty()) {
            if (conf_threads == "auto" || conf_threads == "AUTO") {
                config.mining_threads = 0;  // Auto-detect
            } else {
                int64_t threads = config_parser.GetInt64("threads", 0);
                if (threads > 0 && threads <= 256) {
                    config.mining_threads = static_cast<int>(threads);
                }
            }
        }
    }
    
    // Add nodes from config file (append to command-line nodes)
    std::vector<std::string> conf_addnodes = config_parser.GetList("addnode");
    for (const auto& node : conf_addnodes) {
        if (std::find(config.add_nodes.begin(), config.add_nodes.end(), node) == config.add_nodes.end()) {
            config.add_nodes.push_back(node);
        }
    }
    
    // Connect nodes from config file (append to command-line nodes)
    std::vector<std::string> conf_connect = config_parser.GetList("connect");
    for (const auto& node : conf_connect) {
        if (std::find(config.connect_nodes.begin(), config.connect_nodes.end(), node) == config.connect_nodes.end()) {
            config.connect_nodes.push_back(node);
        }
    }
    
    // Reindex (only if not set via command-line)
    if (!config.reindex) {
        config.reindex = config_parser.GetBool("reindex", false);
    }
    
    // Rescan (only if not set via command-line)
    if (!config.rescan) {
        config.rescan = config_parser.GetBool("rescan", false);
    }
    
    if (config_parser.IsLoaded()) {
        LogPrintf(ALL, INFO, "Configuration loaded from: %s", config_file.c_str());
    }
    
    // UX: Validate configuration values
    std::vector<ConfigValidationResult> validation_results = CConfigValidator::ValidateAll(config_parser);
    bool has_errors = false;
    for (const auto& result : validation_results) {
        if (!result.valid) {
            has_errors = true;
            ErrorMessage error = CErrorFormatter::ConfigError(result.field_name, result.error_message);
            error.recovery_steps = result.suggestions;
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        }
    }
    if (has_errors) {
        std::cerr << std::endl << "Please fix configuration errors and restart the node." << std::endl;
        return 1;
    }

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Node" << std::endl;
    std::cout << "Post-Quantum Cryptocurrency" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    // Initialize chain parameters based on network
    if (config.testnet) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Testnet());
        std::cout << "Network: TESTNET (production difficulty, ~60s blocks)" << std::endl;
    } else {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Mainnet());
        std::cout << "Network: MAINNET" << std::endl;
    }

    // Phase 10: Set default datadir, ports from chain params if not specified
    // (Config file values already applied above, now apply chain params as final fallback)
    if (config.datadir.empty()) {
        config.datadir = Dilithion::g_chainParams->dataDir;
    }
    if (config.rpcport == 0) {
        config.rpcport = Dilithion::g_chainParams->rpcPort;
    }
    if (config.p2pport == 0) {
        config.p2pport = Dilithion::g_chainParams->p2pPort;
    }

    // Initialize logging system (Bitcoin Core style)
    if (!CLogger::GetInstance().Initialize(config.datadir)) {
        std::cerr << "Warning: Failed to initialize logging system" << std::endl;
    }
    LogPrintf(ALL, INFO, "Dilithion Node starting");
    LogPrintf(ALL, INFO, "Data directory: %s", config.datadir.c_str());
    LogPrintf(ALL, INFO, "P2P port: %d", config.p2pport);
    LogPrintf(ALL, INFO, "RPC port: %d", config.rpcport);

    std::cout << "Data directory: " << config.datadir << std::endl;
    std::cout << "P2P port: " << config.p2pport << std::endl;
    std::cout << "RPC port: " << config.rpcport << std::endl;

    if (!config.connect_nodes.empty()) {
        std::cout << "Connect to: ";
        for (size_t i = 0; i < config.connect_nodes.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.connect_nodes[i];
        }
        std::cout << std::endl;
    }
    if (!config.add_nodes.empty()) {
        std::cout << "Additional nodes: ";
        for (size_t i = 0; i < config.add_nodes.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.add_nodes[i];
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    // Setup signal handlers
    // CID 1675274 FIX: Check return value of std::signal to ensure handlers are installed
    // std::signal returns the previous handler or SIG_ERR on error
    if (std::signal(SIGINT, SignalHandler) == SIG_ERR) {
        std::cerr << "WARNING: Failed to install SIGINT handler" << std::endl;
        LogPrintf(ALL, WARN, "Failed to install SIGINT handler");
    }
    if (std::signal(SIGTERM, SignalHandler) == SIG_ERR) {
        std::cerr << "WARNING: Failed to install SIGTERM handler" << std::endl;
        LogPrintf(ALL, WARN, "Failed to install SIGTERM handler");
    }

    // BUG #88: Windows startup crash diagnostics
    std::cerr.flush();
    
    try {
        // Phase 1: Initialize blockchain storage and mempool
        std::cerr.flush();
        LogPrintf(ALL, INFO, "Initializing blockchain storage...");
        std::cout << "Initializing blockchain storage..." << std::endl;
        CBlockchainDB blockchain;
        if (!blockchain.Open(config.datadir + "/blocks")) {
            ErrorMessage error = CErrorFormatter::DatabaseError("open blockchain database", config.datadir + "/blocks");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            return 1;
        }
        LogPrintf(ALL, INFO, "Blockchain database opened successfully");
        std::cout << "  [OK] Blockchain database opened" << std::endl;

        std::cout << "Initializing mempool..." << std::endl;
        CTxMemPool mempool;
        g_mempool.store(&mempool);  // BUG #108 FIX: Set global pointer for TX relay
        std::cout << "  [OK] Mempool initialized" << std::endl;

        // Initialize UTXO set
        std::cout << "Initializing UTXO set..." << std::endl;
        CUTXOSet utxo_set;
        if (!utxo_set.Open(config.datadir + "/chainstate")) {
            ErrorMessage error = CErrorFormatter::DatabaseError("open UTXO database", config.datadir + "/chainstate");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            return 1;
        }
        std::cout << "  [OK] UTXO set opened" << std::endl;
        g_utxo_set.store(&utxo_set);  // BUG #108 FIX: Set global pointer for TX validation

        // Initialize transaction validator
        CTransactionValidator tx_validator;
        g_tx_validator.store(&tx_validator);  // BUG #108 FIX: Set global pointer for TX validation

        // Initialize chain state
        std::cout << "Initializing chain state..." << std::endl;
        g_chainstate.SetDatabase(&blockchain);
        g_chainstate.SetUTXOSet(&utxo_set);
        g_chainstate.SetMemPool(&mempool);  // BUG #109 FIX: Enable mempool cleanup on block connect

        // P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
        if (!g_chainstate.InitializeWAL(config.datadir)) {
            if (g_chainstate.RequiresReindex()) {
                std::cerr << "========================================" << std::endl;
                std::cerr << "CRITICAL: Incomplete reorganization detected!" << std::endl;
                std::cerr << "The database may be in an inconsistent state." << std::endl;
                std::cerr << "" << std::endl;
                std::cerr << "Please restart with -reindex flag:" << std::endl;
                std::cerr << "  dilithion-node --testnet -reindex" << std::endl;
                std::cerr << "========================================" << std::endl;
                return 1;
            }
        }
        std::cout << "  [OK] Chain state initialized" << std::endl;

        // Initialize RandomX (required for block hashing)
        std::cout << "Initializing RandomX..." << std::endl;
        const char* rx_key = "Dilithion-RandomX-v1";

        // Auto-detect RAM to choose appropriate RandomX mode
        // LIGHT mode: ~256MB RAM, ~3-10 H/s (works on 2GB nodes)
        // FULL mode: ~2.5GB RAM, ~100 H/s (requires 4GB+ nodes)
        size_t total_ram_mb = 0;

#ifdef _WIN32
        // Windows: Use GlobalMemoryStatusEx()
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            total_ram_mb = memInfo.ullTotalPhys / (1024 * 1024);  // Convert bytes to MB
        }
#else
        // Linux: Read /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        if (meminfo.is_open()) {
            std::string line;
            while (std::getline(meminfo, line)) {
                if (line.substr(0, 9) == "MemTotal:") {
                    size_t ram_kb = std::stoull(line.substr(9));
                    total_ram_mb = ram_kb / 1024;
                    break;
                }
            }
            meminfo.close();
        }
#endif

        // ========================================================================
        // BUG #55 FIX: Monero-Style Dual-Mode RandomX Architecture
        // ========================================================================
        // Following Monero's proven pattern for instant node startup:
        // - LIGHT mode (256MB): Used for ALL block validation - instant startup
        // - FULL mode (2GB): Used ONLY for mining - async background init
        //
        // This allows nodes to:
        // 1. Start validating blocks immediately (LIGHT mode)
        // 2. Mining starts with LIGHT mode, upgrades to FULL when ready
        // 3. No more 30-60s hang on high-RAM nodes like NYC (3.9GB)
        // ========================================================================
        std::cout << "  Detected RAM: " << total_ram_mb << " MB" << std::endl;

        // Step 1: Always initialize LIGHT mode first for validation (fast, 1-2 seconds)
        std::cout << "  Initializing validation mode (LIGHT)..." << std::endl;
        randomx_init_validation_mode(rx_key, strlen(rx_key));
        // Validation mode is now ready - node can verify blocks immediately

        // Step 2: Check if FULL mode will be available (RAM >= 3GB)
        // NOTE: Actual mining init is deferred until AFTER sync completes (BUG #97 fix)
        bool full_mode_available = (total_ram_mb >= 3072);
        if (config.start_mining && full_mode_available) {
            std::cout << "  Mining mode: FULL (will initialize after sync)" << std::endl;
        } else if (config.start_mining) {
            std::cout << "  Mining mode: LIGHT only (RAM < 3GB)" << std::endl;
        }

        // NO WAIT - node continues immediately, can validate blocks right away

        // Load and verify genesis block
load_genesis_block:  // Bug #29: Label for automatic retry after blockchain wipe
        std::cout << "[1/6] Loading genesis block..." << std::flush;
        CBlock genesis = Genesis::CreateGenesisBlock();

        if (!Genesis::IsGenesisBlock(genesis)) {
            ErrorMessage error = CErrorFormatter::ValidationError("genesis block", 
                "Genesis block verification failed. This indicates a critical configuration problem.");
            error.severity = ErrorSeverity::CRITICAL;
            error.recovery_steps = {
                "Verify you are using the correct network (mainnet/testnet)",
                "Check that blockchain data directory is correct",
                "Try deleting blockchain data and re-syncing",
                "Report this issue if it persists"
            };
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            delete Dilithion::g_chainParams;
            return 1;
        }

        std::cout << "  Network: " << Dilithion::g_chainParams->GetNetworkName() << std::endl;
        std::cout << "  Genesis hash: " << genesis.GetHash().GetHex() << std::endl;
        std::cout << "  Genesis time: " << genesis.nTime << std::endl;
        std::cout << " ✓" << std::endl;
        std::cout << "  [OK] Genesis block verified" << std::endl;

        // Initialize blockchain with genesis block if needed
        uint256 genesisHash = genesis.GetHash();
        if (!blockchain.BlockExists(genesisHash)) {
            std::cout << "Initializing blockchain with genesis block..." << std::endl;

            // Save genesis block
            if (!blockchain.WriteBlock(genesisHash, genesis)) {
                ErrorMessage error = CErrorFormatter::DatabaseError("write genesis block", 
                    "Failed to write genesis block to database");
                error.severity = ErrorSeverity::CRITICAL;
                std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
                LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block saved to database" << std::endl;

            // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
            auto pgenesisIndex = std::make_unique<CBlockIndex>(genesis);
            pgenesisIndex->phashBlock = genesisHash;
            pgenesisIndex->nHeight = 0;
            pgenesisIndex->pprev = nullptr;
            pgenesisIndex->pnext = nullptr;
            pgenesisIndex->nChainWork = pgenesisIndex->GetBlockProof();
            pgenesisIndex->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

            // Save to database
            if (!blockchain.WriteBlockIndex(genesisHash, *pgenesisIndex)) {
                std::cerr << "ERROR: Failed to write genesis block index!" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block index saved (height 0)" << std::endl;

            // Add to chain state and set as tip (transfer ownership with std::move)
            if (!g_chainstate.AddBlockIndex(genesisHash, std::move(pgenesisIndex))) {
                std::cerr << "ERROR: Failed to add genesis to chain state!" << std::endl;
                // HIGH-C001 FIX: No manual delete - ownership already transferred to map
                delete Dilithion::g_chainParams;
                return 1;
            }

            // HIGH-C001 FIX: After move, retrieve pointer from chain state
            CBlockIndex* pgenesisIndexPtr = g_chainstate.GetBlockIndex(genesisHash);
            if (pgenesisIndexPtr == nullptr) {
                std::cerr << "ERROR: Genesis block index not found after adding!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            bool reorgOccurred = false;
            if (!g_chainstate.ActivateBestChain(pgenesisIndexPtr, genesis, reorgOccurred)) {
                std::cerr << "ERROR: Failed to activate genesis block!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            // Set genesis as best block in database
            if (!blockchain.WriteBestBlock(genesisHash)) {
                std::cerr << "ERROR: Failed to set genesis as best block!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block set as blockchain tip" << std::endl;
        } else {
            std::cout << "  [OK] Genesis block already in database" << std::endl;

            // Phase 4.2: Handle -reindex flag
            if (config.reindex) {
                LogPrintf(ALL, INFO, "Rebuilding block index from blocks on disk (--reindex)");
                std::cout << "\n==========================================================" << std::endl;
                std::cout << "REINDEX: Rebuilding block index from blocks on disk..." << std::endl;
                std::cout << "==========================================================" << std::endl;
                
                // Clear existing block index (but keep blocks)
                // We'll rebuild the index by reading all blocks
                std::cout << "  Clearing existing block index..." << std::endl;
                
                // Get all block hashes
                std::vector<uint256> all_blocks;
                if (!blockchain.GetAllBlockHashes(all_blocks)) {
                    std::cerr << "ERROR: Failed to enumerate blocks for reindex" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                
                std::cout << "  Found " << all_blocks.size() << " blocks to reindex" << std::endl;
                
                // Rebuild index
                if (!blockchain.RebuildBlockIndex()) {
                    std::cerr << "ERROR: Failed to rebuild block index" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                
                std::cout << "  [OK] Block index rebuilt successfully" << std::endl;
                std::cout << "==========================================================" << std::endl;
            }

            // Load existing chain state from database
            std::cout << "[2/6] Loading chain state from database..." << std::flush;

            // Load genesis block index first
            CBlockIndex genesisIndexFromDB;
            if (blockchain.ReadBlockIndex(genesisHash, genesisIndexFromDB)) {
                // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
                auto pgenesisIndex = std::make_unique<CBlockIndex>(genesisIndexFromDB);
                pgenesisIndex->pprev = nullptr;
                g_chainstate.AddBlockIndex(genesisHash, std::move(pgenesisIndex));
                std::cout << " ✓" << std::endl;
                std::cout << "  Loaded genesis block index (height 0)" << std::endl;
            } else {
                std::cerr << "ERROR: Cannot load genesis block index from database!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            // Load current best block
            uint256 hashBestBlock;

            // BUG #5 FIX: If best block not set, initialize it to genesis
            // This handles the case where genesis block exists but best block pointer is missing
            if (!blockchain.ReadBestBlock(hashBestBlock)) {
                std::cout << "  Best block not set, initializing to genesis..." << std::endl;
                if (!blockchain.WriteBestBlock(genesisHash)) {
                    std::cerr << "ERROR: Failed to set genesis as best block!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                hashBestBlock = genesisHash;
                std::cout << "  [OK] Genesis set as best block" << std::endl;
            }

            if (hashBestBlock == genesisHash) {
                // Only genesis block exists - set it as tip
                CBlockIndex* pgenesisIndexPtr = g_chainstate.GetBlockIndex(genesisHash);
                if (pgenesisIndexPtr == nullptr) {
                    std::cerr << "ERROR: Genesis block index not found in chain state!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                g_chainstate.SetTip(pgenesisIndexPtr);
                std::cout << " ✓" << std::endl;
                std::cout << "  [OK] Loaded chain state: 1 block (height 0)" << std::endl;
            } else if (!(hashBestBlock.IsNull())) {
                std::cout << "  Best block hash: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;

                // Load best block index and rebuild chain backwards to genesis
                std::vector<uint256> chainHashes;
                uint256 currentHash = hashBestBlock;

                while (!(currentHash == genesisHash)) {
                    chainHashes.push_back(currentHash);

                    CBlockIndex blockIndexFromDB;
                    if (!blockchain.ReadBlockIndex(currentHash, blockIndexFromDB)) {
                        std::cerr << "ERROR: Cannot load block index " << currentHash.GetHex().substr(0, 16) << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // If this block's previous hash is null/zero, it's the genesis block - stop here
                    if (blockIndexFromDB.header.hashPrevBlock.IsNull()) {
                        break;
                    }

                    currentHash = blockIndexFromDB.header.hashPrevBlock;
                }

                // Now load all blocks in forward order (genesis to tip)
                // Genesis already loaded, so start from the chain
                for (auto it = chainHashes.rbegin(); it != chainHashes.rend(); ++it) {
                    const uint256& blockHash = *it;

                    CBlockIndex blockIndexFromDB;
                    if (!blockchain.ReadBlockIndex(blockHash, blockIndexFromDB)) {
                        std::cerr << "ERROR: Cannot load block index " << blockHash.GetHex().substr(0, 16) << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
                    auto pblockIndex = std::make_unique<CBlockIndex>(blockIndexFromDB);
                    pblockIndex->pprev = g_chainstate.GetBlockIndex(pblockIndex->header.hashPrevBlock);

                    if (pblockIndex->pprev == nullptr && !(blockHash == genesisHash)) {
                        std::cerr << "ERROR: Cannot find parent block for " << blockHash.GetHex().substr(0, 16) << std::endl;

                        // CHAIN INTEGRITY: Auto-wipe for testnet, manual intervention for mainnet
                        if (config.testnet) {
                            std::cout << "\n==========================================================" << std::endl;
                            std::cout << "TESTNET: Chain corruption detected during startup" << std::endl;
                            std::cout << "TESTNET: Missing parent block - database inconsistent" << std::endl;
                            std::cout << "TESTNET: Attempting automatic recovery..." << std::endl;
                            std::cout << "==========================================================" << std::endl;

                            // Bug #25 FIX: Close ALL databases before wiping to release file locks (Windows)
                            blockchain.Close();
                            utxo_set.Close();  // CRITICAL: Also close UTXO database (chainstate directory)

                            CChainVerifier verifier;
                            if (!verifier.RepairChain(true)) {
                                std::cerr << "ERROR: Failed to repair testnet blockchain data" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            std::cout << "==========================================================" << std::endl;
                            std::cout << "TESTNET: Blockchain data wiped successfully" << std::endl;
                            std::cout << "TESTNET: Reopening databases and continuing..." << std::endl;
                            std::cout << "==========================================================" << std::endl;

                            // Bug #29 Fix: Close and reopen databases instead of exiting
                            // Close existing databases first
                            blockchain.Close();
                            utxo_set.Close();

                            // Reopen blockchain database
                            std::string blocksPath = config.datadir + "/blocks";
                            if (!blockchain.Open(blocksPath)) {
                                std::cerr << "ERROR: Failed to reopen blockchain database after wipe" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            // Clear mempool (P0-5 FIX: use .load() for atomic)
                            auto* mempool = g_mempool.load();
                            if (mempool) mempool->Clear();

                            // Reopen UTXO set database
                            std::string chainstatePath = config.datadir + "/chainstate";
                            if (!utxo_set.Open(chainstatePath)) {
                                std::cerr << "ERROR: Failed to reopen UTXO database after wipe" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            // Reset chain state
                            g_chainstate.Cleanup();
                            g_chainstate.SetTip(nullptr);

                            // Jump back to genesis loading (will trigger IBD after handshake)
                            goto load_genesis_block;
                        } else {
                            std::cerr << "\n==========================================================" << std::endl;
                            std::cerr << "ERROR: Corrupted blockchain database detected" << std::endl;
                            std::cerr << "Missing parent block - database inconsistent" << std::endl;
                            std::cerr << "==========================================================" << std::endl;
                            std::cerr << "\nThis usually indicates:" << std::endl;
                            std::cerr << "  1. Database corruption from unclean shutdown" << std::endl;
                            std::cerr << "  2. Incomplete blockchain download" << std::endl;
                            std::cerr << "  3. Running different code versions" << std::endl;
                            std::cerr << "\nTo recover:" << std::endl;
                            std::cerr << "  Delete blockchain data for full re-sync:" << std::endl;
                            std::cerr << "    rm -rf ~/.dilithion/blocks ~/.dilithion/chainstate" << std::endl;
                            std::cerr << "    ./dilithion-node" << std::endl;
                            std::cerr << "\nFor more information, see docs/troubleshooting.md\n" << std::endl;

                            delete Dilithion::g_chainParams;
                            return 1;
                        }
                    }

                    // Rebuild chain work
                    pblockIndex->BuildChainWork();

                    // Add to chain state (transfer ownership with std::move)
                    if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                        std::cerr << "ERROR: Failed to add block index to chain state" << std::endl;
                        // HIGH-C001 FIX: No manual delete - ownership transferred
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // HIGH-C001 FIX: After move, retrieve pointer from chain state
                    CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
                    // Set pnext pointer on parent to maintain chain
                    if (pblockIndexPtr->pprev != nullptr) {
                        pblockIndexPtr->pprev->pnext = pblockIndexPtr;
                    }
                }

                // Set the tip
                CBlockIndex* pindexTip = g_chainstate.GetBlockIndex(hashBestBlock);
                if (pindexTip == nullptr) {
                    std::cerr << "ERROR: Cannot find tip block index after loading!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }

                g_chainstate.SetTip(pindexTip);
                g_chain_height.store(static_cast<unsigned int>(pindexTip->nHeight));  // BUG #108 FIX: Set global height for TX validation
                std::cout << "  [OK] Loaded chain state: " << chainHashes.size() + 1 << " blocks (height "
                          << pindexTip->nHeight << ")" << std::endl;
            } else {
                std::cerr << "ERROR: Cannot read best block from database!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
        }

        // ========================================================================
        // CHAIN INTEGRITY VALIDATION (Bug #17)
        // Following Bitcoin Core, Ethereum Geth, Monero best practices
        // Prevents "Cannot find parent block" errors during systemd auto-restart
        // ========================================================================
        {
            std::cout << "Validating blockchain integrity..." << std::endl;

            CChainVerifier verifier;
            std::string error;

            // Quick validation on every startup (1-10 seconds)
            // Checks: genesis exists, best block valid, no missing parents
            if (!verifier.VerifyChainIntegrity(CChainVerifier::LEVEL_QUICK, error)) {

                if (config.testnet) {
                    // TESTNET: Auto-wipe corrupted data (following Ethereum Geth pattern)
                    std::cout << "==========================================================" << std::endl;
                    std::cout << "TESTNET: Chain corruption detected" << std::endl;
                    std::cout << "Error: " << error << std::endl;
                    std::cout << "TESTNET: Attempting automatic recovery..." << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Bug #25 FIX: Close ALL databases before wiping to release file locks (Windows)
                    blockchain.Close();
                    utxo_set.Close();  // CRITICAL: Also close UTXO database (chainstate directory)

                    if (!verifier.RepairChain(true)) {
                        std::cerr << "ERROR: Failed to repair testnet blockchain data" << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    std::cout << "==========================================================" << std::endl;
                    std::cout << "TESTNET: Blockchain data wiped successfully" << std::endl;
                    std::cout << "TESTNET: Please restart the node" << std::endl;
                    std::cout << "TESTNET: Node will rebuild from genesis block" << std::endl;
                    std::cout << "TESTNET: This is normal after code updates" << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Exit gracefully - systemd will auto-restart
                    delete Dilithion::g_chainParams;
                    return 0;  // Clean exit for systemd restart

                } else {
                    // MAINNET: Conservative approach (following Bitcoin Core pattern)
                    std::cerr << "\n==========================================================" << std::endl;
                    std::cerr << "ERROR: Corrupted blockchain database detected" << std::endl;
                    std::cerr << "Error: " << error << std::endl;
                    std::cerr << "==========================================================" << std::endl;
                    std::cerr << "\nThis usually indicates:" << std::endl;
                    std::cerr << "  1. Database corruption from unclean shutdown" << std::endl;
                    std::cerr << "  2. Incomplete blockchain download" << std::endl;
                    std::cerr << "  3. Disk corruption" << std::endl;
                    std::cerr << "\nTo recover:" << std::endl;
                    std::cerr << "  Option 1: Delete blockchain data for full re-sync" << std::endl;
                    std::cerr << "    rm -rf ~/.dilithion/blocks ~/.dilithion/chainstate" << std::endl;
                    std::cerr << "    ./dilithion-node" << std::endl;
                    std::cerr << "\nFor more information, see docs/troubleshooting.md\n" << std::endl;

                    delete Dilithion::g_chainParams;
                    return 1;
                }
            }

            std::cout << "  [OK] Chain integrity validation passed" << std::endl;
        }

        // Set network magic for P2P protocol
        if (config.testnet) {
            NetProtocol::g_network_magic = NetProtocol::TESTNET_MAGIC;
        } else {
            NetProtocol::g_network_magic = NetProtocol::MAINNET_MAGIC;
        }

        // Phase 2: Initialize P2P networking (prepare for later)
        std::cout << "Initializing P2P components..." << std::endl;

        // Phase 1.2: Initialize NodeContext using explicit Init() (Bitcoin Core pattern)
        std::cout << "Initializing NodeContext..." << std::endl;
        if (!g_node_context.Init(config.datadir, &g_chainstate)) {
            std::cerr << "ERROR: Failed to initialize NodeContext" << std::endl;
            return 1;
        }
        std::cout << "  [OK] NodeContext initialized" << std::endl;

        // Keep legacy globals for backward compatibility during migration
        // TODO: Remove after full migration
        g_peer_manager = g_node_context.peer_manager.get();
        g_headers_manager = g_node_context.headers_manager.get();
        g_orphan_manager = g_node_context.orphan_manager.get();
        g_block_fetcher = g_node_context.block_fetcher.get();

        // Initialize transaction relay manager (global)
        // P0-5 FIX: Use .store() for atomic pointer
        g_tx_relay_manager.store(new CTxRelayManager());

        // Initialize IBD managers (Bug #12 - Phase 4.1)
        std::cout << "Initializing IBD managers..." << std::endl;
        std::cout << "  [OK] Headers manager initialized" << std::endl;
        std::cout << "  [OK] Orphan manager initialized (max 100 blocks / 100 MB)" << std::endl;
        std::cout << "  [OK] Block fetcher initialized (max 16 blocks in-flight)" << std::endl;

        // Bug #40 fix: Register HeadersManager callback for chain tip updates
        g_chainstate.RegisterTipUpdateCallback([](const CBlockIndex* pindex) {
            if (g_node_context.headers_manager && pindex) {
                g_node_context.headers_manager->OnBlockActivated(pindex->header, pindex->GetBlockHash());
            }
        });
        std::cout << "  [OK] Chain tip callback registered for HeadersManager" << std::endl;

        // Bug #41 fix: Initialize HeadersManager with existing chain from database
        // This ensures HeadersManager can serve historical headers, not just newly mined ones
        {
            std::cout << "Populating HeadersManager with existing chain..." << std::endl;
            CBlockIndex* pindexTip = g_chainstate.GetTip();

            if (pindexTip != nullptr) {
                // Build chain from tip to genesis
                std::vector<CBlockIndex*> chain;
                CBlockIndex* pindex = pindexTip;
                while (pindex != nullptr) {
                    chain.push_back(pindex);
                    pindex = pindex->pprev;
                }

                // Add headers to HeadersManager from genesis to tip
                // This populates HeadersManager with all historical blocks
                for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
                    g_node_context.headers_manager->OnBlockActivated((*it)->header, (*it)->GetBlockHash());
                }

                std::cout << "  [OK] Populated HeadersManager with " << chain.size()
                          << " header(s) from height 0 to " << pindexTip->nHeight << std::endl;
            } else {
                std::cout << "  [WARN] No chain tip - HeadersManager empty (expected for fresh node)" << std::endl;
            }
        }

        // Create message processor and connection manager (local, using NodeContext peer manager)
        CNetMessageProcessor message_processor(*g_node_context.peer_manager);
        
        // Phase 5: Replace CConnectionManager with CConnman (event-driven networking)
        auto connman = std::make_unique<CConnman>();
        CConnmanOptions connman_opts;
        connman_opts.fListen = true;
        connman_opts.nListenPort = config.p2pport;
        connman_opts.nMaxOutbound = 8;
        connman_opts.nMaxInbound = 117;
        connman_opts.nMaxTotal = 125;
        
        // BUG #138 FIX: Set g_node_context pointers BEFORE starting threads
        // This allows handlers to access connman immediately when messages arrive
        // Start() is called AFTER handlers are registered (see below after SetHeadersHandler)

        // Set global pointers for transaction announcement (NW-005)
        // P0-5 FIX: Use .store() for atomic pointers
        g_message_processor.store(&message_processor);

        // Phase 1.2: Store in NodeContext (Bitcoin Core pattern)
        g_node_context.connman = std::move(connman);
        g_node_context.message_processor = &message_processor;
        
        // Legacy: Keep connection_manager pointer for backward compatibility during migration
        // TODO Phase 5: Remove after full migration
        g_node_context.connection_manager = nullptr;

        // Phase 5: Create and start async broadcaster for non-blocking message broadcasting
        // Now uses CConnman instead of CConnectionManager
        CAsyncBroadcaster async_broadcaster(g_node_context.connman.get());
        g_async_broadcaster = &async_broadcaster;  // Legacy global
        g_node_context.async_broadcaster = &async_broadcaster;

        // Phase 1.2: Store node state flags in NodeContext
        // Note: atomic values must use .load() when copying
        g_node_context.running.store(g_node_state.running.load());
        g_node_context.mining_enabled.store(g_node_state.mining_enabled.load());

        // Phase 5: Start async broadcaster
        if (!async_broadcaster.Start()) {
            std::cerr << "Failed to start async broadcaster" << std::endl;
            return 1;
        }

        // Phase 5: Create feeler connection manager (Bitcoin Core-style eclipse attack protection)
        // Now uses CConnman instead of CConnectionManager
        CFeelerManager feeler_manager(*g_node_context.peer_manager, g_node_context.connman.get(), &message_processor);

        // BUG #125: Create and start async message processing queue
        // This decouples network I/O from message processing to prevent blocking
        CMessageProcessorQueue message_queue(message_processor, 2);  // 2 worker threads
        g_message_queue.store(&message_queue);
        g_node_context.message_queue = &message_queue;

        if (!message_queue.Start()) {
            std::cerr << "Failed to start message queue" << std::endl;
            return 1;
        }
        std::cout << "  [OK] Async message processing enabled (2 workers)" << std::endl;

        // Create and start HTTP API server for dashboard
        // Use port 18334 for testnet, 8334 for mainnet (Bitcoin convention)
        int api_port = config.testnet ? 18334 : 8334;
        CHttpServer http_server(api_port);
        g_node_state.http_server = &http_server;

        // Set stats handler that returns current node statistics as JSON
        http_server.SetStatsHandler([&config]() -> std::string {
            // Get current stats from chain state
            CBlockIndex* tip = g_chainstate.GetTip();
            int block_height = tip ? tip->nHeight : 0;
            uint32_t difficulty = tip ? tip->nBits : 0;
            int64_t total_supply = block_height * 50;  // 50 coins per block
            size_t peer_count = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectedPeers().size() : 0;

            // Get async broadcaster stats
            size_t async_broadcasts = 0;
            size_t async_success = 0;
            size_t async_failed = 0;
            if (g_node_context.async_broadcaster) {
                auto stats = g_node_context.async_broadcaster->GetStats();
                async_broadcasts = stats.total_queued;
                async_success = stats.total_sent;
                async_failed = stats.total_failed;
            }

            // Calculate success rate
            int success_rate = (async_broadcasts > 0)
                ? (int)((async_success * 100) / async_broadcasts)
                : 100;

            // Calculate blocks until halving
            int blocks_until_halving = 210000 - block_height;

            // Build JSON response
            std::ostringstream json;
            json << "{\n";
            json << "  \"timestamp\": \"" << std::time(nullptr) << "\",\n";
            json << "  \"network\": \"" << (config.testnet ? "testnet" : "mainnet") << "\",\n";
            json << "  \"blockHeight\": " << block_height << ",\n";
            json << "  \"difficulty\": " << difficulty << ",\n";
            json << "  \"networkHashRate\": " << (difficulty / 240) << ",\n";
            json << "  \"totalSupply\": " << total_supply << ",\n";
            json << "  \"blockReward\": 50,\n";
            json << "  \"blocksUntilHalving\": " << blocks_until_halving << ",\n";
            json << "  \"peerCount\": " << peer_count << ",\n";
            json << "  \"averageBlockTime\": 240,\n";
            json << "  \"status\": \"live\",\n";
            json << "  \"asyncBroadcasts\": " << async_success << ",\n";
            json << "  \"asyncSuccessRate\": \"" << success_rate << "%\",\n";
            json << "  \"asyncValidation\": \"" << (async_success >= 10 ? "COMPLETE" : "IN_PROGRESS") << "\"\n";
            json << "}";

            return json.str();
        });

        // BUG #140 FIX: Make HTTP server failure non-fatal
        // The stats endpoint is optional - core P2P functionality should continue
        bool http_started = http_server.Start();
        if (!http_started) {
            std::cerr << "[HttpServer] WARNING: Failed to start HTTP API server on port " << api_port << std::endl;
            std::cerr << "[HttpServer] Stats endpoint will be unavailable, but P2P will continue" << std::endl;
        } else {
            std::cout << "[HttpServer] API server started on port " << api_port << std::endl;
            std::cout << "[HttpServer] Dashboard endpoint: http://localhost:" << api_port << "/api/stats" << std::endl;
        }

        // Verify global pointers are properly initialized (audit recommendation)
        assert(g_node_context.connman != nullptr && "connman must be initialized");
        assert(g_node_context.message_processor != nullptr && "message_processor must be initialized");
        assert(g_node_context.peer_manager != nullptr && "peer_manager must be initialized");
        assert(g_tx_relay_manager != nullptr && "g_tx_relay_manager must be initialized");

        // Register version handler to automatically respond with version + verack
        // Bitcoin handshake: A->B: VERSION, B->A: VERSION + VERACK, A->B: VERACK
        message_processor.SetVersionHandler([](int peer_id, const NetProtocol::CVersionMessage& msg) {
            // BUG #62 FIX: Store peer's starting height for later header sync decision
            if (g_node_context.headers_manager) {
                g_node_context.headers_manager->SetPeerStartHeight(peer_id, msg.start_height);
            }

            // Debug: Get CNode to check inbound status
            CNode* node = nullptr;
            bool is_inbound = false;
            if (g_node_context.connman) {
                node = g_node_context.connman->GetNode(peer_id);
                if (node) {
                    is_inbound = node->fInbound;
                }
            }

            // BUG #129 FIX: Only send VERSION for inbound connections (state < VERSION_SENT)
            // For outbound connections, we already sent VERSION in ConnectAndHandshake()
            // Sending VERSION again causes an infinite VERSION ping-pong loop
            auto peer = g_node_context.peer_manager->GetPeer(peer_id);

            // Debug logging for handshake flow analysis
            std::cout << "[P2P-DEBUG] VERSION handler: peer_id=" << peer_id
                      << " inbound=" << (is_inbound ? "true" : "false")
                      << " peer_state=" << (peer ? (int)peer->state : -1)
                      << " peer_ip=" << (peer ? peer->addr.ToStringIP() : "null")
                      << std::endl;

            if (peer && peer->state < CPeer::STATE_VERSION_SENT) {
                // Create and send version message
                NetProtocol::CAddress local_addr;
                local_addr.services = NetProtocol::NODE_NETWORK;
                local_addr.SetIPv4(0);  // 0.0.0.0
                local_addr.port = 0;
                CNetMessage version_msg = g_node_context.message_processor->CreateVersionMessage(peer->addr, local_addr);
                if (g_node_context.connman) {
                    g_node_context.connman->PushMessage(peer_id, version_msg);
                    // Update state after sending VERSION
                    peer->state = CPeer::STATE_VERSION_SENT;
                    std::cout << "[P2P] SetVersionHandler: SendVersionMessage(" << peer_id << ") = SUCCESS (inbound connection)" << std::endl;
                }
            } else {
                std::cout << "[P2P] SetVersionHandler: peer " << peer_id << " state=" << (peer ? (int)peer->state : -1)
                          << " >= VERSION_SENT(3), only sending VERACK" << std::endl;
            }

            // Always send VERACK to acknowledge their VERSION
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage verack_msg = g_node_context.message_processor->CreateVerackMessage();
                g_node_context.connman->PushMessage(peer_id, verack_msg);
                std::cout << "[P2P] SetVersionHandler: Sent VERACK to peer " << peer_id << std::endl;
            }
        });

        // Register verack handler to trigger IBD when handshake completes
        message_processor.SetVerackHandler([](int peer_id) {
            // Debug: Get CNode to check inbound status
            bool is_inbound = false;
            if (g_node_context.connman) {
                CNode* node = g_node_context.connman->GetNode(peer_id);
                if (node) {
                    is_inbound = node->fInbound;
                }
            }
            auto peer = g_node_context.peer_manager->GetPeer(peer_id);
            std::cout << "[P2P-DEBUG] VERACK handler: peer_id=" << peer_id
                      << " inbound=" << (is_inbound ? "true" : "false")
                      << " peer_state=" << (peer ? (int)peer->state : -1)
                      << std::endl;

            std::cout << "[P2P] Handshake complete with peer " << peer_id << std::endl;

            // BUG #36 FIX: Register peer with BlockFetcher so it can download blocks
            if (g_node_context.block_fetcher) {
                g_node_context.block_fetcher->OnPeerConnected(peer_id);
            }

            // Phase C FIX: Notify CPeerManager of handshake completion
            // This is CRITICAL for IsPeerSuitableForDownload() to return true
            if (g_node_context.peer_manager && g_node_context.headers_manager) {
                int peerHeight = g_node_context.headers_manager->GetPeerStartHeight(peer_id);
                g_node_context.peer_manager->OnPeerHandshakeComplete(peer_id, peerHeight, false);
                std::cout << "[P2P] Registered peer " << peer_id << " with CPeerManager (height=" << peerHeight << ")" << std::endl;
            }

            // Request addresses from peer (Bitcoin Core pattern for peer discovery)
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage getaddr_msg = g_node_context.message_processor->CreateGetAddrMessage();
                g_node_context.connman->PushMessage(peer_id, getaddr_msg);
                std::cout << "[P2P] Sent GETADDR to peer " << peer_id << std::endl;
            }

            // Phase 5: Mark peer's address as "good" on successful handshake
            // This moves the address from "new" to "tried" table in AddrMan
            if (g_node_context.peer_manager) {
                auto peer = g_node_context.peer_manager->GetPeer(peer_id);
                if (peer && peer->addr.IsRoutable()) {
                    g_node_context.peer_manager->MarkAddressGood(peer->addr);
                }
            }

            // Check if headers_manager is initialized
            if (!g_node_context.headers_manager) {
                std::cout << "[DEBUG] SetVerackHandler: headers_manager is NULL, skipping IBD" << std::endl;
                return;
            }

            // BUG #62 FIX: Compare our height with peer's announced height
            int ourHeight = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
            int peerHeight = g_node_context.headers_manager->GetPeerStartHeight(peer_id);

            std::cout << "[IBD] SetVerackHandler: ourHeight=" << ourHeight << " peerHeight=" << peerHeight << std::endl;

            // Request headers if peer is ahead OR if we're at genesis
            if (peerHeight > ourHeight || ourHeight == 0) {
                uint256 ourBestBlock;
                if (g_chainstate.GetTip()) {
                    ourBestBlock = g_chainstate.GetTip()->GetBlockHash();
                } else {
                    ourBestBlock.SetHex(Dilithion::g_chainParams->genesisHash);
                }
                std::cout << "[IBD] Requesting headers from peer " << peer_id << " from block " << ourBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
                g_node_context.headers_manager->RequestHeaders(peer_id, ourBestBlock);
            } else {
                std::cout << "[IBD] Not requesting headers - peer not ahead (peer=" << peerHeight << " us=" << ourHeight << ")" << std::endl;
            }
        });

        // Register ping handler to automatically respond with pong
        message_processor.SetPingHandler([](int peer_id, uint64_t nonce) {
            // Silently respond with pong - keepalive is automatic
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage pong_msg = g_node_context.message_processor->CreatePongMessage(nonce);
                g_node_context.connman->PushMessage(peer_id, pong_msg);
            }
        });

        // Register pong handler (keepalive response received)
        message_processor.SetPongHandler([](int peer_id, uint64_t nonce) {
            // Silently acknowledge - keepalive working
        });

        // Register ADDR handler to receive addresses from peers
        message_processor.SetAddrHandler([](int peer_id, const std::vector<NetProtocol::CAddress>& addrs) {
            if (addrs.empty()) {
                return;
            }

            std::cout << "[P2P] Received " << addrs.size() << " addresses from peer " << peer_id << std::endl;

            // Add each address to AddrMan via peer manager
            int added = 0;
            for (const auto& addr : addrs) {
                // Skip non-routable addresses
                if (!addr.IsRoutable()) {
                    continue;
                }

                // Skip localhost
                std::string ip = addr.ToStringIP();
                if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) {
                    continue;
                }

                // Add to address manager
                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->AddPeerAddress(addr);
                    added++;
                }
            }

            if (added > 0) {
                std::cout << "[P2P] Added " << added << " new addresses to AddrMan from peer " << peer_id << std::endl;
            }
        });

        // Register inv handler to request announced blocks
        message_processor.SetInvHandler([&blockchain](
            int peer_id, const std::vector<NetProtocol::CInv>& inv_items) {

            bool hasUnknownBlocks = false;
            std::vector<NetProtocol::CInv> getdata;

            for (const auto& item : inv_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // Check if we already have this block
                    if (!blockchain.BlockExists(item.hash)) {
                        std::cout << "[P2P] Peer " << peer_id << " announced new block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                        hasUnknownBlocks = true;
                        getdata.push_back(item);
                    }
                }
            }

            // BUG #62 FIX: Request headers when peer announces unknown blocks
            // This ensures we get the FULL chain (all intermediate blocks), not just
            // the announced block which may fail validation if we're missing its parent.
            // Rate limited via ShouldFetchHeaders() - max once per 30 seconds per peer.
            if (hasUnknownBlocks && g_node_context.headers_manager) {
                if (g_node_context.headers_manager->ShouldFetchHeaders(peer_id)) {
                    uint256 ourBestBlock;
                    if (g_chainstate.GetTip()) {
                        ourBestBlock = g_chainstate.GetTip()->GetBlockHash();
                    } else {
                        ourBestBlock.SetHex(Dilithion::g_chainParams->genesisHash);
                    }

                    std::cout << "[P2P] Unknown blocks announced by peer " << peer_id
                              << ", requesting headers for full chain" << std::endl;
                    g_node_context.headers_manager->RequestHeaders(peer_id, ourBestBlock);
                }
            }

            // Also request the specific blocks (may succeed if we have their parents)
            if (!getdata.empty() && g_node_context.connman && g_node_context.message_processor) {
                std::cout << "[P2P] Requesting " << getdata.size() << " block(s) from peer " << peer_id << std::endl;
                CNetMessage msg = g_node_context.message_processor->CreateGetDataMessage(getdata);
                g_node_context.connman->PushMessage(peer_id, msg);
            }
        });

        // Register getdata handler to serve blocks to requesting peers
        message_processor.SetGetDataHandler([&blockchain](
            int peer_id, const std::vector<NetProtocol::CInv>& requested_items) {

            for (const auto& item : requested_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // Look up block in database
                    CBlock block;
                    if (blockchain.ReadBlock(item.hash, block)) {
                        // Send block to requesting peer
                        if (g_node_context.connman && g_node_context.message_processor) {
                            CNetMessage blockMsg = g_node_context.message_processor->CreateBlockMessage(block);
                            auto serialized = blockMsg.Serialize();
                            std::cout << "[BLOCK-SERVE] Sending block " << item.hash.GetHex().substr(0, 16)
                                      << "... to peer " << peer_id
                                      << " (vtx=" << block.vtx.size() << " bytes, msg=" << serialized.size() << " bytes)" << std::endl;
                            g_node_context.connman->PushMessage(peer_id, blockMsg);
                            std::cout << "[BLOCK-SERVE] PushMessage SUCCEEDED for block to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] Peer " << peer_id << " requested unknown block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
                // Phase 5: Transaction relay - implement MSG_TX_INV handling after testnet stabilizes
            }
        });

        // Register block handler to validate and save received blocks
        message_processor.SetBlockHandler([&blockchain](int peer_id, const CBlock& block) {
            uint256 blockHash = block.GetHash();

            std::cout << "[P2P] Received block from peer " << peer_id << ": "
                      << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

            // Basic validation: Check PoW
            if (!CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[P2P] ERROR: Block from peer " << peer_id << " has invalid PoW" << std::endl;
                std::cerr << "  Hash must be less than target" << std::endl;
                return;
            }

            // BUG #114 FIX: Check if we have the actual block DATA, not just the header
            // Headers-only entries are created by ProcessHeaders() during IBD
            // We must NOT skip blocks that only have headers - we need the full data!
            CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
            if (pindex && pindex->HaveData()) {
                std::cout << "[P2P] Block already in chain state (have data), skipping" << std::endl;
                // BUG #86 FIX: Mark block as received even when skipping
                // Otherwise it stays "in-flight" forever, causing timeout/retry loops
                if (g_node_context.block_fetcher) {
                    g_node_context.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                }
                return;
            }

            // Check if we already have this block in database
            bool blockInDb = blockchain.BlockExists(blockHash);
            if (blockInDb) {
                // BUG #86 FIX: Mark block as received even when skipping
                if (g_node_context.block_fetcher) {
                    g_node_context.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                }

                // BUG #88 FIX: If block is in DB but NOT in chainstate, try to connect it
                // This can happen when:
                // 1. Block was received as orphan, saved to DB, but never connected
                // 2. Node restarted and orphan pool was lost
                // 3. Orphan's parent has now arrived
                if (!g_chainstate.HasBlockIndex(blockHash)) {
                    CBlockIndex* pParent = g_chainstate.GetBlockIndex(block.hashPrevBlock);
                    if (pParent != nullptr) {
                        std::cout << "[BUG88-FIX] Block in DB but not chainstate, parent now available - connecting" << std::endl;
                        // Don't return - fall through to create block index and connect
                    } else {
                        std::cout << "[P2P] Block in DB but parent still missing, skipping" << std::endl;
                        return;
                    }
                } else {
                    std::cout << "[P2P] Block already in chainstate, skipping" << std::endl;
                    return;
                }
            }

            // Save block to database first (skip if already there from BUG #88 path)
            if (!blockInDb && !blockchain.WriteBlock(blockHash, block)) {
                std::cerr << "[P2P] ERROR: Failed to save block from peer " << peer_id << std::endl;
                return;
            }
            if (!blockInDb) {
                std::cout << "[P2P] Block saved to database" << std::endl;
            }

            // Create block index with proper chain linkage
            // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
            auto pblockIndex = std::make_unique<CBlockIndex>(block);
            pblockIndex->phashBlock = blockHash;
            pblockIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;

            // Link to parent block
            pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pblockIndex->pprev == nullptr) {
                // BUG #12 FIX (Phase 4.3): Orphan block handling
                std::cout << "[P2P] Parent block not found: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                std::cout << "[P2P] Storing block as orphan and requesting parent" << std::endl;

                // CRITICAL-3 FIX: Validate orphan block before storing
                // Cannot do full UTXO validation without parent, but we can verify:
                // - Merkle root matches transactions (prevents tampering)
                // - Block structure is valid (has coinbase, no duplicates)
                CBlockValidator validator;
                std::vector<CTransactionRef> transactions;
                std::string validationError;

                // Deserialize and verify merkle root
                if (!validator.DeserializeBlockTransactions(block, transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Failed to deserialize orphan block transactions" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    std::cerr << "  Rejecting invalid block from peer " << peer_id << std::endl;
                    g_node_context.peer_manager->Misbehaving(peer_id, 100);  // Ban peer sending invalid blocks
                    return;
                }

                if (!validator.VerifyMerkleRoot(block, transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block has invalid merkle root" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    std::cerr << "  Block merkle root: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cerr << "  Rejecting invalid block from peer " << peer_id << std::endl;
                    g_node_context.peer_manager->Misbehaving(peer_id, 100);  // Ban peer sending invalid blocks
                    return;
                }

                // Check for duplicate transactions
                if (!validator.CheckNoDuplicateTransactions(transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block contains duplicate transactions" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    g_node_context.peer_manager->Misbehaving(peer_id, 100);
                    return;
                }

                // Check for double-spends within block
                if (!validator.CheckNoDoubleSpends(transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block contains double-spend" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    g_node_context.peer_manager->Misbehaving(peer_id, 100);
                    return;
                }

                // Add block to orphan manager (now validated)
                if (g_node_context.orphan_manager->AddOrphanBlock(peer_id, block)) {
                    // Request the missing parent block from the peer
                    std::vector<NetProtocol::CInv> getdata;
                    getdata.push_back(NetProtocol::CInv(NetProtocol::MSG_BLOCK_INV, block.hashPrevBlock));

                    std::cout << "[P2P] Requesting parent block from peer " << peer_id << std::endl;
                    if (g_node_context.connman && g_node_context.message_processor) {
                        CNetMessage msg = g_node_context.message_processor->CreateGetDataMessage(getdata);
                        g_node_context.connman->PushMessage(peer_id, msg);
                    }
                } else {
                    std::cerr << "[Orphan] ERROR: Failed to add block to orphan pool" << std::endl;
                    std::cerr << "  Pool may be full or block already exists" << std::endl;
                }

                // Cannot process orphan block yet - return early
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

            // Calculate height and chain work
            pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
            pblockIndex->BuildChainWork();

            std::cout << "[P2P] Block index created (height " << pblockIndex->nHeight << ")" << std::endl;

            // Save block index to database
            if (!blockchain.WriteBlockIndex(blockHash, *pblockIndex)) {
                std::cerr << "[P2P] ERROR: Failed to save block index" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

            // Add to chain state memory map (transfer ownership with std::move)
            if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                std::cerr << "[P2P] ERROR: Failed to add block to chain state" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - ownership transferred
                return;
            }

            // HIGH-C001 FIX: After move, retrieve pointer from chain state
            CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
            if (pblockIndexPtr == nullptr) {
                std::cerr << "[P2P] CRITICAL ERROR: Block index not found after adding!" << std::endl;
                return;
            }

            // Activate best chain (handles reorg if needed)
            bool reorgOccurred = false;
            if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
                if (reorgOccurred) {
                    std::cout << "[P2P] ⚠️  CHAIN REORGANIZATION occurred!" << std::endl;
                    std::cout << "  New tip: " << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                              << " (height " << g_chainstate.GetHeight() << ")" << std::endl;

                    // Signal main loop to update mining template
                    g_node_state.new_block_found = true;

                    // BUG #32 FIX: Immediately update mining template when reorg occurs
                    if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load() && !IsInitialBlockDownload()) {
                        std::cout << "[Mining] Reorg detected - updating template immediately..." << std::endl;
                        auto templateOpt = BuildMiningTemplate(blockchain, *g_node_state.wallet, false);
                        if (templateOpt) {
                            g_node_state.miner->UpdateTemplate(*templateOpt);
                            std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                        }
                    }
                } else {
                    std::cout << "[P2P] Block activated successfully" << std::endl;

                    // Check if this became the new tip
                    if (g_chainstate.GetTip() == pblockIndexPtr) {
                        std::cout << "[P2P] Updated best block to height " << pblockIndexPtr->nHeight << std::endl;
                        g_node_state.new_block_found = true;

                        // BUG #32 FIX: Immediately update mining template when IBD block becomes new tip
                        if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load() && !IsInitialBlockDownload()) {
                            std::cout << "[Mining] IBD block became new tip - updating template immediately..." << std::endl;
                            auto templateOpt = BuildMiningTemplate(blockchain, *g_node_state.wallet, false);
                            if (templateOpt) {
                                g_node_state.miner->UpdateTemplate(*templateOpt);
                                std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                            }
                        }

                        // BUG #43 FIX: Relay received blocks to other peers (Bitcoin Core standard)
                        // When we receive a block that becomes the new tip, relay it to all connected peers
                        // (except the peer that sent it to us) to propagate blocks network-wide
                        if (g_node_context.peer_manager && g_node_context.async_broadcaster) {
                            auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();
                            std::vector<int> relay_peer_ids;

                            // Collect peers with completed handshakes, excluding the sender
                            for (const auto& peer : connected_peers) {
                                if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
                                    relay_peer_ids.push_back(peer->id);
                                }
                            }

                            if (!relay_peer_ids.empty()) {
                                // Queue block relay asynchronously (non-blocking!)
                                if (g_node_context.async_broadcaster->BroadcastBlock(blockHash, relay_peer_ids)) {
                                    std::cout << "[P2P] Relaying block to " << relay_peer_ids.size()
                                              << " peer(s) (excluding sender peer " << peer_id << ")" << std::endl;
                                } else {
                                    std::cerr << "[P2P] ERROR: Failed to queue block relay" << std::endl;
                                }
                            } else {
                                std::cout << "[P2P] No other peers to relay block to" << std::endl;
                            }
                        }
                    } else {
                        std::cout << "[P2P] Block is valid but not on best chain" << std::endl;
                    }
                }

                // Notify BlockFetcher that block was successfully received and activated
                if (g_node_context.block_fetcher) {
                    g_node_context.block_fetcher->MarkBlockReceived(peer_id, blockHash);
                }

                // CRITICAL-2 FIX: Iterative orphan resolution with depth limit
                // Prevents stack overflow from unbounded recursion
                // Check if any orphan blocks are now valid children of this block

                static const int MAX_ORPHAN_CHAIN_DEPTH = 100;  // DoS protection
                std::queue<uint256> orphanQueue;
                int processedCount = 0;

                // Seed queue with direct children of this block
                std::vector<uint256> orphanChildren = g_node_context.orphan_manager->GetOrphanChildren(blockHash);
                for (const uint256& orphanHash : orphanChildren) {
                    orphanQueue.push(orphanHash);
                }

                if (!orphanQueue.empty()) {
                    // Iterative processing instead of recursion
                    while (!orphanQueue.empty() && processedCount < MAX_ORPHAN_CHAIN_DEPTH) {
                        uint256 orphanHash = orphanQueue.front();
                        orphanQueue.pop();

                        CBlock orphanBlock;
                        if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                            // Remove from orphan pool
                            g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);

                            // Process the orphan block inline (instead of recursive call)
                            uint256 orphanBlockHash = orphanBlock.GetHash();

                            // Validate PoW
                            if (!CheckProofOfWork(orphanBlockHash, orphanBlock.nBits)) {
                                std::cerr << "[Orphan] ERROR: Orphan block has invalid PoW" << std::endl;
                                processedCount++;
                                continue;
                            }

                            // Create block index
                            auto pOrphanIndex = std::make_unique<CBlockIndex>(orphanBlock);
                            pOrphanIndex->phashBlock = orphanBlockHash;
                            pOrphanIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;

                            // Link to parent
                            CBlockIndex* pOrphanParent = g_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
                            if (pOrphanParent) {
                                pOrphanIndex->pprev = pOrphanParent;
                                pOrphanIndex->nHeight = pOrphanParent->nHeight + 1;
                                pOrphanIndex->BuildChainWork();

                                // Add to chain state
                                CBlockIndex* pOrphanIndexRaw = pOrphanIndex.get();
                                if (g_chainstate.AddBlockIndex(orphanBlockHash, std::move(pOrphanIndex))) {
                                    // Activate in chain
                                    bool reorg = false;
                                    if (g_chainstate.ActivateBestChain(pOrphanIndexRaw, orphanBlock, reorg)) {
                                        // Save block to database
                                        if (!blockchain.WriteBlock(orphanBlockHash, orphanBlock)) {
                                            std::cerr << "[Orphan] ERROR: Failed to save orphan block to database" << std::endl;
                                        }
                                        // BUG #70 FIX: Save block INDEX to database (was missing!)
                                        // Without this, merkle root is lost on restart because only
                                        // the block is persisted, not the index with header fields
                                        if (!blockchain.WriteBlockIndex(orphanBlockHash, *pOrphanIndexRaw)) {
                                            std::cerr << "[Orphan] ERROR: Failed to save orphan block index to database" << std::endl;
                                        }

                                        // Queue this block's orphan children for processing
                                        std::vector<uint256> nextOrphans = g_node_context.orphan_manager->GetOrphanChildren(orphanBlockHash);
                                        for (const uint256& nextHash : nextOrphans) {
                                            orphanQueue.push(nextHash);
                                        }
                                    }
                                }
                            }

                            processedCount++;
                        }
                    }

                    if (processedCount >= MAX_ORPHAN_CHAIN_DEPTH) {
                        std::cerr << "[Orphan] WARNING: Orphan chain depth limit reached ("
                                  << MAX_ORPHAN_CHAIN_DEPTH << " blocks)" << std::endl;
                        std::cerr << "  Remaining in queue: " << orphanQueue.size() << std::endl;
                        std::cerr << "  This may indicate a DoS attack or network partition" << std::endl;
                    }
                }
            } else {
                std::cerr << "[P2P] ERROR: Failed to activate block in chain" << std::endl;
            }
        });

        // Register GETHEADERS handler - respond with block headers from our chain (Bug #12 - Phase 4.2)
        message_processor.SetGetHeadersHandler([&blockchain](
            int peer_id, const NetProtocol::CGetHeadersMessage& msg) {

            std::cout << "[IBD] Peer " << peer_id << " requested headers (locator size: "
                      << msg.locator.size() << ")" << std::endl;

            // Find the best common block between us and the peer
            uint256 hashStart;
            bool found = false;

            // Search through locator hashes to find first one we have
            for (const uint256& hash : msg.locator) {
                if (g_chainstate.HasBlockIndex(hash)) {
                    hashStart = hash;
                    found = true;
                    std::cout << "[IBD] Found common block: " << hash.GetHex().substr(0, 16) << "..." << std::endl;
                    break;
                }
            }

            if (!found) {
                // Bitcoin Core approach: empty locator means "send from genesis"
                if (msg.locator.empty()) {
                    std::cout << "[IBD] Empty locator - sending from genesis" << std::endl;
                    hashStart.SetHex(Dilithion::g_chainParams->genesisHash);
                    found = true;
                } else {
                    // BUG #59 FIX: Fall back to genesis for divergent chains
                    std::cout << "[IBD] No common block in locator - falling back to genesis" << std::endl;
                    hashStart.SetHex(Dilithion::g_chainParams->genesisHash);
                    found = true;
                }
            }

            // Collect up to 2000 headers starting from hashStart
            std::vector<CBlockHeader> headers;
            CBlockIndex* pindex = g_chainstate.GetBlockIndex(hashStart);

            if (pindex) {
                pindex = pindex->pnext;  // Start from next block (may be NULL if at tip)

                while (pindex && headers.size() < 2000) {
                    // BUG #70 DEBUG: Log merkle root of each header being sent
                    std::cerr << "[BUG70-DEBUG] Sending header height=" << pindex->nHeight
                              << " merkle=" << pindex->header.hashMerkleRoot.GetHex().substr(0,16)
                              << "..." << std::endl;
                    headers.push_back(pindex->header);
                    pindex = pindex->pnext;

                    // Stop if we reach the stop hash
                    if (!msg.hashStop.IsNull() && pindex && pindex->GetBlockHash() == msg.hashStop) {
                        break;
                    }
                }
            }

            // Always send HEADERS response, even if empty (Bitcoin Core protocol requirement)
            std::cout << "[IBD] Sending " << headers.size() << " header(s) to peer " << peer_id << std::endl;
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage headersMsg = g_node_context.message_processor->CreateHeadersMessage(headers);
                g_node_context.connman->PushMessage(peer_id, headersMsg);
            }
        });

        // Register HEADERS handler - process received headers (Bug #12 - Phase 4.2)
        message_processor.SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
            if (headers.empty()) {
                return;
            }

            std::cout << "[IBD] Received " << headers.size() << " header(s) from peer " << peer_id << std::endl;

            // BUG #125: Use async validation to prevent blocking network thread
            // QueueHeadersForValidation does quick structural validation immediately,
            // then queues expensive PoW validation for background thread
            bool useAsync = g_node_context.headers_manager->IsValidating();

            bool success = false;
            if (useAsync) {
                success = g_node_context.headers_manager->QueueHeadersForValidation(peer_id, headers);
                std::cout << "[IBD] Headers queued for async validation" << std::endl;
            } else {
                // Fallback to sync validation if async thread not running
                success = g_node_context.headers_manager->ProcessHeaders(peer_id, headers);
            }

            if (success) {
                int bestHeight = g_node_context.headers_manager->GetBestHeight();
                std::cout << "[IBD] Headers processed. Best height: " << bestHeight << std::endl;

                // Queue blocks for download from this peer
                if (g_node_context.block_fetcher) {
                    int startHeight = bestHeight - static_cast<int>(headers.size()) + 1;
                    for (size_t i = 0; i < headers.size(); i++) {
                        uint256 hash = headers[i].GetHash();
                        int height = startHeight + static_cast<int>(i);
                        g_node_context.block_fetcher->QueueBlockForDownload(hash, height, peer_id);
                    }
                    std::cout << "[IBD] Queued " << headers.size() << " blocks for download" << std::endl;
                }
            } else {
                // BUG #67: Even if ProcessHeaders failed, headers may have been partially processed
                // The main loop will detect header height changes and handle block downloads
                std::cerr << "[IBD] Headers processing incomplete (orphan or invalid header encountered)" << std::endl;
            }
        });

        // BUG #138 FIX: Start CConnman AFTER all handlers are registered
        // This ensures no messages are processed before handlers are in place
        if (!g_node_context.connman->Start(*g_node_context.peer_manager, message_processor, connman_opts)) {
            std::cerr << "Failed to start CConnman" << std::endl;
            return 1;
        }

        std::cout << "  [OK] P2P components ready and started" << std::endl;

        // Phase 3: Initialize mining controller
        std::cout << "Initializing mining controller..." << std::endl;
        int mining_threads = config.mining_threads > 0 ?
                            config.mining_threads :
                            std::thread::hardware_concurrency();
        CMiningController miner(mining_threads);
        g_node_state.miner = &miner;
        std::cout << "  [OK] Mining controller initialized (" << mining_threads << " threads)" << std::endl;

        // Phase 4: Initialize wallet (before mining callback setup)
        // BUG #56 FIX: Full wallet persistence with Bitcoin Core pattern
        std::cout << "Initializing wallet..." << std::endl;
        CWallet wallet;
        g_node_state.wallet = &wallet;

        // Build wallet file path
        std::string wallet_path = config.datadir + "/wallet.dat";
        std::cout << "  Wallet file: " << wallet_path << std::endl;

        // Try to load existing wallet from disk
        bool wallet_loaded = false;
        if (std::filesystem::exists(wallet_path)) {
            std::cout << "[3/6] Loading wallet..." << std::flush;
            std::cout.flush();
            if (wallet.Load(wallet_path)) {
                wallet_loaded = true;
                std::cout << " ✓" << std::endl;
                std::cout << "  [OK] Wallet loaded (" << wallet.GetAddresses().size() << " addresses)" << std::endl;
                std::cout << "       Best block: height " << wallet.GetBestBlockHeight() << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Failed to load wallet, creating new one" << std::endl;
                std::cerr.flush();
            }
        } else {
            std::cout << "  No existing wallet found, creating new one" << std::endl;
        }

        // Generate HD wallet if wallet is empty (new wallet creation)
        if (wallet.GetAddresses().empty()) {
            std::cout << "  Generating HD wallet with 24-word recovery phrase..." << std::endl;
            std::string mnemonic;
            if (wallet.GenerateHDWallet(mnemonic, "")) {
                // Display mnemonic prominently - this is CRITICAL for user to backup
                // BUG #97 FIX: Use ASCII box characters for Windows compatibility
                std::cout << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|              IMPORTANT: YOUR 24-WORD RECOVERY PHRASE                        |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|  Write these words on paper and store in a safe place.                      |" << std::endl;
                std::cout << "|  This is the ONLY way to recover your wallet if you lose access.            |" << std::endl;
                std::cout << "|  NEVER share this phrase with anyone or store it digitally.                 |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;

                // Parse and display words in a formatted grid (6 words per line)
                std::istringstream iss(mnemonic);
                std::vector<std::string> words;
                std::string word;
                while (iss >> word) {
                    words.push_back(word);
                }

                for (size_t i = 0; i < words.size(); i += 6) {
                    std::cout << "|  ";
                    for (size_t j = i; j < std::min(i + 6, words.size()); ++j) {
                        // Format: "NN.word      " (right-pad word to 10 chars)
                        std::ostringstream entry;
                        entry << (j + 1) << "." << std::setw(10) << std::left << words[j];
                        std::cout << std::setw(13) << std::left << entry.str();
                    }
                    // Pad remaining space to fill the row
                    size_t printed = std::min(size_t(6), words.size() - i);
                    for (size_t k = printed; k < 6; ++k) {
                        std::cout << "             ";  // 13 chars padding per missing word
                    }
                    std::cout << "|" << std::endl;
                }

                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;
                std::cout << "  [OK] HD Wallet created successfully!" << std::endl;
                std::cout << std::endl;

                // Generate and display first receiving address prominently
                CDilithiumAddress addr = wallet.GetNewHDAddress();
                std::string addrStr = addr.ToString();

                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|              YOUR PUBLIC RECEIVING ADDRESS (Copy & Share)                   |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  " << addrStr << std::string(76 - addrStr.length(), ' ') << "|" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;
                std::cout << "|  Share this address to receive DIL. Safe to share publicly.                 |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;

                // CRITICAL: Pause to let user write down recovery phrase
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|  IMPORTANT: Have you written down your 24-word recovery phrase?             |" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  This is your ONLY backup. If you lose it, your funds are GONE FOREVER.     |" << std::endl;
                std::cout << "|  Store it safely on PAPER - never digitally!                                |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;

                // Require explicit Y confirmation to ensure user has read and saved the phrase
                std::string confirm;
                while (true) {
                    std::cout << "  >>> Type 'Y' to confirm you have saved your recovery phrase: ";
                    std::cout.flush();
                    std::getline(std::cin, confirm);
                    if (confirm == "Y" || confirm == "y" || confirm == "yes" || confirm == "YES") {
                        break;
                    }
                    std::cout << "  Please type 'Y' to confirm. Your recovery phrase is critical!" << std::endl;
                }
                std::cout << std::endl;
                std::cout << "  [OK] Continuing with node startup..." << std::endl;
                std::cout << std::endl;
            } else {
                // Fallback to legacy key generation if HD fails
                std::cerr << "  WARNING: HD wallet generation failed, using legacy key" << std::endl;
                wallet.GenerateNewKey();
                CDilithiumAddress addr = wallet.GetNewAddress();
                std::cout << "  [OK] Initial address (legacy): " << addr.ToString() << std::endl;
            }
        }

        // Enable auto-save (CRITICAL: must be done after Load or key generation)
        wallet.SetWalletFile(wallet_path);
        std::cout << "  [OK] Auto-save enabled" << std::endl;
        std::cout.flush();

        // BUG #56 FIX: Register wallet callbacks with chain state (Bitcoin Core pattern)
        // Wallet will receive blockConnected/blockDisconnected notifications automatically
        g_chainstate.RegisterBlockConnectCallback([&wallet](const CBlock& block, int height) {
            wallet.blockConnected(block, height);
        });
        g_chainstate.RegisterBlockDisconnectCallback([&wallet](const CBlock& block, int height) {
            wallet.blockDisconnected(block, height);
        });
        std::cout << "  [OK] Registered chain notification callbacks" << std::endl;
        std::cout.flush();

        // BUG #56 FIX: Incremental rescan based on best block pointer (Bitcoin Core pattern)
        int32_t wallet_height = wallet.GetBestBlockHeight();
        int chain_height = g_chainstate.GetHeight();
        std::cout << "  Wallet best block: " << wallet_height << ", Chain height: " << chain_height << std::endl;
        std::cout.flush();

        if (wallet_height < 0 || wallet_height > chain_height) {
            // Full rescan needed: new wallet OR wallet ahead of chain (possible reorg)
            std::cout << "  Rescanning blockchain (full scan from genesis)..." << std::endl;
            std::cout.flush();
            if (wallet.RescanFromHeight(g_chainstate, blockchain, 0, chain_height)) {
                unsigned int height = static_cast<unsigned int>(chain_height);
                // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                // Previously used GetBalance() - GetImmatureBalance() which could differ
                int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
                int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
                int64_t total = mature + immature;
                std::cout << "  [OK] Full scan complete" << std::endl;
                std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Total: " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Rescan failed" << std::endl;
            }
        } else if (wallet_height < chain_height) {
            // Incremental rescan: scan only blocks since wallet's last sync
            std::cout << "  Rescanning blocks " << (wallet_height + 1) << " to " << chain_height
                      << " (incremental)..." << std::endl;
            std::cout.flush();
            if (wallet.RescanFromHeight(g_chainstate, blockchain, wallet_height + 1, chain_height)) {
                unsigned int height = static_cast<unsigned int>(chain_height);
                // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
                int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
                int64_t total = mature + immature;
                std::cout << "  [OK] Incremental scan complete" << std::endl;
                std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Total: " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Rescan failed" << std::endl;
            }
        } else {
            // wallet_height == chain_height: Already synced, no scan needed
            unsigned int height = static_cast<unsigned int>(chain_height);
            // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
            int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
            int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
            int64_t total = mature + immature;
            std::cout << "  [OK] Wallet already synced to chain tip" << std::endl;
            std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
            std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
            std::cout << "       Total: " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
            std::cout.flush();
        }

        // Save wallet if newly created
        if (!wallet_loaded) {
            if (wallet.Save(wallet_path)) {
                std::cout << "  [OK] New wallet saved" << std::endl;
            } else {
                std::cerr << "  WARNING: Failed to save new wallet" << std::endl;
            }
        }

        // Set up block found callback to save mined blocks and credit wallet
        miner.SetBlockFoundCallback([&blockchain, &wallet, &utxo_set](const CBlock& block) {
            // CRITICAL: Check shutdown flag FIRST to prevent database corruption during shutdown
            if (!g_node_state.running) {
                // Shutting down - discard this block to prevent race condition
                return;
            }

            uint256 blockHash = block.GetHash();
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "[OK] BLOCK FOUND!" << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "Block hash: " << blockHash.GetHex() << std::endl;
            std::cout << "Block time: " << block.nTime << std::endl;
            std::cout << "Nonce: " << block.nNonce << std::endl;
            // CID 1675194 FIX: Save and restore ostream format state to prevent affecting subsequent output
            std::ios_base::fmtflags oldFlags = std::cout.flags();
            std::cout << "Difficulty: 0x" << std::hex << block.nBits;
            std::cout.flags(oldFlags);  // Restore original format flags
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << std::endl;

            // BUG #84 FIX: Extract coinbase from actual block, not global
            // Race condition: g_currentCoinbase might be overwritten by template updates
            // before the block is found, causing hash mismatch between wallet and UTXO set
            CTransactionRef coinbase;
            {
                CBlockValidator validator;
                std::vector<CTransactionRef> transactions;
                std::string error;
                if (validator.DeserializeBlockTransactions(block, transactions, error) && !transactions.empty()) {
                    coinbase = transactions[0];  // Coinbase is always first transaction
                } else {
                    std::cerr << "[Wallet] ERROR: Failed to deserialize coinbase from block: " << error << std::endl;
                }
            }

            // BUG #95 FIX: Wallet crediting moved to AFTER chain tip decision below
            // Only credit when block actually becomes chain tip, not for orphaned/stale blocks

            // Save block to blockchain database
            if (!blockchain.WriteBlock(blockHash, block)) {
                std::cerr << "[Blockchain] ERROR: Failed to save block to database!" << std::endl;
                return;
            }
            std::cout << "[Blockchain] Block saved to database" << std::endl;

            // Create block index with proper chain linkage
            // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
            auto pblockIndex = std::make_unique<CBlockIndex>(block);
            pblockIndex->phashBlock = blockHash;
            pblockIndex->nStatus = CBlockIndex::BLOCK_HAVE_DATA;

            // Link to parent block
            pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pblockIndex->pprev == nullptr) {
                std::cerr << "[Blockchain] ERROR: Cannot find parent block "
                          << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

            // Calculate height and chain work
            pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
            pblockIndex->BuildChainWork();

            std::cout << "[Blockchain] Block index created (height " << pblockIndex->nHeight << ")" << std::endl;

            // Save block index to database
            std::cout << "[Blockchain] DEBUG: Calling WriteBlockIndex for " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
            if (!blockchain.WriteBlockIndex(blockHash, *pblockIndex)) {
                std::cerr << "[Blockchain] ERROR: Failed to save block index" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }
            std::cout << "[Blockchain] DEBUG: WriteBlockIndex succeeded" << std::endl;

            // Add to chain state memory map (transfer ownership with std::move)
            if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                std::cerr << "[Blockchain] ERROR: Failed to add block to chain state" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - ownership transferred
                return;
            }

            // HIGH-C001 FIX: After move, retrieve pointer from chain state
            CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
            if (pblockIndexPtr == nullptr) {
                std::cerr << "[Blockchain] CRITICAL ERROR: Block index not found after adding!" << std::endl;
                return;
            }

            // Activate best chain (handles reorg if needed)
            bool reorgOccurred = false;
            if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
                if (reorgOccurred) {
                    std::cout << "[Blockchain] ⚠️  CHAIN REORGANIZATION occurred during mining!" << std::endl;
                    std::cout << "  Our mined block triggered a reorg" << std::endl;
                    std::cout << "  New tip: " << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                              << " (height " << g_chainstate.GetHeight() << ")" << std::endl;

                    // Stop mining - need to reassess chain state
                    g_node_state.new_block_found = true;
                } else if (g_chainstate.GetTip() == pblockIndexPtr) {
                    std::cout << "[Blockchain] Block became new chain tip at height " << pblockIndexPtr->nHeight << std::endl;

                    // BUG #95 FIX: Only credit wallet when block actually becomes chain tip
                    // This prevents crediting for orphaned/stale blocks on competing chains
                    if (coinbase && !coinbase->vout.empty()) {
                        const CTxOut& coinbaseOut = coinbase->vout[0];
                        std::vector<uint8_t> pubkey_hash = WalletCrypto::ExtractPubKeyHash(coinbaseOut.scriptPubKey);
                        std::vector<uint8_t> our_hash = wallet.GetPubKeyHash();

                        if (!pubkey_hash.empty() && pubkey_hash == our_hash) {
                            CDilithiumAddress our_address = wallet.GetNewAddress();
                            wallet.AddTxOut(coinbase->GetHash(), 0, coinbaseOut.nValue, our_address, pblockIndexPtr->nHeight);

                            double amountDIL = static_cast<double>(coinbaseOut.nValue) / 100000000.0;
                            std::cout << "[Wallet] Coinbase credited: " << std::fixed << std::setprecision(8)
                                      << amountDIL << " DIL (immature for 100 blocks)" << std::endl;

                            // Get current height for maturity calculation
                            unsigned int current_height = static_cast<unsigned int>(g_chainstate.GetHeight());

                            // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                            // Mature balance (spendable) - verified against UTXO set
                            int64_t mature_balance = wallet.GetAvailableBalance(utxo_set, current_height);
                            double matureDIL = static_cast<double>(mature_balance) / 100000000.0;

                            // Immature balance (coinbase not yet mature)
                            int64_t immature_balance = wallet.GetImmatureBalance(utxo_set, current_height);
                            double immatureDIL = static_cast<double>(immature_balance) / 100000000.0;

                            // Total balance
                            int64_t total_balance = mature_balance + immature_balance;
                            double totalDIL = static_cast<double>(total_balance) / 100000000.0;

                            std::cout << "[Wallet] Balance: " << std::fixed << std::setprecision(8)
                                      << matureDIL << " DIL (mature/spendable)" << std::endl;
                            std::cout << "[Wallet]          " << std::fixed << std::setprecision(8)
                                      << immatureDIL << " DIL (immature coinbase)" << std::endl;
                            std::cout << "[Wallet]          " << std::fixed << std::setprecision(8)
                                      << totalDIL << " DIL (total)" << std::endl;
                        }
                    }

                    // BUG #32 FIX: Immediately update mining template for locally mined blocks
                    // BUG #65 FIX: Skip IBD check for locally mined blocks - we KNOW we're at chain tip
                    // because we just mined this block ourselves. The IBD check fails when peers
                    // are connected but haven't completed handshake (version=0), which incorrectly
                    // prevents mining from resuming after finding a block.
                    bool immediate_update_succeeded = false;
                    if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load()) {
                        std::cout << "[Mining] Locally mined block became new tip - updating template immediately..." << std::endl;
                        auto templateOpt = BuildMiningTemplate(blockchain, *g_node_state.wallet, false);
                        if (templateOpt) {
                            g_node_state.miner->UpdateTemplate(*templateOpt);
                            std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                            immediate_update_succeeded = true;
                        } else {
                            std::cerr << "[Mining] ERROR: Immediate template build failed" << std::endl;
                        }
                    }

                    // Broadcast block to network (P2P block relay) - Using async broadcaster
                    auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();

                    if (!connected_peers.empty()) {
                        // Collect peer IDs with completed handshakes
                        std::vector<int> peer_ids;
                        for (const auto& peer : connected_peers) {
                            if (peer && peer->IsHandshakeComplete()) {
                                peer_ids.push_back(peer->id);
                            }
                        }

                        if (!peer_ids.empty()) {
                            // Queue block broadcast asynchronously (non-blocking!)
                            if (g_node_context.async_broadcaster->BroadcastBlock(blockHash, peer_ids)) {
                                std::cout << "[P2P] Queued block broadcast to " << peer_ids.size()
                                          << " peer(s) (async)" << std::endl;
                            } else {
                                std::cerr << "[P2P] ERROR: Failed to queue block broadcast" << std::endl;
                            }
                        } else {
                            std::cout << "[P2P] WARNING: No peers with completed handshakes" << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] WARNING: No connected peers to broadcast block" << std::endl;
                    }

                    // BUG #65 FIX: Only signal main loop if immediate update failed
                    // If immediate update succeeded, mining is already continuing - don't let
                    // main loop stop it (which it would do if IBD check fails there)
                    if (!immediate_update_succeeded) {
                        g_node_state.new_block_found = true;
                    }
                } else {
                    std::cout << "[Blockchain] WARNING: Mined block is valid but not on best chain" << std::endl;
                    std::cout << "  This should not happen during solo mining" << std::endl;
                    std::cout << "  Current tip: " << g_chainstate.GetTip()->GetBlockHash().GetHex().substr(0, 16)
                              << " (height " << g_chainstate.GetHeight() << ")" << std::endl;

                    // Stop mining and reassess
                    g_node_state.new_block_found = true;
                }
            } else {
                std::cerr << "[Blockchain] ERROR: Failed to activate mined block in chain" << std::endl;
            }
        });

        // Phase 2.5: Start P2P networking server
        std::cerr.flush();
        std::cout << "[4/6] Starting P2P networking server..." << std::flush;

        // Set running flag before starting threads
        g_node_state.running = true;
        std::cerr.flush();

        // Initialize socket layer (required for Windows)
        std::cerr.flush();
        CSocketInit socket_init;
        std::cerr.flush();

        // Phase 5: CConnman handles socket binding and listening internally
        // The old CSocket p2p_socket code is removed - CConnman already bound to port in NodeContext init
        // g_node_state.p2p_socket is no longer used - kept as nullptr for backward compatibility

        std::cout << " ✓" << std::endl;
        std::cout << "  [OK] P2P server listening on port " << config.p2pport << " (CConnman)" << std::endl;

        // Phase 5: CConnman handles accept internally via ThreadSocketHandler
        // No need for separate p2p_thread - accept is handled in CConnman::SocketHandler()
        std::cout << "  [OK] P2P accept handled by CConnman::ThreadSocketHandler" << std::endl;

        // Helper function to parse IPv4 address string to uint32_t
        auto parseIPv4 = [](const std::string& ip) -> uint32_t {
            if (ip == "localhost") {
                return 0x7F000001;  // 127.0.0.1
            }

            // Parse dotted decimal notation (e.g., "134.122.4.164")
            uint32_t result = 0;
            int shift = 24;
            size_t start = 0;
            int octet_count = 0;

            for (size_t i = 0; i <= ip.length(); ++i) {
                if (i == ip.length() || ip[i] == '.') {
                    if (i > start) {
                        int octet = std::stoi(ip.substr(start, i - start));
                        if (octet < 0 || octet > 255) {
                            return 0;  // Invalid octet
                        }
                        result |= (static_cast<uint32_t>(octet) << shift);
                        shift -= 8;
                        octet_count++;
                    }
                    start = i + 1;
                }
            }

            return (octet_count == 4) ? result : 0;
        };

        // Initiate outbound connections for --connect nodes
        if (!config.connect_nodes.empty()) {
            std::cout << "Initiating outbound connections..." << std::endl;
            for (const auto& node_addr : config.connect_nodes) {
                std::cout << "  Connecting to " << node_addr << "..." << std::endl;

                // Parse ip:port
                size_t colon_pos = node_addr.find(':');
                if (colon_pos != std::string::npos) {
                    std::string ip = node_addr.substr(0, colon_pos);
                    std::string port_str = node_addr.substr(colon_pos + 1);

                    // PHASE 4 FIX: Add exception handling for invalid port in peer address
                    uint16_t port = 0;
                    try {
                        int port_int = std::stoi(port_str);
                        if (port_int < Consensus::MIN_PORT || port_int > Consensus::MAX_PORT) {
                            std::cerr << "    [FAIL] Invalid port number in address: " << node_addr
                                      << " (must be " << Consensus::MIN_PORT << "-" << Consensus::MAX_PORT << ")" << std::endl;
                            continue;
                        }
                        port = static_cast<uint16_t>(port_int);
                    } catch (const std::exception& e) {
                        std::cerr << "    [FAIL] Invalid port format in address: " << node_addr
                                  << " (expected ip:port)" << std::endl;
                        continue;
                    }

                    NetProtocol::CAddress addr;
                    addr.time = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);  // CID 1675257 FIX
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    // Parse IPv4 address
                    uint32_t ip_addr = parseIPv4(ip);
                    if (ip_addr == 0) {
                        std::cerr << "    [FAIL] Invalid IP address: " << ip << std::endl;
                        continue;
                    }
                    addr.SetIPv4(ip_addr);

                    // Phase 5: Use CConnman to connect and send VERSION
                    int peer_id = ConnectAndHandshake(addr);
                    if (peer_id >= 0) {
                        std::cout << "    [OK] Initiated connection to " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;
                        std::cout << "    [INFO] VERSION will be sent after connection completes" << std::endl;
                    } else {
                        std::cout << "    [FAIL] Failed to connect to " << node_addr << std::endl;
                    }
                } else {
                    std::cerr << "    [FAIL] Invalid address format: " << node_addr << " (expected ip:port)" << std::endl;
                }
            }
        }

        // Add additional nodes (non-exclusive)
        if (!config.add_nodes.empty()) {
            std::cout << "Adding additional peer nodes..." << std::endl;
            for (const auto& node_addr : config.add_nodes) {
                std::cout << "  Adding node " << node_addr << "..." << std::endl;

                // Parse ip:port
                size_t colon_pos = node_addr.find(':');
                if (colon_pos != std::string::npos) {
                    std::string ip = node_addr.substr(0, colon_pos);
                    std::string port_str = node_addr.substr(colon_pos + 1);

                    // PHASE 4 FIX: Add exception handling for invalid port in peer address
                    uint16_t port = 0;
                    try {
                        int port_int = std::stoi(port_str);
                        if (port_int < Consensus::MIN_PORT || port_int > Consensus::MAX_PORT) {
                            std::cerr << "    [FAIL] Invalid port number in address: " << node_addr
                                      << " (must be " << Consensus::MIN_PORT << "-" << Consensus::MAX_PORT << ")" << std::endl;
                            continue;
                        }
                        port = static_cast<uint16_t>(port_int);
                    } catch (const std::exception& e) {
                        std::cerr << "    [FAIL] Invalid port format in address: " << node_addr
                                  << " (expected ip:port)" << std::endl;
                        continue;
                    }

                    NetProtocol::CAddress addr;
                    addr.time = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);  // CID 1675257 FIX
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    // Parse IPv4 address
                    uint32_t ip_addr = parseIPv4(ip);
                    if (ip_addr == 0) {
                        std::cerr << "    [FAIL] Invalid IP address: " << ip << std::endl;
                        continue;
                    }
                    addr.SetIPv4(ip_addr);

                    // Phase 5: Use CConnman to initiate connection
                    int peer_id = ConnectAndHandshake(addr);
                    if (peer_id >= 0) {
                        std::cout << "    [OK] Added node " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;
                        std::cout << "    [INFO] VERSION will be sent after connection completes" << std::endl;
                    } else {
                        std::cout << "    [FAIL] Failed to add node " << node_addr << std::endl;
                    }
                } else {
                    std::cerr << "    [FAIL] Invalid address format: " << node_addr << " (expected ip:port)" << std::endl;
                }
            }
        }

        // Automatically connect to hardcoded seed nodes (unless --connect specified)
        // BUG FIX: --connect is exclusive, --addnode is additive with seed nodes
        if (config.connect_nodes.empty()) {
            std::cout << "Connecting to seed nodes..." << std::endl;
            auto seeds = g_node_context.peer_manager->GetSeedNodes();

            for (const auto& seed_addr : seeds) {
                std::string ip_str = seed_addr.ToStringIP();
                uint16_t port = seed_addr.port;

                std::cout << "  Connecting to " << ip_str << ":" << port << "..." << std::endl;

                // Phase 5: Use CConnman to initiate connection
                int peer_id = ConnectAndHandshake(seed_addr);
                if (peer_id >= 0) {
                    std::cout << "    [OK] Connected to seed node (peer_id=" << peer_id << ")" << std::endl;
                    std::cout << "    [INFO] VERSION will be sent after connection completes" << std::endl;
                } else {
                    std::cout << "    [FAIL] Failed to connect to " << ip_str << ":" << port << std::endl;
                }
            }
        }

        // Phase 5: CConnman handles message receiving internally via ThreadSocketHandler and ThreadMessageHandler
        // No need for separate p2p_recv_thread
        std::cout << "  [OK] P2P receive handled by CConnman::ThreadSocketHandler and ThreadMessageHandler" << std::endl;

        // Launch P2P maintenance thread (ping/pong keepalive, reconnection, score decay)
        // BUG #49 FIX: Add automatic peer reconnection and misbehavior score decay
        // BUG #85 FIX: Add exception handling to prevent std::terminate
        // BUG #88: Windows startup crash fix - wrap thread creation in try/catch
        // Phase 5: Updated to use CConnman instead of CConnectionManager
        std::cerr.flush();
        std::thread p2p_maint_thread;
        try {
            p2p_maint_thread = std::thread([&feeler_manager]() {
            // Phase 1.1: Wrap thread entry point in try/catch to prevent silent crashes
            try {
                std::cout << "  [OK] P2P maintenance thread started" << std::endl;

                int cycles_without_peers = 0;
                auto last_reconnect_attempt = std::chrono::steady_clock::now();

                while (g_node_state.running) {
                    try {
                    // Phase 5: Proactive outbound connections handled by CConnman::ThreadOpenConnections
                    // This thread handles reactive reconnection and other maintenance
                    // Ping/pong is handled automatically by message handlers

                    // BUG #49: Check if we need to reconnect to seed nodes
                    size_t peer_count = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectionCount() : 0;

                    if (peer_count == 0) {
                        cycles_without_peers++;

                        // Attempt reconnection every 60 seconds when isolated
                        auto now = std::chrono::steady_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_reconnect_attempt);

                        if (elapsed.count() >= 60) {
                            std::cout << "[P2P-Maintenance] No peers connected - attempting to reconnect to seed nodes..." << std::endl;
                            last_reconnect_attempt = now;

                            // Get seed nodes from peer manager
                            auto seed_nodes = g_node_context.peer_manager ? g_node_context.peer_manager->GetSeedNodes() : std::vector<NetProtocol::CAddress>();

                            // Try to connect to each seed node
                            int successful_connections = 0;
                            for (const auto& seed_addr : seed_nodes) {
                                try {
                                    std::string ip_str = seed_addr.ToStringIP();
                                    uint16_t port = seed_addr.port;

                                    std::cout << "[P2P-Maintenance] Attempting connection to seed " << ip_str << ":" << port << std::endl;

                                    // Phase 5: Use CConnman to connect and send VERSION
                                    int peer_id = ConnectAndHandshake(seed_addr);
                                    if (peer_id >= 0) {
                                        std::cout << "[P2P-Maintenance] Connected to seed node (peer_id=" << peer_id << ")" << std::endl;
                                        std::cout << "[P2P-Maintenance] Sent VERSION to peer " << peer_id << std::endl;
                                        successful_connections++;
                                    } else {
                                        std::cout << "[P2P-Maintenance] Failed to connect to seed " << ip_str << ":" << port << std::endl;
                                    }
                                } catch (const std::exception& e) {
                                    std::cerr << "[P2P-Maintenance] Exception connecting to seed: " << e.what() << std::endl;
                                }
                            }

                            if (successful_connections > 0) {
                                std::cout << "[P2P-Maintenance] Reconnected to " << successful_connections << " seed node(s)" << std::endl;
                                cycles_without_peers = 0;
                            } else {
                                std::cout << "[P2P-Maintenance] Could not reconnect to any seed nodes" << std::endl;
                            }
                        }
                    } else {
                        if (cycles_without_peers > 0) {
                            std::cout << "[P2P-Maintenance] Peer connectivity restored (" << peer_count << " peers)" << std::endl;
                            cycles_without_peers = 0;
                        }
                    }

                    // ThreadOpenConnections: Proactively connect to addresses from AddrMan
                    // Bitcoin Core pattern: maintain target of 8 outbound connections
                    constexpr size_t TARGET_OUTBOUND = 8;
                    if (g_node_context.peer_manager) {
                        size_t outbound_count = g_node_context.peer_manager->GetOutboundCount();

                        if (outbound_count < TARGET_OUTBOUND) {
                            size_t needed = TARGET_OUTBOUND - outbound_count;

                            // Get addresses from AddrMan (request extra in case some fail or are connected)
                            auto addrs = g_node_context.peer_manager->SelectAddressesToConnect(static_cast<int>(needed * 3));

                            if (!addrs.empty()) {
                                // Get currently connected peer IPs to skip
                                std::set<std::string> connected_ips;
                                auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();
                                for (const auto& peer : connected_peers) {
                                    if (peer) {
                                        connected_ips.insert(peer->addr.ToStringIP());
                                    }
                                }

                                size_t connections_made = 0;
                                for (const auto& addr : addrs) {
                                    if (connections_made >= needed) break;

                                    std::string ip_str = addr.ToStringIP();

                                    // Skip already connected
                                    if (connected_ips.count(ip_str)) {
                                        continue;
                                    }

                                    // Skip non-routable
                                    if (!addr.IsRoutable()) {
                                        continue;
                                    }

                                    // Mark as tried before attempting
                                    g_node_context.peer_manager->MarkAddressTried(addr);

                                    try {
                                        // Phase 5: Use CConnman to connect and send VERSION
                                        int peer_id = ConnectAndHandshake(addr);
                                        if (peer_id >= 0) {
                                            std::cout << "[P2P-OpenConn] Connected to " << ip_str
                                                      << " from AddrMan (peer_id=" << peer_id << ")" << std::endl;
                                            connections_made++;
                                            // Phase 5: Mark as good on successful connection
                                            g_node_context.peer_manager->MarkAddressGood(addr);
                                        }
                                    } catch (const std::exception& e) {
                                        // Connection failed - that's OK, we'll try others
                                    }
                                }

                                if (connections_made > 0) {
                                    std::cout << "[P2P-OpenConn] Made " << connections_made
                                              << " new connection(s) from AddrMan" << std::endl;
                                }
                            }
                        }
                    }

                    // BUG #49: Decay misbehavior scores (reduce by 1 point per minute)
                    // This happens every 30 seconds, so decay by 0.5 points
                    if (g_node_context.peer_manager) {
                        g_node_context.peer_manager->DecayMisbehaviorScores();
                        // Periodic maintenance: evict peers if needed, save peers
                        g_node_context.peer_manager->PeriodicMaintenance();
                    }

                    // Process feeler connections (Bitcoin Core-style eclipse attack protection)
                    // Feeler connections test addresses we haven't tried recently
                    // Phase 5: Re-enabled after CFeelerManager migration to CConnman
                    feeler_manager.ProcessFeelerConnections();

                    // Sleep for 30 seconds between maintenance cycles
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                } catch (const std::system_error& e) {
                    std::cerr << "[P2P-Maint] System error in maintenance loop: " << e.what()
                              << " (code: " << e.code() << ")" << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                } catch (const std::exception& e) {
                    std::cerr << "[P2P-Maint] Exception in maintenance loop: " << e.what() << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                } catch (...) {
                    std::cerr << "[P2P-Maint] Unknown exception in maintenance loop" << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
                }

                std::cout << "  P2P maintenance thread stopping..." << std::endl;
            } catch (const std::exception& e) {
                // Phase 1.1: Prevent silent thread crashes
                LogPrintf(NET, ERROR, "P2P maintenance thread exception: %s", e.what());
                std::cerr << "[P2P-Maintenance] FATAL: Thread exception: " << e.what() << std::endl;
            } catch (...) {
                LogPrintf(NET, ERROR, "P2P maintenance thread unknown exception");
                std::cerr << "[P2P-Maintenance] FATAL: Unknown thread exception" << std::endl;
            }
            });
            std::cerr.flush();
        } catch (const std::exception& e) {
            std::cerr.flush();
            g_node_state.running = false;
            throw;
        } catch (...) {
            std::cerr.flush();
            g_node_state.running = false;
            throw;
        }

        // BUG #88: All P2P threads created successfully
        std::cerr.flush();

        // Phase 4: Initialize RPC server
        std::cerr.flush();
        std::cout << "[4/6] Initializing RPC server..." << std::flush;
        CRPCServer rpc_server(config.rpcport);
        g_node_state.rpc_server = &rpc_server;

        // Register components with RPC server
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);
        rpc_server.RegisterBlockchain(&blockchain);
        rpc_server.RegisterChainState(&g_chainstate);
        rpc_server.RegisterMempool(&mempool);
        rpc_server.RegisterUTXOSet(&utxo_set);
        rpc_server.SetTestnet(config.testnet);

        // Phase 1: Initialize authentication and permissions
        std::string rpcuser = config_parser.GetString("rpcuser", "");
        std::string rpcpassword = config_parser.GetString("rpcpassword", "");
        std::string rpc_permissions_file = config.datadir + "/rpc_permissions.json";
        
        if (!rpcuser.empty() && !rpcpassword.empty()) {
            // Initialize permissions system
            if (!rpc_server.InitializePermissions(rpc_permissions_file, rpcuser, rpcpassword)) {
                std::cerr << "WARNING: Failed to initialize RPC permissions, continuing without authentication" << std::endl;
            } else {
                std::cout << "  [AUTH] RPC authentication enabled" << std::endl;
            }
        } else {
            std::cout << "  [INFO] RPC authentication disabled (no rpcuser/rpcpassword in config)" << std::endl;
        }

        // Phase 1: Initialize request logging
        std::string rpc_log_file = config.datadir + "/rpc.log";
        std::string rpc_audit_file = config.datadir + "/rpc_audit.log";
        rpc_server.InitializeLogging(rpc_log_file, rpc_audit_file, CRPCLogger::LogLevel::INFO);

        // Phase 3: Initialize SSL/TLS if configured
        std::string rpc_cert_file = config_parser.GetString("rpcsslcertificatechainfile", "");
        std::string rpc_key_file = config_parser.GetString("rpcsslprivatekeyfile", "");
        if (!rpc_cert_file.empty() && !rpc_key_file.empty()) {
            std::string rpc_ca_file = config_parser.GetString("rpcsslcapath", "");
            if (!rpc_server.InitializeSSL(rpc_cert_file, rpc_key_file, rpc_ca_file)) {
                std::cerr << "WARNING: Failed to initialize SSL/TLS, continuing without encryption" << std::endl;
            }
        }

        // Phase 4: Initialize WebSocket server if configured
        int64_t ws_port = config_parser.GetInt64("rpcwebsocketport", 0);
        if (ws_port > 0 && ws_port <= 65535) {
            if (!rpc_server.InitializeWebSocket(static_cast<uint16_t>(ws_port))) {
                std::cerr << "WARNING: Failed to initialize WebSocket server, continuing without WebSocket" << std::endl;
            }
        }

        if (!rpc_server.Start()) {
            std::cerr << "Failed to start RPC server on port " << config.rpcport << std::endl;
            return 1;
        }
        std::cout << "  [OK] RPC server listening on port " << config.rpcport << std::endl;

        // Start mining if requested
        // BUG #54 FIX: Don't block here - let main loop run for block downloads
        // Mining will start inside main loop after IBD completes
        bool mining_deferred_for_ibd = false;  // Track if we're waiting for IBD
        if (config.start_mining) {
            g_node_state.mining_enabled = true;  // Track that mining was requested
            std::cout << std::endl;
            std::cout << "Mining enabled - checking sync status..." << std::endl;

            // BUG #52 FIX: Check IBD before starting mining (Bitcoin pattern)
            // This prevents fresh nodes from mining on their own chain before syncing
            // BUG #54 FIX: Don't BLOCK here - just defer mining and let main loop run
            if (IsInitialBlockDownload()) {
                std::cout << "  [IBD] Node is syncing - mining will start after sync" << std::endl;
                std::cout << "  [IBD] Main loop will handle block downloads, mining deferred..." << std::endl;
                mining_deferred_for_ibd = true;
                // DO NOT block here - main loop needs to run for block downloads!
            } else {
                std::cout << "  [OK] Already synced with network" << std::endl;

                // BUG #72 FIX: Wait for FULL mode before starting mining threads
                // Following XMRig's proven pattern: "dataset ready" before thread creation
                // Mining threads created in LIGHT mode get LIGHT VMs and never upgrade
                if (!randomx_is_mining_mode_ready()) {
                    // BUG #98 FIX: Must INITIALIZE FULL mode before waiting for it!
                    // The "already synced" path was waiting but never calling init_mining_mode_async
                    std::cout << "  Initializing RandomX mining mode (FULL)..." << std::endl;
                    randomx_init_mining_mode_async(rx_key, strlen(rx_key));
                    std::cout << "  [WAIT] Waiting for RandomX FULL mode..." << std::endl;
                    auto wait_start = std::chrono::steady_clock::now();
                    while (!randomx_is_mining_mode_ready() && g_node_state.running) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        auto elapsed = std::chrono::steady_clock::now() - wait_start;
                        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 600) {
                            std::cerr << "  [WARN] FULL mode init timeout (10min), starting with LIGHT mode" << std::endl;
                            break;
                        }
                        // Show progress every 60 seconds
                        auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                        if (elapsed_sec > 0 && elapsed_sec % 60 == 0) {
                            std::cout << "  [WAIT] Still initializing FULL mode... (" << elapsed_sec << "s)" << std::endl;
                        }
                    }
                    auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - wait_start).count();
                    std::cout << "  [OK] Mining mode ready (FULL, " << wait_time << "s)" << std::endl;
                } else {
                    std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                }

                // Now safe to start mining (synced with network)
                unsigned int current_height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                std::cout << "  [OK] Current blockchain height: " << current_height << std::endl;

                auto templateOpt = BuildMiningTemplate(blockchain, wallet, true);
                if (!templateOpt) {
                    std::cerr << "ERROR: Failed to build mining template" << std::endl;
                    std::cerr << "Blockchain may not be initialized. Cannot start mining." << std::endl;
                    return 1;
                }

                miner.StartMining(*templateOpt);

                std::cout << "  [OK] Mining started with " << mining_threads << " threads" << std::endl;
                std::cout << "  Expected hash rate: ~" << (mining_threads * 65) << " H/s" << std::endl;
            }
        }

        // Node is ready
        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "Node Status: RUNNING" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << std::endl;
        std::cout << "RPC Interface:" << std::endl;
        std::cout << "  URL: http://localhost:" << config.rpcport << std::endl;
        std::cout << "  Methods: getnewaddress, getbalance, getmininginfo, help" << std::endl;
        std::cout << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        std::cout << std::endl;

        // Phase 5.1: Initialize IBD Coordinator (must be after all components are ready)
        CIbdCoordinator ibd_coordinator(g_chainstate, g_node_context);
        LogPrintf(IBD, INFO, "IBD Coordinator initialized");

        // Main loop
        while (g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Check if new block was found and mining template needs update
            if (g_node_state.new_block_found.load()) {
                std::cout << "[Mining] New block found, updating template..." << std::endl;

                // ========================================================================
                // BUG #109 FIX: Stop mining and WAIT for threads to fully stop
                // ========================================================================
                // CRITICAL: We must wait for all mining threads to stop before building
                // a new template. Otherwise, threads may continue mining on old template
                // and submit blocks with stale transactions.
                if (miner.IsMining()) {
                    miner.StopMining();
                    // Wait for threads to actually stop (up to 2 seconds)
                    int wait_count = 0;
                    while (miner.IsMining() && wait_count < 20) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        wait_count++;
                    }
                    if (wait_count >= 20) {
                        std::cerr << "[Mining] WARNING: Mining threads slow to stop" << std::endl;
                    }
                }
                // Additional small delay to ensure any in-flight block submission completes
                std::this_thread::sleep_for(std::chrono::milliseconds(50));

                // Build new template for next block (only if mining was requested)
                if (g_node_state.mining_enabled.load() && !IsInitialBlockDownload()) {
                    // BUG #65 FIX: Retry template build up to 3 times with delays
                    // This handles the race condition where database write hasn't fully synced
                    std::optional<CBlockTemplate> templateOpt;
                    constexpr int MAX_TEMPLATE_RETRIES = 3;

                    for (int attempt = 1; attempt <= MAX_TEMPLATE_RETRIES; attempt++) {
                        templateOpt = BuildMiningTemplate(blockchain, wallet, false);
                        if (templateOpt) {
                            break;  // Success!
                        }
                        std::cerr << "[Mining] Template build failed (attempt " << attempt << "/" << MAX_TEMPLATE_RETRIES << ")" << std::endl;
                        if (attempt < MAX_TEMPLATE_RETRIES) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }
                    }

                    if (templateOpt) {
                        // Restart mining with new template
                        miner.StartMining(*templateOpt);
                        std::cout << "[Mining] Resumed mining on block height " << templateOpt->nHeight << std::endl;
                    } else {
                        std::cerr << "[ERROR] Failed to build mining template after " << MAX_TEMPLATE_RETRIES << " attempts!" << std::endl;
                        // BUG #65: Keep mining_enabled true so we can retry on next iteration
                        // The next main loop iteration will try again
                    }
                }

                // Clear flag
                g_node_state.new_block_found = false;
            }

            // ========================================
            // BUG #54 FIX: Deferred mining startup after IBD
            // ========================================
            // If mining was deferred due to IBD, check if we can start now
            if (mining_deferred_for_ibd && !miner.IsMining()) {
                static int ibd_progress_counter = 0;
                ibd_progress_counter++;

                if (!IsInitialBlockDownload()) {
                    // IBD complete - start mining!
                    std::cout << "[5/6] IBD sync complete!" << std::endl;
                    std::cout << "[6/6] Starting mining..." << std::endl;

                    // BUG #97 FIX: Initialize mining mode AFTER sync completes (not during startup)
                    // This prevents "[MINING] Initializing dataset..." messages during wallet setup
                    if (!randomx_is_mining_mode_ready()) {
                        std::cout << "  Initializing RandomX mining mode (FULL)..." << std::endl;
                        randomx_init_mining_mode_async(rx_key, strlen(rx_key));
                        std::cout << "  [WAIT] Waiting for dataset initialization..." << std::endl;
                        auto wait_start = std::chrono::steady_clock::now();
                        while (!randomx_is_mining_mode_ready() && g_node_state.running) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            auto elapsed = std::chrono::steady_clock::now() - wait_start;
                            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 120) {
                                std::cerr << "  [WARN] FULL mode init timeout, starting with LIGHT mode" << std::endl;
                                break;
                            }
                        }
                        auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - wait_start).count();
                        std::cout << "  [OK] Mining mode ready (FULL, " << wait_time << "s)" << std::endl;
                    } else {
                        std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                    }

                    unsigned int current_height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                    std::cout << "  [OK] Current blockchain height: " << current_height << std::endl;

                    auto templateOpt = BuildMiningTemplate(blockchain, wallet, true);
                    if (templateOpt) {
                        miner.StartMining(*templateOpt);
                        std::cout << "  [OK] Mining started with " << mining_threads << " threads" << std::endl;
                        mining_deferred_for_ibd = false;  // Clear flag
                    } else {
                        std::cerr << "[ERROR] Failed to build mining template!" << std::endl;
                    }
                } else if (ibd_progress_counter % 10 == 0) {
                    // Show progress every 10 seconds
                    int height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                    int peerHeight = g_node_context.peer_manager ? g_node_context.peer_manager->GetBestPeerHeight() : 0;
                    std::cout << "  [IBD] Progress: height=" << height
                              << " peers_best=" << peerHeight << std::endl;
                }
            }

            // Periodic tasks
            // - Update mempool
            // - Process P2P messages
            // - Update mining stats
            // - Block download coordination (IBD)

            // ========================================
            // BLOCK DOWNLOAD COORDINATION (IBD)
            // ========================================
            // Phase 5.1: Use IBD Coordinator instead of inline logic
            // This encapsulates all IBD logic (backoff, queueing, fetching, retries)
            ibd_coordinator.Tick();

            // Print mining stats every 10 seconds if mining
            // BUG #49: Add isolation detection when mining
            static int counter = 0;
            static int mining_without_peers_minutes = 0;
            static auto last_isolation_check = std::chrono::steady_clock::now();

            if (config.start_mining && ++counter % 10 == 0) {
                auto stats = miner.GetStats();
                std::cout << "[Mining] Hash rate: " << miner.GetHashRate() << " H/s, "
                         << "Total hashes: " << stats.nHashesComputed << std::endl;

                // ========================================================================
                // BUG #109 FIX: Periodic template refresh to include mempool transactions
                // ========================================================================
                // Previously, templates were only rebuilt when a new block was found.
                // This caused transactions to never be mined because the miner kept
                // using stale templates without mempool transactions.
                //
                // Now we refresh the template every 10 seconds if:
                // 1. Mining is active
                // 2. Mempool has transactions
                // 3. We're not in IBD
                //
                // This is similar to Bitcoin Core's getblocktemplate behavior.
                if (miner.IsMining() && !IsInitialBlockDownload()) {
                    CTxMemPool* mempool = g_mempool.load();
                    if (mempool && mempool->Size() > 0) {
                        std::cout << "[Mining] BUG #109: Mempool has " << mempool->Size()
                                  << " tx(s), refreshing template..." << std::endl;
                        auto templateOpt = BuildMiningTemplate(blockchain, wallet, false);
                        if (templateOpt) {
                            miner.UpdateTemplate(*templateOpt);
                            std::cout << "[Mining] Template refreshed with mempool transactions" << std::endl;
                        }
                    }
                }

                // BUG #49: Check if mining in isolation
                if (miner.IsMining()) {
                    size_t peer_count = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectionCount() : 0;

                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_isolation_check);

                    if (elapsed.count() >= 1) {
                        last_isolation_check = now;

                        if (peer_count == 0) {
                            mining_without_peers_minutes++;

                            if (mining_without_peers_minutes == 1) {
                                std::cout << "[Mining] WARNING: Mining with no connected peers" << std::endl;
                            } else if (mining_without_peers_minutes == 5) {
                                std::cout << "[Mining] WARNING: Mining in isolation for 5 minutes - possible chain fork" << std::endl;
                            } else if (mining_without_peers_minutes == 10) {
                                std::cout << "[Mining] ⚠️  CRITICAL: Mining in isolation for 10 minutes!" << std::endl;
                                std::cout << "[Mining] ⚠️  You are likely creating a chain fork that will be rejected when reconnecting" << std::endl;
                                std::cout << "[Mining] ⚠️  Consider stopping mining until peers are available" << std::endl;
                            } else if (mining_without_peers_minutes % 10 == 0) {
                                std::cout << "[Mining] ⚠️  Still mining in isolation (" << mining_without_peers_minutes
                                          << " minutes) - chain fork highly likely!" << std::endl;
                            }
                        } else {
                            if (mining_without_peers_minutes > 0) {
                                std::cout << "[Mining] Peer connectivity restored - no longer mining in isolation" << std::endl;
                                mining_without_peers_minutes = 0;
                            }
                        }
                    }
                }
            }
        }

        // Shutdown
        std::cout << std::endl;
        std::cout << "[Shutdown] Initiating graceful shutdown..." << std::endl;

        if (miner.IsMining()) {
            std::cout << "[Shutdown] Stopping mining..." << std::flush;
            miner.StopMining();
            std::cout << " ✓" << std::endl;
        }

        // BUG #125: Stop message queue before P2P shutdown
        std::cout << "[Shutdown] Stopping message queue..." << std::flush;
        message_queue.Stop();
        g_message_queue.store(nullptr);
        g_node_context.message_queue = nullptr;
        std::cout << " done" << std::endl;

        std::cout << "[Shutdown] Stopping P2P server..." << std::flush;
        // Phase 5: Stop CConnman (handles all socket cleanup internally)
        if (g_node_context.connman) {
            g_node_context.connman->Stop();
        }
        // p2p_socket removed - CConnman handles socket cleanup

        // Phase 1.2: Shutdown NodeContext (Bitcoin Core pattern)
        std::cout << "[Shutdown] NodeContext shutdown complete" << std::endl;
        g_node_context.Shutdown();
        
        // Phase 5: p2p_thread and p2p_recv_thread removed - handled by CConnman
        // Only join maintenance thread
        if (p2p_maint_thread.joinable()) {
            p2p_maint_thread.join();
        }

        // Clear global P2P networking pointers (NW-005)
        // P0-5 FIX: Use .store() for atomic pointers
        g_message_processor.store(nullptr);

        // Clean up transaction relay manager (P0-5 FIX: use load/store for atomic)
        delete g_tx_relay_manager.load();
        g_tx_relay_manager.store(nullptr);

        // Clear peer manager pointer (ownership in g_node_context)
        g_peer_manager = nullptr;

        std::cout << "[Shutdown] Stopping RPC server..." << std::flush;
        rpc_server.Stop();

        std::cout << "  Closing UTXO database..." << std::endl;
        utxo_set.Close();

        std::cout << "  Closing blockchain database..." << std::endl;
        blockchain.Close();

        // Phase 1.2: IBD managers are owned by NodeContext and cleaned up by Shutdown()
        // No manual cleanup needed - NodeContext.Shutdown() handles it

        std::cout << "  Cleaning up chain parameters..." << std::endl;
        delete Dilithion::g_chainParams;
        Dilithion::g_chainParams = nullptr;

        std::cout << std::endl;
        std::cout << "Dilithion node stopped cleanly" << std::endl;

    } catch (const std::exception& e) {
        // Phase 2.2: Enhanced crash diagnostics
        LogPrintf(ALL, ERROR, "===========================================================");
        LogPrintf(ALL, ERROR, "FATAL ERROR: Unhandled exception in main()");
        LogPrintf(ALL, ERROR, "Exception type: std::exception");
        LogPrintf(ALL, ERROR, "Exception message: %s", e.what());
        
        // Log stack trace in debug builds
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);  // Skip this frame
            LogPrintf(ALL, ERROR, "Stack trace:");
            LogPrintf(ALL, ERROR, "%s", stackTrace.c_str());
        } catch (...) {
            LogPrintf(ALL, ERROR, "Failed to capture stack trace");
        }
        #endif
        
        LogPrintf(ALL, ERROR, "===========================================================");
        
        // Also print to stderr for immediate visibility
        std::cerr << "\n===========================================================" << std::endl;
        std::cerr << "FATAL ERROR: Unhandled exception in main()" << std::endl;
        std::cerr << "Exception type: std::exception" << std::endl;
        std::cerr << "Exception message: " << e.what() << std::endl;
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);
            std::cerr << "\nStack trace:\n" << stackTrace << std::endl;
        } catch (...) {
            std::cerr << "Failed to capture stack trace" << std::endl;
        }
        #endif
        std::cerr << "===========================================================" << std::endl;

        // Cleanup on error (P0-5 FIX: use load/store for atomic)
        auto* relay_mgr = g_tx_relay_manager.load();
        if (relay_mgr) {
            delete relay_mgr;
            g_tx_relay_manager.store(nullptr);
        }
        // Phase 1.2: All cleanup handled by NodeContext.Shutdown()
        // No manual cleanup needed

        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        // Shutdown logging system
        CLogger::GetInstance().Shutdown();

        return 1;
    } catch (...) {
        // Phase 2.2: Catch all other exceptions (non-std::exception)
        LogPrintf(ALL, ERROR, "===========================================================");
        LogPrintf(ALL, ERROR, "FATAL ERROR: Unknown exception in main()");
        LogPrintf(ALL, ERROR, "Exception type: unknown (not std::exception)");
        
        // Log stack trace in debug builds
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);  // Skip this frame
            LogPrintf(ALL, ERROR, "Stack trace:");
            LogPrintf(ALL, ERROR, "%s", stackTrace.c_str());
        } catch (...) {
            LogPrintf(ALL, ERROR, "Failed to capture stack trace");
        }
        #endif
        
        LogPrintf(ALL, ERROR, "===========================================================");
        
        // Also print to stderr for immediate visibility
        std::cerr << "\n===========================================================" << std::endl;
        std::cerr << "FATAL ERROR: Unknown exception in main()" << std::endl;
        std::cerr << "Exception type: unknown (not std::exception)" << std::endl;
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);
            std::cerr << "\nStack trace:\n" << stackTrace << std::endl;
        } catch (...) {
            std::cerr << "Failed to capture stack trace" << std::endl;
        }
        #endif
        std::cerr << "===========================================================" << std::endl;

        // Cleanup on error (P0-5 FIX: use load/store for atomic)
        auto* relay_mgr = g_tx_relay_manager.load();
        if (relay_mgr) {
            delete relay_mgr;
            g_tx_relay_manager.store(nullptr);
        }
        // Phase 1.2: All cleanup handled by NodeContext.Shutdown()
        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        // Shutdown logging system
        CLogger::GetInstance().Shutdown();

        return 1;
    }

    // Shutdown logging system on successful exit
    LogPrintf(ALL, INFO, "Dilithion node shutting down normally");
    CLogger::GetInstance().Shutdown();

    return 0;
}
