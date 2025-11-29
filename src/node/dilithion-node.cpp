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
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <api/http_server.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <core/chainparams.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <consensus/validation.h>  // CRITICAL-3 FIX: For CBlockValidator
#include <consensus/chain_verifier.h>  // Chain integrity validation (Bug #17)
#include <crypto/randomx_hash.h>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <memory>
#include <csignal>
#include <cstring>
#include <cassert>
#include <thread>
#include <chrono>
#include <atomic>
#include <optional>
#include <queue>  // CRITICAL-2 FIX: For iterative orphan resolution
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

// Global node state for signal handling (defined in src/core/globals.cpp)
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
    CWallet* wallet = nullptr;
    CSocket* p2p_socket = nullptr;
    CHttpServer* http_server = nullptr;
};
extern NodeState g_node_state;

// Global async broadcaster pointer (initialized in main)
CAsyncBroadcaster* g_async_broadcaster = nullptr;

// Global IBD manager pointers (Bug #12 - Phase 4.1)
CHeadersManager* g_headers_manager = nullptr;
COrphanManager* g_orphan_manager = nullptr;
CBlockFetcher* g_block_fetcher = nullptr;

/**
 * BUG #52 & #60 FIX: Check if we're in Initial Block Download (IBD) mode
 *
 * This is a CHEAP O(1) check that prevents mining during initial sync.
 * Following Bitcoin Core's pattern (src/validation.cpp IsInitialBlockDownload()).
 *
 * A node is in IBD if:
 *   1. Headers are ahead of chain tip (BUG #60 - most reliable indicator)
 *   2. Peers report significantly higher chain heights (6+ blocks)
 *   3. Only genesis block exists (no chain tip)
 *   4. Chain tip is more than 24 hours old (stale)
 *
 * Mining is disabled during IBD to prevent fork creation with the network.
 * This is critical for new nodes joining an existing network.
 * BUG #60: Mining during block download creates divergent chains that can't sync.
 */
bool IsInitialBlockDownload() {
    const CBlockIndex* tip = g_chainstate.GetTip();
    int ourHeight = tip ? tip->nHeight : 0;
    int bestPeerHeight = g_peer_manager ? g_peer_manager->GetBestPeerHeight() : 0;
    size_t peerCount = g_peer_manager ? g_peer_manager->GetConnectionCount() : 0;

    // BUG #60 FIX: Check if headers are ahead of chain tip
    // This is the MOST RELIABLE IBD indicator - if we have headers for blocks we
    // don't have yet, we're actively downloading blocks and MUST NOT mine.
    // Mining during block download creates divergent chains that can't sync.
    if (g_headers_manager) {
        int headerHeight = g_headers_manager->GetBestHeight();
        if (headerHeight > ourHeight) {
            return true;  // Headers ahead = actively downloading = IBD mode
        }
    }

    // BUG #60 FIX (part 2): Wait for peer height info before allowing mining
    // At startup, we haven't received any VERSION messages yet, so bestPeerHeight is 0.
    // We MUST wait until at least one peer has reported their height via VERSION message.
    // Otherwise, we might mine blocks while peers have a longer chain we don't know about.
    //
    // bestPeerHeight == 0 means NO peer has completed handshake yet.
    // Once any peer completes handshake, they report their height (even if 0 for true bootstrap).
    // We use peerCount > 0 AND bestPeerHeight == 0 to detect "connections initiated but
    // no VERSION received" vs "no connections at all".
    if (bestPeerHeight == 0 && peerCount > 0) {
        // Connections exist but no VERSION received yet - wait for handshake
        return true;  // In IBD - waiting for peer height information
    }

    // Check 1: Are peers significantly ahead of us?
    // This is a secondary IBD check - prevents mining while syncing with network
    if (bestPeerHeight > ourHeight + 6) {
        return true;  // Peers have 6+ more blocks - we're behind, sync first
    }

    // Check 2: If no peers at all and we're at genesis, allow bootstrap mining
    // This is the TRUE bootstrap scenario - isolated node with no seed connections
    if (ourHeight == 0 && peerCount == 0 && !g_peer_manager) {
        return false;  // True bootstrap - allow mining
    }

    // Check 3: Peers connected and reported their height, and we're close to them
    // This is the normal case after initial sync completes

    // Check 4: Is tip timestamp recent? (Bitcoin's secondary IBD criterion)
    // This is O(1) - just compare timestamps, no full chain verification
    if (tip) {
        int64_t tipTime = tip->nTime;
        int64_t now = GetTime();
        const int64_t MAX_TIP_AGE = 24 * 60 * 60;  // 24 hours (same as Bitcoin)

        if (now - tipTime > MAX_TIP_AGE) {
            // Tip is stale - but only consider IBD if peers are ahead
            if (bestPeerHeight > ourHeight) {
                return true;  // Stale AND peers are ahead - sync first
            }
            // Stale but peers not ahead - could be network-wide stale, allow mining
        }
    }

    return false;  // Synced - safe to mine
}

// Signal handler for graceful shutdown
void SignalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    g_node_state.running = false;

    if (g_node_state.rpc_server) {
        g_node_state.rpc_server->Stop();
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
                        std::cerr << "Error: Invalid RPC port (must be " << Consensus::MIN_PORT
                                  << "-" << Consensus::MAX_PORT << "): " << arg << std::endl;
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
        std::cout << "Dilithion Node v1.0.16 - Post-Quantum Cryptocurrency" << std::endl;
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
    block.nTime = static_cast<uint32_t>(std::time(nullptr));
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

    // Coinbase output (reward to miner)
    CTxOut coinbaseOut;
    coinbaseOut.nValue = nSubsidy;
    coinbaseOut.scriptPubKey = WalletCrypto::CreateScriptPubKey(minerPubKeyHash);
    coinbaseTx.vout.push_back(coinbaseOut);

    // Store coinbase transaction globally for callback access
    {
        std::lock_guard<std::mutex> lock(g_coinbaseMutex);
        g_currentCoinbase = MakeTransactionRef(coinbaseTx);
    }

    // BUG #11 FIX: Serialize coinbase for block with transaction count prefix
    // Must match format expected by DeserializeBlockTransactions: [count][tx1][tx2]...
    // This bug only affected BuildMiningTemplate (used after first block found).
    // RPC CreateBlockTemplate in controller.cpp already had this correct.
    std::vector<uint8_t> coinbaseData = coinbaseTx.Serialize();
    block.vtx.clear();
    block.vtx.reserve(1 + coinbaseData.size());
    block.vtx.push_back(1);  // Transaction count = 1 (only coinbase)
    block.vtx.insert(block.vtx.end(), coinbaseData.begin(), coinbaseData.end());

    // Calculate merkle root (SHA3-256 hash of serialized coinbase)
    uint8_t merkleHash[32];
    extern void SHA3_256(const uint8_t* data, size_t len, uint8_t hash[32]);
    SHA3_256(block.vtx.data(), block.vtx.size(), merkleHash);
    memcpy(block.hashMerkleRoot.data, merkleHash, 32);

    // Calculate target from nBits (compact format)
    uint256 hashTarget = CompactToBig(block.nBits);

    if (verbose) {
        std::cout << "  Block height: " << nHeight << std::endl;
        std::cout << "  Previous block: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "  Difficulty (nBits): 0x" << std::hex << block.nBits << std::dec << std::endl;
        std::cout << "  Target: " << hashTarget.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "  Coinbase: " << coinbaseMsg << std::endl;
        std::cout << "  Merkle root: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // Create and return block template
    return CBlockTemplate(block, hashTarget, nHeight);
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

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Node v1.0.16" << std::endl;
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

    // Set default datadir, ports from chain params if not specified
    if (config.datadir.empty()) {
        config.datadir = Dilithion::g_chainParams->dataDir;
    }
    if (config.rpcport == 0) {
        config.rpcport = Dilithion::g_chainParams->rpcPort;
    }
    if (config.p2pport == 0) {
        config.p2pport = Dilithion::g_chainParams->p2pPort;
    }

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
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    try {
        // Phase 1: Initialize blockchain storage and mempool
        std::cout << "Initializing blockchain storage..." << std::endl;
        CBlockchainDB blockchain;
        if (!blockchain.Open(config.datadir + "/blocks")) {
            std::cerr << "Failed to open blockchain database" << std::endl;
            return 1;
        }
        std::cout << "  [OK] Blockchain database opened" << std::endl;

        std::cout << "Initializing mempool..." << std::endl;
        CTxMemPool mempool;
        std::cout << "  [OK] Mempool initialized" << std::endl;

        // Initialize UTXO set
        std::cout << "Initializing UTXO set..." << std::endl;
        CUTXOSet utxo_set;
        if (!utxo_set.Open(config.datadir + "/chainstate")) {
            std::cerr << "Failed to open UTXO database" << std::endl;
            return 1;
        }
        std::cout << "  [OK] UTXO set opened" << std::endl;

        // Initialize chain state
        std::cout << "Initializing chain state..." << std::endl;
        g_chainstate.SetDatabase(&blockchain);
        g_chainstate.SetUTXOSet(&utxo_set);
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

        // Step 2: If mining enabled AND RAM >= 3GB, start FULL mode in background
        bool full_mode_available = (total_ram_mb >= 3072);
        if (config.start_mining && full_mode_available) {
            std::cout << "  Starting mining mode init (FULL) in background..." << std::endl;
            randomx_init_mining_mode_async(rx_key, strlen(rx_key));
            // Mining will start with LIGHT mode, auto-upgrade to FULL when ready
        } else if (config.start_mining) {
            std::cout << "  Mining mode: LIGHT only (RAM < 3GB)" << std::endl;
        }

        // NO WAIT - node continues immediately, can validate blocks right away

        // Load and verify genesis block
load_genesis_block:  // Bug #29: Label for automatic retry after blockchain wipe
        std::cout << "Loading genesis block..." << std::endl;
        CBlock genesis = Genesis::CreateGenesisBlock();

        if (!Genesis::IsGenesisBlock(genesis)) {
            std::cerr << "ERROR: Genesis block verification failed!" << std::endl;
            std::cerr << "This indicates a critical configuration problem." << std::endl;
            delete Dilithion::g_chainParams;
            return 1;
        }

        std::cout << "  Network: " << Dilithion::g_chainParams->GetNetworkName() << std::endl;
        std::cout << "  Genesis hash: " << genesis.GetHash().GetHex() << std::endl;
        std::cout << "  Genesis time: " << genesis.nTime << std::endl;
        std::cout << "  [OK] Genesis block verified" << std::endl;

        // Initialize blockchain with genesis block if needed
        uint256 genesisHash = genesis.GetHash();
        if (!blockchain.BlockExists(genesisHash)) {
            std::cout << "Initializing blockchain with genesis block..." << std::endl;

            // Save genesis block
            if (!blockchain.WriteBlock(genesisHash, genesis)) {
                std::cerr << "ERROR: Failed to write genesis block to database!" << std::endl;
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

            // Load existing chain state from database
            std::cout << "Loading chain state from database..." << std::endl;

            // Load genesis block index first
            CBlockIndex genesisIndexFromDB;
            if (blockchain.ReadBlockIndex(genesisHash, genesisIndexFromDB)) {
                // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
                auto pgenesisIndex = std::make_unique<CBlockIndex>(genesisIndexFromDB);
                pgenesisIndex->pprev = nullptr;
                g_chainstate.AddBlockIndex(genesisHash, std::move(pgenesisIndex));
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

                    std::cout << "[Startup] DEBUG: Attempting to load block index for " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;
                    CBlockIndex blockIndexFromDB;
                    if (!blockchain.ReadBlockIndex(blockHash, blockIndexFromDB)) {
                        std::cerr << "ERROR: Cannot load block index " << blockHash.GetHex().substr(0, 16) << std::endl;
                        std::cerr << "[Startup] DEBUG: ReadBlockIndex FAILED for this hash" << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }
                    std::cout << "[Startup] DEBUG: Successfully loaded block index (height " << blockIndexFromDB.nHeight << ")" << std::endl;

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

                            // Clear mempool
                            g_mempool->Clear();

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

        // Initialize peer manager as unique_ptr (global)
        g_peer_manager = std::make_unique<CPeerManager>(config.datadir);

        // Initialize transaction relay manager (global)
        g_tx_relay_manager = new CTxRelayManager();

        // Initialize IBD managers (Bug #12 - Phase 4.1)
        std::cout << "Initializing IBD managers..." << std::endl;
        g_headers_manager = new CHeadersManager();
        g_orphan_manager = new COrphanManager();
        g_block_fetcher = new CBlockFetcher();
        std::cout << "  [OK] Headers manager initialized" << std::endl;
        std::cout << "  [OK] Orphan manager initialized (max 100 blocks / 100 MB)" << std::endl;
        std::cout << "  [OK] Block fetcher initialized (max 16 blocks in-flight)" << std::endl;

        // Bug #40 fix: Register HeadersManager callback for chain tip updates
        g_chainstate.RegisterTipUpdateCallback([](const CBlockIndex* pindex) {
            if (g_headers_manager && pindex) {
                g_headers_manager->OnBlockActivated(pindex->header, pindex->GetBlockHash());
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
                    g_headers_manager->OnBlockActivated((*it)->header, (*it)->GetBlockHash());
                }

                std::cout << "  [OK] Populated HeadersManager with " << chain.size()
                          << " header(s) from height 0 to " << pindexTip->nHeight << std::endl;
            } else {
                std::cout << "  [WARN] No chain tip - HeadersManager empty (expected for fresh node)" << std::endl;
            }
        }

        // Create message processor and connection manager (local, using global peer manager)
        CNetMessageProcessor message_processor(*g_peer_manager);
        CConnectionManager connection_manager(*g_peer_manager, message_processor);

        // Set global pointers for transaction announcement (NW-005)
        g_connection_manager = &connection_manager;
        g_message_processor = &message_processor;

        // Create and start async broadcaster for non-blocking message broadcasting
        CAsyncBroadcaster async_broadcaster(connection_manager);
        g_async_broadcaster = &async_broadcaster;

        if (!async_broadcaster.Start()) {
            std::cerr << "Failed to start async broadcaster" << std::endl;
            return 1;
        }

        std::cout << "[AsyncBroadcaster] Initialized and started" << std::endl;

        // Create and start HTTP API server for dashboard
        // Use port 8334 for testnet API
        int api_port = config.testnet ? 8334 : 8333;
        CHttpServer http_server(api_port);
        g_node_state.http_server = &http_server;

        // Set stats handler that returns current node statistics as JSON
        http_server.SetStatsHandler([&config]() -> std::string {
            // Get current stats from chain state
            CBlockIndex* tip = g_chainstate.GetTip();
            int block_height = tip ? tip->nHeight : 0;
            uint32_t difficulty = tip ? tip->nBits : 0;
            int64_t total_supply = block_height * 50;  // 50 coins per block
            size_t peer_count = g_peer_manager ? g_peer_manager->GetConnectedPeers().size() : 0;

            // Get async broadcaster stats
            size_t async_broadcasts = 0;
            size_t async_success = 0;
            size_t async_failed = 0;
            if (g_async_broadcaster) {
                auto stats = g_async_broadcaster->GetStats();
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

        if (!http_server.Start()) {
            std::cerr << "Failed to start HTTP API server on port " << api_port << std::endl;
            return 1;
        }

        std::cout << "[HttpServer] API server started on port " << api_port << std::endl;
        std::cout << "[HttpServer] Dashboard endpoint: http://localhost:" << api_port << "/api/stats" << std::endl;

        // Verify global pointers are properly initialized (audit recommendation)
        assert(g_connection_manager != nullptr && "g_connection_manager must be initialized");
        assert(g_message_processor != nullptr && "g_message_processor must be initialized");
        assert(g_peer_manager != nullptr && "g_peer_manager must be initialized");
        assert(g_tx_relay_manager != nullptr && "g_tx_relay_manager must be initialized");

        // Register version handler to automatically respond with verack
        message_processor.SetVersionHandler([&connection_manager](int peer_id, const NetProtocol::CVersionMessage& msg) {
            std::cout << "[P2P] Handshake with peer " << peer_id << " (" << msg.user_agent << ")"
                      << " start_height=" << msg.start_height << std::endl;

            // BUG #62 FIX: Store peer's starting height for later header sync decision
            if (g_headers_manager) {
                g_headers_manager->SetPeerStartHeight(peer_id, msg.start_height);
            }

            // Send verack in response
            connection_manager.SendVerackMessage(peer_id);
        });

        // Register verack handler to trigger IBD when handshake completes
        message_processor.SetVerackHandler([](int peer_id) {
            std::cout << "[P2P] Handshake complete with peer " << peer_id << std::endl;

            // BUG #36 FIX: Register peer with BlockFetcher so it can download blocks
            if (g_block_fetcher) {
                g_block_fetcher->OnPeerConnected(peer_id);
            }

            // Debug: Check if g_headers_manager is initialized
            if (!g_headers_manager) {
                std::cerr << "[P2P] ERROR: g_headers_manager is null!" << std::endl;
                return;
            }

            // BUG #62 FIX: Compare our height with peer's announced height
            int ourHeight = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
            int peerHeight = g_headers_manager->GetPeerStartHeight(peer_id);

            std::cout << "[P2P] Our height: " << ourHeight << ", Peer height: " << peerHeight << std::endl;

            // Request headers if peer is ahead OR if we're at genesis
            // This is the key fix: only request headers from peers with more blocks
            if (peerHeight > ourHeight || ourHeight == 0) {
                std::cout << "[P2P] Peer " << peer_id << " is ahead or we are at genesis, requesting headers" << std::endl;

                // Trigger IBD - request headers from this peer to sync blockchain
                uint256 ourBestBlock;
                if (g_chainstate.GetTip()) {
                    ourBestBlock = g_chainstate.GetTip()->GetBlockHash();
                } else {
                    ourBestBlock.SetHex(Dilithion::g_chainParams->genesisHash);
                }

                try {
                    g_headers_manager->RequestHeaders(peer_id, ourBestBlock);
                    std::cout << "[P2P] Headers request sent" << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "[P2P] EXCEPTION in RequestHeaders: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "[P2P] UNKNOWN EXCEPTION in RequestHeaders" << std::endl;
                }
            } else {
                std::cout << "[P2P] We are ahead of peer " << peer_id << " (" << ourHeight
                          << " vs " << peerHeight << "), not requesting headers" << std::endl;
            }
        });

        // Register ping handler to automatically respond with pong
        message_processor.SetPingHandler([&connection_manager](int peer_id, uint64_t nonce) {
            // Silently respond with pong - keepalive is automatic
            connection_manager.SendPongMessage(peer_id, nonce);
        });

        // Register pong handler (keepalive response received)
        message_processor.SetPongHandler([](int peer_id, uint64_t nonce) {
            // Silently acknowledge - keepalive working
        });

        // Register inv handler to request announced blocks
        message_processor.SetInvHandler([&blockchain, &connection_manager, &message_processor](
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
            if (hasUnknownBlocks && g_headers_manager) {
                if (g_headers_manager->ShouldFetchHeaders(peer_id)) {
                    uint256 ourBestBlock;
                    if (g_chainstate.GetTip()) {
                        ourBestBlock = g_chainstate.GetTip()->GetBlockHash();
                    } else {
                        ourBestBlock.SetHex(Dilithion::g_chainParams->genesisHash);
                    }

                    std::cout << "[P2P] Unknown blocks announced by peer " << peer_id
                              << ", requesting headers for full chain" << std::endl;
                    g_headers_manager->RequestHeaders(peer_id, ourBestBlock);
                }
            }

            // Also request the specific blocks (may succeed if we have their parents)
            if (!getdata.empty()) {
                std::cout << "[P2P] Requesting " << getdata.size() << " block(s) from peer " << peer_id << std::endl;
                CNetMessage msg = message_processor.CreateGetDataMessage(getdata);
                connection_manager.SendMessage(peer_id, msg);
            }
        });

        // Register getdata handler to serve blocks to requesting peers
        message_processor.SetGetDataHandler([&blockchain, &connection_manager, &message_processor](
            int peer_id, const std::vector<NetProtocol::CInv>& requested_items) {

            for (const auto& item : requested_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // Look up block in database
                    CBlock block;
                    if (blockchain.ReadBlock(item.hash, block)) {
                        std::cout << "[P2P] Serving block " << item.hash.GetHex().substr(0, 16)
                                  << "... to peer " << peer_id << std::endl;

                        // Send block to requesting peer
                        CNetMessage blockMsg = message_processor.CreateBlockMessage(block);
                        connection_manager.SendMessage(peer_id, blockMsg);
                    } else {
                        std::cout << "[P2P] Peer " << peer_id << " requested unknown block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
                // Phase 5: Transaction relay - implement MSG_TX_INV handling after testnet stabilizes
            }
        });

        // Register block handler to validate and save received blocks
        message_processor.SetBlockHandler([&blockchain, &message_processor, &connection_manager](int peer_id, const CBlock& block) {
            uint256 blockHash = block.GetHash();

            std::cout << "[P2P] Received block from peer " << peer_id << ": "
                      << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

            // [CONVERGENCE-DIAG] Log BLOCK message
            std::cout << "[CONVERGENCE-DIAG] BLOCK message received from peer " << peer_id << std::endl;
            std::cout << "[CONVERGENCE-DIAG]   Block hash: " << blockHash.GetHex().substr(0,16) << "..." << std::endl;
            std::cout << "[CONVERGENCE-DIAG]   Prev block: " << block.hashPrevBlock.GetHex().substr(0,16) << "..." << std::endl;

            // Basic validation: Check PoW
            if (!CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[P2P] ERROR: Block from peer " << peer_id << " has invalid PoW" << std::endl;
                std::cerr << "  Hash must be less than target" << std::endl;
                return;
            }

            // Check if we already have this block in memory
            if (g_chainstate.HasBlockIndex(blockHash)) {
                std::cout << "[P2P] Block already in chain state, skipping" << std::endl;
                return;
            }

            // Check if we already have this block in database
            if (blockchain.BlockExists(blockHash)) {
                std::cout << "[P2P] Block already in database, skipping" << std::endl;
                return;
            }

            // Save block to database first
            if (!blockchain.WriteBlock(blockHash, block)) {
                std::cerr << "[P2P] ERROR: Failed to save block from peer " << peer_id << std::endl;
                return;
            }
            std::cout << "[P2P] Block saved to database" << std::endl;

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
                    g_peer_manager->Misbehaving(peer_id, 100);  // Ban peer sending invalid blocks
                    return;
                }

                if (!validator.VerifyMerkleRoot(block, transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block has invalid merkle root" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    std::cerr << "  Block merkle root: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cerr << "  Rejecting invalid block from peer " << peer_id << std::endl;
                    g_peer_manager->Misbehaving(peer_id, 100);  // Ban peer sending invalid blocks
                    return;
                }

                // Check for duplicate transactions
                if (!validator.CheckNoDuplicateTransactions(transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block contains duplicate transactions" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    g_peer_manager->Misbehaving(peer_id, 100);
                    return;
                }

                // Check for double-spends within block
                if (!validator.CheckNoDoubleSpends(transactions, validationError)) {
                    std::cerr << "[Orphan] ERROR: Orphan block contains double-spend" << std::endl;
                    std::cerr << "  Error: " << validationError << std::endl;
                    g_peer_manager->Misbehaving(peer_id, 100);
                    return;
                }

                std::cout << "[Orphan] Block validation passed (merkle root verified, no duplicates/double-spends)" << std::endl;

                // Add block to orphan manager (now validated)
                if (g_orphan_manager->AddOrphanBlock(peer_id, block)) {
                    std::cout << "[Orphan] Block added to orphan pool (count: "
                              << g_orphan_manager->GetOrphanCount() << ")" << std::endl;

                    // Request the missing parent block from the peer
                    std::vector<NetProtocol::CInv> getdata;
                    getdata.push_back(NetProtocol::CInv(NetProtocol::MSG_BLOCK_INV, block.hashPrevBlock));

                    std::cout << "[P2P] Requesting parent block from peer " << peer_id << std::endl;
                    CNetMessage msg = message_processor.CreateGetDataMessage(getdata);
                    connection_manager.SendMessage(peer_id, msg);
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

                    // [CONVERGENCE-DIAG] Log reorg completion after receiving block
                    std::cout << "[CONVERGENCE-DIAG] ✅ REORG COMPLETED after receiving block from peer " << peer_id << std::endl;

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
                        std::cout << "[BUG32-DEBUG] Checking immediate template update conditions:" << std::endl;
                        std::cout << "[BUG32-DEBUG]   miner = " << (g_node_state.miner ? "valid" : "NULL") << std::endl;
                        std::cout << "[BUG32-DEBUG]   wallet = " << (g_node_state.wallet ? "valid" : "NULL") << std::endl;
                        std::cout << "[BUG32-DEBUG]   mining_enabled = " << (g_node_state.mining_enabled.load() ? "true" : "false") << std::endl;

                        if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load() && !IsInitialBlockDownload()) {
                            std::cout << "[Mining] IBD block became new tip - updating template immediately..." << std::endl;
                            auto templateOpt = BuildMiningTemplate(blockchain, *g_node_state.wallet, false);
                            if (templateOpt) {
                                g_node_state.miner->UpdateTemplate(*templateOpt);
                                std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                            } else {
                                std::cout << "[BUG32-DEBUG] BuildMiningTemplate returned empty" << std::endl;
                            }
                        } else {
                            std::cout << "[BUG32-DEBUG] Conditions not met - template NOT updated immediately" << std::endl;
                        }

                        // BUG #43 FIX: Relay received blocks to other peers (Bitcoin Core standard)
                        // When we receive a block that becomes the new tip, relay it to all connected peers
                        // (except the peer that sent it to us) to propagate blocks network-wide
                        if (g_peer_manager && g_async_broadcaster) {
                            auto connected_peers = g_peer_manager->GetConnectedPeers();
                            std::vector<int> relay_peer_ids;

                            // Collect peers with completed handshakes, excluding the sender
                            for (const auto& peer : connected_peers) {
                                if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
                                    relay_peer_ids.push_back(peer->id);
                                }
                            }

                            if (!relay_peer_ids.empty()) {
                                // Queue block relay asynchronously (non-blocking!)
                                if (g_async_broadcaster->BroadcastBlock(blockHash, relay_peer_ids)) {
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
                if (g_block_fetcher) {
                    g_block_fetcher->MarkBlockReceived(peer_id, blockHash);
                }

                // CRITICAL-2 FIX: Iterative orphan resolution with depth limit
                // Prevents stack overflow from unbounded recursion
                // Check if any orphan blocks are now valid children of this block

                static const int MAX_ORPHAN_CHAIN_DEPTH = 100;  // DoS protection
                std::queue<uint256> orphanQueue;
                int processedCount = 0;

                // Seed queue with direct children of this block
                std::vector<uint256> orphanChildren = g_orphan_manager->GetOrphanChildren(blockHash);
                for (const uint256& orphanHash : orphanChildren) {
                    orphanQueue.push(orphanHash);
                }

                if (!orphanQueue.empty()) {
                    std::cout << "[Orphan] Found " << orphanQueue.size()
                              << " orphan block(s) that can now be processed" << std::endl;

                    // Iterative processing instead of recursion
                    while (!orphanQueue.empty() && processedCount < MAX_ORPHAN_CHAIN_DEPTH) {
                        uint256 orphanHash = orphanQueue.front();
                        orphanQueue.pop();

                        CBlock orphanBlock;
                        if (g_orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                            std::cout << "[Orphan] Processing orphan: "
                                      << orphanHash.GetHex().substr(0, 16) << "..."
                                      << " (depth: " << processedCount + 1 << ")" << std::endl;

                            // Remove from orphan pool
                            g_orphan_manager->EraseOrphanBlock(orphanHash);

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
                                        // Save to database
                                        if (!blockchain.WriteBlock(orphanBlockHash, orphanBlock)) {
                                            std::cerr << "[Orphan] ERROR: Failed to save orphan block to database" << std::endl;
                                        }

                                        // Queue this block's orphan children for processing
                                        std::vector<uint256> nextOrphans = g_orphan_manager->GetOrphanChildren(orphanBlockHash);
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

                    std::cout << "[Orphan] Orphan resolution complete" << std::endl;
                    std::cout << "  Processed: " << processedCount << " block(s)" << std::endl;
                    std::cout << "  Remaining orphans: " << g_orphan_manager->GetOrphanCount() << std::endl;
                }
            } else {
                std::cerr << "[P2P] ERROR: Failed to activate block in chain" << std::endl;
            }
        });

        // Register GETHEADERS handler - respond with block headers from our chain (Bug #12 - Phase 4.2)
        message_processor.SetGetHeadersHandler([&blockchain, &connection_manager, &message_processor](
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
            CNetMessage headersMsg = message_processor.CreateHeadersMessage(headers);
            connection_manager.SendMessage(peer_id, headersMsg);
        });

        // Register HEADERS handler - process received headers (Bug #12 - Phase 4.2)
        message_processor.SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
            if (headers.empty()) {
                return;
            }

            std::cout << "[IBD] Received " << headers.size() << " header(s) from peer " << peer_id << std::endl;

            // [CONVERGENCE-DIAG] Log HEADERS message
            std::cout << "[CONVERGENCE-DIAG] HEADERS message received from peer " << peer_id
                      << " (" << headers.size() << " headers)" << std::endl;

            // Pass headers to headers manager for validation and storage
            if (g_headers_manager->ProcessHeaders(peer_id, headers)) {
                // Headers were valid and processed successfully
                int bestHeight = g_headers_manager->GetBestHeight();
                uint256 bestHash = g_headers_manager->GetBestHeaderHash();

                std::cout << "[IBD] Headers processed successfully" << std::endl;
                std::cout << "[IBD] Best header height: " << bestHeight << std::endl;
                std::cout << "[IBD] Best header hash: " << bestHash.GetHex().substr(0, 16) << "..." << std::endl;

                // Bug #34 fix: Queue received blocks for download
                // After headers are validated, tell BlockFetcher to download the actual blocks
                if (g_block_fetcher) {
                    // Calculate starting height for this batch of headers
                    // If we received N headers and best height is now H, first header is at H-N+1
                    int startHeight = bestHeight - static_cast<int>(headers.size()) + 1;

                    for (size_t i = 0; i < headers.size(); i++) {
                        uint256 hash = headers[i].GetHash();
                        int height = startHeight + static_cast<int>(i);

                        // BUG #64: Pass peer_id as announcing_peer for preferred download
                        g_block_fetcher->QueueBlockForDownload(hash, height, peer_id);
                        std::cout << "[IBD] Queued block " << hash.GetHex().substr(0, 16)
                                  << "... (height " << height << ") for download from peer " << peer_id << std::endl;
                    }
                }
            } else {
                std::cerr << "[IBD] ERROR: Failed to process headers from peer " << peer_id << std::endl;
                std::cerr << "  Headers may be invalid or disconnected from our chain" << std::endl;
            }
        });

        std::cout << "  [OK] P2P components ready (not started)" << std::endl;

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
            std::cout << "  Loading existing wallet..." << std::endl;
            std::cout.flush();
            if (wallet.Load(wallet_path)) {
                wallet_loaded = true;
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

        // Generate initial key if wallet is empty
        if (wallet.GetAddresses().empty()) {
            std::cout << "  Generating initial address..." << std::endl;
            wallet.GenerateNewKey();
            CDilithiumAddress addr = wallet.GetNewAddress();
            std::cout << "  [OK] Initial address: " << addr.ToString() << std::endl;
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
                int64_t balance = wallet.GetBalance();
                double balanceInDIL = static_cast<double>(balance) / 100000000.0;
                std::cout << "  [OK] Full scan complete, balance: " << std::fixed << std::setprecision(8)
                          << balanceInDIL << " DIL" << std::endl;
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
                int64_t balance = wallet.GetBalance();
                double balanceInDIL = static_cast<double>(balance) / 100000000.0;
                std::cout << "  [OK] Incremental scan complete, balance: " << std::fixed << std::setprecision(8)
                          << balanceInDIL << " DIL" << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Rescan failed" << std::endl;
            }
        } else {
            // wallet_height == chain_height: Already synced, no scan needed
            int64_t balance = wallet.GetBalance();
            double balanceInDIL = static_cast<double>(balance) / 100000000.0;
            std::cout << "  [OK] Wallet already synced to chain tip, balance: " << std::fixed << std::setprecision(8)
                      << balanceInDIL << " DIL" << std::endl;
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
        miner.SetBlockFoundCallback([&blockchain, &connection_manager, &message_processor, &wallet](const CBlock& block) {
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
            std::cout << "Difficulty: 0x" << std::hex << block.nBits << std::dec << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << std::endl;

            // Credit coinbase transaction to wallet using globally stored coinbase
            CTransactionRef coinbase;
            {
                std::lock_guard<std::mutex> lock(g_coinbaseMutex);
                coinbase = g_currentCoinbase;
            }

            if (coinbase && !coinbase->vout.empty()) {
                const CTxOut& coinbaseOut = coinbase->vout[0];

                // Extract public key hash from scriptPubKey to verify it's ours
                std::vector<uint8_t> pubkey_hash = WalletCrypto::ExtractPubKeyHash(coinbaseOut.scriptPubKey);
                std::vector<uint8_t> our_hash = wallet.GetPubKeyHash();

                // Verify this coinbase belongs to our wallet
                if (!pubkey_hash.empty() && pubkey_hash == our_hash) {
                    // BUG #6 FIX: Use wallet's actual address instead of reconstructing from hash
                    // The CDilithiumAddress constructor expects a public key, not a hash, so we use GetNewAddress()
                    // which returns the correct address that matches the coinbase scriptPubKey
                    CDilithiumAddress our_address = wallet.GetNewAddress();

                    // Get block height for UTXO tracking
                    uint32_t block_height = 0;
                    CBlockIndex tempIndex;
                    if (blockchain.ReadBlockIndex(block.hashPrevBlock, tempIndex)) {
                        block_height = tempIndex.nHeight + 1;
                    }

                    // Add coinbase UTXO to wallet
                    wallet.AddTxOut(coinbase->GetHash(), 0, coinbaseOut.nValue, our_address, block_height);

                    // Display credited amount
                    double amountDIL = static_cast<double>(coinbaseOut.nValue) / 100000000.0;
                    std::cout << "[Wallet] Coinbase credited: " << std::fixed << std::setprecision(8)
                              << amountDIL << " DIL" << std::endl;
                }
            }

            // Display updated wallet balance
            int64_t balance = wallet.GetBalance();
            double balanceInDIL = static_cast<double>(balance) / 100000000.0;
            std::cout << "[Wallet] Total Balance: " << std::fixed << std::setprecision(8)
                      << balanceInDIL << " DIL (" << balance << " ions)" << std::endl;
            std::cout << std::endl;

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

                    // [CONVERGENCE-DIAG] Log reorg completion from locally mined block
                    std::cout << "[CONVERGENCE-DIAG] ✅ REORG COMPLETED after locally mined block" << std::endl;

                    // Stop mining - need to reassess chain state
                    g_node_state.new_block_found = true;
                } else if (g_chainstate.GetTip() == pblockIndexPtr) {
                    std::cout << "[Blockchain] Block became new chain tip at height " << pblockIndexPtr->nHeight << std::endl;

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
                    auto connected_peers = g_peer_manager->GetConnectedPeers();

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
                            if (g_async_broadcaster->BroadcastBlock(blockHash, peer_ids)) {
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
        std::cout << "Starting P2P networking server..." << std::endl;

        // Set running flag before starting threads
        g_node_state.running = true;

        // Initialize socket layer (required for Windows)
        CSocketInit socket_init;

        // Create P2P listening socket
        CSocket p2p_socket;
        g_node_state.p2p_socket = &p2p_socket;

        // Bind to P2P port
        if (!p2p_socket.Bind(config.p2pport)) {
            std::cerr << "Failed to bind P2P socket on port " << config.p2pport << std::endl;
            std::cerr << "Error: " << p2p_socket.GetLastErrorString() << std::endl;
            return 1;
        }

        // Start listening
        if (!p2p_socket.Listen(10)) {
            std::cerr << "Failed to listen on P2P socket" << std::endl;
            std::cerr << "Error: " << p2p_socket.GetLastErrorString() << std::endl;
            return 1;
        }

        std::cout << "  [OK] P2P server listening on port " << config.p2pport << std::endl;

        // Set socket to non-blocking for graceful shutdown
        p2p_socket.SetNonBlocking(true);
        p2p_socket.SetReuseAddr(true);

        // Launch P2P accept thread
        std::thread p2p_thread([&p2p_socket, &connection_manager]() {
            std::cout << "  [OK] P2P accept thread started" << std::endl;

            while (g_node_state.running) {
                // Accept new connection (non-blocking)
                auto client = p2p_socket.Accept();

                if (client && client->IsValid()) {
                    std::string peer_addr = client->GetPeerAddress();
                    uint16_t peer_port = client->GetPeerPort();

                    std::cout << "[P2P] New peer connected: " << peer_addr << ":" << peer_port << std::endl;

                    // Create NetProtocol::CAddress from peer info
                    NetProtocol::CAddress addr;
                    addr.time = static_cast<uint32_t>(std::time(nullptr));
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = peer_port;

                    // Parse IPv4 address using inet_pton (Bitcoin Core standard)
                    struct in_addr ipv4_addr;
                    if (inet_pton(AF_INET, peer_addr.c_str(), &ipv4_addr) == 1) {
                        // Convert from network byte order to host byte order
                        uint32_t ipv4 = ntohl(ipv4_addr.s_addr);
                        addr.SetIPv4(ipv4);

                        // Bitcoin Core-style validation: IsRoutable() check
                        if (!addr.IsRoutable()) {
                            std::cout << "[P2P] Rejecting non-routable inbound connection from "
                                      << peer_addr << " (loopback/private/multicast)" << std::endl;
                            continue; // Drop non-routable addresses (Bitcoin Core behavior)
                        }

                        std::cout << "[HANDSHAKE-DIAG] Accepted routable inbound peer: " << peer_addr
                                  << " (0x" << std::hex << ipv4 << std::dec << ")" << std::endl;

                        // BUG #58 FIX: Check for self-connection on ACCEPT side
                        // When seed nodes try to connect to themselves via external IP,
                        // the outbound check may happen AFTER accept() creates a peer entry.
                        // We need to detect and reject self-connections on the inbound side too.
                        //
                        // Detection method: Get our own local addresses using gethostname + getaddrinfo
                        // and check if the peer IP matches any of our local interface IPs.
                        bool isSelfConnection = false;

                        // Method 1: Check if peer IP matches any local interface IP
                        // Get local hostname and resolve to IPs
                        char hostname[256];
                        if (gethostname(hostname, sizeof(hostname)) == 0) {
                            struct addrinfo hints, *result;
                            memset(&hints, 0, sizeof(hints));
                            hints.ai_family = AF_INET;
                            hints.ai_socktype = SOCK_STREAM;

                            if (getaddrinfo(hostname, nullptr, &hints, &result) == 0) {
                                for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
                                    struct sockaddr_in* addr_in = (struct sockaddr_in*)p->ai_addr;
                                    char local_ip[INET_ADDRSTRLEN];
                                    inet_ntop(AF_INET, &addr_in->sin_addr, local_ip, INET_ADDRSTRLEN);

                                    if (peer_addr == local_ip) {
                                        isSelfConnection = true;
                                        std::cout << "[P2P] Detected INBOUND self-connection from " << peer_addr
                                                  << " (matches local interface " << local_ip << ") - rejecting" << std::endl;
                                        break;
                                    }
                                }
                                freeaddrinfo(result);
                            }
                        }

                        // Method 2: Also check if peer IP matches our socket's local address
                        // (handles cases where hostname resolution doesn't work)
                        if (!isSelfConnection) {
                            std::string socket_local_ip = client->GetLocalAddress();
                            if (!socket_local_ip.empty() && socket_local_ip == peer_addr) {
                                isSelfConnection = true;
                                std::cout << "[P2P] Detected INBOUND self-connection from " << peer_addr
                                          << " (matches socket local IP) - rejecting" << std::endl;
                            }
                        }

                        if (isSelfConnection) {
                            continue; // Drop self-connection
                        }
                    } else {
                        std::cout << "[P2P] ERROR: Failed to parse inbound peer IPv4: " << peer_addr
                                  << " (invalid format)" << std::endl;
                        continue; // Invalid IP format - drop connection
                    }

                    // Handle connection via connection manager
                    int peer_id = connection_manager.AcceptConnection(addr, std::move(client));
                    if (peer_id >= 0) {
                        std::cout << "[P2P] Peer accepted and added to connection pool (peer_id=" << peer_id << ")" << std::endl;

                        // Perform version/verack handshake
                        if (connection_manager.PerformHandshake(peer_id)) {
                            std::cout << "[P2P] Sent version message to peer " << peer_id << std::endl;
                        } else {
                            std::cout << "[P2P] Failed to send version to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] Failed to accept peer connection" << std::endl;
                        // Note: socket is already moved, no need to close
                    }
                } else {
                    // No connection available, sleep briefly to avoid busy-wait
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }

            std::cout << "  P2P accept thread stopping..." << std::endl;
        });

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
                    addr.time = static_cast<uint32_t>(std::time(nullptr));
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    // Parse IPv4 address
                    uint32_t ip_addr = parseIPv4(ip);
                    if (ip_addr == 0) {
                        std::cerr << "    [FAIL] Invalid IP address: " << ip << std::endl;
                        continue;
                    }
                    addr.SetIPv4(ip_addr);

                    int peer_id = connection_manager.ConnectToPeer(addr);
                    if (peer_id >= 0) {
                        std::cout << "    [OK] Connected to " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;

                        // Perform version/verack handshake
                        if (connection_manager.PerformHandshake(peer_id)) {
                            std::cout << "    [OK] Sent version message to peer " << peer_id << std::endl;
                        } else {
                            std::cout << "    [FAIL] Failed to send version to peer " << peer_id << std::endl;
                        }
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
                    addr.time = static_cast<uint32_t>(std::time(nullptr));
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    // Parse IPv4 address
                    uint32_t ip_addr = parseIPv4(ip);
                    if (ip_addr == 0) {
                        std::cerr << "    [FAIL] Invalid IP address: " << ip << std::endl;
                        continue;
                    }
                    addr.SetIPv4(ip_addr);

                    int peer_id = connection_manager.ConnectToPeer(addr);
                    if (peer_id >= 0) {
                        std::cout << "    [OK] Added node " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;

                        // Perform version/verack handshake
                        if (connection_manager.PerformHandshake(peer_id)) {
                            std::cout << "    [OK] Sent version message to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "    [FAIL] Failed to add node " << node_addr << std::endl;
                    }
                } else {
                    std::cerr << "    [FAIL] Invalid address format: " << node_addr << " (expected ip:port)" << std::endl;
                }
            }
        }

        // Automatically connect to hardcoded seed nodes (unless --connect or --addnode specified)
        if (config.connect_nodes.empty() && config.add_nodes.empty()) {
            std::cout << "Connecting to seed nodes..." << std::endl;
            auto seeds = g_peer_manager->GetSeedNodes();

            for (const auto& seed_addr : seeds) {
                std::string ip_str = seed_addr.ToStringIP();
                uint16_t port = seed_addr.port;

                std::cout << "  Connecting to " << ip_str << ":" << port << "..." << std::endl;

                int peer_id = connection_manager.ConnectToPeer(seed_addr);
                if (peer_id >= 0) {
                    std::cout << "    [OK] Connected to seed node (peer_id=" << peer_id << ")" << std::endl;

                    // Perform version/verack handshake
                    if (connection_manager.PerformHandshake(peer_id)) {
                        std::cout << "    [OK] Sent version message to peer " << peer_id << std::endl;
                    } else {
                        std::cout << "    [FAIL] Failed to send version to peer " << peer_id << std::endl;
                    }
                } else {
                    std::cout << "    [FAIL] Failed to connect to " << ip_str << ":" << port << std::endl;
                }
            }
        }

        // Launch P2P message receive thread
        std::thread p2p_recv_thread([&connection_manager]() {
            std::cout << "  [OK] P2P receive thread started" << std::endl;

            while (g_node_state.running) {
                // Get all connected peers
                auto peers = g_peer_manager->GetConnectedPeers();

                // Try to receive messages from each peer
                for (const auto& peer : peers) {
                    connection_manager.ReceiveMessages(peer->id);
                }

                // Sleep briefly to avoid busy-wait
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            std::cout << "  P2P receive thread stopping..." << std::endl;
        });

        // Launch P2P maintenance thread (ping/pong keepalive, reconnection, score decay)
        // BUG #49 FIX: Add automatic peer reconnection and misbehavior score decay
        std::thread p2p_maint_thread([&connection_manager]() {
            std::cout << "  [OK] P2P maintenance thread started" << std::endl;

            int cycles_without_peers = 0;
            auto last_reconnect_attempt = std::chrono::steady_clock::now();

            while (g_node_state.running) {
                // Send periodic pings, check timeouts
                connection_manager.PeriodicMaintenance();

                // BUG #49: Check if we need to reconnect to seed nodes
                size_t peer_count = g_peer_manager ? g_peer_manager->GetConnectionCount() : 0;

                if (peer_count == 0) {
                    cycles_without_peers++;

                    // Attempt reconnection every 60 seconds when isolated
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_reconnect_attempt);

                    if (elapsed.count() >= 60) {
                        std::cout << "[P2P-Maintenance] No peers connected - attempting to reconnect to seed nodes..." << std::endl;
                        last_reconnect_attempt = now;

                        // Get seed nodes from peer manager
                        auto seed_nodes = g_peer_manager ? g_peer_manager->GetSeedNodes() : std::vector<NetProtocol::CAddress>();

                        // Try to connect to each seed node
                        int successful_connections = 0;
                        for (const auto& seed_addr : seed_nodes) {
                            std::string ip_str = seed_addr.ToStringIP();
                            uint16_t port = seed_addr.port;

                            std::cout << "[P2P-Maintenance] Attempting connection to seed " << ip_str << ":" << port << std::endl;

                            int peer_id = connection_manager.ConnectToPeer(seed_addr);
                            if (peer_id >= 0) {
                                std::cout << "[P2P-Maintenance] Connected to seed node (peer_id=" << peer_id << ")" << std::endl;

                                // Perform handshake
                                if (connection_manager.PerformHandshake(peer_id)) {
                                    std::cout << "[P2P-Maintenance] Handshake successful with peer " << peer_id << std::endl;
                                    successful_connections++;
                                } else {
                                    std::cout << "[P2P-Maintenance] Handshake failed with peer " << peer_id << std::endl;
                                }
                            } else {
                                std::cout << "[P2P-Maintenance] Failed to connect to seed " << ip_str << ":" << port << std::endl;
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

                // BUG #49: Decay misbehavior scores (reduce by 1 point per minute)
                // This happens every 30 seconds, so decay by 0.5 points
                if (g_peer_manager) {
                    g_peer_manager->DecayMisbehaviorScores();
                }

                // Sleep for 30 seconds between maintenance cycles
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }

            std::cout << "  P2P maintenance thread stopping..." << std::endl;
        });

        // Phase 4: Initialize RPC server
        std::cout << "Initializing RPC server..." << std::endl;
        CRPCServer rpc_server(config.rpcport);
        g_node_state.rpc_server = &rpc_server;

        // Register components with RPC server
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);
        rpc_server.RegisterBlockchain(&blockchain);
        rpc_server.RegisterChainState(&g_chainstate);
        rpc_server.RegisterMempool(&mempool);
        rpc_server.RegisterUTXOSet(&utxo_set);

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

                // BUG #55 FIX: Validation mode is already initialized (LIGHT mode)
                // Mining can start immediately - will use LIGHT mode, upgrade to FULL when ready
                if (randomx_is_mining_mode_ready()) {
                    std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                } else {
                    std::cout << "  [OK] Mining will start with LIGHT mode (FULL mode initializing...)" << std::endl;
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

        // Main loop
        while (g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // Check if new block was found and mining template needs update
            if (g_node_state.new_block_found.load()) {
                std::cout << "[Mining] New block found, updating template..." << std::endl;

                // Stop current mining
                if (miner.IsMining()) {
                    miner.StopMining();
                }

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
                    std::cout << "[IBD] Sync complete! Starting mining..." << std::endl;

                    // BUG #55 FIX: Validation mode already ready, mining can start immediately
                    if (randomx_is_mining_mode_ready()) {
                        std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                    } else {
                        std::cout << "  [OK] Mining will start with LIGHT mode (FULL mode initializing...)" << std::endl;
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
                    int peerHeight = g_peer_manager ? g_peer_manager->GetBestPeerHeight() : 0;
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
            // BUG #33 DEBUG: Add comprehensive logging to diagnose why blocks aren't downloading
            // BUG #49 FIX: Add exponential backoff when no peers available for IBD
            static int ibd_no_peer_cycles = 0;
            static auto last_ibd_attempt = std::chrono::steady_clock::now();

            if (g_headers_manager && g_block_fetcher) {
                int headerHeight = g_headers_manager->GetBestHeight();
                int chainHeight = g_chainstate.GetHeight();

                // If headers are ahead, we need to download blocks
                if (headerHeight > chainHeight) {
                    // Check if we should attempt IBD based on backoff
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_ibd_attempt);

                    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
                    int backoff_seconds = std::min(30, (1 << std::min(ibd_no_peer_cycles, 5)));

                    if (elapsed.count() >= backoff_seconds) {
                        // Check if we have any connected peers
                        size_t peer_count = g_peer_manager ? g_peer_manager->GetConnectionCount() : 0;

                        if (peer_count == 0) {
                            // No peers available
                            if (ibd_no_peer_cycles == 0) {
                                std::cout << "[IBD] No peers available for block download - entering backoff mode" << std::endl;
                            }
                            ibd_no_peer_cycles++;
                            last_ibd_attempt = now;

                            // Log periodically (every 10th cycle)
                            if (ibd_no_peer_cycles % 10 == 0) {
                                std::cout << "[IBD] Still waiting for peers (backoff: " << backoff_seconds
                                          << "s, attempts: " << ibd_no_peer_cycles << ")" << std::endl;
                            }
                        } else {
                            // We have peers, attempt IBD
                            if (ibd_no_peer_cycles > 0) {
                                std::cout << "[IBD] Peers available - resuming block download" << std::endl;
                                ibd_no_peer_cycles = 0;  // Reset backoff
                            }

                            std::cout << "[IBD] Headers ahead of chain - downloading blocks (header="
                                      << headerHeight << " chain=" << chainHeight << ")" << std::endl;

                            // Queue missing blocks for download (only queue next batch to avoid memory issues)
                            int blocksToQueue = std::min(100, headerHeight - chainHeight);  // Queue max 100 at a time
                            std::cout << "[IBD] Queueing " << blocksToQueue << " blocks for download..." << std::endl;

                            for (int h = chainHeight + 1; h <= chainHeight + blocksToQueue; h++) {
                                // Get header hash at this height
                                std::vector<uint256> hashesAtHeight = g_headers_manager->GetHeadersAtHeight(h);

                                for (const uint256& hash : hashesAtHeight) {
                                    // Only queue if we don't already have the block
                                    if (!g_chainstate.HasBlockIndex(hash) &&
                                        !g_block_fetcher->IsQueued(hash) &&
                                        !g_block_fetcher->IsDownloading(hash)) {
                                        g_block_fetcher->QueueBlockForDownload(hash, h, false);
                                        std::cout << "[IBD] Queued block " << hash.GetHex().substr(0, 16) << "... at height " << h << std::endl;
                                    }
                                }
                            }

                            // Get next blocks to fetch (respects 16 in-flight limit)
                            auto blocksToFetch = g_block_fetcher->GetNextBlocksToFetch(16);

                            if (blocksToFetch.empty() && g_block_fetcher->GetBlocksInFlight() == 0) {
                                // Nothing to fetch and nothing in flight - might have no suitable peers
                                ibd_no_peer_cycles++;
                                last_ibd_attempt = now;
                                std::cout << "[IBD] No blocks could be fetched (no suitable peers?)" << std::endl;
                            } else {
                                std::cout << "[IBD] Fetching " << blocksToFetch.size() << " blocks (max 16 in-flight)..." << std::endl;

                                // For each block, select peer and send GETDATA
                                int successful_requests = 0;
                                for (const auto& [hash, height] : blocksToFetch) {
                                    // BUG #64: Get preferred peer (the one that announced this block)
                                    NodeId preferred = g_block_fetcher->GetPreferredPeer(hash);
                                    // Select best peer for download, preferring announcing peer
                                    NodeId peer = g_block_fetcher->SelectPeerForDownload(hash, preferred);
                                    if (peer != -1) {
                                        // Request block from fetcher (updates in-flight tracking)
                                        if (g_block_fetcher->RequestBlock(peer, hash, height)) {
                                            // Send GETDATA message
                                            std::vector<NetProtocol::CInv> getdata;
                                            getdata.push_back(NetProtocol::CInv(NetProtocol::MSG_BLOCK_INV, hash));

                                            CNetMessage msg = message_processor.CreateGetDataMessage(getdata);
                                            connection_manager.SendMessage(peer, msg);
                                            std::cout << "[IBD] Sent GETDATA for block " << hash.GetHex().substr(0, 16) << "... (height " << height << ") to peer " << peer << std::endl;
                                            successful_requests++;
                                        }
                                    } else {
                                        // BUG #63 FIX: Re-queue block if no peer available
                                        // Without this, blocks are LOST - removed from queue but never added to in-flight
                                        // BUG #64: Use -1 for announcing_peer since we lost track, true for high priority
                                        g_block_fetcher->QueueBlockForDownload(hash, height, -1, true);
                                    }
                                }

                                if (successful_requests == 0 && !blocksToFetch.empty()) {
                                    // Had blocks to fetch but couldn't send any requests
                                    ibd_no_peer_cycles++;
                                    last_ibd_attempt = now;
                                    std::cout << "[IBD] Could not send any block requests (no suitable peers)" << std::endl;
                                }
                            }

                            // Check for timed-out block requests (60 second timeout)
                            auto timedOut = g_block_fetcher->CheckTimeouts();
                            if (!timedOut.empty()) {
                                std::cout << "[BlockFetcher] " << timedOut.size() << " block(s) timed out, retrying..." << std::endl;
                                g_block_fetcher->RetryTimedOutBlocks(timedOut);
                            }
                        }
                    }
                }
            }

            // Print mining stats every 10 seconds if mining
            // BUG #49: Add isolation detection when mining
            static int counter = 0;
            static int mining_without_peers_minutes = 0;
            static auto last_isolation_check = std::chrono::steady_clock::now();

            if (config.start_mining && ++counter % 10 == 0) {
                auto stats = miner.GetStats();
                std::cout << "[Mining] Hash rate: " << miner.GetHashRate() << " H/s, "
                         << "Total hashes: " << stats.nHashesComputed << std::endl;

                // BUG #49: Check if mining in isolation
                if (miner.IsMining()) {
                    size_t peer_count = g_peer_manager ? g_peer_manager->GetConnectionCount() : 0;

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
        std::cout << "Shutting down..." << std::endl;

        if (miner.IsMining()) {
            std::cout << "  Stopping mining..." << std::endl;
            miner.StopMining();
        }

        std::cout << "  Stopping P2P server..." << std::endl;
        connection_manager.Cleanup();  // Close all peer sockets
        p2p_socket.Close();
        if (p2p_thread.joinable()) {
            p2p_thread.join();
        }
        if (p2p_recv_thread.joinable()) {
            p2p_recv_thread.join();
        }
        if (p2p_maint_thread.joinable()) {
            p2p_maint_thread.join();
        }

        // Clear global P2P networking pointers (NW-005)
        g_connection_manager = nullptr;
        g_message_processor = nullptr;

        // Clean up transaction relay manager
        delete g_tx_relay_manager;
        g_tx_relay_manager = nullptr;

        // Reset peer manager unique_ptr
        g_peer_manager.reset();

        std::cout << "  Stopping RPC server..." << std::endl;
        rpc_server.Stop();

        std::cout << "  Closing UTXO database..." << std::endl;
        utxo_set.Close();

        std::cout << "  Closing blockchain database..." << std::endl;
        blockchain.Close();

        std::cout << "  Cleaning up IBD managers..." << std::endl;
        if (g_block_fetcher) {
            delete g_block_fetcher;
            g_block_fetcher = nullptr;
        }
        if (g_orphan_manager) {
            delete g_orphan_manager;
            g_orphan_manager = nullptr;
        }
        if (g_headers_manager) {
            delete g_headers_manager;
            g_headers_manager = nullptr;
        }

        std::cout << "  Cleaning up chain parameters..." << std::endl;
        delete Dilithion::g_chainParams;
        Dilithion::g_chainParams = nullptr;

        std::cout << std::endl;
        std::cout << "Dilithion node stopped cleanly" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;

        // Cleanup on error
        if (g_tx_relay_manager) {
            delete g_tx_relay_manager;
            g_tx_relay_manager = nullptr;
        }
        g_peer_manager.reset();

        // Clean up IBD managers
        if (g_block_fetcher) {
            delete g_block_fetcher;
            g_block_fetcher = nullptr;
        }
        if (g_orphan_manager) {
            delete g_orphan_manager;
            g_orphan_manager = nullptr;
        }
        if (g_headers_manager) {
            delete g_headers_manager;
            g_headers_manager = nullptr;
        }

        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        return 1;
    }

    return 0;
}
