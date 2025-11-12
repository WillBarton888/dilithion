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
#include <api/http_server.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <core/chainparams.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <crypto/randomx_hash.h>

#include <iostream>
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

// Windows API macro conflicts - undef after including headers
#ifdef _WIN32
    #ifdef SendMessage
        #undef SendMessage  // Windows defines this as SendMessageA/SendMessageW
    #endif
#endif

// Global chain state
CChainState g_chainstate;

// Global async broadcaster pointer (initialized in main)
CAsyncBroadcaster* g_async_broadcaster = nullptr;

// Global node state for signal handling
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
    CSocket* p2p_socket = nullptr;
    CHttpServer* http_server = nullptr;
} g_node_state;

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
        std::cout << "Dilithion Node v1.0.0 - Post-Quantum Cryptocurrency" << std::endl;
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
        std::cout << "  --testnet             Use testnet (256x easier difficulty)" << std::endl;
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
        std::cout << "  " << program << " --testnet --addnode=170.64.203.134:18444 --mine     (Connect to seed)" << std::endl;
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

    if (!blockchain.ReadBestBlock(hashBestBlock)) {
        std::cerr << "[ERROR] Cannot read best block from blockchain" << std::endl;
        return std::nullopt;
    }

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
    CAddress minerAddress = wallet.GetNewAddress();
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
        std::cout << "  • Seed node:  170.64.203.134:18444 (official)" << std::endl;
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
        config.add_nodes.push_back("170.64.203.134:18444");
    }
    else if (!config.ParseArgs(argc, argv)) {
        config.PrintUsage(argv[0]);
        return 1;
    }

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Node v1.0.0" << std::endl;
    std::cout << "Post-Quantum Cryptocurrency" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    // Initialize chain parameters based on network
    if (config.testnet) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Testnet());
        std::cout << "Network: TESTNET (256x easier difficulty)" << std::endl;
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
        // LIGHT mode for broader compatibility (2GB RAM nodes)
        // LIGHT mode: ~256MB RAM, ~3-10 H/s (works on all testnet nodes)
        // FULL mode: ~2.5GB RAM, ~100 H/s (requires 4GB+ nodes)
        int light_mode = 1;  // LIGHT mode: ~256MB RAM, compatible with 2GB nodes
        randomx_init_for_hashing(rx_key, strlen(rx_key), light_mode);
        std::cout << "  [OK] RandomX initialized (" << (light_mode ? "LIGHT" : "FULL") << " mode)" << std::endl;

        // Load and verify genesis block
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
                        // HIGH-C001 FIX: No manual delete - smart pointer auto-destructs
                        delete Dilithion::g_chainParams;
                        return 1;
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

        // Set network magic for P2P protocol
        if (config.testnet) {
            NetProtocol::g_network_magic = NetProtocol::TESTNET_MAGIC;
        } else {
            NetProtocol::g_network_magic = NetProtocol::MAINNET_MAGIC;
        }

        // Phase 2: Initialize P2P networking (prepare for later)
        std::cout << "Initializing P2P components..." << std::endl;

        // Initialize peer manager as unique_ptr (global)
        g_peer_manager = std::make_unique<CPeerManager>();

        // Initialize transaction relay manager (global)
        g_tx_relay_manager = new CTxRelayManager();

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
            std::cout << "[P2P] Handshake with peer " << peer_id << " (" << msg.user_agent << ")" << std::endl;

            // Send verack in response
            connection_manager.SendVerackMessage(peer_id);

            // Check if handshake is now complete (both sides sent verack)
            auto peer = g_peer_manager->GetPeer(peer_id);
            if (peer && peer->IsHandshakeComplete()) {
                std::cout << "[P2P] Handshake complete with peer " << peer_id << std::endl;
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

            std::vector<NetProtocol::CInv> getdata;

            for (const auto& item : inv_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // Check if we already have this block
                    if (!blockchain.BlockExists(item.hash)) {
                        std::cout << "[P2P] Peer " << peer_id << " announced new block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                        getdata.push_back(item);
                    }
                }
            }

            // Request blocks we don't have
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
                std::cerr << "[P2P] ERROR: Cannot find parent block "
                          << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                std::cerr << "  This is an orphan block - need to download more blocks" << std::endl;
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
                } else {
                    std::cout << "[P2P] Block activated successfully" << std::endl;

                    // Check if this became the new tip
                    if (g_chainstate.GetTip() == pblockIndex.get()) {
                        std::cout << "[P2P] Updated best block to height " << pblockIndex->nHeight << std::endl;
                        g_node_state.new_block_found = true;
                    } else {
                        std::cout << "[P2P] Block is valid but not on best chain (orphan)" << std::endl;
                    }
                }
            } else {
                std::cerr << "[P2P] ERROR: Failed to activate block in chain" << std::endl;
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
        std::cout << "Initializing wallet..." << std::endl;
        CWallet wallet;

        // Generate initial key if wallet is empty
        if (wallet.GetAddresses().empty()) {
            std::cout << "  Generating initial address..." << std::endl;
            wallet.GenerateNewKey();
            CAddress addr = wallet.GetNewAddress();
            std::cout << "  [OK] Initial address: " << addr.ToString() << std::endl;
        } else {
            std::cout << "  [OK] Wallet loaded (" << wallet.GetAddresses().size() << " addresses)" << std::endl;
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
                    // The CAddress constructor expects a public key, not a hash, so we use GetNewAddress()
                    // which returns the correct address that matches the coinbase scriptPubKey
                    CAddress our_address = wallet.GetNewAddress();

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
            if (!blockchain.WriteBlockIndex(blockHash, *pblockIndex)) {
                std::cerr << "[Blockchain] ERROR: Failed to save block index" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

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

                    // Signal main loop to update mining template for next block
                    g_node_state.new_block_found = true;
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

                    // Parse IPv4 address (simple implementation for 127.0.0.1 style addresses)
                    // TODO: More robust IP parsing
                    if (peer_addr == "127.0.0.1" || peer_addr == "localhost") {
                        addr.SetIPv4(0x7F000001); // 127.0.0.1
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

        // Launch P2P maintenance thread (ping/pong keepalive)
        std::thread p2p_maint_thread([&connection_manager]() {
            std::cout << "  [OK] P2P maintenance thread started" << std::endl;

            while (g_node_state.running) {
                // Send periodic pings, check timeouts
                connection_manager.PeriodicMaintenance();

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
        if (config.start_mining) {
            g_node_state.mining_enabled = true;  // Track that mining was requested
            std::cout << std::endl;
            std::cout << "Starting mining..." << std::endl;

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
                if (g_node_state.mining_enabled.load()) {
                    auto templateOpt = BuildMiningTemplate(blockchain, wallet, false);
                    if (templateOpt) {
                        // Restart mining with new template
                        miner.StartMining(*templateOpt);
                        std::cout << "[Mining] Resumed mining on block height " << templateOpt->nHeight << std::endl;
                    } else {
                        std::cerr << "[ERROR] Failed to build new mining template!" << std::endl;
                    }
                }

                // Clear flag
                g_node_state.new_block_found = false;
            }

            // Periodic tasks
            // - Update mempool
            // - Process P2P messages
            // - Update mining stats

            // Print mining stats every 10 seconds if mining
            static int counter = 0;
            if (config.start_mining && ++counter % 10 == 0) {
                auto stats = miner.GetStats();
                std::cout << "[Mining] Hash rate: " << miner.GetHashRate() << " H/s, "
                         << "Total hashes: " << stats.nHashesComputed << std::endl;
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

        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        return 1;
    }

    return 0;
}
