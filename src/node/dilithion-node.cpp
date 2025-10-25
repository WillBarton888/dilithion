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
#include <net/peers.h>
#include <net/net.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>

#include <iostream>
#include <string>
#include <memory>
#include <csignal>
#include <thread>
#include <chrono>

// Global node state for signal handling
struct NodeState {
    bool running = false;
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
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
}

// Parse command line arguments
struct NodeConfig {
    std::string datadir = ".dilithion";
    uint16_t rpcport = 8332;
    bool start_mining = false;
    int mining_threads = 0;  // 0 = auto-detect

    bool ParseArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg.find("--datadir=") == 0) {
                datadir = arg.substr(10);
            }
            else if (arg.find("--rpcport=") == 0) {
                rpcport = std::stoi(arg.substr(10));
            }
            else if (arg == "--mine") {
                start_mining = true;
            }
            else if (arg.find("--threads=") == 0) {
                mining_threads = std::stoi(arg.substr(10));
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
        std::cout << "Options:" << std::endl;
        std::cout << "  --datadir=<path>      Data directory (default: .dilithion)" << std::endl;
        std::cout << "  --rpcport=<port>      RPC server port (default: 8332)" << std::endl;
        std::cout << "  --mine                Start mining automatically" << std::endl;
        std::cout << "  --threads=<n>         Mining threads (default: auto-detect)" << std::endl;
        std::cout << "  --help, -h            Show this help message" << std::endl;
        std::cout << std::endl;
        std::cout << "Post-Quantum Security Stack:" << std::endl;
        std::cout << "  Mining:      RandomX (CPU-friendly, ASIC-resistant)" << std::endl;
        std::cout << "  Signatures:  CRYSTALS-Dilithium3 (NIST PQC standard)" << std::endl;
        std::cout << "  Hashing:     SHA-3/Keccak-256 (quantum-resistant)" << std::endl;
        std::cout << std::endl;
    }
};

int main(int argc, char* argv[]) {
    // Parse configuration
    NodeConfig config;
    if (!config.ParseArgs(argc, argv)) {
        config.PrintUsage(argv[0]);
        return 1;
    }

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Node v1.0.0" << std::endl;
    std::cout << "Post-Quantum Cryptocurrency" << std::endl;
    std::cout << "======================================" << std::endl;
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
        std::cout << "  ✓ Blockchain database opened" << std::endl;

        std::cout << "Initializing mempool..." << std::endl;
        CTxMemPool mempool;
        std::cout << "  ✓ Mempool initialized" << std::endl;

        // Phase 2: Initialize P2P networking (prepare for later)
        std::cout << "Initializing P2P components..." << std::endl;
        CPeerManager peer_manager;
        CNetMessageProcessor message_processor;
        CConnectionManager connection_manager(peer_manager, message_processor);
        std::cout << "  ✓ P2P components ready (not started)" << std::endl;

        // Phase 3: Initialize mining controller
        std::cout << "Initializing mining controller..." << std::endl;
        int mining_threads = config.mining_threads > 0 ?
                            config.mining_threads :
                            std::thread::hardware_concurrency();
        CMiningController miner(mining_threads);
        g_node_state.miner = &miner;
        std::cout << "  ✓ Mining controller initialized (" << mining_threads << " threads)" << std::endl;

        // Phase 4: Initialize wallet
        std::cout << "Initializing wallet..." << std::endl;
        CWallet wallet;

        // Generate initial key if wallet is empty
        if (wallet.GetAddresses().empty()) {
            std::cout << "  Generating initial address..." << std::endl;
            wallet.GenerateNewKey();
            CAddress addr = wallet.GetNewAddress();
            std::cout << "  ✓ Initial address: " << addr.ToString() << std::endl;
        } else {
            std::cout << "  ✓ Wallet loaded (" << wallet.GetAddresses().size() << " addresses)" << std::endl;
        }

        // Phase 4: Initialize RPC server
        std::cout << "Initializing RPC server..." << std::endl;
        CRPCServer rpc_server(config.rpcport);
        g_node_state.rpc_server = &rpc_server;

        // Register components with RPC server
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);

        if (!rpc_server.Start()) {
            std::cerr << "Failed to start RPC server on port " << config.rpcport << std::endl;
            return 1;
        }
        std::cout << "  ✓ RPC server listening on port " << config.rpcport << std::endl;

        // Start mining if requested
        if (config.start_mining) {
            std::cout << std::endl;
            std::cout << "Starting mining..." << std::endl;

            // Create dummy block template for now
            // TODO: Get real block template from blockchain
            CBlock block;
            block.nVersion = 1;
            block.nTime = static_cast<uint32_t>(std::time(nullptr));
            block.nBits = 0x1d00ffff;  // Difficulty target
            block.nNonce = 0;

            // Create block template
            uint256 hashTarget;  // Default initialized to zero
            // TODO: Calculate hashTarget from nBits
            CBlockTemplate blockTemplate(block, hashTarget, 0);

            miner.StartMining(blockTemplate);

            std::cout << "  ✓ Mining started with " << mining_threads << " threads" << std::endl;
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
        g_node_state.running = true;
        while (g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

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

        std::cout << "  Stopping RPC server..." << std::endl;
        rpc_server.Stop();

        std::cout << "  Closing blockchain database..." << std::endl;
        blockchain.Close();

        std::cout << std::endl;
        std::cout << "Dilithion node stopped cleanly" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
