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
#include <node/genesis.h>
#include <node/block_index.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/socket.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <core/chainparams.h>
#include <consensus/pow.h>

#include <iostream>
#include <string>
#include <memory>
#include <csignal>
#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>
#include <optional>

// Global node state for signal handling
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
    CSocket* p2p_socket = nullptr;
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
                rpcport = std::stoi(arg.substr(10));
            }
            else if (arg.find("--port=") == 0) {
                p2pport = std::stoi(arg.substr(7));
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
        std::cout << "  --testnet             Use testnet (256x easier difficulty)" << std::endl;
        std::cout << "  --datadir=<path>      Data directory (default: network-specific)" << std::endl;
        std::cout << "  --port=<port>         P2P network port (default: network-specific)" << std::endl;
        std::cout << "  --rpcport=<port>      RPC server port (default: network-specific)" << std::endl;
        std::cout << "  --connect=<ip:port>   Connect to node (disables DNS seeds)" << std::endl;
        std::cout << "  --addnode=<ip:port>   Add node to connect to (repeatable)" << std::endl;
        std::cout << "  --mine                Start mining automatically" << std::endl;
        std::cout << "  --threads=<n>         Mining threads (default: auto-detect)" << std::endl;
        std::cout << "  --help, -h            Show this help message" << std::endl;
        std::cout << std::endl;
        std::cout << "Network Defaults:" << std::endl;
        std::cout << "  Mainnet:  datadir=.dilithion         port=8444  rpcport=8332" << std::endl;
        std::cout << "  Testnet:  datadir=.dilithion-testnet port=18444 rpcport=18332" << std::endl;
        std::cout << std::endl;
        std::cout << "P2P Examples:" << std::endl;
        std::cout << "  " << program << " --testnet --port=18445" << std::endl;
        std::cout << "  " << program << " --testnet --connect=127.0.0.1:18444" << std::endl;
        std::cout << "  " << program << " --testnet --addnode=127.0.0.1:18444" << std::endl;
        std::cout << std::endl;
        std::cout << "Post-Quantum Security Stack:" << std::endl;
        std::cout << "  Mining:      RandomX (CPU-friendly, ASIC-resistant)" << std::endl;
        std::cout << "  Signatures:  CRYSTALS-Dilithium3 (NIST PQC standard)" << std::endl;
        std::cout << "  Hashing:     SHA-3/Keccak-256 (quantum-resistant)" << std::endl;
        std::cout << std::endl;
    }
};

/**
 * Build mining template for next block
 * @param blockchain Reference to blockchain database
 * @param verbose If true, print detailed template information
 * @return Optional containing template if successful, nullopt if error
 */
std::optional<CBlockTemplate> BuildMiningTemplate(CBlockchainDB& blockchain, bool verbose = false) {
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

    // Create coinbase transaction (block reward)
    std::string coinbaseMsg = "Block " + std::to_string(nHeight) + " mined by Dilithion";
    block.vtx.resize(coinbaseMsg.size());
    memcpy(block.vtx.data(), coinbaseMsg.c_str(), coinbaseMsg.size());

    // Calculate merkle root (SHA3-256 hash of coinbase)
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
        std::cout << "  ✓ Blockchain database opened" << std::endl;

        std::cout << "Initializing mempool..." << std::endl;
        CTxMemPool mempool;
        std::cout << "  ✓ Mempool initialized" << std::endl;

        // Initialize RandomX (required for block hashing)
        std::cout << "Initializing RandomX..." << std::endl;
        extern void randomx_init_cache(const void* key, size_t key_len);
        const char* rx_key = "Dilithion";
        randomx_init_cache(rx_key, strlen(rx_key));
        std::cout << "  ✓ RandomX initialized" << std::endl;

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
        std::cout << "  ✓ Genesis block verified" << std::endl;

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
            std::cout << "  ✓ Genesis block saved to database" << std::endl;

            // Create genesis block index
            CBlockIndex genesisIndex(genesis);
            genesisIndex.phashBlock = genesisHash;
            genesisIndex.nHeight = 0;
            genesisIndex.nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

            if (!blockchain.WriteBlockIndex(genesisHash, genesisIndex)) {
                std::cerr << "ERROR: Failed to write genesis block index!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  ✓ Genesis block index saved (height 0)" << std::endl;

            // Set genesis as best block
            if (!blockchain.WriteBestBlock(genesisHash)) {
                std::cerr << "ERROR: Failed to set genesis as best block!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  ✓ Genesis block set as blockchain tip" << std::endl;
        } else {
            std::cout << "  ✓ Genesis block already in database" << std::endl;
        }

        // Set network magic for P2P protocol
        if (config.testnet) {
            NetProtocol::g_network_magic = NetProtocol::TESTNET_MAGIC;
        } else {
            NetProtocol::g_network_magic = NetProtocol::MAINNET_MAGIC;
        }

        // Phase 2: Initialize P2P networking (prepare for later)
        std::cout << "Initializing P2P components..." << std::endl;
        CPeerManager peer_manager;
        CNetMessageProcessor message_processor(peer_manager);
        CConnectionManager connection_manager(peer_manager, message_processor);

        // Register version handler to automatically respond with verack
        message_processor.SetVersionHandler([&connection_manager, &peer_manager](int peer_id, const NetProtocol::CVersionMessage& msg) {
            std::cout << "[P2P] Handshake with peer " << peer_id << " (" << msg.user_agent << ")" << std::endl;

            // Send verack in response
            connection_manager.SendVerackMessage(peer_id);

            // Check if handshake is now complete (both sides sent verack)
            auto peer = peer_manager.GetPeer(peer_id);
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

                        // Debug: Print block fields being sent
                        std::cout << "[DEBUG] Block fields being sent:" << std::endl;
                        std::cout << "  nVersion: " << block.nVersion << std::endl;
                        std::cout << "  nTime: " << block.nTime << std::endl;
                        std::cout << "  nBits: 0x" << std::hex << block.nBits << std::dec << std::endl;
                        std::cout << "  nNonce: " << block.nNonce << std::endl;
                        std::cout << "  hashPrevBlock: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                        std::cout << "  hashMerkleRoot: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;

                        // Send block to requesting peer
                        CNetMessage blockMsg = message_processor.CreateBlockMessage(block);
                        connection_manager.SendMessage(peer_id, blockMsg);
                    } else {
                        std::cout << "[P2P] Peer " << peer_id << " requested unknown block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
                // TODO: Handle MSG_TX_INV for transactions
            }
        });

        // Register block handler to validate and save received blocks
        message_processor.SetBlockHandler([&blockchain](int peer_id, const CBlock& block) {
            uint256 blockHash = block.GetHash();

            std::cout << "[P2P] Received block from peer " << peer_id << ": "
                      << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

            // Debug: Print received block fields
            std::cout << "[DEBUG] Block fields received:" << std::endl;
            std::cout << "  nVersion: " << block.nVersion << std::endl;
            std::cout << "  nTime: " << block.nTime << std::endl;
            std::cout << "  nBits: 0x" << std::hex << block.nBits << std::dec << std::endl;
            std::cout << "  nNonce: " << block.nNonce << std::endl;
            std::cout << "  hashPrevBlock: " << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout << "  hashMerkleRoot: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
            std::cout << "  Calculated hash: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

            // Basic validation: Check PoW
            uint256 target = CompactToBig(block.nBits);
            std::cout << "[DEBUG] PoW validation:" << std::endl;
            std::cout << "  Hash:   " << blockHash.GetHex() << std::endl;
            std::cout << "  Target: " << target.GetHex() << std::endl;
            std::cout << "  nBits:  0x" << std::hex << block.nBits << std::dec << std::endl;

            if (!CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[P2P] ERROR: Block from peer " << peer_id << " has invalid PoW" << std::endl;
                std::cerr << "  Hash must be less than target" << std::endl;
                return;
            }

            // Check if we already have this block
            if (blockchain.BlockExists(blockHash)) {
                std::cout << "[P2P] Block already in database, skipping" << std::endl;
                return;
            }

            // Save block to database
            if (blockchain.WriteBlock(blockHash, block)) {
                std::cout << "[P2P] Block saved to database" << std::endl;

                // Create and save block index
                CBlockIndex blockIndex(block);
                blockIndex.phashBlock = blockHash;
                blockIndex.nHeight = 0;  // Will be updated below

                // Try to get previous block's height
                CBlockIndex prevIndex;
                if (blockchain.ReadBlockIndex(block.hashPrevBlock, prevIndex)) {
                    blockIndex.nHeight = prevIndex.nHeight + 1;
                }

                if (blockchain.WriteBlockIndex(blockHash, blockIndex)) {
                    std::cout << "[P2P] Block index saved (height " << blockIndex.nHeight << ")" << std::endl;
                }

                // Check if this block extends the best chain
                uint256 currentBest;
                if (blockchain.ReadBestBlock(currentBest)) {
                    CBlockIndex currentBestIndex;
                    if (blockchain.ReadBlockIndex(currentBest, currentBestIndex)) {
                        // Simple longest chain rule: if new block has greater height, update tip
                        if (blockIndex.nHeight > currentBestIndex.nHeight) {
                            if (blockchain.WriteBestBlock(blockHash)) {
                                std::cout << "[P2P] Updated best block pointer to height " << blockIndex.nHeight << std::endl;

                                // Signal main loop to update mining template
                                g_node_state.new_block_found = true;
                            }
                        }
                    }
                }
            } else {
                std::cerr << "[P2P] ERROR: Failed to save block from peer " << peer_id << std::endl;
            }
        });

        std::cout << "  ✓ P2P components ready (not started)" << std::endl;

        // Phase 3: Initialize mining controller
        std::cout << "Initializing mining controller..." << std::endl;
        int mining_threads = config.mining_threads > 0 ?
                            config.mining_threads :
                            std::thread::hardware_concurrency();
        CMiningController miner(mining_threads);
        g_node_state.miner = &miner;
        std::cout << "  ✓ Mining controller initialized (" << mining_threads << " threads)" << std::endl;

        // Set up block found callback to save mined blocks
        miner.SetBlockFoundCallback([&blockchain, &connection_manager, &peer_manager, &message_processor](const CBlock& block) {
            // CRITICAL: Check shutdown flag FIRST to prevent database corruption during shutdown
            if (!g_node_state.running) {
                // Shutting down - discard this block to prevent race condition
                return;
            }

            uint256 blockHash = block.GetHash();
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "✓ BLOCK FOUND!" << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "Block hash: " << blockHash.GetHex() << std::endl;
            std::cout << "Block time: " << block.nTime << std::endl;
            std::cout << "Nonce: " << block.nNonce << std::endl;
            std::cout << "Difficulty: 0x" << std::hex << block.nBits << std::dec << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << std::endl;

            // Save block to blockchain database
            if (blockchain.WriteBlock(blockHash, block)) {
                std::cout << "[Blockchain] Block saved to database" << std::endl;

                // Create and save block index
                CBlockIndex blockIndex(block);  // Constructor copies header
                blockIndex.phashBlock = blockHash;
                blockIndex.nHeight = 0;  // Will be updated below

                // Try to get previous block's height
                CBlockIndex prevIndex;
                if (blockchain.ReadBlockIndex(block.hashPrevBlock, prevIndex)) {
                    blockIndex.nHeight = prevIndex.nHeight + 1;
                }

                if (blockchain.WriteBlockIndex(blockHash, blockIndex)) {
                    std::cout << "[Blockchain] Block index saved (height " << blockIndex.nHeight << ")" << std::endl;
                }

                // Update best block pointer
                if (blockchain.WriteBestBlock(blockHash)) {
                    std::cout << "[Blockchain] Updated best block pointer" << std::endl;
                }

                // Broadcast block to network (P2P block relay)
                auto connected_peers = peer_manager.GetConnectedPeers();
                if (!connected_peers.empty()) {
                    // Create inv message announcing new block
                    std::vector<NetProtocol::CInv> inv;
                    inv.push_back(NetProtocol::CInv(NetProtocol::MSG_BLOCK_INV, blockHash));

                    CNetMessage invMsg = message_processor.CreateInvMessage(inv);

                    int broadcast_count = 0;
                    for (const auto& peer : connected_peers) {
                        if (peer && peer->IsHandshakeComplete()) {
                            if (connection_manager.SendMessage(peer->id, invMsg)) {
                                broadcast_count++;
                            }
                        }
                    }

                    if (broadcast_count > 0) {
                        std::cout << "[P2P] Broadcasted block inv to " << broadcast_count << " peer(s)" << std::endl;
                    }
                }

                // Signal main loop to update mining template for next block
                g_node_state.new_block_found = true;
            } else {
                std::cerr << "[Blockchain] ERROR: Failed to save block to database!" << std::endl;
            }
        });

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

        std::cout << "  ✓ P2P server listening on port " << config.p2pport << std::endl;

        // Set socket to non-blocking for graceful shutdown
        p2p_socket.SetNonBlocking(true);
        p2p_socket.SetReuseAddr(true);

        // Launch P2P accept thread
        std::thread p2p_thread([&p2p_socket, &connection_manager]() {
            std::cout << "  ✓ P2P accept thread started" << std::endl;

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

        // Initiate outbound connections for --connect nodes
        if (!config.connect_nodes.empty()) {
            std::cout << "Initiating outbound connections..." << std::endl;
            for (const auto& node_addr : config.connect_nodes) {
                std::cout << "  Connecting to " << node_addr << "..." << std::endl;

                // Parse ip:port
                size_t colon_pos = node_addr.find(':');
                if (colon_pos != std::string::npos) {
                    std::string ip = node_addr.substr(0, colon_pos);
                    uint16_t port = std::stoi(node_addr.substr(colon_pos + 1));

                    NetProtocol::CAddress addr;
                    addr.time = static_cast<uint32_t>(std::time(nullptr));
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    // Simple IP parsing (127.0.0.1 style)
                    if (ip == "127.0.0.1" || ip == "localhost") {
                        addr.SetIPv4(0x7F000001);
                    }

                    int peer_id = connection_manager.ConnectToPeer(addr);
                    if (peer_id >= 0) {
                        std::cout << "    ✓ Connected to " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;

                        // Perform version/verack handshake
                        if (connection_manager.PerformHandshake(peer_id)) {
                            std::cout << "    ✓ Sent version message to peer " << peer_id << std::endl;
                        } else {
                            std::cout << "    ✗ Failed to send version to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "    ✗ Failed to connect to " << node_addr << std::endl;
                    }
                } else {
                    std::cerr << "    ✗ Invalid address format: " << node_addr << " (expected ip:port)" << std::endl;
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
                    uint16_t port = std::stoi(node_addr.substr(colon_pos + 1));

                    NetProtocol::CAddress addr;
                    addr.time = static_cast<uint32_t>(std::time(nullptr));
                    addr.services = NetProtocol::NODE_NETWORK;
                    addr.port = port;

                    if (ip == "127.0.0.1" || ip == "localhost") {
                        addr.SetIPv4(0x7F000001);
                    }

                    int peer_id = connection_manager.ConnectToPeer(addr);
                    if (peer_id >= 0) {
                        std::cout << "    ✓ Added node " << node_addr << " (peer_id=" << peer_id << ")" << std::endl;

                        // Perform version/verack handshake
                        if (connection_manager.PerformHandshake(peer_id)) {
                            std::cout << "    ✓ Sent version message to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "    ✗ Failed to add node " << node_addr << std::endl;
                    }
                } else {
                    std::cerr << "    ✗ Invalid address format: " << node_addr << " (expected ip:port)" << std::endl;
                }
            }
        }

        // Launch P2P message receive thread
        std::thread p2p_recv_thread([&connection_manager, &peer_manager]() {
            std::cout << "  ✓ P2P receive thread started" << std::endl;

            while (g_node_state.running) {
                // Get all connected peers
                auto peers = peer_manager.GetConnectedPeers();

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
            std::cout << "  ✓ P2P maintenance thread started" << std::endl;

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

        if (!rpc_server.Start()) {
            std::cerr << "Failed to start RPC server on port " << config.rpcport << std::endl;
            return 1;
        }
        std::cout << "  ✓ RPC server listening on port " << config.rpcport << std::endl;

        // Start mining if requested
        if (config.start_mining) {
            g_node_state.mining_enabled = true;  // Track that mining was requested
            std::cout << std::endl;
            std::cout << "Starting mining..." << std::endl;

            auto templateOpt = BuildMiningTemplate(blockchain, true);
            if (!templateOpt) {
                std::cerr << "ERROR: Failed to build mining template" << std::endl;
                std::cerr << "Blockchain may not be initialized. Cannot start mining." << std::endl;
                return 1;
            }

            miner.StartMining(*templateOpt);

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
                    auto templateOpt = BuildMiningTemplate(blockchain, false);
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

        std::cout << "  Stopping RPC server..." << std::endl;
        rpc_server.Stop();

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
        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        return 1;
    }

    return 0;
}
