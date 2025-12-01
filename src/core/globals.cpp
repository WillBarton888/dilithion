// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Global State Variables
 *
 * This file contains global state variables that are shared across the application.
 * Extracted from dilithion-node.cpp to allow utilities (genesis_gen, check-wallet-balance)
 * to link without requiring the full node implementation.
 */

#include <consensus/chain.h>
#include <atomic>

// Global chain state
CChainState g_chainstate;

// Global node state for RPC and signal handling
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};
    std::atomic<bool> mining_enabled{false};
    class CRPCServer* rpc_server = nullptr;
    class CMiningController* miner = nullptr;
    class CSocket* p2p_socket = nullptr;
    class CHttpServer* http_server = nullptr;
};

NodeState g_node_state;
