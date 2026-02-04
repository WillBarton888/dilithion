// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Global State Variables
 *
 * This file contains global state variables that are shared across the application.
 * Extracted from dilithion-node.cpp to allow utilities (genesis_gen, check-wallet-balance)
 * to link without requiring the full node implementation.
 *
 * Phase 1.2: Migrated to NodeContext pattern (Bitcoin Core style)
 * Old g_* globals are now accessed via g_node_context for better initialization control.
 */

#include <consensus/chain.h>
#include <core/node_context.h>
#include <atomic>

// Global chain state (kept separate for utilities that don't need full NodeContext)
CChainState g_chainstate;

// Legacy NodeState struct (kept for backward compatibility during migration)
// TODO: Remove after full migration to NodeContext
// NOTE: This struct MUST match the definition in dilithion-node.cpp exactly
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    std::atomic<uint64_t> template_version{0}; // BUG #109 FIX: Template version counter for race detection
    std::string mining_address_override;       // --mining-address=Dxxx (empty = use wallet default)
    bool rotate_mining_address{false};         // --rotate-mining-address (new HD address per block)
    class CRPCServer* rpc_server = nullptr;
    class CMiningController* miner = nullptr;
    class CWallet* wallet = nullptr;
    class CSocket* p2p_socket = nullptr;
    class CHttpServer* http_server = nullptr;
};

NodeState g_node_state;
